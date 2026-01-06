#!/usr/bin/env python3
# ============================================================
# REAL UDS TESTER over DoIP
# Smart | Stateful | Token-Aware | OEM-like
# ============================================================

import socket
import struct
import threading
import time
import sys

# ================= S3 Shadow Timer (Tester-side) =================
S3_TIMEOUT = 5          # لازم يساوي S3 في السيرفر
last_activity_time = 0
current_session = "DEFAULT"


# ===================== CONFIG =====================
DOIP_PORT = 13400
BROADCAST = "ff02::1"

TESTER_ADDR = 0x0E80
KEY_CONST   = 0x11223344

# ===================== COLORS =====================
R="\033[0m"
G="\033[32m"
Y="\033[33m"
B="\033[34m"
C="\033[36m"
E="\033[31m"

# ===================== STATE =====================
ecu_ip = None
ecu_logical = None
tcp = None

security_unlocked = False
current_session = 1
session_token = None
token_required = False

last_seed = None
tp_running = False

# ===================== NRC MAP =====================
NRC = {
    0x10:"General Reject",
    0x11:"Service Not Supported",
    0x12:"SubFunction Not Supported",
    0x13:"Invalid Length",
    0x22:"Conditions Not Correct",
    0x24:"Request Sequence Error (Token?)",
    0x31:"Request Out Of Range",
    0x33:"Security Access Required",
    0x35:"Invalid Key",
    0x36:"Exceeded Attempts",
    0x37:"ECU Locked",
    0x78:"Response Pending",
    0x7E:"Sub-function not supported in active session"
}

# ===================== PRINT HELPERS =====================
def ok(m):   print(f"{G}[ OK ]{R} {m}")
def info(m): print(f"{C}[INFO]{R} {m}")
def warn(m): print(f"{Y}[WARN]{R} {m}")
def err(m):  print(f"{E}[ERR ]{R} {m}")

def tx(m):
    if m.lower() == "3e00":
        return
    print(f"{B}→ TX{R} {m}")

def rx(m):
    if m.lower() == "7e00":
        return
    print(f"{Y}← RX{R} {m}")

# ===================== DoIP =====================
def doip(ptype, payload):
    return struct.pack("!BBHI", 0x02, 0xFD, ptype, len(payload)) + payload

# ===================== DISCOVERY =====================

def discover():
    global ecu_ip, ecu_logical

    udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    # Ephemeral port (OEM correct)
    udp.bind(("::", 0))

    ifindex = socket.if_nametoindex("vethA")
    udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)

    udp.settimeout(3)

    udp.sendto(doip(0x0001, b""), ("ff02::1", DOIP_PORT, 0, ifindex))


    data, addr = udp.recvfrom(4096)

    payload = data[8:]
    vin = payload[:17].decode(errors="ignore")
    ecu_logical = struct.unpack("!H", payload[17:19])[0]
    ecu_ip = "fd00::10"


    ok(f"ECU FOUND @ {ecu_ip}")
    ok(f"VIN = {vin}")
    ok(f"ECU Logical = 0x{ecu_logical:04X}")


 

# ===================== ROUTING =====================
def routing():
    global tcp

    tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    ifindex = socket.if_nametoindex("vethA")
    print("DEBUG socket family =", tcp.family)

    tcp.connect((ecu_ip, DOIP_PORT, 0, ifindex))

    payload = struct.pack("!HBBI", TESTER_ADDR, 0x10, 0, 0)
    tx("Routing Activation")
    tcp.send(doip(0x0005, payload))
    tcp.recv(4096)

    ok("Routing Response Received")



# ===================== SEND / RECV =====================
def send_uds(data):
    global session_token

    if token_required and data[0] in (0x10,0x11) and session_token is not None:
        data += bytes([session_token])
    tx(data.hex())
    frame = struct.pack("!HH", TESTER_ADDR, ecu_logical) + data
    tcp.send(doip(0x8001, frame))
    reset_s3_timer()


    resp = tcp.recv(4096)
    uds = resp[12:]

    if not uds:
        warn("Empty response")
        return

    rx(uds.hex())
    handle_response(uds)

# ===================== RESPONSE LOGIC =====================
def handle_response(r):
    global security_unlocked, last_seed
    global current_session, session_token, token_required

    if not r:
        warn("Empty UDS response")
        return

    reset_s3_timer()

    # ===== Session Control Tracking =====
    if r[0] == 0x50 and len(r) >= 2:
        if r[1] == 0x01:
            current_session = "DEFAULT"
            ok("Default Session active")

        elif r[1] == 0x02:
            current_session = "PROGRAMMING"
            ok("Programming Session active")

        elif r[1] == 0x03:
            current_session = "EXTENDED"
            ok("Extended Session active")

    # ===== NRC Handling =====
    if r[0] == 0x7F:
        sid = r[1]
        code = r[2]

        if code == 0x7E:
            warn("ECU reports wrong session → Session expired (S3 timeout)")
            current_session = "DEFAULT"

        err(f"NRC {code:02X} → {NRC.get(code,'Unknown')}")
        return

    sid = r[0] - 0x40

    # -------- Security --------
    if sid == 0x27:
        sub = r[1]
        if sub == 0x01:
            last_seed = int.from_bytes(r[2:6],'big')
            ok(f"Seed received: {last_seed:08X}")
            key = (last_seed + KEY_CONST) & 0xFFFFFFFF
            info(f"Auto Key = {key:08X}")
            send_uds(bytes([0x27,0x02]) + key.to_bytes(4,'big'))
            return

        if sub == 0x02:
            security_unlocked = True
            ok("Security Access GRANTED 🔓")
            return

    # -------- Session --------
    if sid == 0x10:
        name = {1:"Default",2:"Programming",3:"Extended"}.get(r[1],"?")
        ok(f"Entered {name} Session")

        if len(r) > 2:
            session_token = r[2]
            token_required = True
            ok(f"Session Token received = 0x{session_token:02X}")
        return

    # -------- Generic --------
    if r[0] == 0x62:
        did = r[1:3].hex()
        data = r[3:].hex()
        ok(f"DID {did} → {data}")
        return

    # -------- ECU Reset --------
    if r[0] == 0x51:   # 0x11 + 0x40
        ok("ECU Reset acknowledged")

        # ===== RESET TESTER STATE =====
        security_unlocked = False
        token_required = False
        session_token = None
        current_session = "DEFAULT"

        warn("Tester state reset (Security locked, Session default)")
        return

    #info("Positive Response")


# ===================== TESTER PRESENT =====================
def tp_loop():
    while tp_running:
        send_uds(bytes([0x3E,0x00]))
        time.sleep(2)

def start_tp():
    global tp_running
    if not tp_running:
        tp_running = True
        threading.Thread(target=tp_loop,daemon=True).start()
        ok("TesterPresent started")

def stop_tp():
    global tp_running
    tp_running = False
    info("TesterPresent stopped")

def reset_s3_timer():
    global last_activity_time
    last_activity_time = time.time()


# ===================== CLI =====================
def status():
    print(f"""
{C}======== STATUS ========{R}
 ECU IP      : {ecu_ip}
 Session     : {current_session}
 Security    : {"UNLOCKED" if security_unlocked else "LOCKED"}
 Token       : {session_token}
===========================
""")

def cli():
    print(f"""
{C}Commands:{R}
 10 01 / 10 02 / 10 03   → Enter Session Default/Programming/Extended 
 27 01                   → Security Access
 22 F190 / F18C / F1A0   → Read DID
 2E F1A0                 → Write DID CONFIG
 31 01 1234 / 5678       → Start Routine RID
 31 02 1234 / 5678       → Stop Routine RID
 31 03 1234 / 5678       → Result Routine RID
 s                       → Start TesterPresent
 f                       → Stop TesterPresent
 st                      → Show Status
 c                       → Show Commands
 e                       → Exit
""")

    while True:
        cmd = input("> ").strip()
        if cmd == "e":
            break
        if cmd == "s":
            start_tp(); continue
        if cmd == "f":
            stop_tp(); continue
        if cmd == "st":
            status(); continue
        if cmd == "c":
            cli(); continue
        try:
            data = bytes.fromhex(cmd)
        except ValueError:
            warn("Invalid hex input (use format like: 10 03)")
            continue

        send_uds(data)


def s3_shadow_watchdog():
    global current_session
    while True:
        time.sleep(0.5)

        if current_session != "DEFAULT":
            if time.time() - last_activity_time > S3_TIMEOUT:
                print("[INFO] Possible S3 timeout (no activity)")
                current_session = "DEFAULT"

# ===================== MAIN =====================
print(f"{C}=== REAL DoIP UDS TESTER ==={R}")
discover()


routing()
threading.Thread(target=s3_shadow_watchdog, daemon=True).start()

cli()
