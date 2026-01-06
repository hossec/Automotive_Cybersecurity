#!/usr/bin/env python3
# ============================================================
# DoIP UDS Client with TLS 1.2 and Downgrade Retry
# FIXED: Works with MACsec encrypted network
# ============================================================

import socket
import struct
import threading
import time
import sys
import ssl
import netifaces

# ================= S3 Shadow Timer =================
S3_TIMEOUT = 5
last_activity_time = 0
current_session = "DEFAULT"

# ===================== CONFIG =====================
DOIP_UDP_PORT = 13400      # UDP discovery only
TLS_DOIP_PORT = 13401      # All DoIP over TLS
BROADCAST = "10.0.0.255"

TESTER_ADDR = 0x0E80
KEY_CONST   = 0x11223344

# ===================== COLORS =====================
R="\033[0m"
G="\033[32m"
Y="\033[33m"
B="\033[34m"
C="\033[36m"
E="\033[31m"
M="\033[35m"

# ===================== STATE =====================
ecu_ip = None
ecu_logical = None
tcp = None
tls_socket = None

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
def success(m): print(f"{G}[SUCCESS]{R} {m}")

def tx(m):
    if m.lower() == "3e00":
        return
    print(f"{B}→ TX{R} 🔐 {m}")

def rx(m):
    if m.lower() == "7e00":
        return
    print(f"{Y}← RX{R} 🔐 {m}")

# ===================== DoIP =====================
def doip(ptype, payload):
    return struct.pack("!BBHI", 0x02, 0xFD, ptype, len(payload)) + payload

# ===================== GET BROADCAST ADDRESS =====================
def get_broadcast_address():
    """
    Find the correct broadcast address for the current network interface
    This is needed for MACsec networks where macsec0 is the active interface
    """
    try:
        # Try to find macsec0 first (MACsec interface)
        interfaces = netifaces.interfaces()
        
        for iface in ['macsec0', 'vethA', 'eth0', 'ens33']:
            if iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        if 'broadcast' in addr_info:
                            info(f"Found broadcast address {addr_info['broadcast']} on {iface}")
                            return addr_info['broadcast'], iface
                        # If no broadcast, calculate it
                        if 'addr' in addr_info and 'netmask' in addr_info:
                            ip = addr_info['addr']
                            if ip.startswith('10.0.0.'):
                                info(f"Using interface {iface} with IP {ip}")
                                return "10.0.0.255", iface
    except Exception as e:
        warn(f"Could not auto-detect network: {e}")
    
    return "10.0.0.255", None

# ===================== STEP 1: UDP DISCOVERY =====================
def discover():
    """
    Step 1: UDP broadcast to find ECU IP and VIN
    FIXED: Binds to correct interface for MACsec
    """
    global ecu_ip, ecu_logical

    broadcast_addr, interface = get_broadcast_address()
    
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind to specific interface if found
    if interface:
        try:
            # Bind to the interface's IP address
            udp.bind(('10.0.0.20', 0))  # Bind to tester's IP
            info(f"Bound to tester address 10.0.0.20")
        except:
            udp.bind(('', 0))
    else:
        udp.bind(('', 0))
    
    udp.settimeout(5)

    info("📡 Step 1: UDP Vehicle Discovery (unencrypted)")
    info(f"Broadcasting to {broadcast_addr}:{DOIP_UDP_PORT}")
    
    try:
        udp.sendto(doip(0x0001, b""), (broadcast_addr, DOIP_UDP_PORT))
        
        data, addr = udp.recvfrom(4096)
        payload = data[8:]

        vin = payload[:17].decode(errors="ignore")
        ecu_logical = struct.unpack("!H", payload[17:19])[0]
        ecu_ip = addr[0]

        ok(f"ECU Found: {ecu_ip}")
        ok(f"VIN: {vin}")
        ok(f"Logical Address: 0x{ecu_logical:04X}")
        print()
        
    except socket.timeout:
        err("UDP discovery timeout!")
        info("Trying direct connection to known ECU address...")
        # Fallback: try known ECU address
        ecu_ip = "10.0.0.10"
        ecu_logical = 0x0E00
        warn(f"Using fallback ECU address: {ecu_ip}")
        warn(f"Using fallback logical address: 0x{ecu_logical:04X}")
        print()

# ===================== STEP 2: TLS HANDSHAKE =====================
def establish_tls(use_downgraded=False):
    """
    Step 2: Establish TLS tunnel BEFORE any DoIP
    This happens BEFORE routing activation
    FIXED: Now includes compatible ciphers for TLS 1.1
    """
    global tcp, tls_socket
    
    if use_downgraded:
        info(f"🔻 Step 2: TLS 1.1 Handshake on port {TLS_DOIP_PORT} (downgraded)")
        # Create TLS 1.1 context (downgraded)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:
            context.minimum_version = ssl.TLSVersion.TLSv1_1
            context.maximum_version = ssl.TLSVersion.TLSv1_1
            
            # FIXED: Use TLS 1.1 compatible cipher suites
            context.set_ciphers('ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA:DES-CBC3-SHA:@SECLEVEL=0')
            
        except Exception as e:
            # Fallback if TLS 1.1 not available
            warn(f"TLS 1.1 not available: {e}")
            warn("Using TLS 1.2 instead")
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        info(f"🔒 Step 2: TLS 1.2 Handshake on port {TLS_DOIP_PORT}")
        # Create TLS 1.2 context - prefer modern ciphers
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # Use strong TLS 1.2 ciphers
        context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256')
    
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Create TCP socket
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    info(f"🔌 Connecting to {ecu_ip}:{TLS_DOIP_PORT}...")
    tcp.connect((ecu_ip, TLS_DOIP_PORT))
    
    # TLS handshake
    if use_downgraded:
        info("🤝 Initiating TLS 1.1 handshake (downgraded)...")
    else:
        info("🤝 Initiating TLS 1.2 handshake...")
    
    tls_socket = context.wrap_socket(tcp, server_hostname="ECU")
    
    ok(f"✅ TLS Handshake Complete!")
    ok(f"🔐 Protocol: {tls_socket.version()}")
    ok(f"🔐 Cipher: {tls_socket.cipher()[0]}")
    
    if use_downgraded:
        warn(f"⚠️  Using downgraded TLS 1.1!")
    else:
        ok(f"🔒 Secure channel established (TLS 1.2)")
    print()

# ===================== STEP 3: DoIP ROUTING (ENCRYPTED) =====================
def routing():
    """
    Step 3: DoIP Routing Activation over TLS
    This is the FIRST DoIP message, and it's encrypted
    """
    info("🔐 Step 3: DoIP Routing Activation (encrypted)")
    
    payload = struct.pack("!HBBI", TESTER_ADDR, 0x10, 0, 0)
    tls_socket.send(doip(0x0005, payload))
    
    resp = tls_socket.recv(4096)
    
    ok("✅ Routing Activation Response received (encrypted)")
    ok("🔐 All DoIP communication now secure")
    print()

# ===================== SEND / RECV =====================
def send_uds(data):
    global session_token

    if token_required and data[0] in (0x10,0x11) and session_token is not None:
        data += bytes([session_token])
    tx(data.hex())
    frame = struct.pack("!HH", TESTER_ADDR, ecu_logical) + data
    tls_socket.send(doip(0x8001, frame))
    reset_s3_timer()

    resp = tls_socket.recv(4096)
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
    if r[0] == 0x51:
        ok("ECU Reset acknowledged")

        # ===== RESET TESTER STATE =====
        security_unlocked = False
        token_required = False
        session_token = None
        current_session = "DEFAULT"

        warn("Tester state reset (Security locked, Session default)")
        return

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
    tls_info = f"{tls_socket.version()}" if tls_socket else "N/A"
    cipher = tls_socket.cipher()[0] if tls_socket else "N/A"
    print(f"""
{C}========== STATUS =========={R}
 ECU IP       : {ecu_ip}
 TLS Port     : {TLS_DOIP_PORT}
 Session      : {current_session}
 Security     : {"🔓 UNLOCKED" if security_unlocked else "🔒 LOCKED"}
 Token        : {session_token if session_token else "None"}
 TLS Protocol : {tls_info}
 TLS Cipher   : {cipher}
 🔐 Encryption : ACTIVE
 🛡️  MACsec    : ACTIVE (Layer 2)
============================
""")

def cli():
    print(f"""
{M}🔒 Secure DoIP Commands:{R}
 {C}Session Control:{R}
   10 01 / 10 02 / 10 03   → Default/Programming/Extended Session
 
 {C}Security:{R}
   27 01                   → Request Seed (auto-sends key)
 
 {C}Data Identifiers:{R}
   22 F190                 → Read VIN
   22 F18C                 → Read Model
   22 F1A0                 → Read Config
   2E F1A0 XX              → Write Config (01/02/03/04)
 
 {C}Routines:{R}
   31 01 1234 / 5678       → Start Routine
   31 02 1234 / 5678       → Stop Routine
   31 03 1234 / 5678       → Get Results
 
 {C}Control:{R}
   s                       → Start TesterPresent
   f                       → Stop TesterPresent
   st                      → Show Status
   c                       → Show Commands
   e                       → Exit

{Y}🔐 All traffic encrypted via TLS + MACsec{R}
""")

    while True:
        cmd = input(f"{M}>{R} ").strip()
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
            warn("Invalid hex input (example: 10 03)")
            continue

        send_uds(data)

def s3_shadow_watchdog():
    global current_session
    while True:
        time.sleep(0.5)

        if current_session != "DEFAULT":
            if time.time() - last_activity_time > S3_TIMEOUT:
                info("S3 timeout - session may have expired")
                current_session = "DEFAULT"

# ===================== MAIN =====================
print("="*70)
print(f"{M}🔒 DoIP UDS Tester with TLS 1.2 + MACsec Encryption{R}")
print(f"{M}📋 Connection Flow:{R}")
print(f"{M}   0. MACsec Layer 2 encryption (already active){R}")
print(f"{M}   1. UDP Discovery → Find ECU{R}")
print(f"{M}   2. TLS 1.2 Handshake → Establish encryption{R}")
print(f"{M}   3. DoIP Routing  → Activate connection (encrypted){R}")
print(f"{M}   4. UDS Diagnostics → All commands doubly encrypted{R}")
print(f"{Y}   ⚠️  Will retry with TLS 1.1 if downgrade attack occurs{R}")
print("="*70)
print()

# Execute connection sequence
discover()

# Try TLS 1.2 first (may be attacked and downgraded)
try:
    establish_tls(use_downgraded=False)
    routing()
except ssl.SSLError as e:
    error_str = str(e)
    if "PROTOCOL_VERSION" in error_str or "ALERT" in error_str or "UNSUPPORTED_PROTOCOL" in error_str or "handshake failure" in error_str.lower():
        warn("⚠️  TLS 1.2 handshake failed (possible downgrade attack)")
        info("🔄 Retrying with TLS 1.1 (downgraded)...")
        time.sleep(3)  # Wait for attacker to disconnect
        
        try:
            # Close old socket
            if tcp:
                tcp.close()
            
            establish_tls(use_downgraded=True)
            routing()
            success("✅ Connected with downgraded TLS 1.1!")
            warn("⚠️  This connection is vulnerable! Downgrade attack succeeded!")
        except Exception as e2:
            err(f"Connection failed: {e2}")
            sys.exit(1)
    else:
        err(f"TLS Error: {e}")
        sys.exit(1)
except Exception as e:
    err(f"Connection error: {e}")
    sys.exit(1)

# Start session watchdog
threading.Thread(target=s3_shadow_watchdog, daemon=True).start()

# Enter CLI
cli()

# Cleanup
if tls_socket:
    tls_socket.close()
if tcp:
    tcp.close()