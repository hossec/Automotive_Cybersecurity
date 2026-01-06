#!/usr/bin/env python3
"""
FULL ECU – UDS over DoIP over TLS 1.2
TLS tunnel established BEFORE any DoIP communication
FIXED: Compatible ciphers for TLS 1.1 downgrade attacks
"""

import socket, struct, threading, time, random, ssl

# ==========================================================
# DoIP CONFIG
# ==========================================================
DOIP_UDP_PORT = 13400      # UDP discovery only
TLS_DOIP_PORT = 13401      # All DoIP over TLS
LOGICAL_ADDR_ECU = 0x0E00
LOGICAL_ADDR_TESTER = 0x0E80

ALLOWED_TESTERS = {
    0x0E80
}

VIN   = b"12345678901234567"
MODEL = b"ABCD"
EID   = b"\x01\x02\x03\x04\x05\x06"
GID   = b"\xAA\xBB\xCC\xDD\xEE\xFF"

# ==========================================================
# TLS CONFIG
# ==========================================================
TLS_CERT_FILE = "server.crt"
TLS_KEY_FILE = "server.key"

# ==========================================================
# ECU STATE
# ==========================================================
CONFIG = b"01"

SESSION_FLAG = 1
SEC_ACCESS_FLAG = 0

session_token = 0xAA
token_runtime_enabled = False

KEY = 0x11223344
LAST_SEED = None
LAST_REQUEST_DATA = b""

MAX_ATTEMPTS = 3
LOCKOUT_TIME = 600
SEED_DELAY = 5
S3 = 5

CONNECTED_TESTER_LOGICAL = None

attempts = 0
locked = False
lockout_timer = 0
seed_given = False
seed_delay_timer = 0
last_activity_time = time.time()

tcp_conn = None

# ==========================================================
# Helpers
# ==========================================================
def doip_header(ptype, payload):
    return struct.pack("!BBHI", 0x02, 0xFD, ptype, len(payload)) + payload

def doip_send_uds(uds, conn):
    frame = struct.pack("!HH", LOGICAL_ADDR_ECU, LOGICAL_ADDR_TESTER) + uds
    conn.send(doip_header(0x8001, frame))
    print(f"[ECU] 🔒 TX (encrypted): {uds.hex()}")


def send_nrc(sid, nrc, conn):
    doip_send_uds(bytes([0x7F, sid, nrc]), conn)

def send_pos(sid=None, sub=None, did=None, data=b"", conn=None):
    resp = (sid + 0x40) & 0xFF
    if sub is not None:
        payload = bytes([resp, sub]) + data
    elif did is not None:
        payload = bytes([resp]) + did.to_bytes(2,"big") + data
    else:
        payload = bytes([resp]) + data
    doip_send_uds(payload, conn)

# ==========================================================
# CONFIG helpers
# ==========================================================
def parse_config_value(data):
    try:
        txt = bytes(data).decode()
        if txt in ("01","02","03","04"):
            return txt.encode()
    except:
        pass
    return None

def token_enabled(): return CONFIG in (b"03", b"04")
def lockout_enabled(): return CONFIG in (b"02", b"04")

# ==========================================================
# Security Access
# ==========================================================
def handle_security_access(sub, conn=None):
    global LAST_SEED, SEC_ACCESS_FLAG, attempts, locked
    global seed_given, seed_delay_timer, token_runtime_enabled

    now = time.time()

    if lockout_enabled() and locked and now < lockout_timer:
        send_nrc(0x27,0x37, conn)
        return

    if sub == 0x01:
        if seed_given and now < seed_delay_timer:
            send_nrc(0x27,0x78, conn); return
        LAST_SEED = random.randint(0x1000,0x1FFF)
        seed_given = True
        seed_delay_timer = now + SEED_DELAY
        send_pos(0x27,0x01,data=LAST_SEED.to_bytes(4,'big'), conn=conn)
        return

    if sub == 0x02:
        if len(LAST_REQUEST_DATA) < 6:
            send_nrc(0x27,0x22, conn); return
        recv = int.from_bytes(LAST_REQUEST_DATA[2:6],'big')
        if recv == (LAST_SEED + KEY) & 0xFFFFFFFF:
            SEC_ACCESS_FLAG = 1
            attempts = 0
            seed_given = False
            send_pos(0x27,0x02,conn=conn)
            if token_enabled():
                token_runtime_enabled = True
            return
        attempts += 1

        if lockout_enabled() and attempts >= MAX_ATTEMPTS:
            locked = True
            lockout_timer = now + LOCKOUT_TIME
            send_nrc(0x27,0x36, conn)
            return

        send_nrc(0x27,0x35, conn)
        return

    send_nrc(0x27,0x12, conn)

# ==========================================================
# Session Control
# ==========================================================
def handle_session_control(sub, conn=None):
    global SESSION_FLAG
    if SEC_ACCESS_FLAG != 1:
        send_nrc(0x10,0x33, conn); return
    if sub not in (1,2,3):
        send_nrc(0x10,0x12, conn); return
    SESSION_FLAG = sub
    if token_runtime_enabled:
        doip_send_uds(bytes([0x50,sub,session_token]), conn)
    else:
        send_pos(0x10,sub,conn=conn)

# ==========================================================
# Reset
# ==========================================================
def handle_reset(sub, conn=None):
    global SESSION_FLAG, SEC_ACCESS_FLAG, token_runtime_enabled, VIN, MODEL, CONFIG
    if SEC_ACCESS_FLAG != 1:
        send_nrc(0x11,0x33, conn); return
    send_pos(0x11,sub,conn=conn)
    SESSION_FLAG = 1
    SEC_ACCESS_FLAG = 0
    token_runtime_enabled = False
    VIN   = b"12345678901234567"
    MODEL = b"ABCD"
    CONFIG = b"01"

# ==========================================================
# Routine Control
# ==========================================================
def handle_routine(msg, conn=None):
    sub = msg[1]
    rid = (msg[2]<<8)|msg[3]
    if sub not in (0x01,0x02,0x03):
        send_nrc(0x31,0x12, conn); return
    if rid not in (0x1234,0x5678):
        send_nrc(0x31,0x31, conn); return

    elif rid == (0x1234):
        send_pos(0x31,sub,data=msg[2:4], conn=conn)

    elif rid == (0x5678):
        if SESSION_FLAG in (2,3):
            send_pos(0x31,sub,data=msg[2:4], conn=conn)
        else:
            send_nrc(0x31, 0x7E, conn)

# ==========================================================
# UDS DISPATCH
# ==========================================================
def uds_dispatch(msg, conn):
    global LAST_REQUEST_DATA, last_activity_time, CONFIG, token_runtime_enabled

    LAST_REQUEST_DATA = msg
    subb = (msg[1]) if len(msg) > 1 else 0
    last_activity_time = time.time()

    sid = msg[0]

    if token_runtime_enabled and sid in (0x10,0x11):
        if msg[-1] != session_token:
            send_nrc(sid,0x24, conn); return
        msg = msg[:-1]

    if sid == 0x27:
        handle_security_access(msg[1], conn)
    elif sid == 0x10:
        handle_session_control(msg[1], conn)
    elif sid == 0x11:
        handle_reset(msg[1], conn)
    elif sid == 0x22:
        did = (msg[1]<<8)|msg[2]
        if SESSION_FLAG == 1 and did != 0xF1A0:
            send_nrc(0x22,0x7E, conn); return
        if did == 0xF1A0:
            send_pos(0x22,did=did,data=CONFIG, conn=conn)
        elif did == 0xF190:
            send_pos(0x22,did=did,data=VIN, conn=conn)
        elif did == 0xF18C:
            send_pos(0x22,did=did,data=MODEL, conn=conn)
        else:
            send_nrc(0x22,0x31, conn)
    elif sid == 0x2E:
        if SESSION_FLAG == 1:
            send_nrc(0x2E,0x7E, conn); return
        if SEC_ACCESS_FLAG != 1:
            send_nrc(0x2E,0x33, conn); return
        did = (msg[1]<<8)|msg[2]
        if did != 0xF1A0:
            send_nrc(0x2E,0x31, conn); return
        parsed = parse_config_value(msg[3:])
        if not parsed:
            send_nrc(0x2E,0x31, conn); return
        CONFIG = parsed
        send_pos(0x2E,did=did,data=CONFIG, conn=conn)
        if not token_enabled():
            token_runtime_enabled = False

    elif sid == 0x31:
        handle_routine(msg, conn)
    elif sid == 0x3E:
        send_pos(0x3E,sub=subb, conn=conn)
    else:
        send_nrc(sid,0x11, conn)

# ==========================================================
# Networking
# ==========================================================
def udp_discovery():
    """
    UDP discovery - minimal response with TLS port info
    Client must establish TLS tunnel before any DoIP communication
    """
    u = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    u.bind(("",DOIP_UDP_PORT))
    print(f"[ECU] 📡 UDP discovery service on port {DOIP_UDP_PORT}")
    print(f"[ECU] ⚠️  Only provides IP/VIN - All DoIP requires TLS on port {TLS_DOIP_PORT}")
    
    while True:
        d,a = u.recvfrom(4096)
        if struct.unpack("!H",d[2:4])[0]==0x0001:
            print(f"[ECU] 📡 Vehicle ID request from {a[0]} → Sending VIN + TLS port")
            # Minimal response: VIN + logical address + EID + GID + TLS port
            payload = VIN + struct.pack("!H",LOGICAL_ADDR_ECU)+EID+GID+struct.pack("!H", TLS_DOIP_PORT)
            u.sendto(doip_header(0x0004,payload),a)

def check_session_timeout():
    global SESSION_FLAG
    if SESSION_FLAG != 1 and time.time()-last_activity_time > S3:
        SESSION_FLAG = 1
        print("[ECU] ⏱️  S3 timeout → Default session")

def session_watchdog():
    while True:
        time.sleep(0.5)
        check_session_timeout()

def handle_tester(conn, addr):
    """
    Handle TLS-secured DoIP connection
    All DoIP communication happens here AFTER TLS handshake
    """
    RA_ACCEPTED = 0x10
    RA_DENIED_UNKNOWN = 0x00
    CONNECTED_TESTER_LOGICAL = None
    
    # Detect TLS version negotiated
    try:
        tls_version = conn.version()
        print(f"[ECU] ✅ TLS handshake complete: {tls_version}")
        if "TLSv1.0" in tls_version or "TLSv1.1" in tls_version:
            print(f"[ECU] ⚠️  VULNERABLE: Accepted downgraded {tls_version}!")
        print(f"[ECU] 🔓 Connection from {addr[0]}")
    except:
        print(f"[ECU] ✅ TLS handshake complete with {addr[0]}")
    
    print(f"[ECU] 🔐 Secure channel established - Ready for DoIP")
    
    try:
        while True:
            d = conn.recv(4096)
            if not d:
                print("[ECU] ❌ Client disconnected")
                break

            # All DoIP traffic is now encrypted
            ptype = struct.unpack("!H", d[2:4])[0]
            ln = struct.unpack("!I", d[4:8])[0]
            payload = d[8:8+ln]

            # Routing Activation (encrypted)
            if ptype == 0x0005:
                src_logical, act_type, _, _ = struct.unpack("!HBBI", payload)
                print(f"[ECU] 🔒 Routing Activation from 0x{src_logical:04X} (encrypted)")

                if src_logical not in ALLOWED_TESTERS:
                    print(f"[ECU] ❌ Rejected: unknown tester 0x{src_logical:04X}")
                    nack = struct.pack(
                        "!HHBBI",
                        LOGICAL_ADDR_ECU,
                        src_logical,
                        RA_DENIED_UNKNOWN,
                        0x00,
                        0x00000000
                    )
                    conn.send(doip_header(0x0006, nack))
                    continue

                CONNECTED_TESTER_LOGICAL = src_logical
                print(f"[ECU] ✅ Routing accepted for 0x{src_logical:04X}")
                ack = struct.pack(
                    "!HHBBI",
                    LOGICAL_ADDR_ECU,
                    src_logical,
                    RA_ACCEPTED,
                    0x00,
                    0x00000000
                )
                conn.send(doip_header(0x0006, ack))

            # UDS Diagnostic Messages (encrypted)
            elif ptype == 0x8001:
                tester_la, ecu_la = struct.unpack("!HH", payload[:4])
                if tester_la != CONNECTED_TESTER_LOGICAL:
                    print(f"[ECU] ⚠️  Ignored: wrong tester 0x{tester_la:04X}")
                    continue
                if ecu_la != LOGICAL_ADDR_ECU:
                    print("[ECU] ⚠️  Not for this ECU")
                    continue
                uds_dispatch(payload[4:], conn)

            check_session_timeout()
    
    except ssl.SSLError as e:
        print(f"[ECU] ⚠️  TLS error: {e}")
    except Exception as e:
        print(f"[ECU] ⚠️  Error: {e}")
    finally:
        conn.close()
        print("[ECU] 🔒 Connection closed")

def tcp_tls_server():
    """
    VULNERABLE TLS server - accepts TLS 1.1 and 1.2 with compatible ciphers
    FIXED: Now includes TLS 1.1 compatible cipher suites
    """
    
    import sys
    
    # Create VULNERABLE TLS context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    if sys.version_info >= (3, 13):
        # Python 3.13+ completely removed TLS 1.0/1.1
        print(f"[ECU] ⚠️  Python 3.13+ detected - TLS 1.0/1.1 not available")
        print(f"[ECU] ⚠️  Accepting only TLS 1.2 (attack will demonstrate but fail)")
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    elif sys.version_info >= (3, 10):
        # Python 3.10-3.12: TLS 1.1 is deprecated but can be enabled
        print(f"[ECU] ⚠️  Python 3.10+ detected - Enabling TLS 1.1 (deprecated)")
        try:
            # IMPORTANT: Minimum 1.1, but clients should negotiate UP to 1.2
            context.minimum_version = ssl.TLSVersion.TLSv1_1
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            
            # FIXED: Use TLS 1.1 compatible cipher suites
            # Order matters: TLS 1.2 ciphers first (preferred), then TLS 1.1 fallbacks
            context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA:DES-CBC3-SHA:@SECLEVEL=0')
            
            # Prefer server cipher order (so TLS 1.2 ciphers are chosen first)
            context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
            
            print(f"[ECU] ✅ TLS 1.1-1.2 enabled (VULNERABLE! Prefers 1.2)")
        except Exception as e:
            print(f"[ECU] ⚠️  Could not enable TLS 1.1: {e}")
            print(f"[ECU] ⚠️  Using TLS 1.2 only")
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        # Python 3.9 and below
        context.minimum_version = ssl.TLSVersion.TLSv1_1
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA:@SECLEVEL=0')
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        context.load_cert_chain(certfile=TLS_CERT_FILE, keyfile=TLS_KEY_FILE)
        print(f"[ECU] ✅ Certificates loaded: {TLS_CERT_FILE}, {TLS_KEY_FILE}")
    except FileNotFoundError:
        print(f"[ECU] ❌ ERROR: Certificate files not found!")
        print(f"[ECU] Generate with:")
        print(f"      openssl req -new -x509 -days 365 -nodes \\")
        print(f"              -out {TLS_CERT_FILE} -keyout {TLS_KEY_FILE} \\")
        print(f"              -subj '/CN=ECU'")
        return
    
    # Create and bind TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", TLS_DOIP_PORT))
    s.listen(5)
    
    print(f"[ECU] ⚠️  VULNERABLE DoIP Server on port {TLS_DOIP_PORT}")
    print(f"[ECU] ⚠️  Accepts TLS 1.1-1.2, PREFERS 1.2 (NO downgrade protection!)")
    print(f"[ECU] 📡 UDP discovery on port {DOIP_UDP_PORT} (unencrypted)")
    print(f"[ECU] 🎯 Normal clients will use TLS 1.2, attacks can force 1.1")
    print("="*60)
    
    # Accept connections and wrap with TLS
    while True:
        try:
            # Accept raw TCP connection
            raw_sock, addr = s.accept()
            print(f"[ECU] 🔌 TCP connection from {addr[0]}")
            print(f"[ECU] 🤝 Starting TLS handshake (accepts 1.1/1.2)...")
            
            # Wrap with TLS (handshake happens here)
            tls_conn = context.wrap_socket(raw_sock, server_side=True)
            
            # Now handle DoIP over the encrypted channel
            threading.Thread(target=handle_tester, args=(tls_conn, addr), daemon=True).start()
            
        except ssl.SSLError as e:
            print(f"[ECU] ❌ TLS handshake failed: {e}")
        except Exception as e:
            print(f"[ECU] ❌ Error: {e}")

# ==========================================================
# MAIN
# ==========================================================
print("="*60)
print("[ECU] ⚠️  VULNERABLE DoIP ECU")
print("[ECU] ⚠️  Accepts TLS 1.1/1.2 WITHOUT downgrade protection")
print("[ECU] 📋 Architecture:")
print("[ECU]    1. UDP Discovery (port 13400) - VIN only")
print("[ECU]    2. TLS Handshake (accepts 1.1/1.2)")
print("[ECU]    3. DoIP Routing (encrypted)")
print("[ECU]    4. UDS Diagnostics (encrypted)")
print("[ECU] 🎯 For demonstrating successful downgrade attacks")
print("="*60)

threading.Thread(target=udp_discovery, daemon=True).start()
threading.Thread(target=session_watchdog, daemon=True).start()

tcp_tls_server()