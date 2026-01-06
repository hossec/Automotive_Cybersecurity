#!/usr/bin/env python3
"""
FULL ECU - MULTI-TESTER SUPPORT
- SOME/IP (mirror logic) over IPv4
- DoIP / UDS ECU over IPv6 with MULTIPLE TESTER SUPPORT
- SAME PROJECT, SAME LOGIC
- SINGLE PROCESS, MULTIPLE THREADS
"""

import threading
import time
from threading import Lock


# shared globals
security_unlocked = False
current_session = "DEFAULT"



# ================= SHARED STATE =================
state_lock = Lock()

position = {"x": 0, "y": 0}
security_unlocked = False
current_session = "DEFAULT"
config = b"01"


def run_someip():
    import socket, struct, json, threading, time, logging
    from threading import Lock

    # ================= CONFIG =================
    MIRROR_IP = "10.0.0.10"
    BCAST_IP  = "10.0.0.255"
    PORT      = 30490

    MIRROR_SERVICE_ID = 0x2222
    BUTTON_SERVICE_ID = 0x1111
    INSTANCE_ID = 0x0001

    DIR_EVENT_ID = 0x0100
    POS_EVENT_ID = 0x0101
    GET_POSITION_METHOD_ID = 0x0200

    MSG_REQUEST  = 0x00
    MSG_RESPONSE = 0x80
    MSG_NOTIFY   = 0x02

    PROTO_VER = 1
    IFACE_VER = 1

    SD_SERVICE_ID = 0xFFFF
    SD_METHOD_ID  = 0x8100
    SD_CLIENT_ID  = 0x0000

    ENTRY_FIND_SERVICE     = 0x00
    ENTRY_OFFER_SERVICE    = 0x01
    ENTRY_SUBSCRIBE_EG     = 0x06
    ENTRY_SUBSCRIBE_EG_ACK = 0x07

    EG_DIR_ID = 0x0001
    EG_POS_ID = 0x0002
    TTL = 3

    AUTO_SUBSCRIBE_ON_OFFER = True

    logging.basicConfig(level=logging.INFO,
                        format='[SOME/IP] %(message)s')

    # ================= STATE =================
    state_lock_local = Lock()
    session_id = 0
    offers_enabled = True

    providers = {}            # Button providers
    subscribers = set()       # POS subscribers
    subscription_state = {}   # DIR subscription state

    # ================= SOCKET =================
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", PORT))

    # ================= HELPERS =================
    def next_session():
        nonlocal session_id
        session_id = (session_id + 1) & 0xFFFF
        return session_id or 1

    def build_someip(sid, mid, msg_type, cid, payload):
        rid = (cid << 16) | next_session()
        hdr = struct.pack("!HHI", sid, mid, len(payload) + 8)
        info = struct.pack("!I B B B B", rid, PROTO_VER, IFACE_VER, msg_type, 0)
        return hdr + info + payload

    def parse_someip(d):
        if len(d) < 16:
            return None
        sid, mid, ln = struct.unpack("!HHI", d[:8])
        if len(d) < 8 + ln:
            return None
        return {"sid": sid, "mid": mid, "payload": d[16:16 + ln - 8]}

    # ================= SD HELPERS =================
    def sd_service_entry(t, sid, inst, ttl, m):
        return struct.pack("!BBBBHHII", t, 0, 0, 0, sid, inst, ttl, m)

    def sd_eg_entry(t, sid, inst, ttl, eg):
        return struct.pack("!BBBBHHIHH", t, 0, 0, 0, sid, inst, ttl, 0, eg)

    OPT_IPV4 = 0x10
    OPT_PORT = 0x11

    def sd_option_ipv4(ip):
        return struct.pack("!BB4s", OPT_IPV4, 4, socket.inet_aton(ip))

    def sd_option_port(p):
        return struct.pack("!BBH", OPT_PORT, 2, p)

    def build_sd(entries, opts=b""):
        flags = 0x40
        total = len(entries) + len(opts)
        payload = struct.pack("!B3xI", flags, total) + entries + opts + struct.pack("!I", 0)
        return build_someip(SD_SERVICE_ID, SD_METHOD_ID, MSG_NOTIFY, SD_CLIENT_ID, payload)

    # ================= OFFER =================
    def send_reactive_offer(ip):
        e = sd_service_entry(ENTRY_OFFER_SERVICE, MIRROR_SERVICE_ID, INSTANCE_ID, TTL, 0)
        o = sd_option_ipv4(MIRROR_IP) + sd_option_port(PORT)
        sock.sendto(build_sd(e, o), (ip, PORT))

    def periodic_offer():
        while True:
            if offers_enabled:
                e = sd_service_entry(ENTRY_OFFER_SERVICE, MIRROR_SERVICE_ID, INSTANCE_ID, TTL, 0)
                o = sd_option_ipv4(MIRROR_IP) + sd_option_port(PORT)
                sock.sendto(build_sd(e, o), (BCAST_IP, PORT))
            time.sleep(TTL)

    # ================= SUBSCRIBE DIR =================
    def start_subscribe(ip):
        with state_lock_local:
            st = subscription_state.get(ip)
            if st and st.get("confirmed"):
                return
            subscription_state[ip] = {"confirmed": False}

        entry = sd_eg_entry(ENTRY_SUBSCRIBE_EG,
                            BUTTON_SERVICE_ID,
                            INSTANCE_ID,
                            TTL,
                            EG_DIR_ID)
        sock.sendto(build_sd(entry), (ip, PORT))

    # ================= SD HANDLER =================
    def handle_sd(payload, src_ip):
        if len(payload) < 8:
            return
        elen = struct.unpack("!I", payload[4:8])[0]
        data = payload[8:8 + elen]
        i = 0

        while i + 16 <= len(data):
            e = data[i:i + 16]
            t = e[0]
            sid, inst = struct.unpack("!HH", e[4:8])
            eg = struct.unpack("!H", e[-2:])[0]

            # ---- Button Service ----
            if sid == BUTTON_SERVICE_ID:
                if t == ENTRY_OFFER_SERVICE:
                    providers[src_ip] = {"last": time.time()}
                    st = subscription_state.get(src_ip)
                    if AUTO_SUBSCRIBE_ON_OFFER and not (st and st.get("confirmed")):
                        start_subscribe(src_ip)

                elif t == ENTRY_SUBSCRIBE_EG_ACK and eg == EG_DIR_ID:
                    st = subscription_state.get(src_ip)
                    if st:
                        st["confirmed"] = True

            # ---- Mirror Service ----
            if sid == MIRROR_SERVICE_ID:
                if t == ENTRY_FIND_SERVICE:
                    send_reactive_offer(src_ip)

                elif t == ENTRY_SUBSCRIBE_EG and eg == EG_POS_ID:
                    subscribers.add(src_ip)
                    ack = sd_eg_entry(ENTRY_SUBSCRIBE_EG_ACK,
                                      MIRROR_SERVICE_ID,
                                      INSTANCE_ID,
                                      TTL,
                                      eg)
                    sock.sendto(build_sd(ack), (src_ip, PORT))

            i += 16

    # ================= APP =================
    def send_pos_event():
        with state_lock:
            payload = json.dumps(position).encode()

        msg = build_someip(MIRROR_SERVICE_ID,
                           POS_EVENT_ID,
                           MSG_NOTIFY,
                           2,
                           payload)

        for ip in subscribers:
            sock.sendto(msg, (ip, PORT))

    def handle_app(sid, mid, payload, src_ip):
        if sid == BUTTON_SERVICE_ID and mid == DIR_EVENT_ID:
            d = json.loads(payload.decode()).get("dir")
            with state_lock:
                if d == "UP": position["y"] += 1
                if d == "DOWN": position["y"] -= 1
                if d == "LEFT": position["x"] -= 1
                if d == "RIGHT": position["x"] += 1
            send_pos_event()

        elif sid == MIRROR_SERVICE_ID and mid == GET_POSITION_METHOD_ID:
            with state_lock:
                resp = json.dumps(position).encode()

            msg = build_someip(MIRROR_SERVICE_ID,
                               GET_POSITION_METHOD_ID,
                               MSG_RESPONSE,
                               1,
                               resp)
            sock.sendto(msg, (src_ip, PORT))

    # ================= LISTENER =================
    def listener():
        while True:
            data, (ip, _) = sock.recvfrom(4096)
            msg = parse_someip(data)
            if not msg:
                continue
            if msg["sid"] == SD_SERVICE_ID:
                handle_sd(msg["payload"], ip)
            else:
                handle_app(msg["sid"], msg["mid"], msg["payload"], ip)

    logging.info("SOME/IP ECU (MIRROR LOGIC) STARTED")

    threading.Thread(target=periodic_offer, daemon=True).start()
    threading.Thread(target=listener, daemon=True).start()



def run_doip():
    import socket, struct, threading, time, random

    # ==========================================================
    # DoIP CONFIG
    # ==========================================================
    DOIP_PORT = 13400
    LOGICAL_ADDR_ECU = 0x0E00

    ALLOWED_TESTERS = {0x0E80, 0x0E81, 0x0E82, 0x0E83}  # Support multiple testers

    VIN   = b"12345678901234567"
    MODEL = b"ABCD"
    EID   = b"\x01\x02\x03\x04\x05\x06"
    GID   = b"\xAA\xBB\xCC\xDD\xEE\xFF"

    # ==========================================================
    # GLOBAL CONFIG (shared across testers)
    # ==========================================================
    CONFIG = b"01"
    config_lock = Lock()

    # ==========================================================
    # PER-TESTER STATE
    # ==========================================================
    tester_sessions = {}  # conn -> session state
    sessions_lock = Lock()

    # ==========================================================
    # Constants
    # ==========================================================
    KEY = 0x11223344
    MAX_ATTEMPTS = 3
    LOCKOUT_TIME = 600
    SEED_DELAY = 5
    S3 = 5

    # ==========================================================
    # Helpers
    # ==========================================================
    def doip_header(ptype, payload):
        return struct.pack("!BBHI", 0x02, 0xFD, ptype, len(payload)) + payload

    def doip_send_uds(uds, conn, tester_logical):
        frame = struct.pack("!HH", LOGICAL_ADDR_ECU, tester_logical) + uds
        conn.send(doip_header(0x8001, frame))
        print(f"[ECU -> {hex(tester_logical)}] TX {uds.hex()}")

    def send_nrc(sid, nrc, conn, tester_logical):
        doip_send_uds(bytes([0x7F, sid, nrc]), conn, tester_logical)

    def send_pos(sid, sub=None, did=None, data=b"", conn=None, tester_logical=None):
        resp = (sid + 0x40) & 0xFF
        if sub is not None:
            payload = bytes([resp, sub]) + data
        elif did is not None:
            payload = bytes([resp]) + did.to_bytes(2, "big") + data
        else:
            payload = bytes([resp]) + data
        doip_send_uds(payload, conn, tester_logical)

    # ==========================================================
    # CONFIG helpers
    # ==========================================================
    def parse_config_value(data):
        try:
            txt = bytes(data).decode()
            if txt in ("01", "02", "03", "04"):
                return txt.encode()
        except:
            pass
        return None

    def token_enabled(): 
        with config_lock:
            return CONFIG in (b"03", b"04")
    
    def lockout_enabled(): 
        with config_lock:
            return CONFIG in (b"02", b"04")

    # ==========================================================
    # Session State Management
    # ==========================================================
    def create_session_state(conn, tester_logical):
        """Create a new session state for a tester"""
        with sessions_lock:
            tester_sessions[conn] = {
                'tester_logical': tester_logical,
                'session_flag': 1,
                'sec_access_flag': 0,
                'session_token': random.randint(0x00, 0xFF),
                'token_runtime_enabled': False,
                'last_seed': None,
                'last_request_data': b"",
                'attempts': 0,
                'locked': False,
                'lockout_timer': 0,
                'seed_given': False,
                'seed_delay_timer': 0,
                'last_activity_time': time.time()
            }
        print(f"[ECU] Created session for tester {hex(tester_logical)}")

    def get_session_state(conn):
        """Get session state for a connection"""
        with sessions_lock:
            return tester_sessions.get(conn)

    def update_activity(state):
        """Update last activity time"""
        state['last_activity_time'] = time.time()

    def cleanup_session(conn):
        """Remove session state when tester disconnects"""
        with sessions_lock:
            if conn in tester_sessions:
                tester_logical = tester_sessions[conn]['tester_logical']
                del tester_sessions[conn]
                print(f"[ECU] Cleaned up session for tester {hex(tester_logical)}")

    # ==========================================================
    # Security Access (0x27) - Per Tester
    # ==========================================================
    def handle_security_access(sub, conn, state):
        now = time.time()

        if lockout_enabled() and state['locked'] and now < state['lockout_timer']:
            send_nrc(0x27, 0x37, conn, state['tester_logical'])
            return

        if sub == 0x01:
            if state['seed_given'] and now < state['seed_delay_timer']:
                send_nrc(0x27, 0x78, conn, state['tester_logical'])
                return
            state['last_seed'] = random.randint(0x1000, 0x1FFF)
            state['seed_given'] = True
            state['seed_delay_timer'] = now + SEED_DELAY
            send_pos(0x27, 0x01, data=state['last_seed'].to_bytes(4, "big"), 
                    conn=conn, tester_logical=state['tester_logical'])
            return

        if sub == 0x02:
            recv = int.from_bytes(state['last_request_data'][2:6], "big")
            if recv == (state['last_seed'] + KEY) & 0xFFFFFFFF:
                state['sec_access_flag'] = 1
                state['attempts'] = 0
                state['seed_given'] = False
                send_pos(0x27, 0x02, conn=conn, tester_logical=state['tester_logical'])
                if token_enabled():
                    state['token_runtime_enabled'] = True
                return

            state['attempts'] += 1
            if lockout_enabled() and state['attempts'] >= MAX_ATTEMPTS:
                state['locked'] = True
                state['lockout_timer'] = now + LOCKOUT_TIME
                send_nrc(0x27, 0x36, conn, state['tester_logical'])
            else:
                send_nrc(0x27, 0x35, conn, state['tester_logical'])

    # ==========================================================
    # Session Control (0x10) - Per Tester
    # ==========================================================
    def handle_session_control(sub, conn, state):
        if state['sec_access_flag'] != 1:
            send_nrc(0x10, 0x33, conn, state['tester_logical'])
            return
        if sub not in (1, 2, 3):
            send_nrc(0x10, 0x12, conn, state['tester_logical'])
            return
        state['session_flag'] = sub
        if state['token_runtime_enabled']:
            doip_send_uds(bytes([0x50, sub, state['session_token']]), 
                         conn, state['tester_logical'])
        else:
            send_pos(0x10, sub, conn=conn, tester_logical=state['tester_logical'])

    # ==========================================================
    # Reset (0x11) - Per Tester
    # ==========================================================
    def handle_reset(sub, conn, state):
        if state['sec_access_flag'] != 1:
            send_nrc(0x11, 0x33, conn, state['tester_logical'])
            return
        send_pos(0x11, sub, conn=conn, tester_logical=state['tester_logical'])
        
        # Reset tester's state
        state['session_flag'] = 1
        state['sec_access_flag'] = 0
        state['token_runtime_enabled'] = False
        
        # Reset global config
        with config_lock:
            global CONFIG
            CONFIG = b"01"

    # ==========================================================
    # Routine Control (0x31) - Per Tester
    # ==========================================================
    def handle_routine(msg, conn, state):
        sub = msg[1]
        rid = (msg[2] << 8) | msg[3]

        if sub not in (0x01, 0x02, 0x03):
            send_nrc(0x31, 0x12, conn, state['tester_logical'])
            return

        if rid not in (0x1234, 0x5678):
            send_nrc(0x31, 0x31, conn, state['tester_logical'])
            return

        if rid == 0x1234:
            send_pos(0x31, sub, data=msg[2:4], conn=conn, 
                    tester_logical=state['tester_logical'])

        elif rid == 0x5678:
            if state['session_flag'] in (2, 3):
                send_pos(0x31, sub, data=msg[2:4], conn=conn, 
                        tester_logical=state['tester_logical'])
            else:
                send_nrc(0x31, 0x7E, conn, state['tester_logical'])

    # ==========================================================
    # UDS DISPATCH - Per Tester
    # ==========================================================
    def uds_dispatch(msg, conn, state):
        global CONFIG
        state['last_request_data'] = msg
        update_activity(state)
        sid = msg[0]

        if state['token_runtime_enabled'] and sid in (0x10, 0x11):
            if msg[-1] != state['session_token']:
                send_nrc(sid, 0x24, conn, state['tester_logical'])
                return
            msg = msg[:-1]

        if sid == 0x27:
            handle_security_access(msg[1], conn, state)
        elif sid == 0x10:
            handle_session_control(msg[1], conn, state)
        elif sid == 0x11:
            handle_reset(msg[1], conn, state)
        elif sid == 0x22:
            did = (msg[1] << 8) | msg[2]
            if state['session_flag'] == 1 and did != 0xF1A0:
                send_nrc(0x22, 0x7E, conn, state['tester_logical'])
            elif did == 0xF190:
                send_pos(0x22, did=did, data=VIN, conn=conn, 
                        tester_logical=state['tester_logical'])
            elif did == 0xF18C:
                send_pos(0x22, did=did, data=MODEL, conn=conn, 
                        tester_logical=state['tester_logical'])
            elif did == 0xF1A0:
                with config_lock:
                    send_pos(0x22, did=did, data=CONFIG, conn=conn, 
                            tester_logical=state['tester_logical'])
            else:
                send_nrc(0x22, 0x31, conn, state['tester_logical'])
        elif sid == 0x2E:
            if state['session_flag'] == 1:
                send_nrc(0x2E, 0x7E, conn, state['tester_logical'])
            elif state['sec_access_flag'] != 1:
                send_nrc(0x2E, 0x33, conn, state['tester_logical'])
            else:
                did = (msg[1] << 8) | msg[2]
                parsed = parse_config_value(msg[3:])
                if did == 0xF1A0 and parsed:
                    with config_lock:
                        
                        CONFIG = parsed
                    send_pos(0x2E, did=did, data=parsed, conn=conn, 
                            tester_logical=state['tester_logical'])
                else:
                    send_nrc(0x2E, 0x31, conn, state['tester_logical'])
        elif sid == 0x31:
            handle_routine(msg, conn, state)
        elif sid == 0x3E:
            send_pos(0x3E, sub=msg[1], conn=conn, tester_logical=state['tester_logical'])
        else:
            send_nrc(sid, 0x11, conn, state['tester_logical'])

    # ==========================================================
    # Networking
    # ==========================================================
    def udp_discovery():
        u = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        u.bind(("::", DOIP_PORT))

        ifindex = socket.if_nametoindex("vethC")
        mreq = socket.inet_pton(socket.AF_INET6, "ff02::1") + struct.pack("@I", ifindex)
        u.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

        print("[ECU] DoIP discovery (link-local) - Multi-tester support enabled")

        while True:
            d, a = u.recvfrom(4096)

            if struct.unpack("!H", d[2:4])[0] == 0x0001:
                payload = (
                    VIN +
                    struct.pack("!H", LOGICAL_ADDR_ECU) +
                    EID +
                    GID +
                    b"\x00\x00"
                )

                u.sendto(
                    doip_header(0x0004, payload),
                    (a[0], a[1], 0, a[3])
                )

    def session_watchdog():
        """Monitor all tester sessions for S3 timeout"""
        while True:
            time.sleep(0.5)
            now = time.time()
            with sessions_lock:
                for conn, state in list(tester_sessions.items()):
                    if state['session_flag'] != 1 and now - state['last_activity_time'] > S3:
                        state['session_flag'] = 1
                        print(f"[ECU] S3 timeout for tester {hex(state['tester_logical'])} → Default")

    def handle_tester(conn, addr):
        print(f"[ECU] Tester connected from {addr[0]}")
        state = None
        
        try:
            while True:
                d = conn.recv(4096)
                if not d:
                    break
                    
                ptype = struct.unpack("!H", d[2:4])[0]
                ln = struct.unpack("!I", d[4:8])[0]
                payload = d[8:8 + ln]

                if ptype == 0x0005:  # Routing Activation
                    src, _, _, _ = struct.unpack("!HBBI", payload)
                    if src not in ALLOWED_TESTERS:
                        nack = struct.pack("!HHBBI", LOGICAL_ADDR_ECU, src, 0, 0, 0)
                        conn.send(doip_header(0x0006, nack))
                        print(f"[ECU] Rejected unauthorized tester {hex(src)}")
                    else:
                        create_session_state(conn, src)
                        state = get_session_state(conn)
                        ack = struct.pack("!HHBBI", LOGICAL_ADDR_ECU, src, 0x10, 0, 0)
                        conn.send(doip_header(0x0006, ack))
                        print(f"[ECU] Activated routing for tester {hex(src)}")

                elif ptype == 0x8001:  # Diagnostic message
                    if state is None:
                        print(f"[ECU] Received UDS without routing activation from {addr[0]}")
                        continue
                        
                    tester_la, ecu_la = struct.unpack("!HH", payload[:4])
                    if tester_la == state['tester_logical'] and ecu_la == LOGICAL_ADDR_ECU:
                        uds_dispatch(payload[4:], conn, state)
                        
        except Exception as e:
            print(f"[ECU] Error handling tester {addr[0]}: {e}")
        finally:
            if conn in tester_sessions:
                cleanup_session(conn)
            conn.close()

    def tcp_server():
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("fd00::10", DOIP_PORT))
        s.listen(10)  # Increased backlog for multiple testers
        print("[ECU] TCP server listening for multiple testers...")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_tester, args=(conn, addr), daemon=True).start()

    print("[ECU] FULL DoIP ECU STARTED - MULTI-TESTER SUPPORT")
    threading.Thread(target=udp_discovery, daemon=True).start()
    threading.Thread(target=session_watchdog, daemon=True).start()
    tcp_server()


# ================= MAIN =================
print("[ECU] FULL ECU STARTING - MULTI-TESTER SUPPORT")

threading.Thread(target=run_someip, daemon=True).start()
threading.Thread(target=run_doip, daemon=True).start()

while True:
    time.sleep(1)