#!/usr/bin/env python3
"""
button_pro_final.py
Button (DIR provider / POS client)
+ Method: GetPosition (REQUEST)
"""
import socket, struct, json, threading, time, logging
from threading import Lock

# ================= CONFIG =================
BUTTON_IP = "10.0.0.20"
MIRROR_IP = "10.0.0.10"      # 🔥 DIRECT METHOD TARGET
BCAST_IP  = "10.0.0.255"
PORT      = 30490

BUTTON_SERVICE_ID = 0x1111
MIRROR_SERVICE_ID = 0x2222
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

# ================= LOG =================
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] %(message)s',
                    datefmt='%H:%M:%S')

# ================= STATE =================
state_lock = Lock()
session_id = 0
offers_enabled = True

providers = {}            # mirror providers (for EVENTS only)
subscribers = set()       # DIR subscribers
subscription_state = {}   # POS subscription state

# ================= SOCKET =================
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.bind(("0.0.0.0", PORT))

# ================= HELPERS =================
def next_session():
    global session_id
    session_id = (session_id + 1) & 0xFFFF
    return session_id or 1

def build_someip(sid, mid, msg_type, cid, payload):
    rid = (cid << 16) | next_session()
    hdr = struct.pack("!HHI", sid, mid, len(payload) + 8)
    info = struct.pack("!I B B B B",
                       rid,
                       PROTO_VER,
                       IFACE_VER,
                       msg_type,
                       0)
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

# ================= OFFER (Button Service) =================
def send_reactive_offer(ip):
    e = sd_service_entry(ENTRY_OFFER_SERVICE,
                         BUTTON_SERVICE_ID,
                         INSTANCE_ID,
                         TTL,
                         0)
    o = sd_option_ipv4(BUTTON_IP) + sd_option_port(PORT)
    sock.sendto(build_sd(e, o), (ip, PORT))
    logging.info(f"[BUTTON] Reactive OFFER -> {ip}")

def periodic_offer():
    while True:
        if offers_enabled:
            e = sd_service_entry(ENTRY_OFFER_SERVICE,
                                 BUTTON_SERVICE_ID,
                                 INSTANCE_ID,
                                 TTL,
                                 0)
            o = sd_option_ipv4(BUTTON_IP) + sd_option_port(PORT)
            sock.sendto(build_sd(e, o), (BCAST_IP, PORT))
            logging.info("[BUTTON] Periodic Offer")
        time.sleep(TTL)

# ================= SUBSCRIBE POS (EVENT ONLY) =================
def start_subscribe(ip):
    with state_lock:
        st = subscription_state.get(ip)
        if st and st.get("confirmed"):
            return
        subscription_state[ip] = {"confirmed": False}

    entry = sd_eg_entry(ENTRY_SUBSCRIBE_EG,
                        MIRROR_SERVICE_ID,
                        INSTANCE_ID,
                        TTL,
                        EG_POS_ID)
    sock.sendto(build_sd(entry), (ip, PORT))
    logging.info(f"[BUTTON] SUBSCRIBE POS -> {ip}")

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

        # ---- Mirror Service (EVENTS ONLY) ----
        if sid == MIRROR_SERVICE_ID:
            if t == ENTRY_OFFER_SERVICE:
                with state_lock:
                    providers[src_ip] = {"last": time.time()}
                    st = subscription_state.get(src_ip)

                if not (st and st.get("confirmed")) and AUTO_SUBSCRIBE_ON_OFFER:
                    start_subscribe(src_ip)

            elif t == ENTRY_SUBSCRIBE_EG_ACK and eg == EG_POS_ID:
                with state_lock:
                    st = subscription_state.get(src_ip)
                    if st:
                        st["confirmed"] = True
                logging.info(f"[BUTTON] POS subscription confirmed <- {src_ip}")

        # ---- Button Service ----
        if sid == BUTTON_SERVICE_ID:
            if t == ENTRY_FIND_SERVICE:
                send_reactive_offer(src_ip)

            elif t == ENTRY_SUBSCRIBE_EG and eg == EG_DIR_ID:
                subscribers.add(src_ip)
                ack = sd_eg_entry(ENTRY_SUBSCRIBE_EG_ACK,
                                  BUTTON_SERVICE_ID,
                                  INSTANCE_ID,
                                  TTL,
                                  eg)
                sock.sendto(build_sd(ack), (src_ip, PORT))
                logging.info(f"[BUTTON] SUBACK DIR -> {src_ip}")

        i += 16

# ================= TTL MONITOR (EVENTS ONLY) =================
def ttl_monitor():
    while True:
        now = time.time()
        expired = []

        with state_lock:
            for ip, v in providers.items():
                if now - v["last"] > TTL * 2:
                    expired.append(ip)

        for ip in expired:
            with state_lock:
                providers.pop(ip, None)
                subscription_state.pop(ip, None)
                subscribers.discard(ip)
            logging.warning(f"[BUTTON] Mirror service expired -> {ip}")

        time.sleep(1)

# ================= APP =================
def send_dir(direction):
    msg = build_someip(BUTTON_SERVICE_ID,
                       DIR_EVENT_ID,
                       MSG_NOTIFY,
                       1,
                       json.dumps({"dir": direction}).encode())
    for ip in subscribers:
        sock.sendto(msg, (ip, PORT))
    logging.info(f"[BUTTON] DIR={direction} -> {list(subscribers)}")

def handle_app(sid, mid, payload, src_ip):
    if sid == MIRROR_SERVICE_ID and mid == POS_EVENT_ID:
        pos = json.loads(payload.decode())
        logging.info(f"[BUTTON] POS from {src_ip}: {pos}")

    elif sid == MIRROR_SERVICE_ID and mid == GET_POSITION_METHOD_ID:
        pos = json.loads(payload.decode())
        logging.info(f"[BUTTON] GetPosition RESPONSE from {src_ip}: {pos}")

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

# ================= CONSOLE =================
def console():
    global offers_enabled
    print("\n[BUTTON READY]")
    print("f = find Mirror service (EVENTS)")
    print("w/a/s/d = DIR event")
    print("m = GetPosition METHOD (DIRECT)")
    print("o = toggle Button offer")
    print("q = quit\n")

    while True:
        c = input("BUTTON>> ").strip().lower()

        if c == "f":
            e = sd_service_entry(ENTRY_FIND_SERVICE,
                                 MIRROR_SERVICE_ID,
                                 INSTANCE_ID,
                                 TTL,
                                 0)
            sock.sendto(build_sd(e), (BCAST_IP, PORT))
            logging.info("[BUTTON] FIND MirrorService sent")

        elif c in ("w", "a", "s", "d"):
            m = {"w": "UP", "s": "DOWN", "a": "LEFT", "d": "RIGHT"}
            send_dir(m[c])

        elif c == "m":
            payload = json.dumps({"method": "GetPosition"}).encode()
            msg = build_someip(MIRROR_SERVICE_ID,
                               GET_POSITION_METHOD_ID,
                               MSG_REQUEST,
                               1,
                               payload)
            sock.sendto(msg, (MIRROR_IP, PORT))
            logging.info(f"[BUTTON] GetPosition CALL -> {MIRROR_IP}")

        elif c == "o":
            offers_enabled = not offers_enabled
            logging.info(f"[BUTTON] periodic offer = {offers_enabled}")

        elif c == "q":
            break

# ================= MAIN =================
if __name__ == "__main__":
    logging.info("== BUTTON READY (METHOD INDEPENDENT) ==")
    threading.Thread(target=periodic_offer, daemon=True).start()
    threading.Thread(target=listener, daemon=True).start()
    threading.Thread(target=ttl_monitor, daemon=True).start()
    console()
