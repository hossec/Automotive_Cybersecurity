#!/usr/bin/env python3
"""
Merged ECU script - Option B (Security Access first; protections enabled by CONFIG F1A0)
With fixes:
 - Accept CONFIG values like 02, 32, "30 32", etc.
 - Correct ISO-TP data type handling: DATA = bytes(DATA)
 - Require session token for SID 0x10 (session control) and SID 0x11 (reset) when token protection enabled
"""

import can
import time
import isotp
import random

# -----------------------------------
# CAN + ISO-TP
# -----------------------------------
bus = can.interface.Bus(channel='vcan0', interface='socketcan')

addr = isotp.Address(
    isotp.AddressingMode.Normal_11bits,
    rxid=0x7E0,
    txid=0x7E8
)

isotp_stack = isotp.CanStack(bus=bus, address=addr)

# -----------------------------------
# CONFIG values allowed:
# 01 = No protection
# 02 = Lockout only
# 03 = Token only
# 04 = Full protection
# -----------------------------------
CONFIG = b"01"   # default

# ==========================================================
# Flexible CONFIG value parser
# Accepts weird tester encodings (02 / 32 / 30 32 / 00 02 ...)
# ==========================================================
def parse_config_value(data_bytes):
    """
    Convert any weird format into one of:
      b"01", b"02", b"03", b"04"
    If unrecognized → return None
    """

    if not data_bytes:
        return None

    # Normalize to bytes
    data = bytes(data_bytes)

    # Case A: single byte direct (02, 03, 04)
    if len(data) == 1:
        val = data[0]

        if val == 0x01:
            return b"01"
        if val == 0x02:
            return b"02"
        if val == 0x03:
            return b"03"
        if val == 0x04:
            return b"04"

        # Special case: testers sending ASCII digit codes
        # "32" means ASCII '2' = 0x32
        if val == 0x31:  # ASCII '1'
            return b"01"
        if val == 0x32:  # ASCII '2'
            return b"02"
        if val == 0x33:  # ASCII '3'
            return b"03"
        if val == 0x34:  # ASCII '4'
            return b"04"

        return None

    # Case B: two bytes ASCII e.g. 0x30 0x32 = "02"
    if len(data) == 2:
        try:
            txt = data.decode(errors='ignore')
            if txt == "01":
                return b"01"
            if txt == "02":
                return b"02"
            if txt == "03":
                return b"03"
            if txt == "04":
                return b"04"
        except:
            pass

    # Case C: many bytes → try extract ASCII digits
    digits = ""
    for b in data:
        if 48 <= b <= 57:  # '0'..'9'
            digits += chr(b)

    if digits in ("01", "02", "03", "04"):
        return digits.encode()

    return None


# ----------------------------------------------------------
# Protection enable helpers
# ----------------------------------------------------------
def lockout_config_enabled():
    return CONFIG in (b"02", b"04")

def token_config_enabled():
    return CONFIG in (b"03", b"04")


# ----------------------------------------------------------
# Security + Token System
# ----------------------------------------------------------
session_token = 0xAA
token_runtime_enabled = False

MAX_ATTEMPTS = 3
LOCKOUT_TIME = 600
SEED_DELAY = 5

SESSION_FLAG = 1
SEC_ACCESS_FLAG = 0
KEY = 0x11223344
S3 = 5
LAST_SEED = None
LAST_REQUEST_DATA = b""
last_activity_time = 0

attempts = 0
locked = False
lockout_timer = 0
seed_given = False
key_verified = False
seed_delay_timer = 0

# ----------------------------------------------------------
# ECU data
# ----------------------------------------------------------
VIN = b"12345678901234567"
MODEL = b"ABCD"
SPEED = b"100"
TEMP = b"90"
FUEL = b"50"
OIL = b"20"

# ----------------------------------------------------------
def send_nrc(SID, nrc):
    payload = bytes([0x7F, SID, nrc])
    isotp_stack.send(payload)
    print(f"[ECU] NRC = 7F {SID:02X} {nrc:02X}")

def update_session_timer():
    global last_activity_time
    last_activity_time = time.time()

def combine_u16(a, b):
    return (a << 8) | b

def send_positive_response(SID, SUB=None, RID_DID=None, data=b""):
    resp = (SID + 0x40) & 0xFF
    if SUB is None and RID_DID is None:
        payload = bytes([resp]) + data
    elif SUB is None:
        payload = bytes([resp]) + RID_DID.to_bytes(2,"big") + data
    elif RID_DID is None:
        payload = bytes([resp, SUB]) + data
    else:
        payload = bytes([resp, SUB]) + RID_DID.to_bytes(2,"big") + data

    isotp_stack.send(payload)
    print(f"[ECU] POS: {payload.hex()}")

    while isotp_stack.transmitting():
        isotp_stack.process()


# ----------------------------------------------------------
# RESET ECU
# ----------------------------------------------------------
def Reset_Ecu():
    global VIN, MODEL, CONFIG, SPEED, TEMP, FUEL, OIL
    global SESSION_FLAG, SEC_ACCESS_FLAG, LAST_SEED, LAST_REQUEST_DATA
    global token_runtime_enabled, attempts, locked, lockout_timer
    global seed_given, key_verified, seed_delay_timer

    VIN = b"12345678901234567"
    MODEL = b"ABCD"
    CONFIG = b"01"
    SPEED = b"100"
    TEMP = b"90"
    FUEL = b"50"
    OIL = b"20"

    SESSION_FLAG = 1
    SEC_ACCESS_FLAG = 0
    LAST_SEED = None
    LAST_REQUEST_DATA = b""
    token_runtime_enabled = False

    attempts = 0
    locked = False
    lockout_timer = 0
    seed_given = False
    key_verified = False
    seed_delay_timer = 0

    print("[ECU] RESET COMPLETE")


# ----------------------------------------------------------
# Handle RESET SID=0x11
# ----------------------------------------------------------
def RESET(SID, SUB):
    if SEC_ACCESS_FLAG != 1:
        send_nrc(SID, 0x33)
        return
    send_positive_response(0x11, SUB)
    Reset_Ecu()


# ----------------------------------------------------------
def TesterPresent(SID, SUB):
    if SUB in (0x00, 0x80):
        update_session_timer()
        send_positive_response(0x3E, SUB)
    else:
        send_nrc(SID, 0x12)


# ----------------------------------------------------------
def check_session_timeout():
    global SESSION_FLAG
    if SESSION_FLAG != 1:
        if time.time() - last_activity_time > S3:
            SESSION_FLAG = 1
            print("[ECU] Session timeout → Default")


# ----------------------------------------------------------
# Security Access
# ----------------------------------------------------------
def handle_security_access(SID, SUB):
    global LAST_SEED, SEC_ACCESS_FLAG, attempts, locked
    global lockout_timer, seed_given, key_verified, seed_delay_timer
    global token_runtime_enabled

    now = time.time()

    if lockout_config_enabled() and locked:
        if now < lockout_timer:
            send_nrc(SID, 0x37)
            print("[ECU] Locked")
            return
        else:
            locked = False
            attempts = 0

    if SUB == 0x01:
        if seed_given and not key_verified and now < seed_delay_timer:
            send_nrc(SID, 0x78)
            return

        LAST_SEED = random.randint(0x1000, 0x1FFF)
        seed_given = True
        key_verified = False
        seed_delay_timer = now + SEED_DELAY
        send_positive_response(SID, SUB, data=LAST_SEED.to_bytes(4,"big"))
        return

    elif SUB == 0x02:
        if not seed_given or LAST_SEED is None:
            send_nrc(SID, 0x24)
            return

        if len(LAST_REQUEST_DATA) < 6:
            send_nrc(SID, 0x22)
            return

        recv_key = int.from_bytes(LAST_REQUEST_DATA[2:6],'big')
        expected = (LAST_SEED + KEY) & 0xFFFFFFFF

        if recv_key == expected:
            SEC_ACCESS_FLAG = 1
            attempts = 0
            seed_given = False
            send_positive_response(SID, SUB)

            if token_config_enabled():
                token_runtime_enabled = True
                print(f"[ECU] SESSION TOKEN runtime ENABLED = 0x{session_token:02X}")
            return

        # wrong key
        if lockout_config_enabled():
            attempts += 1
            if attempts >= MAX_ATTEMPTS:
                locked = True
                lockout_timer = now + LOCKOUT_TIME
                send_nrc(SID, 0x36)
                return
            send_nrc(SID, 0x35)
            return

        # lockout disabled
        send_nrc(SID, 0x35)
        return

    send_nrc(SID, 0x12)


# ----------------------------------------------------------
# Session Control (0x10)
# ----------------------------------------------------------
def handle_session_access(SID, SUB):
    global SESSION_FLAG, token_runtime_enabled

    if token_runtime_enabled:
        resp = bytes([0x50, SUB, session_token])
    else:
        resp = bytes([0x50, SUB])

    isotp_stack.send(resp)
    print(f"[ECU] POS: {resp.hex()}")

    if SUB == 0x01:
        SESSION_FLAG = 1
    elif SUB == 0x02:
        SESSION_FLAG = 2
    elif SUB == 0x03:
        SESSION_FLAG = 3
    else:
        send_nrc(SID, 0x12)


# ----------------------------------------------------------
# SESSION_CONTROL
# ----------------------------------------------------------
def SESSION_CONTROL():
    global LAST_REQUEST_DATA

    isotp_stack.process()
    if not isotp_stack.available():
        return None, None, None, None

    msg = isotp_stack.recv()
    if not msg:
        return None, None, None, None

    SID = msg[0]

    # Token verification for 0x10 and for 0x11 (RESET) when token_runtime_enabled True
    if SID == 0x10 and SEC_ACCESS_FLAG == 1 and token_runtime_enabled:
        if len(msg) < 3:
            send_nrc(0x10, 0x24)
            print("[ECU] WRONG / MISSING TOKEN FOR 10xx (too short)")
            return None, None, None, None
        if msg[-1] != session_token:
            send_nrc(0x10, 0x24)
            print("[ECU] WRONG / MISSING TOKEN FOR 10xx (invalid)")
            return None, None, None, None
        # token present & valid -> strip token byte before further processing
        print("[ECU] TOKEN VALID ✔ for 0x10 request")
        msg = msg[:-1]

    # Token verification for RESET (0x11)
    if SID == 0x11 and SEC_ACCESS_FLAG == 1 and token_runtime_enabled:
        if len(msg) < 3:
            send_nrc(0x11, 0x24)
            print("[ECU] RESET Missing Token")
            return None, None, None, None
        if msg[-1] != session_token:
            send_nrc(0x11, 0x24)
            print("[ECU] RESET Wrong Token")
            return None, None, None, None
        # Strip token
        msg = msg[:-1]
        LAST_REQUEST_DATA = msg
        SID = msg[0] if len(msg) > 0 else SID
        print("[ECU] RESET TOKEN VALID ✔")

    LAST_REQUEST_DATA = msg
    SUB = msg[1] if len(msg)>1 else None

    if SID == 0x10:
        handle_session_access(SID, SUB)
        return SID,SUB,None,None

    if SID == 0x11:
        RESET(SID, SUB)
        return SID,SUB,None,None

    if SID == 0x27:
        handle_security_access(SID, SUB)
        return SID,SUB,None,None

    if SID == 0x3E:
        TesterPresent(SID, SUB)
        return SID,SUB,None,None

    if SID in (0x22,0x2E):
        if len(msg)>=3:
            DID = combine_u16(msg[1], msg[2])
            DATA = msg[3:]
            return SID,SUB,DID,DATA
        send_nrc(SID, 0x13)
        return None,None,None,None

    if SID == 0x31:
        if len(msg)>=4:
            DID = combine_u16(msg[2], msg[3])
            return SID,SUB,DID,None
        send_nrc(SID, 0x13)
        return None,None,None,None

    send_nrc(SID, 0x11)
    return None,None,None,None


# ----------------------------------------------------------
# Session loops
# ----------------------------------------------------------
def do_write_F1A0(DATA):
    global CONFIG, token_runtime_enabled
    DATA = bytes(DATA)

    parsed = parse_config_value(DATA)
    if parsed is None:
        return False

    CONFIG = parsed

    if not token_config_enabled():
        token_runtime_enabled = False

    print(f"[ECU] CONFIG updated → {CONFIG}")
    return True


def Session_Default():
    print("Default Session")
    update_session_timer()

    global SESSION_FLAG
    while SESSION_FLAG == 1:
        check_session_timeout()

        SID,SUB,DID,DATA = SESSION_CONTROL()
        if SID is None:
            continue

        if SID == 0x22:
            if DID == 0xF1A0:
                send_positive_response(0x22, RID_DID=DID, data=CONFIG)
            elif DID == 0xF190:
                send_positive_response(0x22, RID_DID=DID, data=VIN)
            elif DID == 0xF18C:
                send_positive_response(0x22, RID_DID=DID, data=MODEL)
            else:
                send_nrc(0x22, 0x31)

        elif SID == 0x2E:
            if DID == 0xF1A0:
                if SEC_ACCESS_FLAG != 1:
                    send_nrc(0x2E,0x33)
                    continue

                if not DATA:
                    send_nrc(0x2E,0x13)
                    continue

                if do_write_F1A0(DATA):
                    send_positive_response(0x2E, RID_DID=DID, data=DATA)
                else:
                    send_nrc(0x2E,0x31)
            else:
                send_nrc(0x2E,0x31)


def Session_Program():
    print("Program Session")
    update_session_timer()

    global SESSION_FLAG
    while SESSION_FLAG == 2:
        check_session_timeout()

        SID,SUB,DID,DATA = SESSION_CONTROL()
        if SID is None:
            continue

        if SID == 0x22:
            if DID == 0xF1A0:
                send_positive_response(0x22, RID_DID=DID, data=CONFIG)
            elif DID == 0xF190:
                send_positive_response(0x22, RID_DID=DID, data=VIN)
            elif DID == 0xF18C:
                send_positive_response(0x22, RID_DID=DID, data=MODEL)

        elif SID == 0x2E:
            if DID == 0xF1A0:
                if not DATA:
                    send_nrc(0x2E,0x13)
                    continue
                if do_write_F1A0(DATA):
                    send_positive_response(0x2E, RID_DID=DID, data=DATA)
                else:
                    send_nrc(0x2E,0x31)


def Session_Extended():
    print("Extended Session")
    update_session_timer()

    global SESSION_FLAG
    while SESSION_FLAG == 3:
        check_session_timeout()

        SID,SUB,DID,DATA = SESSION_CONTROL()
        if SID is None:
            continue

        if SID == 0x22:
            if DID == 0xF1A0:
                send_positive_response(0x22, RID_DID=DID, data=CONFIG)
            elif DID == 0xF190:
                send_positive_response(0x22, RID_DID=DID, data=VIN)
            elif DID == 0xF18C:
                send_positive_response(0x22, RID_DID=DID, data=MODEL)

        elif SID == 0x2E:
            if DID == 0xF1A0:
                if not DATA:
                    send_nrc(0x2E,0x13)
                    continue
                if do_write_F1A0(DATA):
                    send_positive_response(0x2E, RID_DID=DID, data=DATA)
                else:
                    send_nrc(0x2E,0x31)


# ----------------------------------------------------------
# MAIN LOOP
# ----------------------------------------------------------
print("[ECU] Merged ECU Started (Flexible CONFIG Mode Enabled, RESET requires token when enabled)")

while True:
    if SESSION_FLAG == 1:
        Session_Default()
    elif SESSION_FLAG == 2:
        Session_Program()
    elif SESSION_FLAG == 3:
        Session_Extended()
