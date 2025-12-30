#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UDS Tester — CLEAN VERSION (NO RAW CAN MODE)
✓ You only write: 27 01 / 10 02 / 22 F1A0 ...
✓ Uses TX/RX IDs defined at startup
✓ Auto Security Access (seed → key)
✓ Auto Token Append for 10/11
✓ Flush ISO-TP buffer before every request
✓ Fully compatible with updated ECU
"""

import can
import isotp
import threading
import time
import sys


# -------------------------------------------------------
# Input Helpers
# -------------------------------------------------------
def get_hex_input(prompt, default=None):
    try:
        s = input(prompt).strip()
        if s == "" and default is not None:
            return default
        return int(s, 16)
    except:
        print("Invalid hex.")
        return get_hex_input(prompt, default)


print("UDS Tester — CLEAN MODE (ISO-TP ONLY)")

TX_ID = get_hex_input("Enter Tester → ECU TX ID (default 7E0): 0x", 0x7E0)
RX_ID = get_hex_input("Enter ECU → Tester RX ID (default 7E8): 0x", 0x7E8)

print(f"Using TX=0x{TX_ID:03X}  RX=0x{RX_ID:03X}\n")


# -------------------------------------------------------
# Constants
# -------------------------------------------------------
KEY_SOURCE = 0x11223344

NRC_MEANINGS = {
    0x10: "General Reject",
    0x11: "Service Not Supported",
    0x12: "Sub-Function Not Supported",
    0x13: "Incorrect Message Length",
    0x22: "Conditions Not Correct",
    0x24: "Wrong Sequence / Missing Token",
    0x31: "Request Out Of Range",
    0x33: "Security Access Denied",
    0x35: "Invalid Key",
    0x36: "Exceeded Number of Attempts",
    0x37: "Required Time Delay Not Expired",
    0x78: "Response Pending"
}


# -------------------------------------------------------
# CAN + ISO-TP
# -------------------------------------------------------
bus = can.interface.Bus(channel='vcan0', interface='socketcan')

addr = isotp.Address(
    isotp.AddressingMode.Normal_11bits,
    rxid=RX_ID,
    txid=TX_ID
)

stack = isotp.CanStack(bus=bus, address=addr)


# -------------------------------------------------------
# State
# -------------------------------------------------------
tester_present_running = False
stored_token = None
token_required = False
last_seed = None


# -------------------------------------------------------
# Flush ISO-TP buffer
# -------------------------------------------------------
def flush_isotp_stack():
    for _ in range(50):
        stack.process()
        msg = stack.recv()
        if not msg:
            break


# -------------------------------------------------------
# Send Frame
# -------------------------------------------------------
def send_frame(data):
    stack.send(data)
    print(f"→ Sent: {data.hex().upper()}")


# -------------------------------------------------------
# Receive Frame
# -------------------------------------------------------
def receive_frame(timeout=2.0):
    start = time.time()
    while time.time() - start < timeout:
        stack.process()
        msg = stack.recv()
        if msg:
            return msg
        time.sleep(0.005)
    return None


# -------------------------------------------------------
# Response Handler
# -------------------------------------------------------
def handle_response_for(sent_sid, resp):
    global stored_token, token_required, last_seed

    if resp[0] == 0x7F and len(resp) >= 3:
        nrc = resp[2]
        print(f"❌ NRC 0x{nrc:02X}: {NRC_MEANINGS.get(nrc, 'Unknown')}")
        return False

    # 0x50 - Session response (token inside)
    if resp[0] == 0x50:
        if len(resp) == 3:
            stored_token = resp[2]
            token_required = True
            print(f"✔ Session OK — TOKEN=0x{stored_token:02X}")
        else:
            print("✔ Session OK")
        return True

    # 0x67 01 - seed
    if resp[0] == 0x67 and resp[1] == 0x01:
        seed = resp[2:6]
        last_seed = seed
        print(f"🔐 SEED = {seed.hex().upper()}")
        calc_and_send_key(seed)
        return True

    if resp[0] == 0x67 and resp[1] == 0x02:
        print("✔ Security Access GRANTED")
        return True

    if resp[0] == 0x51:
        print("✔ Reset OK")
        return True

    if resp[0] == 0x62:
        did = resp[1:3].hex().upper()
        data = resp[3:]
        ascii_val = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        print(f"✔ Read DID 0x{did}: {data.hex().upper()} ASCII={ascii_val}")
        return True

    if resp[0] == 0x6E:
        did = resp[1:3].hex().upper()
        print(f"✔ Write DID OK 0x{did}")
        return True

    print("→ Response:", resp.hex().upper())
    return True


# -------------------------------------------------------
# Calc + Send Key
# -------------------------------------------------------
def calc_and_send_key(seed_bytes):
    seed_int = int.from_bytes(seed_bytes, "big")
    key_int = seed_int + KEY_SOURCE
    key = key_int.to_bytes(4, "big")

    print(f"→ KEY = {key.hex().upper()}")
    send_frame(bytes([0x27, 0x02]) + key)

    resp = receive_frame()
    if resp:
        handle_response_for("27", resp)


# -------------------------------------------------------
# TesterPresent Thread
# -------------------------------------------------------
def tester_present_loop():
    while tester_present_running:
        stack.send(bytes([0x3E, 0x00]))
        stack.process()
        time.sleep(4)


def start_tester_present():
    global tester_present_running
    if not tester_present_running:
        tester_present_running = True
        threading.Thread(target=tester_present_loop, daemon=True).start()


def stop_tester_present():
    global tester_present_running
    tester_present_running = False


# -------------------------------------------------------
# Build and Send (ONLY SID + DATA)
# -------------------------------------------------------
def build_and_send(cmd):
    global stored_token, token_required

    flush_isotp_stack()

    parts = cmd.split()
    try:
        sid = int(parts[0], 16)
    except:
        print("Invalid SID")
        return

    data = b""
    if len(parts) > 1:
        try:
            data = bytes.fromhex(" ".join(parts[1:]))
        except:
            print("Invalid data hex")
            return

    payload = bytes([sid]) + data

    if sid in (0x10, 0x11) and token_required and stored_token is not None:
        payload += bytes([stored_token])
        print(f"[AUTO] Appended token {stored_token:02X}")

    send_frame(payload)
    resp = receive_frame()

    if resp:
        handle_response_for(parts[0], resp)
    else:
        print("No response")


# -------------------------------------------------------
# CLI
# -------------------------------------------------------
def main_loop():
    print("Write UDS commands normally:  ")
    print(" 27 01")
    print(" 10 02")
    print(" 22 F1A0")
    print(" 2E F1A0 02")
    print("\nCommands:")
    print(" s = start TesterPresent")
    print(" f = stop TesterPresent")
    print(" c = change IDs")
    print(" e = exit")
    print("Anything else is treated as UDS frame.\n")

    while True:
        cmd = input("> ").strip().lower()

        if cmd == "s": start_tester_present()
        elif cmd == "f": stop_tester_present()
        elif cmd == "c": change_ids()
        elif cmd == "e":
            stop_tester_present()
            print("Bye.")
            break
        else:
            build_and_send(cmd)


def change_ids():
    global TX_ID, RX_ID, stack, addr

    stop_tester_present()

    TX_ID = get_hex_input("New TX: 0x", TX_ID)
    RX_ID = get_hex_input("New RX: 0x", RX_ID)

    addr = isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=RX_ID, txid=TX_ID)
    stack = isotp.CanStack(bus=bus, address=addr)

    print(f"Updated TX=0x{TX_ID:03X} RX=0x{RX_ID:03X}")


if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        stop_tester_present()
        print("\nInterrupted.")
        sys.exit(0)
