import can
import time
import isotp
import random

# ============================
# CAN Bus
# ============================
bus = can.interface.Bus(channel='vcan0', interface='socketcan')

# ============================
# Data
# ============================
VIN = b"12345678901234567"
Speed = [0]
A = 0
B = 0
RPM = [A, B]  # 6904 rpm

Function_Address = [0x7DF, 0x7E0]

PID = [0x0C, 0x0D, 0x02>, 0x00]  # RPM, SPEED, VIN, (reserved)

# ============================
# NRC Helper
# ============================
def send_negative_response(request_mode, response_id, nrc):
    """
    UDS-style Negative Response:
    [LEN=0x03, 0x7F, request_mode, NRC, padding...]
    """
    msg = can.Message(
        arbitration_id=response_id,
        data=[0x03, 0x7F, request_mode, nrc, 0x00, 0x00, 0x00, 0x00],
        is_extended_id=False
    )
    print(f"ECU1 → Sending NRC {hex(nrc)} for mode {hex(request_mode)}")
    bus.send(msg)



def Vehicle_Information(mode, pid, arb_id):
    iso_addr = isotp.Address(
        isotp.AddressingMode.Normal_11bits,
        rxid=arb_id,   # Tester → ECU
        txid=0x7E8     # ECU → Tester
    )

    stack = isotp.CanStack(
        bus=bus,
        address=iso_addr
    )

    if pid == 0x02:
        response = bytes([0x49, PID[2]]) + VIN
        print("ECU1 → Sending VIN via ISO-TP...")
        stack.send(response)
        while stack.transmitting():
            stack.process()
            time.sleep(0.01)
    else:
        print("[ECU1 ERROR] PID not supported for Vehicle Info")
        # NRC 0x12 = Sub-function not supported
        send_negative_response(mode, 0x7E8, 0x12)


# ============================
# Current Data (Speed / RPM)
# ============================
def Current_Data(mode, pid, arb_id):
    obd_mode = mode + 0x40
    response_id = 0x7E8

    # RPM
    if pid == PID[0]:
        length = 2 + len(RPM)
        msg = can.Message(
            arbitration_id=response_id,
            data=[length, obd_mode, pid] + RPM + [0x00] * (8 - (3 + len(RPM))),
            is_extended_id=False
        )
        print("ECU1 → Sending RPM...")
        bus.send(msg)

    # Speed
    elif pid == PID[1]:
        length = 2 + len(Speed)
        msg = can.Message(
            arbitration_id=response_id,
            data=[length, obd_mode, pid] + Speed + [0x00] * (8 - (3 + len(Speed))),
            is_extended_id=False
        )
        print("ECU1 → Sending Speed...")
        bus.send(msg)

    else:
        print("[ECU1 ERROR] PID not supported for Current Data")
        # NRC 0x12 = Sub-function (PID) not supported
        send_negative_response(mode, response_id, 0x12)


# ============================
# Mode Handler
# ============================
def analays_mode(mode, pid, arb_id):
    # mode 0x01 → Current Data
    if mode == 0x01:
        Current_Data(mode, pid, arb_id)

    # mode 0x09 → Vehicle Information (VIN, etc.)
    elif mode == 0x09:
        Vehicle_Information(mode, pid, arb_id)

    else:
        print("[ECU1 ERROR] Mode is not correct")
        # NRC 0x11 = Service not supported
        send_negative_response(mode, 0x7E8, 0x11)


# ============================
# Main Loop
# ============================
print("ECU 1 Started...")
while True:
    Speed = [random.randint(0, 250)]
    A = random.randint(0, 255)
    B = random.randint(0, 255)
    RPM = [A, B]

    msg = bus.recv(timeout=2)
    if msg:
        ids = msg.arbitration_id
        if ids in Function_Address:
            mode = msg.data[1]
            pid = msg.data[2]
            analays_mode(mode, pid, ids)
        else:
            print("[ECU1 ERROR] address is not for me")
