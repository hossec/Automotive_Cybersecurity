import can
import isotp
import time
from datetime import datetime

# ============================
# Logger Setup
# ============================
LOG_FILE = "tester_log.txt"

def log_print(msg):
    """Print to console AND save to log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    final_msg = f"[{timestamp}] {msg}"

    print(final_msg)  # Show on terminal

    with open(LOG_FILE, "a") as f:
        f.write(final_msg + "\n")  # Save in file


# ============================
# CAN Bus
# ============================
can_bus = can.interface.Bus(channel='vcan0', interface='socketcan')

# ============================
# NRC CODES
# ============================
NRC_CODES = {
    0x11: "Service not supported",
    0x12: "Sub-function (PID) not supported",
    0x13: "Incorrect message length or format",
    0x22: "Conditions not correct",
    0x31: "Request out of range",
    0x33: "Security Access Denided",
    0x35: "Invalid Key"
}

def handle_nrc(msg):
    """
    Decode and log Negative Response (0x7F).
    Format: [len, 0x7F, requested_service, NRC, ...]
    """
    if len(msg.data) < 4:
        log_print("[Tester] Invalid NRC frame (too short)")
        return

    requested_service = msg.data[2]
    nrc = msg.data[3]
    reason = NRC_CODES.get(nrc, "Unknown NRC")

    log_print(
        f"[Tester] ❌ Negative Response: service={hex(requested_service)}, "
        f"NRC={hex(nrc)} ({reason})"
    )


# ===========================================================
# ISO-TP (VIN)
# ===========================================================

def get_vin_physical():
    isotp_addr = isotp.Address(
        isotp.AddressingMode.Normal_11bits,
        txid=0x7E0,
        rxid=0x7E8
    )

    isotp_stack = isotp.CanStack(
        bus=can_bus,
        address=isotp_addr,
        error_handler=None,
        params={'blocksize': 8, 'stmin': 0}
    )
    log_print("[Tester] Sending VIN ISO-TP request...")
    isotp_stack.send(bytes([0x09, 0x02]))

    while True:
        isotp_stack.process()

        if isotp_stack.available():
            resp = isotp_stack.recv()
            if resp[0] == 0x49 and resp[1] == 0x02:
                vin = resp[2:].decode()
                log_print(f"[Tester] VIN = {vin}")
            return

        time.sleep(0.01)


def get_vin_function():
    isotp_addr = isotp.Address(
        isotp.AddressingMode.Normal_11bits,
        txid=0x7EF,
        rxid=0x7E8
    )

    isotp_stack = isotp.CanStack(
        bus=can_bus,
        address=isotp_addr,
        error_handler=None,
        params={'blocksize': 8, 'stmin': 0}
    )

    log_print("[Tester] Sending VIN ISO-TP request...")
    isotp_stack.send(bytes([0x09, 0x02]))

    while True:
        isotp_stack.process()

        if isotp_stack.available():
            resp = isotp_stack.recv()
            if resp[0] == 0x49 and resp[1] == 0x02:
                vin = resp[2:].decode()
                log_print(f"[Tester] VIN = {vin}")
            return

        time.sleep(0.01)


# ===========================================================
# CAN ECU1 (Speed + RPM)
# ===========================================================

def get_speed_ECU1():
    log_print("[Tester] Sending Speed request...")
    data = [0x02, 0x01, 0x0D, 0, 0, 0, 0, 0]
    can_bus.send(can.Message(arbitration_id=0x7E0, data=data, is_extended_id=False))

    msg = can_bus.recv(timeout=2)
    if msg and msg.arbitration_id == 0x7E8:
        # Check for NRC
        if msg.data[1] == 0x7F:
            handle_nrc(msg)
            return

        speed = msg.data[3]
        log_print(f"[Tester] Speed = {speed} km/h")
    else:
        log_print("[Tester] No Speed response")


def get_rpm_ECU1():
    log_print("[Tester] Sending RPM request...")
    data = [0x02, 0x01, 0x0C, 0, 0, 0, 0, 0]
    can_bus.send(can.Message(arbitration_id=0x7E0, data=data, is_extended_id=False))

    msg = can_bus.recv(timeout=2)
    if msg and msg.arbitration_id == 0x7E8:
        # Check for NRC
        if msg.data[1] == 0x7F:
            handle_nrc(msg)
            return

        A, B = msg.data[3], msg.data[4]
        rpm = ((A * 256) + B) / 4
        log_print(f"[Tester] RPM = {rpm}")
    else:
        log_print("[Tester] No RPM response")


# ===========================================================
# Temp ECU2
# ===========================================================

def get_temp_ECU2():
    log_print("[Tester] Sending Temp request...")
    data = [0x02, 0x01, 0x05, 0, 0, 0, 0, 0]
    can_bus.send(can.Message(arbitration_id=0x7E1, data=data, is_extended_id=False))

    msg = can_bus.recv(timeout=2)
    if msg and msg.arbitration_id == 0x7E9:
        # Check for NRC
        if msg.data[1] == 0x7F:
            handle_nrc(msg)
            return

        temp = msg.data[3]
        log_print(f"[Tester] Temp = {temp} C")
    else:
        log_print("[Tester] No Temp response")


# ===========================================================
# Functional CAN (0x7DF)
# ===========================================================

def get_speed():
    log_print("[Tester] Sending Speed request (functional)...")
    data = [0x02, 0x01, 0x0D, 0, 0, 0, 0, 0]
    can_bus.send(can.Message(arbitration_id=0x7DF, data=data, is_extended_id=False))

    msg = can_bus.recv(timeout=2)
    if msg and msg.arbitration_id == 0x7E8:
        if msg.data[1] == 0x7F:
            handle_nrc(msg)
            return

        speed = msg.data[3]
        log_print(f"[Tester] Speed = {speed} km/h")
    else:
        log_print("[Tester] No Speed response")


def get_rpm():
    log_print("[Tester] Sending RPM request (functional)...")
    data = [0x02, 0x01, 0x0C, 0, 0, 0, 0, 0]
    can_bus.send(can.Message(arbitration_id=0x7DF, data=data, is_extended_id=False))

    msg = can_bus.recv(timeout=2)
    if msg and msg.arbitration_id == 0x7E8:
        if msg.data[1] == 0x7F:
            handle_nrc(msg)
            return

        A, B = msg.data[3], msg.data[4]
        rpm = ((A * 256) + B) / 4
        log_print(f"[Tester] RPM = {rpm}")
    else:
        log_print("[Tester] No RPM response")


def get_temp():
    log_print("[Tester] Sending Temp request (functional)...")
    data = [0x02, 0x01, 0x05, 0, 0, 0, 0, 0]
    can_bus.send(can.Message(arbitration_id=0x7DF, data=data, is_extended_id=False))

    msg = can_bus.recv(timeout=2)
    if msg and msg.arbitration_id == 0x7E9:
        if msg.data[1] == 0x7F:
            handle_nrc(msg)
            return

        temp = msg.data[3]
        log_print(f"[Tester] Temp = {temp} C")
    else:
        log_print("[Tester] No Temp response")


# ===========================================================
# PHYSICAL MENU
# ===========================================================

def ECU_Physical():
    while True:
        print("\n==== ECU'S MENU ====")
        print("1) Get Speed (ECU1)")
        print("2) Get RPM (ECU1)")
        print("3) Get Temp (ECU2)")
        print("4) Get VIN (Physical)")
        print("0) Get FULL")
        print("e) Back to main menu")
        choice = input("Enter choice: ")

        if choice == "1":
            get_speed_ECU1()
        elif choice == "2":
            get_rpm_ECU1()
        elif choice == "3":
            get_temp_ECU2()
        elif choice == "4":
            get_vin_physical()
        elif choice == "0":
            get_speed_ECU1()
            get_rpm_ECU1()
            get_temp_ECU2()
            get_vin_physical()
        elif choice.lower() == "e":
            log_print("Exiting Physical...")
            main()
            break
        else:
            log_print("Invalid choice.")


# ===========================================================
# FUNCTIONAL MENU
# ===========================================================

def ECU_Functional():
    while True:
        print("\n==== PID'S MENU ====")
        print("1) Get Speed")
        print("2) Get RPM")
        print("3) Get Temp")
        print("4) Get VIN")
        print("e) Back to main menu")
        choice = input("Enter choice: ")

        if choice == "1":
            get_speed()
        elif choice == "2":
            get_rpm()
        elif choice == "3":
            get_temp()
        elif choice == "4":
            get_vin_function()
        elif choice.lower() == "e":
            log_print("Exiting Functional...")
            main()
            break
        else:
            log_print("Invalid choice.")


# ===========================================================
# CUSTOM MODE
# ===========================================================

def Custom():
    try:
        address_input = input("Enter ECU Address (hex), e.g. 7E0 or 7DF: ")
        ID = int(address_input, 16)

        mood_input = input("Enter Mood (hex), e.g. 01: ")
        Mood = int(mood_input, 16)

        pid_input = input("Enter PID (hex), e.g. 0C: ")
        PID_val = int(pid_input, 16)

        data = [0x02, Mood, PID_val, 0, 0, 0, 0, 0]

        log_print(f"[Tester] Sending frame to {hex(ID)} -> {data}")
        can_bus.send(can.Message(arbitration_id=ID, data=data, is_extended_id=False))

        msg = can_bus.recv(timeout=2)
        if msg is None:
            log_print("❌ No response received")
            return main()

        log_print(f"[Tester] Received ID: {hex(msg.arbitration_id)}, Data: {list(msg.data)}")

        # Check for NRC first
        if msg.data[1] == 0x7F:
            handle_nrc(msg)
            return main()

        if msg.arbitration_id == 0x7E9:
            temp = msg.data[3]
            log_print(f"🌡️ Temp = {temp} C")
            return

        if msg.arbitration_id == 0x7E8:
            PID_resp = msg.data[2]

            if PID_resp == 0x0C:
                speed = msg.data[3]
                log_print(f"🚗 Speed = {speed} km/h")
                return

            elif PID_resp == 0x0D:
                A, B = msg.data[3], msg.data[4]
                rpm = ((A * 256) + B) / 4
                log_print(f"🔧 RPM = {rpm}")
                return

            else:
                log_print("❌ Unsupported PID in response")
                return main()

    except Exception as e:
        log_print(f"❌ Exception: {e}")
        return main()


# ===========================================================
# MAIN MENU
# ===========================================================

def main():
    while True:
        print("\n==== TESTER MENU ====")
        print("1) Use Physical Address")
        print("2) Use Functional Address")
        print("3) Use Custom")
        print("e) Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            ECU_Physical()
        elif choice == "2":
            ECU_Functional()
        elif choice == "3":
            Custom()
        elif choice.lower() == "e":
            log_print("Exiting Tester...")
            break
        else:
            log_print("Invalid choice.")


if __name__ == "__main__":
    log_print("[Tester Started]")
    main()
