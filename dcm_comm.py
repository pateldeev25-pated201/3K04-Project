"""
dcm_comm.py
Serial communication and protocol logic for DCM <-> Pacemaker interface.
Implements packet construction, parsing, and UART communication as per requirements.
"""
import serial
import struct
import threading
import time

# Protocol constants (from requirements)
SYNC = 0x16  # Example value, update as needed
SOH = 0x01   # Example value, update as needed

# Function codes
def get_fn_codes():
    return {
        'k_pparams': 0x01,  # Receive parameters
        'k_echo': 0x02,     # Send parameters
        'k_egram': 0x03,    # Request egram
        'k_estop': 0x04,    # Stop egram
    }

# Packet sizes
DATA_SIZE = 13  # n = 13
PKT_SIZE = DATA_SIZE + 3

class DCMComm:
    def __init__(self, port, baudrate=115200, timeout=1):
        self.ser = serial.Serial(port, baudrate, timeout=timeout)
        self.lock = threading.Lock()

    def build_packet(self, fn_code, data_bytes=None):
        """Builds a packet according to the protocol."""
        if data_bytes is None:
            data_bytes = bytes([0] * DATA_SIZE)
        header = bytes([SYNC, SOH, fn_code])
        header_chksum = (SYNC + SOH + fn_code) & 0xFF
        data_chksum = sum(data_bytes) & 0xFF
        pkt = header + bytes([header_chksum]) + data_bytes + bytes([data_chksum])
        return pkt

    def send_packet(self, fn_code, data_bytes=None):
        pkt = self.build_packet(fn_code, data_bytes)
        with self.lock:
            self.ser.write(pkt)

    def read_packet(self):
        """Reads a packet from the serial port."""
        with self.lock:
            pkt = self.ser.read(PKT_SIZE)
        if len(pkt) != PKT_SIZE:
            return None
        # Validate header checksum
        if pkt[3] != ((pkt[0] + pkt[1] + pkt[2]) & 0xFF):
            return None
        # Validate data checksum
        if pkt[-1] != (sum(pkt[4:-1]) & 0xFF):
            return None
        return pkt

    def close(self):
        self.ser.close()

    # Example: send parameters
    def send_params(self, params_bytes):
        fn_codes = get_fn_codes()
        self.send_packet(fn_codes['k_echo'], params_bytes)

    # Example: request egram
    def request_egram(self):
        fn_codes = get_fn_codes()
        self.send_packet(fn_codes['k_egram'])

    # Example: stop egram
    def stop_egram(self):
        fn_codes = get_fn_codes()
        self.send_packet(fn_codes['k_estop'])

    # Example: receive parameters
    def receive_params(self):
        fn_codes = get_fn_codes()
        self.send_packet(fn_codes['k_pparams'])
        pkt = self.read_packet()
        if pkt:
            return pkt[4:-1]  # Data bytes
        return None

# Utility: pack parameters into bytes (to be implemented as per parameter spec)

# Parameter packing order and sizes (from requirements):
# 0: p_pacingState (1 byte)
# 1: p_pacingMode (1 byte)
# 2: p_hysteresis (1 byte)
# 3-4: p_hysteresisInterval (2 bytes, little endian)
# 5-6: p_lowrateInterval (2 bytes, little endian)
# 7-8: p_vPaceAmp (2 bytes, little endian)
# 9-10: 10*p_vPaceWidth (2 bytes, little endian)
# 11-12: p_VRP (2 bytes, little endian)

def pack_params(params_dict):
    # Helper to get int value with default
    def getval(key, default=0):
        v = params_dict.get(key, default)
        try:
            return int(float(v))
        except Exception:
            return default

    # Map canonical keys to protocol fields
    # You may need to adjust these mappings to match your UI/param names
    pacing_state = getval('pacingState', 1)  # 1=active, 0=inactive (example)
    pacing_mode = getval('mode', 0)          # Should be mapped to mode code (see below)
    hysteresis = getval('Hysteresis', 0)
    hysteresis_interval = getval('Hysteresis_Interval', 0)
    lowrate_interval = getval('LRL', 60)
    vpace_amp = getval('V_ventricular_amp', 25)  # e.g., 2.5V * 10
    vpace_width = getval('V_pulse_width', 1)     # ms
    vrp = getval('VRP', 250)

    # Map mode string to code (example mapping, update as needed)
    mode_map = {
        'AOO': 0x00, 'VOO': 0x01, 'AAI': 0x02, 'VVI': 0x03,
        'DOO': 0x04, 'DDD': 0x05, 'DDI': 0x06, 'VDD': 0x07,
        'AOOR': 0x08, 'VOOR': 0x09, 'AAIR': 0x0A, 'VVIR': 0x0B,
        'DDDR': 0x0C, 'AAT': 0x0D, 'VVT': 0x0E, 'VDDR': 0x0F,
        'DOOR': 0x10, 'DDIR': 0x11
    }
    mode_str = params_dict.get('mode', 'VOO')
    pacing_mode = mode_map.get(str(mode_str).upper(), 0x01)

    # Convert to protocol units
    # vpace_amp: V * 10 (e.g., 2.5V -> 25)
    vpace_amp = int(float(params_dict.get('V_ventricular_amp', 2.5)) * 10)
    # vpace_width: ms * 10 (e.g., 1.0ms -> 10)
    vpace_width = int(float(params_dict.get('V_pulse_width', 1.0)) * 10)

    # Pack into bytes (little endian for 2-byte fields)
    pkt = bytearray(13)
    pkt[0] = pacing_state & 0xFF
    pkt[1] = pacing_mode & 0xFF
    pkt[2] = hysteresis & 0xFF
    pkt[3:5] = int(hysteresis_interval).to_bytes(2, 'little', signed=False)
    pkt[5:7] = int(lowrate_interval).to_bytes(2, 'little', signed=False)
    pkt[7:9] = int(vpace_amp).to_bytes(2, 'little', signed=False)
    pkt[9:11] = int(vpace_width).to_bytes(2, 'little', signed=False)
    pkt[11:13] = int(vrp).to_bytes(2, 'little', signed=False)
    return bytes(pkt)

# Utility: unpack parameters from bytes (to be implemented as per parameter spec)

def unpack_params(data_bytes):
    # Unpack 13 bytes into parameter dict (reverse of pack_params)
    if len(data_bytes) != 13:
        return {}
    pacing_state = data_bytes[0]
    pacing_mode = data_bytes[1]
    hysteresis = data_bytes[2]
    hysteresis_interval = int.from_bytes(data_bytes[3:5], 'little', signed=False)
    lowrate_interval = int.from_bytes(data_bytes[5:7], 'little', signed=False)
    vpace_amp = int.from_bytes(data_bytes[7:9], 'little', signed=False)
    vpace_width = int.from_bytes(data_bytes[9:11], 'little', signed=False)
    vrp = int.from_bytes(data_bytes[11:13], 'little', signed=False)

    # Reverse protocol units
    vpace_amp_v = vpace_amp / 10.0
    vpace_width_ms = vpace_width / 10.0

    # Reverse mode code to string (example mapping)
    mode_map_rev = {v: k for k, v in {
        'AOO': 0x00, 'VOO': 0x01, 'AAI': 0x02, 'VVI': 0x03,
        'DOO': 0x04, 'DDD': 0x05, 'DDI': 0x06, 'VDD': 0x07,
        'AOOR': 0x08, 'VOOR': 0x09, 'AAIR': 0x0A, 'VVIR': 0x0B,
        'DDDR': 0x0C, 'AAT': 0x0D, 'VVT': 0x0E, 'VDDR': 0x0F,
        'DOOR': 0x10, 'DDIR': 0x11
    }.items()}
    mode_str = mode_map_rev.get(pacing_mode, 'VOO')

    return {
        'pacingState': pacing_state,
        'mode': mode_str,
        'Hysteresis': hysteresis,
        'Hysteresis_Interval': hysteresis_interval,
        'LRL': lowrate_interval,
        'V_ventricular_amp': vpace_amp_v,
        'V_pulse_width': vpace_width_ms,
        'VRP': vrp
    }
