import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import os
import hashlib
import secrets
import time
import glob
from typing import Optional

# Import serial communication module
import dcm_comm

# -----------------------
# Files / config
# -----------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

USERS_FILE = os.path.join(BASE_DIR, "users.json")
LAST_DEVICE_FILE = os.path.join(BASE_DIR, "last_device.json")
EGRAM_DIR = os.path.join(BASE_DIR, "egrams")

MAX_USERS = 10

# Modes for dropdown
MODE_OPTIONS = ["AOO", "VOO", "AAI", "VVI", "DOO", "DDD", "DDI", "VDD", "AOOR", "VOOR", "AAIR", "VVIR", "DDDR", "AAT", "VVT", "VDDR", "DOOR", "DDIR"]

# Expanded required parameters (display label, canonical key, unit)
REQUIRED_PARAMS = [
	("Lower Rate Limit", "LRL", "bpm"),
	("Upper Rate Limit", "URL", "bpm"),
	("Maximum Sensor Rate", "MSR", "bpm"),
	("Fixed AV Delay", "Fixed_AV_Delay", "ms"),
	("Dynamic AV Delay", "Dynamic_AV_Delay", "On/Off"),
	("Minimum Dynamic AV Delay", "Min_Dyn_AV_Delay", "ms"),
	("Sensed AV Delay Offset", "Sensed_AV_Delay_Offset", "ms"),
	("Atrial Amplitude", "A_atrial_amp", "V"),
	("Ventricular Amplitude", "V_ventricular_amp", "V"),
	("Atrial Pulse Width", "A_pulse_width", "ms"),
	("Ventricular Pulse Width", "V_pulse_width", "ms"),
	("Atrial Sensitivity", "A_sensitivity", "mV"),
	("Ventricular Sensitivity", "V_sensitivity", "mV"),
	("VRP", "VRP", "ms"),
	("ARP", "ARP", "ms"),
	("PVARP", "PVARP", "ms"),
	("PVARP Extension", "PVARP_Extension", "ms"),
	("Hysteresis", "Hysteresis", "On/Off"),
	("Hysteresis Rate Limit", "HRL", "bpm"),
	("Rate Smoothing", "Rate_Smoothing", "%"),
	("ATR Duration", "ATR_Duration", "cycles"),
	("ATR Fallback Mode", "ATR_Fallback_Mode", "Mode"),
	("ATR Fallback Time", "ATR_Fallback_Time", "min"),
	("Activity Threshold", "Activity_Threshold", "Level"),
	("Reaction Time", "Reaction_Time", "sec"),
	("Response Factor", "Response_Factor", ""),
	("Recovery Time", "Recovery_Time", "min"),
]

# Expanded PARAMS_BY_MODE (from Table 6)
PARAMS_BY_MODE = {
	"aoo": {"LRL", "URL", "A_atrial_amp", "A_pulse_width"},
	"voo": {"LRL", "URL", "V_ventricular_amp", "V_pulse_width"},
	"aai": {"LRL", "URL", "A_atrial_amp", "A_pulse_width", "ARP", "A_sensitivity", "Hysteresis"},
	"vvi": {"LRL", "URL", "V_ventricular_amp", "V_pulse_width", "VRP", "V_sensitivity", "Hysteresis"},
	"aoor": {"LRL", "URL", "MSR", "A_atrial_amp", "A_pulse_width", "Activity_Threshold", "Reaction_Time", "Response_Factor", "Recovery_Time"},
	"voor": {"LRL", "URL", "MSR", "V_ventricular_amp", "V_pulse_width", "Activity_Threshold", "Reaction_Time", "Response_Factor", "Recovery_Time"},
	"aair": {"LRL", "URL", "MSR", "A_atrial_amp", "A_pulse_width", "ARP", "A_sensitivity", "Hysteresis", "Activity_Threshold", "Reaction_Time", "Response_Factor", "Recovery_Time"},
	"vvir": {"LRL", "URL", "MSR", "V_ventricular_amp", "V_pulse_width", "VRP", "V_sensitivity", "Hysteresis", "Activity_Threshold", "Reaction_Time", "Response_Factor", "Recovery_Time"},
	"aat": {"LRL", "URL", "A_atrial_amp", "A_pulse_width", "ARP", "A_sensitivity"},
	"vvt": {"LRL", "URL", "V_ventricular_amp", "V_pulse_width", "VRP", "V_sensitivity"},
	"doo": {"LRL", "URL", "A_atrial_amp", "A_pulse_width", "V_ventricular_amp", "V_pulse_width", "Fixed_AV_Delay", "Dynamic_AV_Delay", "Min_Dyn_AV_Delay", "Sensed_AV_Delay_Offset", "VRP", "ARP", "PVARP", "PVARP_Extension"},
	"ddd": {"LRL", "URL", "A_atrial_amp", "A_pulse_width", "V_ventricular_amp", "V_pulse_width", "Fixed_AV_Delay", "Dynamic_AV_Delay", "Min_Dyn_AV_Delay", "Sensed_AV_Delay_Offset", "VRP", "ARP", "PVARP", "PVARP_Extension", "A_sensitivity", "V_sensitivity", "Rate_Smoothing", "ATR_Duration", "ATR_Fallback_Mode", "ATR_Fallback_Time", "Activity_Threshold", "Reaction_Time", "Response_Factor", "Recovery_Time", "Hysteresis", "HRL"},
	"ddi": {"LRL", "URL", "A_atrial_amp", "A_pulse_width", "V_ventricular_amp", "V_pulse_width", "Fixed_AV_Delay", "Dynamic_AV_Delay", "Min_Dyn_AV_Delay", "Sensed_AV_Delay_Offset", "VRP", "ARP", "PVARP", "PVARP_Extension"},
	"vdd": {"LRL", "URL", "A_atrial_amp", "A_pulse_width", "V_ventricular_amp", "V_pulse_width", "Fixed_AV_Delay", "Dynamic_AV_Delay", "Min_Dyn_AV_Delay", "Sensed_AV_Delay_Offset", "VRP", "PVARP", "PVARP_Extension"},
	"dddr": {"LRL", "URL", "MSR", "A_atrial_amp", "A_pulse_width", "V_ventricular_amp", "V_pulse_width", "Fixed_AV_Delay", "Dynamic_AV_Delay", "Min_Dyn_AV_Delay", "Sensed_AV_Delay_Offset", "VRP", "ARP", "PVARP", "PVARP_Extension", "A_sensitivity", "V_sensitivity", "Rate_Smoothing", "ATR_Duration", "ATR_Fallback_Mode", "ATR_Fallback_Time", "Activity_Threshold", "Reaction_Time", "Response_Factor", "Recovery_Time", "Hysteresis", "HRL"},
	"vddr": {"LRL", "URL", "MSR", "A_atrial_amp", "A_pulse_width", "V_ventricular_amp", "V_pulse_width", "Fixed_AV_Delay", "Dynamic_AV_Delay", "Min_Dyn_AV_Delay", "Sensed_AV_Delay_Offset", "VRP", "PVARP", "PVARP_Extension", "A_sensitivity", "V_sensitivity", "Activity_Threshold", "Reaction_Time", "Response_Factor", "Recovery_Time", "Hysteresis", "HRL"},
	"door": {"LRL", "URL", "MSR", "A_atrial_amp", "A_pulse_width", "V_ventricular_amp", "V_pulse_width", "Fixed_AV_Delay", "Dynamic_AV_Delay", "Min_Dyn_AV_Delay", "Sensed_AV_Delay_Offset", "VRP", "ARP", "PVARP", "PVARP_Extension", "A_sensitivity", "V_sensitivity", "Activity_Threshold", "Reaction_Time", "Response_Factor", "Recovery_Time", "Hysteresis", "HRL"},
	"ddir": {"LRL", "URL", "A_atrial_amp", "A_pulse_width", "V_ventricular_amp", "V_pulse_width", "Fixed_AV_Delay", "Dynamic_AV_Delay", "Min_Dyn_AV_Delay", "Sensed_AV_Delay_Offset", "VRP", "ARP", "PVARP", "PVARP_Extension"},
}

# Expanded numeric ranges (update as needed per your requirements doc)
PARAM_RANGES = {
	"LRL": (30, 175),
	"URL": (50, 175),
	"MSR": (50, 175),
	"Fixed_AV_Delay": (70, 300),
	"Dynamic_AV_Delay": (0, 1),  # 0=Off, 1=On
	"Min_Dyn_AV_Delay": (30, 100),
	"Sensed_AV_Delay_Offset": (-100, 0),
	"A_atrial_amp": (0.1, 5.0),
	"V_ventricular_amp": (0.1, 5.0),
	"A_pulse_width": (1, 30),
	"V_pulse_width": (1, 30),
	"A_sensitivity": (0.25, 10),
	"V_sensitivity": (0.25, 10),
	"VRP": (150, 500),
	"ARP": (150, 500),
	"PVARP": (150, 500),
	"PVARP_Extension": (0, 400),
	"Hysteresis": (0, 1),  # 0=Off, 1=On
	"HRL": (30, 175),
	"Rate_Smoothing": (0, 25),
	"ATR_Duration": (10, 2000),
	"ATR_Fallback_Mode": (0, 1),  # 0=Off, 1=On or use string if needed
	"ATR_Fallback_Time": (1, 5),
	"Activity_Threshold": (1, 7),  # e.g., 1=V-Low, 7=V-High
	"Reaction_Time": (10, 50),
	"Response_Factor": (1, 16),
	"Recovery_Time": (2, 16),
}

DEFAULT_VALUES = {
	"LRL": 60,
	"URL": 120,
	"MSR": 120,
	"Fixed_AV_Delay": 150,
	"Dynamic_AV_Delay": 0,
	"Min_Dyn_AV_Delay": 50,
	"Sensed_AV_Delay_Offset": 0,
	"A_atrial_amp": 2.5,
	"V_ventricular_amp": 2.5,
	"A_pulse_width": 1,
	"V_pulse_width": 1,
	"A_sensitivity": 0.75,
	"V_sensitivity": 2.5,
	"VRP": 320,
	"ARP": 250,
	"PVARP": 250,
	"PVARP_Extension": 0,
	"Hysteresis": 0,
	"HRL": 50,
	"Rate_Smoothing": 0,
	"ATR_Duration": 20,
	"ATR_Fallback_Mode": 0,
	"ATR_Fallback_Time": 1,
	"Activity_Threshold": 4,
	"Reaction_Time": 30,
	"Response_Factor": 8,
	"Recovery_Time": 5,
}

# Numeric ranges for required parameters (assumptions -- adjust if you have official ranges):
# - LRL/URL: beats per minute
# - Amplitudes: volts
# - Pulse widths: milliseconds
# - VRP/ARP: milliseconds
PARAM_RANGES = {
	"LRL": (30, 170),
	"URL": (50, 175),
	"A_atrial_amp": (0.1, 7.5),
	"V_ventricular_amp": (0.1, 7.5),
	"A_pulse_width": (0.1, 2.0),
	"V_pulse_width": (0.1, 2.0),
	"VRP": (150, 500),
	"ARP": (150, 500),
}

# Defaults for required params when missing
DEFAULT_VALUES = {
	"LRL": 60,
	"URL": 120,
	"A_atrial_amp": 2.5,
	"A_pulse_width": 0.5,
	"V_ventricular_amp": 2.5,
	"V_pulse_width": 0.5,
	"VRP": 250,
	"ARP": 150,
}

# Optional external authoritative metadata file (if the project supplies exact ranges/units)
PARAM_METADATA_FILE = os.path.join(BASE_DIR, "param_metadata.json")


def _load_param_metadata():
	"""Load authoritative per-parameter metadata from PARAM_METADATA_FILE if present.
	Expected JSON shape: { "canon_name": { "unit": "ms|bpm|V|...", "min": <num>, "max": <num>, "default": <num> }, ... }
	When present, this updates the runtime PARAM_RANGES and DEFAULT_VALUES and updates the unit strings in REQUIRED_PARAMS.
	"""
	global PARAM_RANGES, DEFAULT_VALUES, REQUIRED_PARAMS
	if not os.path.exists(PARAM_METADATA_FILE):
		return
	try:
		with open(PARAM_METADATA_FILE, "r", encoding="utf-8") as f:
			meta = json.load(f)
		if not isinstance(meta, dict):
			return
		# build new ranges/defaults
		new_ranges = {}
		new_defaults = DEFAULT_VALUES.copy()
		# update REQUIRED_PARAMS units by rebuilding the tuple list
		new_required = []
		for display, canon, unit in REQUIRED_PARAMS:
			entry = meta.get(canon) or meta.get(_normalize_name(canon))
			if isinstance(entry, dict):
				# accept keys 'min','max','default','unit'
				try:
					if "min" in entry and "max" in entry:
						new_ranges[canon] = (float(entry["min"]), float(entry["max"]))
				except Exception:
					pass
				if "default" in entry:
					try:
						new_defaults[canon] = float(entry["default"])
					except Exception:
						pass
				new_unit = entry.get("unit", unit)
			else:
				new_unit = unit
			new_required.append((display, canon, new_unit))
		if new_ranges:
			PARAM_RANGES.update(new_ranges)
		DEFAULT_VALUES.update(new_defaults)
		REQUIRED_PARAMS = new_required
	except Exception:
		# if anything goes wrong, leave existing defaults in place
		return


# Load param metadata at import time if present
_load_param_metadata()

# -----------------------
# Egram data structures and persistence
# -----------------------
#
# Egram JSON schema (per file):
# {
#   "device_id": "<device id>",
#   "recorded_at": "<ISO8601 UTC timestamp>",
#   "sampling_rate_hz": 1000,                 # samples per second
#   "duration_ms": 1000,
#   "params_snapshot": { ... },               # copy of device param_set at recording
#   "samples": [                               # time-ordered samples
#       {"t_ms": 0, "atrial_mV": 0.8, "ventricular_mV": 1.1},
#       {"t_ms": 1, "atrial_mV": 0.9, "ventricular_mV": 1.0},
#       ...
#   ]
# }
#
# The DCM will save each egram as a separate JSON file under EGRAM_DIR.

def ensure_egram_dir():
	if not os.path.exists(EGRAM_DIR):
		os.makedirs(EGRAM_DIR, exist_ok=True)


def save_egram_snapshot(device_id: str, samples: list, params_snapshot: dict, sampling_rate_hz: int = 1000):
	"""Persist an egram snapshot to a timestamped JSON file.

	Args:
	  device_id: device identifier string
	  samples: list of sample dicts (see schema above)
	  params_snapshot: dict of parameter snapshot
	  sampling_rate_hz: integer sampling rate
	Returns: path to saved file
	"""
	ensure_egram_dir()
	payload = {
		"device_id": device_id,
		"recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
		"sampling_rate_hz": sampling_rate_hz,
		"duration_ms": samples[-1]["t_ms"] if samples else 0,
		"params_snapshot": params_snapshot,
		"samples": samples,
	}
	fname = f"egram_{device_id}_{int(time.time())}.json"
	path = os.path.join(EGRAM_DIR, fname)
	with open(path, "w", encoding="utf-8") as f:
		json.dump(payload, f, indent=2)
	return path


def list_egram_files(device_id: Optional[str] = None) -> list:
	"""Return list of egram filenames (optionally filtered by device_id)."""
	ensure_egram_dir()
	files = sorted(glob.glob(os.path.join(EGRAM_DIR, "egram_*.json")))
	basenames = [os.path.basename(p) for p in files]
	if device_id:
		return [b for b in basenames if b.startswith(f"egram_{device_id}_")]
	return basenames


# -----------------------
# Simple user utils (kept as your original simple approach)
# -----------------------
def load_users():
	if not os.path.exists(USERS_FILE):
		return []
	try:
		with open(USERS_FILE, "r", encoding="utf-8") as f:
			data = json.load(f)
			if isinstance(data, list):
				return data
	except Exception:
		pass
	return []


def save_users(users):
	with open(USERS_FILE, "w", encoding="utf-8") as f:
		json.dump(users, f, indent=2)


def hash_password(password: str, salt_hex: str) -> str:
	# salt_hex is hex string
	salt = bytes.fromhex(salt_hex)
	h = hashlib.sha256()
	h.update(salt + password.encode("utf-8"))
	return h.hexdigest()

def ensure_file(path, default):
	if not os.path.exists(path):
		with open(path, "w", encoding="utf-8") as f:
			json.dump(default, f, indent=2)

# -----------------------
# DeviceManager: persists last device (keeps requirement 7)
# -----------------------
class DeviceManager:
	def __init__(self):
		ensure_file(LAST_DEVICE_FILE, {})
		self._load_last()

	def _load_last(self):
		try:
			with open(LAST_DEVICE_FILE, "r", encoding="utf-8") as f:
				self.last = json.load(f) or {}
		except Exception:
			self.last = {}

	def compare_with_last(self, device_id):
		if not self.last or "device_id" not in self.last:
			return "none"
		return "same" if self.last.get("device_id") == device_id else "different"

	def set_last(self, device_record):
		self.last = {
			"device_id": device_record.get("device_id", ""),
			"model": device_record.get("model", ""),
			"params_snapshot": device_record.get("param_set", {}),
			"last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
		}
		with open(LAST_DEVICE_FILE, "w", encoding="utf-8") as f:
			json.dump(self.last, f, indent=2)

# -----------------------
# Utilities: scan device files
# -----------------------
def find_param_files():
	# find all files matching *_params.json in BASE_DIR
	pattern = os.path.join(BASE_DIR, "*_params.json")
	files = sorted(glob.glob(pattern))
	return [os.path.basename(p) for p in files]

def load_params_from_file(basename):
	path = os.path.join(BASE_DIR, basename)
	try:
		with open(path, "r", encoding="utf-8") as f:
			data = json.load(f)
	except Exception:
		return None, None
	# Accept multiple possible shapes:
	# 1) {"device_id": "...", "param_set": {...}}
	# 2) {"param_set": {...}}
	# 3) {"params": {...}}
	# 4) {"device_id": "...", "params": {...}}
	device_id = data.get("device_id") or os.path.splitext(basename)[0].replace("_params", "")
	param_set = None
	if isinstance(data, dict):
		if "param_set" in data and isinstance(data["param_set"], dict):
			param_set = data["param_set"]
		elif "params" in data and isinstance(data["params"], dict):
			param_set = data["params"]
		# fallback: if file itself looks like a params object
		elif all(isinstance(v, (int, float, str)) for v in data.values()):
			# treat entire dict as params (no device_id inside)
			param_set = data
	# final fallback
	if param_set is None:
		param_set = {}
	return device_id, param_set

def write_params_to_file(basename, device_id, param_set):
	path = os.path.join(BASE_DIR, basename)
	# preserve existing extra fields if present
	existing = {}
	try:
		with open(path, "r", encoding="utf-8") as f:
			existing = json.load(f) or {}
	except Exception:
		existing = {}
	# Build object to write: prefer {"device_id","param_set"}
	out = existing.copy() if isinstance(existing, dict) else {}
	out["device_id"] = device_id
	out["param_set"] = param_set
	with open(path, "w", encoding="utf-8") as f:
		json.dump(out, f, indent=2)


# Helpers for parameter name normalization and lookup
def _normalize_name(s: str) -> str:
	return ''.join(ch.lower() for ch in str(s) if ch.isalnum())

def _find_matching_key(params: dict, target_names: list) -> Optional[str]:
    """Return the actual key in params that matches any of the target_names (by normalized form), or None."""
    if not isinstance(params, dict):
        return None
    norm_map = { _normalize_name(k): k for k in params.keys() }
    for t in target_names:
        nn = _normalize_name(t)
        if nn in norm_map:
            return norm_map[nn]
    return None


def _is_number(v) -> bool:
	"""Return True if value is a number or numeric string."""
	if v is None:
		return False
	try:
		# allow numeric types and numeric strings
		float(v)
		return True
	except Exception:
		return False


def _mode_allowed_params(mode: Optional[str]) -> set:
	"""Return set of canonical keys allowed for the provided mode string."""
	if not mode:
		return set()
	m = _normalize_name(mode)
	return PARAMS_BY_MODE.get(m, set())


def _clamp_to_range(name: str, value) -> tuple[bool, str]:
	"""Return (ok, message). If value not numeric or out of range, ok=False and message contains reason."""
	# If we don't have authoritative range info, treat as OK (no enforcement)
	if name not in PARAM_RANGES:
		return True, ""
	lo, hi = PARAM_RANGES[name]
	# ensure numeric
	try:
		num = float(value)
	except Exception:
		return False, f"Value '{value}' is not numeric"
	# check bounds
	if num < lo or num > hi:
		# try to find unit for nicer messaging
		unit = ""
		for _disp, canon, u in REQUIRED_PARAMS:
			if canon == name:
				unit = u
				break
		if unit:
			return False, f"{num} {unit} out of range [{lo}..{hi} {unit}]"
		return False, f"{num} out of range [{lo}..{hi}]"
	return True, ""

# -----------------------
# Main Application (login + DCM UI)
# -----------------------
class WelcomeApp(tk.Tk):

	def __init__(self):
		super().__init__()
		self.title("DCM — Login / DCM UI")
		self.resizable(False, False)
		self.users = load_users()
		self.device_mgr = DeviceManager()

		# Serial comm state
		self.serial = None  # dcm_comm.DCMComm instance
		self.serial_port = None
		self.serial_connected = False

		# Frames
		self.frame_welcome = tk.Frame(self)
		self.frame_login = tk.Frame(self)
		self.frame_register = tk.Frame(self)
		self.frame_dcm = tk.Frame(self)

		# UI state
		self.device_files = []      # list of basenames
		self.current_file = None    # currently loaded basename
		self.current_device = None  # dict { device_id, model, param_set }

		self._build_welcome()
		self._build_login()
		self._build_register()
		self._build_dcm()

		self.show_frame(self.frame_welcome)

	def show_frame(self, frame):
		for f in (self.frame_welcome, self.frame_login, self.frame_register, self.frame_dcm):
			f.pack_forget()
		frame.pack(padx=12, pady=12)

	# -----------------------
	# Welcome / login / register
	# -----------------------
	def _build_welcome(self):
		f = self.frame_welcome
		tk.Label(f, text="Welcome!", font=("Arial", 18)).pack(pady=(0, 10))
		tk.Button(f, text="Login", width=20, command=lambda: self.show_frame(self.frame_login)).pack(pady=5)
		tk.Button(f, text="Register", width=20, command=lambda: self.show_frame(self.frame_register)).pack(pady=5)
		tk.Button(f, text="Exit", width=20, command=self.quit).pack(pady=(10, 0))

	def _build_login(self):
		f = self.frame_login
		tk.Label(f, text="Login", font=("Arial", 14)).grid(row=0, column=0, columnspan=2, pady=(0, 8))
		tk.Label(f, text="Username:").grid(row=1, column=0, sticky="e")
		self.login_user = tk.Entry(f); self.login_user.grid(row=1, column=1)
		tk.Label(f, text="Password:").grid(row=2, column=0, sticky="e")
		self.login_pass = tk.Entry(f, show="*"); self.login_pass.grid(row=2, column=1)
		self.login_msg = tk.Label(f, text="", fg="red"); self.login_msg.grid(row=3, column=0, columnspan=2)
		tk.Button(f, text="Submit", width=12, command=self.attempt_login).grid(row=4, column=0, pady=8)
		tk.Button(f, text="Back", width=12, command=lambda: self.show_frame(self.frame_welcome)).grid(row=4, column=1)

	def _build_register(self):
		f = self.frame_register
		tk.Label(f, text="Register", font=("Arial", 14)).grid(row=0, column=0, columnspan=2, pady=(0, 8))
		tk.Label(f, text="Username:").grid(row=1, column=0, sticky="e")
		self.reg_user = tk.Entry(f); self.reg_user.grid(row=1, column=1)
		tk.Label(f, text="Password:").grid(row=2, column=0, sticky="e")
		self.reg_pass = tk.Entry(f, show="*"); self.reg_pass.grid(row=2, column=1)
		tk.Label(f, text="Confirm:").grid(row=3, column=0, sticky="e")
		self.reg_pass2 = tk.Entry(f, show="*"); self.reg_pass2.grid(row=3, column=1)
		self.reg_msg = tk.Label(f, text="", fg="red"); self.reg_msg.grid(row=4, column=0, columnspan=2)
		tk.Button(f, text="Create", width=12, command=self.attempt_register).grid(row=5, column=0, pady=8)
		tk.Button(f, text="Back", width=12, command=lambda: self.show_frame(self.frame_welcome)).grid(row=5, column=1)

	def attempt_register(self):
		username = self.reg_user.get().strip()
		pw = self.reg_pass.get()
		pw2 = self.reg_pass2.get()

		if not username:
			self.reg_msg.config(text="Enter a username"); return
		if not pw:
			self.reg_msg.config(text="Enter a password"); return
		if pw != pw2:
			self.reg_msg.config(text="Passwords do not match"); return
		if any(u.get("username") == username for u in self.users):
			self.reg_msg.config(text="Username already exists"); return
		if len(self.users) >= MAX_USERS:
			self.reg_msg.config(text=f"Max users reached ({MAX_USERS})"); return

		salt = secrets.token_bytes(16).hex()
		pw_hash = hash_password(pw, salt)
		user_obj = {"username": username, "salt": salt, "pw_hash": pw_hash}
		self.users.append(user_obj)
		save_users(self.users)
		messagebox.showinfo("Success", "User registered successfully")
		self.reg_user.delete(0, tk.END); self.reg_pass.delete(0, tk.END); self.reg_pass2.delete(0, tk.END)
		self.reg_msg.config(text="")
		self.show_frame(self.frame_login)

	def attempt_login(self):
		username = self.login_user.get().strip()
		pw = self.login_pass.get()
		if not username or not pw:
			self.login_msg.config(text="Enter username and password"); return
		matched = None
		for u in self.users:
			if u.get("username") == username:
				matched = u; break
		if not matched:
			self.login_msg.config(text="Unknown username"); return
		salt = matched.get("salt")
		expected = matched.get("pw_hash")
		if hash_password(pw, salt) == expected:
			self.login_msg.config(text="")
			self.login_user.delete(0, tk.END); self.login_pass.delete(0, tk.END)
			self.show_dcm(username)
		else:
			self.login_msg.config(text="Incorrect password")

	# -----------------------
	# DCM UI build
	# -----------------------

	def _build_dcm(self):
		f = self.frame_dcm

		# Top: user + logout
		top = tk.Frame(f); top.pack(fill="x", pady=(0,8))
		self.logged_label = tk.Label(top, text=""); self.logged_label.pack(side="left")
		tk.Button(top, text="Logout", command=self._dcm_logout).pack(side="right")

		# Left: connection / status / device select
		left = tk.Frame(f)
		left.pack(side="left", padx=(0,12))

		tk.Label(left, text="Connection").pack()
		self.status_label = tk.Label(left, text="Disconnected", bg="lightgray", width=18)
		self.status_label.pack(pady=(4,8))

		# Serial port controls
		tk.Label(left, text="Serial Port:").pack(pady=(2,0))
		self.serial_port_var = tk.StringVar(value="COM0")  # Default port, update as needed
		self.serial_entry = tk.Entry(left, textvariable=self.serial_port_var, width=16)
		self.serial_entry.pack(pady=(0,2))
		self.serial_btn = tk.Button(left, text="Connect Serial", width=18, command=self._connect_serial)
		self.serial_btn.pack(pady=(2,2))
		self.serial_disc_btn = tk.Button(left, text="Disconnect Serial", width=18, command=self._disconnect_serial, state="disabled")
		self.serial_disc_btn.pack(pady=(0,8))

		# Device selector dropdown
		tk.Label(left, text="Choose device file:").pack(pady=(6,2))
		self.device_var = tk.StringVar(value="(none)")
		self.device_menu = tk.OptionMenu(left, self.device_var, "(none)")
		self.device_menu.config(width=22)
		self.device_menu.pack()
		tk.Button(left, text="Refresh Device List", width=18, command=self._refresh_device_list).pack(pady=(6,2))
		tk.Button(left, text="Disconnect", width=18, command=self._dcm_disconnect).pack(pady=(6,2))

		# Middle: parameter viewer / editor
		mid = tk.Frame(f)
		mid.pack(side="left")
		tk.Label(mid, text="Programmable Parameters", font=("Arial", 12)).pack()

		self.params_frame = tk.Frame(mid, bd=1, relief="sunken", padx=6, pady=6)
		self.params_frame.pack(pady=(6,4))

		# Parameter entries will be created dynamically
		self.param_vars = {}
		self.param_entries = {}


		btns = tk.Frame(mid); btns.pack(pady=6)
		tk.Button(btns, text="Save to File", command=self._save_params_to_file).pack(side="left", padx=6)
		tk.Button(btns, text="Show Last Device Info", command=self._show_last_device_info).pack(side="left")
		# Serial comm actions
		tk.Button(btns, text="Send Params to Device", command=self._send_params_to_device).pack(side="left", padx=6)
		tk.Button(btns, text="Verify Parameters", command=self._verify_params_on_device).pack(side="left", padx=6)
		tk.Button(btns, text="Request Egram", command=self._request_egram).pack(side="left", padx=6)
		tk.Button(btns, text="Start Live Egram", command=self._start_live_egram).pack(side="left", padx=6)
		tk.Button(btns, text="Stop Egram", command=self._stop_egram).pack(side="left", padx=6)

		# Live egram canvas (hidden by default)
		self.live_egram_win = None
		self._live_egram_running = False
	def _verify_params_on_device(self):
		if not self.serial_connected or not self.serial:
			self._append_log("Serial not connected")
			messagebox.showwarning("Serial", "Serial port not connected")
			return
		try:
			self.serial.send_packet(dcm_comm.get_fn_codes()['k_pparams'])
			pkt = self.serial.read_packet()
			if not pkt:
				self._append_log("No response from device for parameter verification")
				messagebox.showerror("Verify", "No response from device.")
				return
			dev_params = dcm_comm.unpack_params(pkt[4:-1])
			gui_params = self._gather_ui_params()
			mismatches = []
			for k in dev_params:
				v_dev = dev_params[k]
				v_gui = gui_params.get(k)
				# Allow small float tolerance
				if isinstance(v_dev, float) and isinstance(v_gui, float):
					if abs(v_dev - v_gui) > 0.01:
						mismatches.append(f"{k}: device={v_dev}, gui={v_gui}")
				else:
					if str(v_dev) != str(v_gui):
						mismatches.append(f"{k}: device={v_dev}, gui={v_gui}")
			if not mismatches:
				messagebox.showinfo("Verify", "Parameters match device.")
				self._append_log("Parameter verification: MATCH")
			else:
				messagebox.showwarning("Verify", "Mismatch:\n" + "\n".join(mismatches))
				self._append_log("Parameter verification: MISMATCH\n" + "\n".join(mismatches))
		except Exception as e:
			self._append_log(f"Verify params error: {e}")
			messagebox.showerror("Verify Error", f"Failed to verify parameters: {e}")

	def _start_live_egram(self):
		if not self.serial_connected or not self.serial:
			self._append_log("Serial not connected")
			messagebox.showwarning("Serial", "Serial port not connected")
			return
		if self._live_egram_running:
			return
		self._live_egram_running = True
		self._append_log("Starting live egram display")
		self.serial.request_egram()
		self._open_live_egram_window()
		self.after(100, self._poll_live_egram)

	def _stop_live_egram(self):
		self._live_egram_running = False
		if self.serial_connected and self.serial:
			try:
				self.serial.stop_egram()
			except Exception:
				pass
		if self.live_egram_win:
			self.live_egram_win.destroy()
			self.live_egram_win = None
		self._append_log("Stopped live egram display")

	def _open_live_egram_window(self):
		if self.live_egram_win:
			return
		self.live_egram_win = tk.Toplevel(self)
		self.live_egram_win.title("Live Egram Display")
		self.live_egram_canvas = tk.Canvas(self.live_egram_win, width=900, height=360, bg="white")
		self.live_egram_canvas.pack(padx=8, pady=8)
		btn = tk.Button(self.live_egram_win, text="Stop", command=self._stop_live_egram)
		btn.pack(pady=(0,8))

	def _poll_live_egram(self):
		if not self._live_egram_running:
			return
		if self.serial is None:
			# add a window popup that says serial disconnected
			self._append_log("Serial disconnected, stopping live egram")
			return  # Serial connection is not available
		try:
			pkt = self.serial.read_packet()
			if pkt:
				# Assume egram data is in pkt[4:-1] as a simple example (real protocol may differ)
				# For demo, treat as two 2-byte signed ints: atrial, ventricular (in mV*1000)
				data = pkt[4:-1]
				if len(data) >= 4:
					atr = int.from_bytes(data[0:2], 'little', signed=True) / 1000.0
					vent = int.from_bytes(data[2:4], 'little', signed=True) / 1000.0
					self._update_live_egram_plot(atr, vent)
		except Exception as e:
			self._append_log(f"Live egram error: {e}")
		self.after(50, self._poll_live_egram)

	def _update_live_egram_plot(self, atrial_mv, ventricular_mv):
		# Simple scrolling plot: keep last N points
		if not hasattr(self, '_live_egram_data'):
			self._live_egram_data = []
		self._live_egram_data.append((atrial_mv, ventricular_mv))
		if len(self._live_egram_data) > 900:
			self._live_egram_data = self._live_egram_data[-900:]
		# Redraw
		c = self.live_egram_canvas
		c.delete("all")
		h = 360; w = 900
		pady = 20
		plot_h = h - 2*pady
		# Find min/max for scaling
		atr_vals = [a for a, v in self._live_egram_data]
		vent_vals = [v for a, v in self._live_egram_data]
		vmin = min(atr_vals + vent_vals)
		vmax = max(atr_vals + vent_vals)
		if vmin == vmax:
			vmin -= 1.0; vmax += 1.0
		# Draw axes
		c.create_rectangle(0, pady, w, h-pady, outline="#ddd")
		# Draw atrial (blue) and ventricular (red)
		for i in range(1, len(self._live_egram_data)):
			x0 = w - len(self._live_egram_data) + i - 1
			x1 = w - len(self._live_egram_data) + i
			y0a = pady + plot_h - ((atr_vals[i-1] - vmin) / (vmax - vmin)) * plot_h
			y1a = pady + plot_h - ((atr_vals[i] - vmin) / (vmax - vmin)) * plot_h
			y0v = pady + plot_h - ((vent_vals[i-1] - vmin) / (vmax - vmin)) * plot_h
			y1v = pady + plot_h - ((vent_vals[i] - vmin) / (vmax - vmin)) * plot_h
			c.create_line(x0, y0a, x1, y1a, fill="blue")
			c.create_line(x0, y0v, x1, y1v, fill="red")
		# Legend
		c.create_rectangle(w-180, 8, w-8, 48, fill="#f7f7f7", outline="#ccc")
		c.create_line(w-170, 20, w-140, 20, fill="blue")
		c.create_text(w-130, 20, anchor="w", text="Atrial (mV)")
		c.create_line(w-170, 34, w-140, 34, fill="red")
		c.create_text(w-130, 34, anchor="w", text="Ventricular (mV)")

		# Right: packet log

		right = tk.Frame(self.frame_dcm)
		right.pack(side="left", padx=(12,0))
		tk.Label(right, text="Comm Log", font=("Arial", 10)).pack(pady=(0,4))
		self.log_text = tk.Text(right, width=48, height=16, state="disabled")
		self.log_text.pack(pady=(4,0))

		# placeholder for egram viewer + quick egram actions
		frame_eg = tk.Frame(self.frame_dcm)
		frame_eg.pack(side="bottom", pady=(12,0))
		tk.Label(frame_eg, text="Egram Viewer (placeholder)", fg="gray").pack(side="left")
		try:
			tk.Button(frame_eg, text="Save Egram Snapshot", command=self._ui_save_egram).pack(side="left", padx=(8,4))
		except Exception:
			btn = tk.Button(frame_eg, text="Save Egram Snapshot", command=self._ui_save_egram)
			btn.pack(side="left", padx=(8,4))
		try:
			tk.Button(frame_eg, text="List Egrams", command=self._ui_list_egms).pack(side="left", padx=(4,0))
		except Exception:
			btn2 = tk.Button(frame_eg, text="List Egrams", command=self._ui_list_egms)
			btn2.pack(side="left", padx=(4,0))

		# initial device list
		self._refresh_device_list()
		self.device_var.trace_add("write", self._on_device_selected)

	def _connect_serial(self):
		port = self.serial_port_var.get().strip()
		if not port:
			self._append_log("No serial port specified")
			return
		try:
			self.serial = dcm_comm.DCMComm(port)
			self.serial_connected = True
			self.serial_port = port
			self.status_label.config(text=f"Serial: {port}", bg="lightblue")
			self.serial_btn.config(state="disabled")
			self.serial_disc_btn.config(state="normal")
			self._append_log(f"Serial connected on {port}")
		except Exception as e:
			self._append_log(f"Serial connect error: {e}")
			messagebox.showerror("Serial Error", f"Could not open serial port: {e}")

	def _disconnect_serial(self):
		if self.serial:
			try:
				self.serial.close()
			except Exception:
				pass
		self.serial = None
		self.serial_connected = False
		self.serial_port = None
		self.status_label.config(text="Disconnected", bg="lightgray")
		self.serial_btn.config(state="normal")
		self.serial_disc_btn.config(state="disabled")
		self._append_log("Serial disconnected")

	def _send_params_to_device(self):
		if not self.serial_connected or not self.serial:
			self._append_log("Serial not connected")
			messagebox.showwarning("Serial", "Serial port not connected")
			return
		params = self._gather_ui_params()
		# Pack parameters into bytes (implement in dcm_comm)
		try:
			params_bytes = dcm_comm.pack_params(params)
			self.serial.send_params(params_bytes)
			self._append_log("Sent parameters to device")
		except Exception as e:
			self._append_log(f"Send params error: {e}")
			messagebox.showerror("Send Error", f"Failed to send parameters: {e}")

	def _request_egram(self):
		if not self.serial_connected or not self.serial:
			self._append_log("Serial not connected")
			messagebox.showwarning("Serial", "Serial port not connected")
			return
		try:
			self.serial.request_egram()
			self._append_log("Requested egram from device")
		except Exception as e:
			self._append_log(f"Request egram error: {e}")
			messagebox.showerror("Egram Error", f"Failed to request egram: {e}")

	def _stop_egram(self):
		if not self.serial_connected or not self.serial:
			self._append_log("Serial not connected")
			messagebox.showwarning("Serial", "Serial port not connected")
			return
		try:
			self.serial.stop_egram()
			self._append_log("Stopped egram transmission")
		except Exception as e:
			self._append_log(f"Stop egram error: {e}")
			messagebox.showerror("Egram Error", f"Failed to stop egram: {e}")

	# -----------------------
	# DCM behaviors
	# -----------------------
	def show_dcm(self, username):
		self.logged_label.config(text=f"User: {username}")
		self.show_frame(self.frame_dcm)
		self._clear_params_view()

	def _dcm_logout(self):
		# Ensure we disconnect the device (which records it as last)
		if self.current_device:
			self._dcm_disconnect()
		self.show_frame(self.frame_welcome)

	def _dcm_disconnect(self):
		"""Disconnect the currently loaded device.
		This records the device as the last-interrogated device, then
		clears the UI state so the DCM shows no connected device.
		"""
		if not self.current_device:
			self._append_log("No device to disconnect")
			return
		# Record last device (the one we are disconnecting)
		try:
			self.device_mgr.set_last(self.current_device)
		except Exception as e:
			self._append_log(f"Error recording last device: {e}")
		# Clear UI and state
		dev_id = self.current_device.get("device_id")
		self.current_device = None
		self.current_file = None
		self._clear_params_view()
		self.status_label.config(text="Disconnected", bg="lightgray")
		# reset dropdown
		try:
			self.device_var.set("(none)")
		except Exception:
			pass
		self._append_log(f"Disconnected device {dev_id}")

	def _refresh_device_list(self):
		files = find_param_files()
		self.device_files = files
		menu = self.device_menu["menu"]
		menu.delete(0, "end")
		if not files:
			menu.add_command(label="(no _params.json files)", command=lambda v="(none)": self.device_var.set(v))
			self.device_var.set("(none)")
			self._append_log("No param files found")
			return
		for fname in files:
			menu.add_command(label=fname, command=lambda v=fname: self.device_var.set(v))
		# if previously loaded file still exists, re-select it; otherwise choose first file
		if self.current_file and self.current_file in files:
			self.device_var.set(self.current_file)
		else:
			self.device_var.set(files[0])

	def _on_device_selected(self, *args):
		selection = self.device_var.get()
		if not selection or selection == "(none)":
			return
		# If user re-selects the currently loaded file, do nothing
		if selection == self.current_file:
			return
		# load the selected file
		self._append_log(f"Selecting file {selection}")
		device_id, params = load_params_from_file(selection)
		if device_id is None:
			self._append_log(f"Failed to load {selection}")
			messagebox.showerror("Load error", f"Could not read {selection}")
			return
		# If we are currently connected to a different device, prompt the user
		if self.current_device and self.current_device.get("device_id") != device_id:
			resp = messagebox.askyesno("Different pacemaker detected",
				f"Device {device_id} (from {selection}) differs from currently connected ({self.current_device.get('device_id')}).\n\nSwitch to new device?")
			if not resp:
				self._append_log("User cancelled switching device")
				# revert dropdown to previous file (if any)
				if self.current_file:
					try:
						self.device_var.set(self.current_file)
					except Exception:
						pass
				return
			# record the previous (currently connected) device as last since we're switching away
			try:
				self.device_mgr.set_last(self.current_device)
			except Exception as e:
				self._append_log(f"Error recording last device: {e}")
		else:
			# No current device — fall back to comparing with persisted last device
			compare = self.device_mgr.compare_with_last(device_id)
			if compare == "different":
				resp = messagebox.askyesno("Different pacemaker detected",
					f"Device {device_id} (from {selection}) differs from last interrogated ({self.device_mgr.last.get('device_id')}).\n\nAccept new device and load its parameters?")
				if not resp:
					self._append_log("User cancelled loading new device")
					# revert dropdown to previous file (if any)
					if self.current_file:
						try:
							self.device_var.set(self.current_file)
						except Exception:
							pass
					return
	# accept and load
		self.current_file = selection
		self.current_device = {"device_id": device_id, "param_set": params, "model": ""}
		self._load_params_into_ui(params)
		self.status_label.config(text="Connected", bg="lightgreen")
		self._append_log(f"Loaded params from {selection} (device_id={device_id})")
		# update last device record (we treat selection as interrogation)
		# Note: do not update last-device here — last device should reflect
		# the previously connected device. We record the last device when
		# the user explicitly disconnects.

	def _append_log(self, text):
		if not hasattr(self, 'log_text') or self.log_text is None:
			# Optionally print to console as fallback
			print(f"LOG: {text}")
			return
		self.log_text.config(state="normal")
		self.log_text.insert("end", f"{time.strftime('%H:%M:%S')} {text}\n")
		self.log_text.see("end")
		self.log_text.config(state="disabled")

	# -----------------------
	# Parameter UI helpers
	# -----------------------
	def _clear_params_view(self):
		for w in self.params_frame.winfo_children():
			w.destroy()
		self.param_vars.clear()
		self.param_entries.clear()

	def _load_params_into_ui(self, params):
		# clear
		self._clear_params_view()
		row = 0
		matched_keys = set()
		# Mode first (if present) — show as dropdown
		mode_key = _find_matching_key(params, ["mode"]) if isinstance(params, dict) else None
		mode_val = ""
		if mode_key:
			mode_val = params.get(mode_key, "")
		# render mode row
		if mode_key is not None:
			k = "mode"
			v = mode_val
			matched_keys.add(mode_key)
			tk.Label(self.params_frame, text=f"{k}:").grid(row=row, column=0, sticky="e", padx=(0,6), pady=2)
			var = tk.StringVar(value=str(v))
			options = list(MODE_OPTIONS)
			if str(v) not in options and str(v) != "":
				options.insert(0, str(v))
			opt = tk.OptionMenu(self.params_frame, var, *options)
			opt.config(width=10)
			opt.grid(row=row, column=1, pady=2)
			self.param_vars["mode"] = var
			self.param_entries["mode"] = opt
			row += 1
			# attach a trace so mode changes apply constraints
			try:
				var.trace_add("write", lambda *a: self._on_mode_changed())
			except Exception:
				# older tkinter may use trace
				var.trace("w", lambda *a: self._on_mode_changed())
		# Render required params in order
		for display, canon, unit in REQUIRED_PARAMS:
			# try to find an existing key that matches this param (many synonyms)
			found = _find_matching_key(params, [display, canon, display.replace(" ", "")])
			val = ""
			if found:
				val = params.get(found, "")
				matched_keys.add(found)
			# show label with unit
			label_text = f"{display} ({unit}):"
			tk.Label(self.params_frame, text=label_text).grid(row=row, column=0, sticky="e", padx=(0,6), pady=2)
			var = tk.StringVar(value=str(val))
			ent = tk.Entry(self.params_frame, textvariable=var, width=12)
			ent.grid(row=row, column=1, pady=2)
			# store under canonical key so saving uses consistent names
			self.param_vars[canon] = var
			self.param_entries[canon] = ent
			row += 1
		# Render any remaining keys present in params
		if isinstance(params, dict):
			for k in params.keys():
				if k in matched_keys:
					continue
				# skip mode as we've already handled it
				if _normalize_name(k) == _normalize_name("mode"):
					continue
				v = params.get(k, "")
				tk.Label(self.params_frame, text=f"{k}:").grid(row=row, column=0, sticky="e", padx=(0,6), pady=2)
				var = tk.StringVar(value=str(v))
				ent = tk.Entry(self.params_frame, textvariable=var, width=12)
				ent.grid(row=row, column=1, pady=2)
				self.param_vars[k] = var
				self.param_entries[k] = ent
				row += 1
		if row == 0:
			tk.Label(self.params_frame, text="(no params loaded)", fg="gray").pack()
		# set defaults for any required params that are empty
		for _, canon, _ in REQUIRED_PARAMS:
			var = self.param_vars.get(canon)
			if var is not None and var.get().strip() == "":
				if canon in DEFAULT_VALUES:
					var.set(str(DEFAULT_VALUES[canon]))
		# apply mode constraints (enable/disable fields)
		# call after widgets are created
		try:
			self._on_mode_changed()
		except Exception:
			pass


	def _on_mode_changed(self):
		"""Enable/disable required parameter entries based on selected mode and apply defaults."""
		mode = None
		mode_var = self.param_vars.get("mode")
		if mode_var:
			mode = mode_var.get()
		allowed = _mode_allowed_params(mode)
		# iterate required params and enable/disable accordingly
		for _, canon, _ in REQUIRED_PARAMS:
			widget = self.param_entries.get(canon)
			var = self.param_vars.get(canon)
			if widget is None or var is None:
				continue
			if canon in allowed:
				# enable entry
				try:
					widget.config(state="normal")
				except Exception:
					# some widgets may be OptionMenu etc; ignore
					pass
				# if empty, set default
				if var.get().strip() == "" and canon in DEFAULT_VALUES:
					var.set(str(DEFAULT_VALUES[canon]))
			else:
				# disable entry so it cannot be edited
				try:
					widget.config(state="disabled")
				except Exception:
					pass

	def _gather_ui_params(self):
		if not self.current_device:
			return {}
		new_params = {}
		for k, var in self.param_vars.items():
			val = var.get().strip()
			# keep mode as string
			if k.lower() == "mode":
				new_params[k] = val
				continue
			# try to convert numeric fields to numbers, otherwise keep string
			try:
				if "." in val:
					new_params[k] = float(val)
				else:
					new_params[k] = int(val)
			except Exception:
				new_params[k] = val
		return new_params

	def _save_params_to_file(self):
		if not self.current_file or not self.current_device:
			messagebox.showwarning("No device", "No device selected")
			return
		new_params = self._gather_ui_params()
		# Validate only parameters that are programmable in the selected mode
		mode_var = self.param_vars.get("mode")
		mode = mode_var.get() if mode_var else None
		allowed = _mode_allowed_params(mode)
		invalid = []
		range_errors = []
		for display, canon, unit in REQUIRED_PARAMS:
			# only validate this required param if it is programmable in current mode
			if canon not in allowed:
				continue
			# if programmable, validate if present in new_params
			if canon in new_params:
				v = new_params.get(canon)
				# allow empty, but if non-empty enforce numeric
				if v != "" and not _is_number(v):
					invalid.append(display)
				# if numeric, check range if known
				if v != "" and _is_number(v):
					ok, msg = _clamp_to_range(canon, v)
					if not ok:
						range_errors.append(msg)
		if invalid:
			messagebox.showerror("Invalid input", f"The following fields must be numeric: {', '.join(invalid)}")
			return
		if range_errors:
			messagebox.showerror("Out of range", "\n".join(range_errors))
			return

		# Ensure logical relationship: Lower Rate Limit (LRL) must not exceed Upper Rate Limit (URL)
		lrl_val = new_params.get("LRL")
		url_val = new_params.get("URL")
		if lrl_val is not None and url_val is not None and lrl_val != "" and url_val != "":
			if _is_number(lrl_val) and _is_number(url_val):
				try:
					if float(lrl_val) > float(url_val):
						messagebox.showerror("Invalid rate limits", "Lower Rate Limit (LRL) cannot be greater than Upper Rate Limit (URL).")
						return
				except Exception:
					# if conversion unexpectedly fails, fall through to normal save error handling
					pass
		# update current_device record
		self.current_device["param_set"] = new_params
		# write back to file
		try:
			write_params_to_file(self.current_file, self.current_device.get("device_id",""), new_params)
			self._append_log(f"Saved parameters to {self.current_file}")
			messagebox.showinfo("Saved", f"Parameters saved to {self.current_file}")
			# Note: Do not update last-device on save; only record on explicit disconnect
		except Exception as e:
			self._append_log(f"Error saving to {self.current_file}: {e}")
			messagebox.showerror("Save error", f"Could not save: {e}")

	def _ui_save_egram(self):
		"""UI action: create a small simulated egram and save it to disk."""
		if not self.current_device:
			messagebox.showwarning("No device", "No device connected to record egram")
			return
		device_id = self.current_device.get("device_id", "unknown")
		params_snapshot = self.current_device.get("param_set", {})
		# simple simulated waveform: 200 ms at 1 kHz -> 200 samples
		sampling_rate = 1000
		duration_ms = 200
		samples = []
		# amplitude scaling: try to use atrial/ventricular amps if present
		a_amp = None
		v_amp = None
		if isinstance(params_snapshot, dict):
			a_amp = params_snapshot.get("A_atrial_amp") or params_snapshot.get("atrial_amplitude")
			v_amp = params_snapshot.get("V_ventricular_amp") or params_snapshot.get("ventricular_amplitude")
		# fallback numeric values
		try:
			a_amp = float(a_amp) if a_amp is not None else 1.0
		except Exception:
			a_amp = 1.0
		try:
			v_amp = float(v_amp) if v_amp is not None else 1.0
		except Exception:
			v_amp = 1.0
		for t in range(0, duration_ms):
			# simple synthetic signals (sinusoidal small amplitude)
			s = {
				"t_ms": t,
				"atrial_mV": round(a_amp * 0.5 * (1 + __import__("math").sin(2 * __import__("math").pi * t / 50)), 3),
				"ventricular_mV": round(v_amp * 0.5 * (1 + __import__("math").sin(2 * __import__("math").pi * t / 40)), 3),
			}
			samples.append(s)
		try:
			path = save_egram_snapshot(device_id, samples, params_snapshot, sampling_rate_hz=sampling_rate)
			self._append_log(f"Saved egram snapshot to {path}")
			messagebox.showinfo("Egram saved", f"Saved egram to:\n{path}")
		except Exception as e:
			self._append_log(f"Error saving egram: {e}")
			messagebox.showerror("Egram error", f"Could not save egram: {e}")

	def _ui_list_egms(self):
		"""UI action: list saved egram files (for current device or all)."""
		device_id = None
		if self.current_device:
			device_id = self.current_device.get("device_id")
		files = list_egram_files(device_id)
		if not files:
			messagebox.showinfo("Egrams", "No egram files found.")
			return
		# show in a simple Toplevel with a Listbox
		win = tk.Toplevel(self)
		win.title("Saved Egrams")
		lb = tk.Listbox(win, width=80, height=12)
		for f in files:
			lb.insert("end", f)
		lb.pack(padx=8, pady=8)
		frame = tk.Frame(win)
		frame.pack(pady=(0,8))
		btn_preview = tk.Button(frame, text="Preview Selected", command=lambda: self._preview_selected_egram(lb))
		btn_preview.pack(side="left", padx=(0,6))
		btn_close = tk.Button(frame, text="Close", command=win.destroy)
		btn_close.pack(side="left")

	def _preview_selected_egram(self, listbox: tk.Listbox):
		sel = None
		try:
			i = listbox.curselection()
			if not i:
				messagebox.showinfo("Preview", "No file selected")
				return
			sel = listbox.get(i[0])
		except Exception:
			messagebox.showerror("Preview error", "Could not determine selected file")
			return
		self._preview_egram(sel)

	def _preview_egram(self, basename: str):
		"""Open and draw a simple preview of the egram file on a Canvas."""
		path = os.path.join(EGRAM_DIR, basename)
		try:
			with open(path, "r", encoding="utf-8") as f:
				payload = json.load(f)
		except Exception as e:
			messagebox.showerror("Egram load error", f"Could not load {basename}: {e}")
			return
		samples = payload.get("samples", [])
		if not samples:
			messagebox.showinfo("Preview", "No samples in egram file")
			return
		# Build arrays for plotting
		times = [s.get("t_ms", 0) for s in samples]
		atr = [s.get("atrial_mV", 0.0) for s in samples]
		vent = [s.get("ventricular_mV", 0.0) for s in samples]
		# create window and canvas
		w = tk.Toplevel(self)
		w.title(f"Egram Preview: {basename}")
		cw = 900; ch = 360
		canvas = tk.Canvas(w, width=cw, height=ch, bg="white")
		canvas.pack(padx=8, pady=8)
		# compute scales
		t_min, t_max = min(times), max(times)
		v_min = min(min(atr), min(vent))
		v_max = max(max(atr), max(vent))
		# avoid zero-range
		if v_min == v_max:
			v_min -= 1.0; v_max += 1.0
		padx, pady = 40, 20
		plot_w = cw - 2*padx
		plot_h = ch - 2*pady
		# axes
		canvas.create_rectangle(padx, pady, padx+plot_w, pady+plot_h, outline="#ddd")
		# map functions
		def map_x(t):
			return padx + ((t - t_min) / max(1, (t_max - t_min))) * plot_w
		def map_y(v):
			# flip y
			return pady + plot_h - ((v - v_min) / (v_max - v_min)) * plot_h
		# draw atrial in blue, ventricular in red
		pts_a = []
		pts_v = []
		for s in samples:
			t = s.get("t_ms", 0)
			pts_a.append((map_x(t), map_y(s.get("atrial_mV", 0.0))))
			pts_v.append((map_x(t), map_y(s.get("ventricular_mV", 0.0))))
		# draw polylines
		for idx in range(1, len(pts_a)):
			canvas.create_line(pts_a[idx-1][0], pts_a[idx-1][1], pts_a[idx][0], pts_a[idx][1], fill="blue")
		for idx in range(1, len(pts_v)):
			canvas.create_line(pts_v[idx-1][0], pts_v[idx-1][1], pts_v[idx][0], pts_v[idx][1], fill="red")
		# legend
		canvas.create_rectangle(cw-180, 8, cw-8, 48, fill="#f7f7f7", outline="#ccc")
		canvas.create_line(cw-170, 20, cw-140, 20, fill="blue")
		canvas.create_text(cw-130, 20, anchor="w", text="Atrial (mV)")
		canvas.create_line(cw-170, 34, cw-140, 34, fill="red")
		canvas.create_text(cw-130, 34, anchor="w", text="Ventricular (mV)")
		btn = tk.Button(w, text="Close", command=w.destroy)
		btn.pack(pady=(0,8))

	# -----------------------
	# Misc
	# -----------------------
	def _show_last_device_info(self):
		last = self.device_mgr.last
		if not last:
			messagebox.showinfo("Last device", "No last device recorded.")
			return
		txt = f"Last Device ID: {last.get('device_id')}\nModel: {last.get('model')}\nLast seen: {last.get('last_seen')}"
		messagebox.showinfo("Last device", txt)

# -----------------------
# bootstrap / ensure files
# -----------------------
ensure_file(USERS_FILE, [])
ensure_file(LAST_DEVICE_FILE, {})

# create root and start
root = WelcomeApp()

def main():
	root.mainloop()

if __name__ == "__main__":
	main()
