import tkinter as tk
from tkinter import messagebox
import json
import os
import hashlib
import secrets
import time
import glob

# -----------------------
# Files / config
# -----------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")
LAST_DEVICE_FILE = os.path.join(BASE_DIR, "last_device.json")

MAX_USERS = 10

# Modes for dropdown
MODE_OPTIONS = ["AOO", "VOO", "AAI", "VVI"]

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
		# Logout button stays in the top bar; Disconnect moved to the left panel.
		tk.Button(top, text="Logout", command=self._dcm_logout).pack(side="right")

		# Left: connection / status / device select
		left = tk.Frame(f)
		left.pack(side="left", padx=(0,12))

		tk.Label(left, text="Connection").pack()
		self.status_label = tk.Label(left, text="Disconnected", bg="lightgray", width=18)
		self.status_label.pack(pady=(4,8))

		# Device selector dropdown
		tk.Label(left, text="Choose device file:").pack(pady=(6,2))
		self.device_var = tk.StringVar(value="(none)")
		self.device_menu = tk.OptionMenu(left, self.device_var, "(none)")
		self.device_menu.config(width=22)
		self.device_menu.pack()
		tk.Button(left, text="Refresh Device List", width=18, command=self._refresh_device_list).pack(pady=(6,2))
		# Disconnect placed under the device selector as requested
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

		# Right: packet log
		right = tk.Frame(f)
		right.pack(side="left", padx=(12,0))
		tk.Label(right, text="Comm Log", font=("Arial", 10)).pack(pady=(0,4))
		self.log_text = tk.Text(right, width=48, height=16, state="disabled")
		self.log_text.pack(pady=(4,0))

		# placeholder for egram viewer
		tk.Label(f, text="Egram Viewer (placeholder)", fg="gray").pack(side="bottom", pady=(12,0))

		# initial device list
		self._refresh_device_list()
		# trace selection
		self.device_var.trace_add("write", self._on_device_selected)

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
		# load the selected file
		self._append_log(f"Selecting file {selection}")
		device_id, params = load_params_from_file(selection)
		if device_id is None:
			self._append_log(f"Failed to load {selection}")
			messagebox.showerror("Load error", f"Could not read {selection}")
			return
		# compare with last device
		compare = self.device_mgr.compare_with_last(device_id)
		if compare == "different":
			resp = messagebox.askyesno("Different pacemaker detected",
				f"Device {device_id} (from {selection}) differs from last interrogated ({self.device_mgr.last.get('device_id')}).\n\nAccept new device and load its parameters?")
			if not resp:
				self._append_log("User cancelled loading new device")
				# revert dropdown to previous file (if any)
				if self.current_file:
					self.device_var.set(self.current_file)
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
		# Show fields in a grid: label / entry
		row = 0
		# Ensure "mode" appears first if present
		keys = list(params.keys())
		if "mode" in keys:
			keys.remove("mode")
			keys.insert(0, "mode")
		for k in keys:
			v = params[k]
			tk.Label(self.params_frame, text=f"{k}:").grid(row=row, column=0, sticky="e", padx=(0,6), pady=2)
			var = tk.StringVar(value=str(v))
			# If key is 'mode' use dropdown
			if k.lower() == "mode":
				options = list(MODE_OPTIONS)
				if str(v) not in options:
					options.insert(0, str(v))
				opt = tk.OptionMenu(self.params_frame, var, *options)
				opt.config(width=10)
				opt.grid(row=row, column=1, pady=2)
				self.param_vars[k] = var
				self.param_entries[k] = opt
			else:
				ent = tk.Entry(self.params_frame, textvariable=var, width=12)
				ent.grid(row=row, column=1, pady=2)
				self.param_vars[k] = var
				self.param_entries[k] = ent
			row += 1
		if row == 0:
			tk.Label(self.params_frame, text="(no params loaded)", fg="gray").pack()

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
		# update current_device record
		self.current_device["param_set"] = new_params
		# write back to file
		try:
			write_params_to_file(self.current_file, self.current_device.get("device_id",""), new_params)
			self._append_log(f"Saved parameters to {self.current_file}")
			messagebox.showinfo("Saved", f"Parameters saved to {self.current_file}")
			# update last device snapshot as well
			# Do not update last-device on save; only record on explicit disconnect
		except Exception as e:
			self._append_log(f"Error saving to {self.current_file}: {e}")
			messagebox.showerror("Save error", f"Could not save: {e}")

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
