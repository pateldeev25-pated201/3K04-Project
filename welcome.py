import tkinter as tk
from tkinter import messagebox
import json
import os
import hashlib
import secrets


USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")
MAX_USERS = 10


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


class WelcomeApp(tk.Tk):
	def __init__(self):
		super().__init__()
		self.title("Welcome — Login/Register")
		self.resizable(False, False)
		self.users = load_users()

		# Frames
		self.frame_welcome = tk.Frame(self)
		self.frame_login = tk.Frame(self)
		self.frame_register = tk.Frame(self)
		self.frame_logged_in = tk.Frame(self)

		self._build_welcome()
		self._build_login()
		self._build_register()
		self._build_logged_in()

		self.show_frame(self.frame_welcome)

	def show_frame(self, frame):
		for f in (self.frame_welcome, self.frame_login, self.frame_register, self.frame_logged_in):
			f.pack_forget()
		frame.pack(padx=20, pady=20)

	def _build_welcome(self):
		f = self.frame_welcome
		tk.Label(f, text="Welcome!", font=(None, 18)).pack(pady=(0, 10))
		tk.Label(f, text="Please choose an action:").pack(pady=(0, 10))
		tk.Button(f, text="Login", width=20, command=lambda: self.show_frame(self.frame_login)).pack(pady=5)
		tk.Button(f, text="Register", width=20, command=lambda: self.show_frame(self.frame_register)).pack(pady=5)
		tk.Button(f, text="Exit", width=20, command=self.quit).pack(pady=(10, 0))

	def _build_login(self):
		f = self.frame_login
		tk.Label(f, text="Login", font=(None, 16)).grid(row=0, column=0, columnspan=2, pady=(0, 10))

		tk.Label(f, text="Username:").grid(row=1, column=0, sticky="e")
		self.login_user = tk.Entry(f)
		self.login_user.grid(row=1, column=1)

		tk.Label(f, text="Password:").grid(row=2, column=0, sticky="e")
		self.login_pass = tk.Entry(f, show="*")
		self.login_pass.grid(row=2, column=1)

		self.login_msg = tk.Label(f, text="", fg="red")
		self.login_msg.grid(row=3, column=0, columnspan=2)

		tk.Button(f, text="Submit", width=12, command=self.attempt_login).grid(row=4, column=0, pady=8)
		tk.Button(f, text="Back", width=12, command=lambda: self.show_frame(self.frame_welcome)).grid(row=4, column=1)

	def _build_register(self):
		f = self.frame_register
		tk.Label(f, text="Register", font=(None, 16)).grid(row=0, column=0, columnspan=2, pady=(0, 10))

		tk.Label(f, text="Username:").grid(row=1, column=0, sticky="e")
		self.reg_user = tk.Entry(f)
		self.reg_user.grid(row=1, column=1)

		tk.Label(f, text="Password:").grid(row=2, column=0, sticky="e")
		self.reg_pass = tk.Entry(f, show="*")
		self.reg_pass.grid(row=2, column=1)

		tk.Label(f, text="Confirm:").grid(row=3, column=0, sticky="e")
		self.reg_pass2 = tk.Entry(f, show="*")
		self.reg_pass2.grid(row=3, column=1)

		self.reg_msg = tk.Label(f, text="", fg="red")
		self.reg_msg.grid(row=4, column=0, columnspan=2)

		tk.Button(f, text="Create", width=12, command=self.attempt_register).grid(row=5, column=0, pady=8)
		tk.Button(f, text="Back", width=12, command=lambda: self.show_frame(self.frame_welcome)).grid(row=5, column=1)

	def _build_logged_in(self):
		f = self.frame_logged_in
		self.logged_label = tk.Label(f, text="", font=(None, 14))
		self.logged_label.pack(pady=(0, 10))
		tk.Button(f, text="Logout", width=12, command=self.logout).pack()

	def attempt_register(self):
		username = self.reg_user.get().strip()
		pw = self.reg_pass.get()
		pw2 = self.reg_pass2.get()

		# Basic validation
		if not username:
			self.reg_msg.config(text="Enter a username")
			return
		if not pw:
			self.reg_msg.config(text="Enter a password")
			return
		if pw != pw2:
			self.reg_msg.config(text="Passwords do not match")
			return

		# Check for duplicate
		if any(u.get("username") == username for u in self.users):
			self.reg_msg.config(text="Username already exists")
			return

		# Check max users
		if len(self.users) >= MAX_USERS:
			self.reg_msg.config(text=f"Max users reached ({MAX_USERS})")
			return

		# Create user
		salt = secrets.token_bytes(16).hex()
		pw_hash = hash_password(pw, salt)
		user_obj = {"username": username, "salt": salt, "pw_hash": pw_hash}
		self.users.append(user_obj)
		save_users(self.users)

		messagebox.showinfo("Success", "User registered successfully")
		# clear fields
		self.reg_user.delete(0, tk.END)
		self.reg_pass.delete(0, tk.END)
		self.reg_pass2.delete(0, tk.END)
		self.reg_msg.config(text="")
		self.show_frame(self.frame_login)

	def attempt_login(self):
		username = self.login_user.get().strip()
		pw = self.login_pass.get()

		if not username or not pw:
			self.login_msg.config(text="Enter username and password")
			return

		matched = None
		for u in self.users:
			if u.get("username") == username:
				matched = u
				break

		if not matched:
			self.login_msg.config(text="Unknown username")
			return

		salt = matched.get("salt")
		expected = matched.get("pw_hash")
		if hash_password(pw, salt) == expected:
			# success
			self.login_msg.config(text="")
			self.login_user.delete(0, tk.END)
			self.login_pass.delete(0, tk.END)
			self.show_logged_in(username)
		else:
			self.login_msg.config(text="Incorrect password")

	def show_logged_in(self, username):
		self.logged_label.config(text=f"Logged in as: {username}")
		self.show_frame(self.frame_logged_in)

	def logout(self):
		self.show_frame(self.frame_welcome)


def ensure_users_file_exists():
	if not os.path.exists(USERS_FILE):
		save_users([])


def main():
	ensure_users_file_exists()
	app = WelcomeApp()
	app.mainloop()


if __name__ == "__main__":
	main()
