# DCM Software Implementation and Change Log (With Code Highlights)

## Introduction
This document explains the Device Controller Monitor (DCM) software for Deliverable 2, referencing and highlighting specific code sections to help readers understand how the system works.

---

## 1. Main GUI and Logic (`welcome.py`)

### User Authentication
- **Relevant Code:**
  ```python
  def attempt_register(self): ...
  def attempt_login(self): ...
  ```
- **Explanation:**
  These methods handle user registration and login, using password hashing and salt for security. See the `hash_password` function for the hashing logic.

### Device File Management
- **Relevant Code:**
  ```python
  def load_params_from_file(basename): ...
  def write_params_to_file(basename, device_id, param_set): ...
  ```
- **Explanation:**
  These functions load and save device parameter sets as JSON files, allowing persistent storage and recall of device configurations.

### Parameter Editing and Validation
- **Relevant Code:**
  ```python
  def _load_params_into_ui(self, params): ...
  def _on_mode_changed(self): ...
  def _gather_ui_params(self): ...
  def _clamp_to_range(name, value): ...
  ```
- **Explanation:**
  The GUI dynamically generates input fields for all programmable parameters, enabling/disabling them based on the selected pacing mode. Validation ensures all values are within safe ranges and logical relationships (e.g., LRL ≤ URL) are enforced.

### Serial Communication Integration
- **Relevant Code:**
  ```python
  def _connect_serial(self): ...
  def _disconnect_serial(self): ...
  def _send_params_to_device(self): ...
  ```
- **Explanation:**
  These methods allow the user to connect to the pacemaker hardware via a serial port, send parameters, and disconnect safely.

### Parameter Verification
- **Relevant Code:**
  ```python
  def _verify_params_on_device(self): ...
  ```
- **Explanation:**
  This method requests the current parameters from the device, unpacks them, and compares them to the GUI values. Any mismatches are reported to the user.

### Egram Handling
- **Relevant Code:**
  ```python
  def _ui_save_egram(self): ...
  def _start_live_egram(self): ...
  def _poll_live_egram(self): ...
  def _update_live_egram_plot(self, atrial_mv, ventricular_mv): ...
  ```
- **Explanation:**
  The DCM can generate and display simulated egram data, or stream and plot live egram data from the device in real time. The plot is updated on a Tkinter Canvas.

### Logging
- **Relevant Code:**
  ```python
  def _append_log(self, text): ...
  ```
- **Explanation:**
  All actions and communication events are logged in a dedicated window. If the log widget is not available, logs are printed to the console.

---

## 2. Serial Communication and Protocol (`dcm_comm.py`)

### Serial Port Management
- **Relevant Code:**
  ```python
  class DCMComm:
      def __init__(self, port, baudrate=115200, timeout=1): ...
      def close(self): ...
  ```
- **Explanation:**
  Handles opening, closing, and locking the serial port to prevent concurrent access issues.

### Packet Construction and Parsing
- **Relevant Code:**
  ```python
  def build_packet(self, fn_code, data_bytes=None): ...
  def send_packet(self, fn_code, data_bytes=None): ...
  def read_packet(self): ...
  ```
- **Explanation:**
  These methods build and parse protocol-compliant packets, including header and data checksums for integrity.

### Parameter Packing/Unpacking
- **Relevant Code:**
  ```python
  def pack_params(params_dict): ...
  def unpack_params(data_bytes): ...
  ```
- **Explanation:**
  Converts between Python dictionaries and the 13-byte binary format required by the pacemaker protocol, ensuring correct field order, scaling, and data types.

### Egram Data Handling
- **Relevant Code:**
  ```python
  def request_egram(self): ...
  def stop_egram(self): ...
  ```
- **Explanation:**
  Sends requests to the device to start or stop egram data streaming.

---

## 3. Example Workflow
1. **User logs in** (`attempt_login`)
2. **Loads or creates a device file** (`load_params_from_file`)
3. **Edits parameters** (`_load_params_into_ui`, `_on_mode_changed`)
4. **Connects to serial** (`_connect_serial`)
5. **Sends parameters** (`_send_params_to_device`)
6. **Verifies parameters** (`_verify_params_on_device`)
7. **Starts live egram** (`_start_live_egram`, `_poll_live_egram`, `_update_live_egram_plot`)

---

## 4. Design Rationale
- **Separation of concerns:** Serial logic is isolated in `dcm_comm.py`, GUI logic in `welcome.py`.
- **Safety:** Parameter verification and validation reduce risk of programming errors.
- **User experience:** Dynamic UI and logging provide clear feedback and prevent invalid actions.

---

## 5. Further Reading
For more details, see the code sections referenced above in `welcome.py` and `dcm_comm.py`.

---

## Authorship
Generated and maintained with the assistance of GitHub Copilot (GPT-4.1) and the project team.
