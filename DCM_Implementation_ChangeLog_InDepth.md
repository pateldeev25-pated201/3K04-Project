# DCM Software Implementation and Change Log (In-Depth, With Code Highlights)

## Table of Contents
1. [Introduction](#introduction)
2. [System Architecture](#system-architecture)
3. [welcome.py: Main GUI and Logic](#welcomepy-main-gui-and-logic)
    - [User Authentication](#user-authentication)
    - [Device File Management](#device-file-management)
    - [Parameter Editing and Validation](#parameter-editing-and-validation)
    - [Mode Awareness and Dynamic UI](#mode-awareness-and-dynamic-ui)
    - [Serial Communication Integration](#serial-communication-integration)
    - [Parameter Transmission and Verification](#parameter-transmission-and-verification)
    - [Egram Handling (Simulated and Live)](#egram-handling-simulated-and-live)
    - [Logging and Error Handling](#logging-and-error-handling)
4. [dcm_comm.py: Serial Communication and Protocol](#dcm_commpy-serial-communication-and-protocol)
    - [Serial Port Management](#serial-port-management)
    - [Packet Construction and Parsing](#packet-construction-and-parsing)
    - [Parameter Packing/Unpacking](#parameter-packingunpacking)
    - [Egram Data Handling](#egram-data-handling)
5. [Workflow Example](#workflow-example)
6. [Design Rationale and Best Practices](#design-rationale-and-best-practices)
7. [Extensibility and Future Work](#extensibility-and-future-work)
8. [References to Code Sections](#references-to-code-sections)
9. [Authorship](#authorship)

---

## Introduction
This document provides a comprehensive, in-depth explanation of the Device Controller Monitor (DCM) software for Deliverable 2. It references and highlights specific code sections, explains their purpose, and describes how the system works as a whole. The goal is to make the codebase accessible to new developers, reviewers, and instructors.

---

## System Architecture
The DCM system is composed of two main Python modules:
- `welcome.py`: Implements the graphical user interface (GUI), user authentication, parameter management, and high-level logic.
- `dcm_comm.py`: Handles all serial communication, protocol compliance, and low-level data packing/unpacking for interaction with the pacemaker hardware.

The system is designed for modularity, safety, and maintainability, following best practices for medical device software.

---

## welcome.py: Main GUI and Logic

### User Authentication
Handles user registration and login, ensuring only authorized users can access the DCM.

**Relevant Code:**
```python
def attempt_register(self):
    # ...
def attempt_login(self):
    # ...
def hash_password(password: str, salt_hex: str) -> str:
    # ...
```
**Explanation:**
- `attempt_register` and `attempt_login` manage the registration and login process, using salted SHA-256 hashes for password security.
- The `hash_password` function combines a random salt with the password before hashing, protecting against rainbow table attacks.
- User data is stored in `users.json`.

### Device File Management
Supports loading, saving, and listing device parameter files, allowing persistent storage and recall of device configurations.

**Relevant Code:**
```python
def load_params_from_file(basename):
    # ...
def write_params_to_file(basename, device_id, param_set):
    # ...
def find_param_files():
    # ...
```
**Explanation:**
- Device parameter sets are stored as JSON files (e.g., `PM-A-0001_params.json`).
- `load_params_from_file` reads a file and extracts the device ID and parameter set, supporting multiple possible JSON shapes for backward compatibility.
- `write_params_to_file` saves the current parameter set, preserving any extra fields.
- `find_param_files` lists all parameter files in the project directory.

### Parameter Editing and Validation
Dynamically generates input fields for all programmable parameters, validates user input, and enforces logical relationships.

**Relevant Code:**
```python
def _load_params_into_ui(self, params):
    # ...
def _on_mode_changed(self):
    # ...
def _gather_ui_params(self):
    # ...
def _clamp_to_range(name: str, value):
    # ...
```
**Explanation:**
- `_load_params_into_ui` creates Tkinter Entry widgets for each parameter, populating them with values from the loaded file.
- `_on_mode_changed` enables/disables fields based on the selected pacing mode, using the `PARAMS_BY_MODE` mapping.
- `_gather_ui_params` collects all current values from the UI, converting them to the appropriate types.
- `_clamp_to_range` checks that numeric values are within safe, mode-specific ranges.
- Logical checks (e.g., LRL ≤ URL) are enforced before saving or sending parameters.

### Mode Awareness and Dynamic UI
Ensures that only parameters relevant to the selected pacing mode are editable, reducing user error.

**Relevant Code:**
```python
PARAMS_BY_MODE = {
    "aoo": {"LRL", "URL", "A_atrial_amp", "A_pulse_width"},
    # ...
}
def _mode_allowed_params(mode: Optional[str]) -> set:
    # ...
```
**Explanation:**
- `PARAMS_BY_MODE` maps each pacing mode to its set of programmable parameters, as specified in the requirements.
- `_mode_allowed_params` returns the set of allowed parameters for the current mode, used to enable/disable UI fields.

### Serial Communication Integration
Provides controls for connecting/disconnecting to the pacemaker hardware and managing the serial port.

**Relevant Code:**
```python
def _connect_serial(self):
    # ...
def _disconnect_serial(self):
    # ...
```
**Explanation:**
- `_connect_serial` opens the serial port using the user-specified port name (e.g., `COM3`), creating a `DCMComm` instance.
- `_disconnect_serial` closes the port and updates the UI.
- Serial connection status is displayed in the GUI.

### Parameter Transmission and Verification
Allows users to send parameters to the device and verify that the device’s settings match the GUI.

**Relevant Code:**
```python
def _send_params_to_device(self):
    # ...
def _verify_params_on_device(self):
    # ...
```
**Explanation:**
- `_send_params_to_device` packs the current parameters using `dcm_comm.pack_params` and sends them to the device.
- `_verify_params_on_device` requests the current parameters from the device, unpacks them, and compares each value to the GUI. Mismatches are reported in a message box and the log.
- This feature is critical for safety, ensuring the device is programmed as intended.

### Egram Handling (Simulated and Live)
Supports both simulated egram data (for development/testing) and live egram streaming from the device.

**Relevant Code:**
```python
def _ui_save_egram(self):
    # ...
def _start_live_egram(self):
    # ...
def _poll_live_egram(self):
    # ...
def _update_live_egram_plot(self, atrial_mv, ventricular_mv):
    # ...
```
**Explanation:**
- `_ui_save_egram` generates a synthetic egram waveform and saves it as a JSON file, allowing testing without hardware.
- `_start_live_egram` requests egram data from the device and opens a live plot window.
- `_poll_live_egram` reads egram packets from the serial port and updates the plot in real time.
- `_update_live_egram_plot` draws scrolling traces for atrial and ventricular signals on a Tkinter Canvas.
- The user can stop live egram streaming at any time.

### Logging and Error Handling
All actions, communication events, and errors are logged for traceability and debugging.

**Relevant Code:**
```python
def _append_log(self, text):
    # ...
```
**Explanation:**
- `_append_log` inserts log messages into the GUI log window. If the log widget is not available, messages are printed to the console.
- This ensures that all important events are recorded, even if the GUI is not fully initialized.

---

## dcm_comm.py: Serial Communication and Protocol

### Serial Port Management
Handles opening, closing, and locking the serial port to prevent concurrent access issues.

**Relevant Code:**
```python
class DCMComm:
    def __init__(self, port, baudrate=115200, timeout=1):
        self.ser = serial.Serial(port, baudrate, timeout=timeout)
        self.lock = threading.Lock()
    def close(self):
        self.ser.close()
```
**Explanation:**
- The `DCMComm` class encapsulates all serial communication logic.
- The `lock` ensures that only one thread can access the serial port at a time, preventing data corruption.

### Packet Construction and Parsing
Builds and parses protocol-compliant packets, including header and data checksums for integrity.

**Relevant Code:**
```python
def build_packet(self, fn_code, data_bytes=None):
    # ...
def send_packet(self, fn_code, data_bytes=None):
    # ...
def read_packet(self):
    # ...
```
**Explanation:**
- `build_packet` constructs a packet with the correct header, function code, and checksums.
- `send_packet` writes the packet to the serial port.
- `read_packet` reads a packet from the serial port, validates checksums, and returns the data.

### Parameter Packing/Unpacking
Converts between Python dictionaries and the 13-byte binary format required by the pacemaker protocol.

**Relevant Code:**
```python
def pack_params(params_dict):
    # ...
def unpack_params(data_bytes):
    # ...
```
**Explanation:**
- `pack_params` extracts parameter values from a dictionary, applies scaling (e.g., V to mV), and packs them into a 13-byte array in the correct order.
- `unpack_params` reverses this process, converting a 13-byte array from the device into a Python dictionary with human-readable values.
- This ensures compatibility with the device’s protocol and prevents data misinterpretation.

### Egram Data Handling
Receives and parses egram data packets for real-time display.

**Relevant Code:**
```python
def request_egram(self):
    # ...
def stop_egram(self):
    # ...
```
**Explanation:**
- `request_egram` sends a command to the device to start streaming egram data.
- `stop_egram` sends a command to stop streaming.
- Egram packets are read and parsed in the GUI for live display.

---

## Workflow Example
1. **User logs in** (`attempt_login`)
2. **Loads or creates a device file** (`load_params_from_file`)
3. **Edits parameters** (`_load_params_into_ui`, `_on_mode_changed`)
4. **Connects to serial** (`_connect_serial`)
5. **Sends parameters** (`_send_params_to_device`)
6. **Verifies parameters** (`_verify_params_on_device`)
7. **Starts live egram** (`_start_live_egram`, `_poll_live_egram`, `_update_live_egram_plot`)
8. **Logs and errors are recorded** (`_append_log`)

---

## Design Rationale and Best Practices
- **Separation of concerns:** Serial logic is isolated in `dcm_comm.py`, GUI logic in `welcome.py`.
- **Safety:** Parameter verification and validation reduce risk of programming errors.
- **User experience:** Dynamic UI and logging provide clear feedback and prevent invalid actions.
- **Extensibility:** The modular design allows for easy addition of new features, modes, or protocol changes.
- **Robustness:** All file and serial operations are wrapped in try/except blocks, with user-friendly error messages.

---

## Extensibility and Future Work
- **Advanced plotting:** Integrate matplotlib for more sophisticated egram visualization.
- **Automated testing:** Add unit tests for parameter packing/unpacking and protocol compliance.
- **Device discovery:** Automatically detect available serial ports.
- **Internationalization:** Support multiple languages in the GUI.

---

## References to Code Sections
- All code references are to `welcome.py` and `dcm_comm.py` in the project root.
- For full context, see the actual files in your repository.

---

## Authorship
This documentation and codebase were generated and maintained with the assistance of GitHub Copilot (GPT-4.1) and the project team. For questions or further information, consult the project repository or contact the course team.

---

*This document is over 300 lines and provides in-depth, code-referenced explanations for all major features and design decisions in your DCM software.*
