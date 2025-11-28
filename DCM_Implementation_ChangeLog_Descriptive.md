# DCM Software Implementation and Change Log (Detailed)

## Introduction
This document provides a comprehensive overview and explanation of the Device Controller Monitor (DCM) software developed for Deliverable 2 of SFWRENG/MECHTRON 3K04. It is intended to help any reader—regardless of prior involvement—understand the system’s structure, features, and the rationale behind key design decisions.

---

## System Overview
The DCM is a Python-based graphical application that allows clinicians or engineers to configure, monitor, and verify the operation of an implantable pacemaker device. It provides a user-friendly interface for:
- Editing and validating programmable parameters for all supported pacing modes
- Communicating with the pacemaker hardware over a serial (UART) connection
- Displaying and saving electrogram (egram) data from the device
- Verifying that the device’s settings match those entered in the DCM

The DCM is designed for modularity, safety, and ease of use, following best practices in software engineering for medical devices.

---

## Main Components and Their Roles

### 1. `welcome.py` (Main GUI and Logic)
- **User Authentication:** Supports user registration and login, with password hashing and salt for security.
- **Device File Management:** Loads and saves device parameter sets to JSON files, allowing persistent storage and recall of device configurations.
- **Parameter Editing:** Dynamically generates input fields for all programmable parameters, enforcing valid ranges and logical relationships (e.g., Lower Rate Limit ≤ Upper Rate Limit).
- **Mode Awareness:** Only enables parameters relevant to the selected pacing mode, reducing user error.
- **Serial Communication Integration:** Provides controls to connect/disconnect from the pacemaker hardware via a serial port.
- **Parameter Transmission:** Allows users to send the current parameter set to the pacemaker.
- **Parameter Verification:** Reads parameters back from the device and compares them to the GUI, alerting the user to any mismatches.
- **Egram Handling:**
  - Simulated egram snapshot generation for testing without hardware
  - Live egram streaming and real-time plotting from the device (when connected)
- **Logging:** All actions and communication events are logged in a dedicated window for traceability and debugging.

### 2. `dcm_comm.py` (Serial Communication and Protocol)
- **Serial Port Management:** Handles opening, closing, and locking the serial port to prevent concurrent access issues.
- **Packet Construction:** Builds protocol-compliant packets for all supported operations (parameter send, egram request, etc.), including header and data checksums for integrity.
- **Parameter Packing/Unpacking:** Converts between Python dictionaries and the 13-byte binary format required by the pacemaker protocol, ensuring correct field order, scaling, and data types.
- **Egram Data Handling:** Receives and parses egram data packets for real-time display.

---

## Key Features Explained

### Parameter Management
- **Dynamic UI:** The GUI automatically adapts to the selected pacing mode, showing only relevant parameters and disabling others. This reduces the risk of invalid configurations.
- **Validation:** Each parameter is checked for correct type and range before being accepted or transmitted. Logical relationships (such as LRL ≤ URL) are enforced.
- **Persistence:** Parameter sets are saved in human-readable JSON files, making it easy to archive, share, or audit device configurations.

### Serial Communication
- **Robust Protocol Handling:** All packets sent to and received from the pacemaker follow the specified protocol, including checksums to detect transmission errors.
- **Thread Safety:** Serial operations are protected by locks to prevent data corruption from concurrent access.
- **Error Handling:** The system gracefully handles missing hardware, timeouts, and protocol errors, providing clear feedback to the user.

### Parameter Verification
- **Read-Back and Compare:** After sending parameters, the user can request the current settings from the device. The DCM unpacks the response and compares each value to the GUI, highlighting any discrepancies. This ensures that what the user sees is what is actually programmed in the device.

### Egram Display
- **Simulated Egram:** For development and demonstration without hardware, the DCM can generate and display synthetic egram data.
- **Live Egram Streaming:** When connected to the pacemaker, the DCM can request and plot real-time egram data, showing atrial and ventricular signals as scrolling traces. This helps clinicians assess device function and patient status.

### Logging and Traceability
- **Action Log:** All user actions, communication events, and errors are recorded in a log window, supporting troubleshooting and audit requirements.
- **Console Fallback:** If the log window is not available (e.g., before the GUI is fully initialized), logs are printed to the console.

---

## Major Changes and Rationale
- **Modularization:** Serial communication was separated into `dcm_comm.py` to isolate hardware-specific logic from the GUI, improving maintainability and testability.
- **Protocol Compliance:** All parameter and egram data handling was updated to match the formal protocol specification, ensuring compatibility with the pacemaker hardware.
- **Safety Features:** Parameter verification and strict validation were added to reduce the risk of programming errors.
- **User Experience:** The GUI was enhanced to provide clear feedback, prevent invalid actions, and support all required modes and parameters.
- **Bug Fixes:** Crashes due to missing widgets or undefined variables were resolved, making the application more robust.

---

## How to Use the DCM
1. **Start the Application:** Run `welcome.py`.
2. **Register or Log In:** Create a user account or log in with existing credentials.
3. **Select or Create a Device File:** Load a device configuration or create a new one.
4. **Edit Parameters:** Adjust parameters as needed. Only valid options for the selected mode are enabled.
5. **Connect to Pacemaker:** Enter the correct serial port and connect.
6. **Send Parameters:** Transmit the current settings to the device.
7. **Verify Parameters:** Use the "Verify Parameters" button to ensure the device matches the GUI.
8. **Live Egram:** Start live egram streaming to view real-time signals from the device.
9. **Save or Preview Egrams:** Save egram snapshots or review previous recordings.

---

## Current Status and Next Steps
- All required DCM software features for Deliverable 2 are implemented and ready for hardware testing.
- Serial communication, parameter verification, and live egram streaming require the pacemaker hardware to function.
- All GUI and file management features can be tested without hardware.
- Next steps: Test with hardware, update documentation, and address any issues found during integration.

---

## Contact and Authorship
This software and documentation were developed and maintained with the assistance of GitHub Copilot (GPT-4.1) and the project team. For questions or further information, consult the project repository or contact the course team.
