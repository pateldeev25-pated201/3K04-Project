# DCM Software Implementation and Change Log

## Overview
This document summarizes the features implemented, changes made, and the current status of the DCM (Device Controller Monitor) software for Deliverable 2 of SFWRENG/MECHTRON 3K04.

---

## Features Implemented

### 1. Parameter Management
- All programmable parameters and per-mode mappings (per Table 6 of requirements) are supported in the GUI.
- Parameter validation, range enforcement, and logical checks (e.g., LRL ≤ URL).
- Parameters can be saved to and loaded from JSON files.

### 2. Serial Communication
- UART/serial communication implemented in `dcm_comm.py`.
- Protocol-compliant packet construction, parsing, and checksum validation.
- Parameter packing/unpacking to match the 13-byte protocol structure.
- Functions to send parameters, request egram, stop egram, and receive parameters.

### 3. DCM GUI Integration
- Serial connect/disconnect controls in the GUI.
- Buttons for sending parameters, verifying device parameters, requesting egram, and starting/stopping live egram display.
- Log window for communication and status messages.

### 4. Parameter Verification
- "Verify Parameters" button reads parameters from the device, compares with GUI, and displays match/mismatch results.

### 5. Egram Handling
- Simulated egram snapshot saving and preview.
- Live egram streaming and real-time plotting from device (scrolling plot for atrial and ventricular signals).

---

## Change Log

### Major Code Changes
- Created `dcm_comm.py` for all serial/protocol logic.
- Updated `welcome.py` to:
  - Import and use `dcm_comm.py` for all device communication.
  - Add serial port controls and status display.
  - Add parameter verification and live egram display features.
  - Add robust error handling for serial and GUI operations.
  - Fix crash in `_append_log` when log widget is not present.
- Added parameter packing/unpacking logic to match protocol.
- Added GUI hooks for all new features.

### Bug Fixes
- Fixed crash when `_append_log` was called before the DCM frame was built.
- Fixed undefined variable `f` in frame construction.

---

## Current Status
- All DCM software features for Deliverable 2 are implemented and ready for hardware testing.
- Serial communication, parameter verification, and live egram streaming require the pacemaker hardware to function.
- All GUI and file management features can be tested without hardware.

---

## Next Steps
- Test all serial and live egram features with the pacemaker hardware.
- Update documentation and assurance case as required by the course deliverable.
- Add further enhancements (e.g., advanced plotting, more robust error handling) as needed.

---

## Author
Generated and maintained with the assistance of GitHub Copilot (GPT-4.1).
