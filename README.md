# 🏢 Smart Building Floor Access Control System

A multi-layered physical security system for a 4-floor building, combining RFID card access, fingerprint biometrics, and live face recognition, all controlled through a Raspberry Pi GUI dashboard.

---

## 📸 System Overview

The system enforces a strict entry/exit sequence:

```
ENTER:  Fingerprint scan (building gate) → RFID tap Floor 1 → RFID tap target floor
EXIT:   RFID tap target floor (OUT) → RFID tap Floor 1 (return to lobby) → Fingerprint scan (gate)
```

Skipping any step triggers a **CRITICAL anomaly alert** and denies access.

---

## ⚙️ Hardware Architecture

| Component | Role |
|---|---|
| **Raspberry Pi** | Central controller, runs the GUI dashboard |
| **ESP32-S3** | Manages all 4 RFID readers + fingerprint sensor, communicates with Pi via USB serial |
| **Arduino Nano** | Controls relays (floor lights) and servos (door locks) via single-byte commands from ESP32 |
| **MFRC522 x 4** | RFID readers, one per floor (shared SPI bus, individual SS pins) |
| **R307S** | Fingerprint sensor (UART, up to 127 templates) |
| **PCA9685** | I2C servo driver, controls door locks on Floors 2-4 |
| **8-channel relay module** | White + red lights per floor (Active LOW) |
| **Pi Camera x 2** | Live surveillance on Floors 2 and 3 |

### Wiring Quick Reference

**ESP32-S3 RFID (shared SPI)**
```
SCK  → GPIO 36 | MISO → GPIO 37 | MOSI → GPIO 35 | RST → GPIO 8
SS1 (F1) → GPIO 4 | SS2 (F2) → GPIO 5 | SS3 (F3) → GPIO 6 | SS4 (F4) → GPIO 7
```

**R307S Fingerprint Sensor**
```
Red → 5V | Black → GND
Yellow (TX) → GPIO 16 | Green (RX) → GPIO 19 | White (Wake) → GPIO 20
```

**ESP32 → Arduino Nano UART**
```
ESP32 TX1 (GPIO 17) → Nano D0 (via 1kΩ resistor)
ESP32 RX1 (GPIO 18) ← Nano D1 | GND ↔ GND
```

---

## 🖥️ Software Stack

- **Python 3** - Main application (`syste1.py`)
- **CustomTkinter** - Dark-themed GUI dashboard
- **OpenCV + face_recognition** - Real-time face detection and recognition
- **Picamera2** - Pi camera integration
- **SQLite** - Persistent access log, anomaly log, and card state
- **PySerial** - USB serial communication with ESP32
- **Arduino (C++)** - Firmware for ESP32-S3 and Arduino Nano

---

## 🛡️ Security Features

### 10 Anomaly Types (4 Severity Levels)

| Severity | Anomaly | Action Required |
|---|---|---|
| 🔴 CRITICAL | Unknown Card | Confiscate card, no identity on record |
| 🔴 CRITICAL | No FP Sign-In | Intercept, possible tailgate or stolen card |
| 🔴 CRITICAL | FP Exit Order Violation | Intercept, unaccounted exit |
| 🟠 HIGH | Unauthorized Floor | Escort out, verify clearance |
| 🟠 HIGH | Floor 1 Bypass | Check entry point, possible back-door |
| 🟡 MEDIUM | Out-of-Order Exit | Remind of correct exit sequence |
| 🟡 MEDIUM | Orphan Out | Review entry log |
| 🟡 MEDIUM | Multi-Floor In | Verify occupancy |
| 🔵 LOW | Floor Skip | Verify floor compliance |
| 🔵 LOW | Rapid Re-entry | Check for card sharing |

### Additional Security Layers
- **Strict Mode** - denies access on any anomaly detection
- **Camera surveillance** - cross-references face recognition with RFID state
- **Multi-floor face detection** - alerts when the same person appears on two camera feeds simultaneously
- **Stale-state sweep** - hourly check flags anyone marked "inside" for 24+ hours
- **Emergency/Evacuation Mode** - grants all access unconditionally, loops alarm sound

---

## 📋 Dashboard Pages

| Page | Description |
|---|---|
| **Dashboard** | Live floor occupancy tiles, light/sensor controls, FP sensor status |
| **Live Feed** | Real-time timestamped event log |
| **Camera** | Dual camera surveillance with face recognition overlay |
| **Personnel** | Employee management, RFID + fingerprint enrollment + face data capture |
| **Access Log** | Full access history with granted/denied status |
| **Building Activity** | Per-employee location, state, and violation history, undo violations without FP gate |
| **Anomaly Log** | Security violations with severity, action guidance, and strict mode controls |
| **Visitors** | External visitor request approval workflow |
| **Temp Access** | Employee temporary floor access requests with countdown timer |
| **System** | Connection, time sync, emergency mode, diagnostics |

---

## 🚀 Setup & Installation

### 1. Python Dependencies

```bash
pip install customtkinter pyserial opencv-python pillow face_recognition picamera2 numpy
```

> `face_recognition` requires `dlib`. On Raspberry Pi:
> ```bash
> pip install cmake dlib face_recognition
> ```

### 2. Arduino Firmware

- **ESP32-S3** - Flash `floor_access_fingerprint_v4.ino` using Arduino IDE
  - Board: `ESP32S3 Dev Module`
  - Flash: 16MB, PSRAM: OPI PSRAM (8MB)
  - Required library: `Adafruit Fingerprint Sensor Library`

- **Arduino Nano** - Flash `nano_relay_servo_controller_fixed__1__ino.ino`
  - Required library: `Adafruit PWMServoDriver` (for PCA9685)

### 3. Face Recognition Setup

Create a `dataset/` folder with one sub-folder per employee (named exactly as registered in the system):

```
dataset/
  Juan Dela Cruz/
    photo1.jpg
    photo2.jpg
  Maria Santos/
    photo1.jpg
```

Then train the model from the Personnel page (🧠 TRAIN MODEL button) or via the Face Capture dialog.

### 4. Audio Files

Place WAV files in an `audios/` folder next to `syste1.py`:

```
audios/
  grant.wav
  grant_fp.wav
  grant_floor.wav
  grant_floor1.wav
  grant_temp.wav
  deny.wav
  deny_unknown_card.wav
  deny_fp_required.wav
  deny_sequence.wav
  violation.wav
  alert_fp_missing.wav
  alert_intercept.wav
  alert_bypass.wav
  alert_out_of_order.wav
  alert_multi_floor.wav
  alert_floor_skip.wav
  emergency.wav
```

### 5. Run

```bash
python3 syste1.py
```

The app auto-scans for the ESP32 on startup. Use the PORT dropdown to select manually if needed.

---

## 📡 ESP32 ↔ Pi Protocol

**Pi → ESP32 (text commands):**
```
ADD:<uid>,<floor>,<name>     # Register RFID card
DEL:<uid>                    # Remove card
LIST_CARDS                   # Fetch all cards
FP_ENROLL:<id>,<floor>,<name>  # Start fingerprint enrollment
FP_DELETE:<id>               # Delete fingerprint
GRANT_FLOOR:<floor>          # Unlock door for one access
LIGHT:<floor>,<normal|alert> # Override floor lighting
EMERGENCY:<ON|OFF>           # Toggle evacuation mode
TIME:<epoch>                 # Sync RTC
```

**ESP32 → Pi (JSON events):**
```json
{"event": "scan",    "floor": 2, "uid": "AA BB CC DD", "result": "GRANTED", "name": "Juan", "dir": "IN",  "time": "2025-01-01 08:00:00"}
{"event": "fp_scan", "floor": 0, "fp_id": 1, "confidence": 250, "result": "GRANTED", "name": "Juan", "dir": "IN"}
{"event": "fp_status", "status": "ready", "count": 3}
```

---

## 🗂️ File Structure

```
smart building security/
├── syste1.py                          # Main Raspberry Pi application
├── floor_access_fingerprint_v4.ino    # ESP32-S3 firmware
├── nano_relay_servo_controller_fixed__1__ino/
│   └── nano_relay_servo_controller_fixed__1__ino.ino  # Arduino Nano firmware
├── audios/                            # WAV audio files (not tracked)
├── dataset/                           # Face recognition training images (not tracked)
├── captured_faces/                    # Auto-captured face snapshots (not tracked)
├── encodings.pickle                   # Trained face model (not tracked, auto-generated)
└── floor_access.db                    # SQLite database (not tracked, auto-generated)
```

---

## .gitignore Recommendations

```gitignore
# Auto-generated
floor_access.db
encodings.pickle
security_system.log

# Face data (privacy)
dataset/
captured_faces/

# Audio assets
audios/
```

---

## 📝 Notes

- Baud rate between Pi and ESP32: **115200**
- Maximum registered employees: **50** (RFID) / **127** (fingerprint templates)
- Supports up to **4 floors**
- Face recognition uses HOG model (`face_recognition` library) scaled at 1/3 resolution for performance
- All camera UI updates are marshalled to the main Tkinter thread via `after(0, ...)` for thread safety
- Database uses `threading.RLock` for re-entrant access between the main event loop and camera thread
