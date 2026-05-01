/*
 * ================================================================
 *  Arduino Nano  —  Relay + Servo Controller
 *  Receives single-char commands from ESP32-S3 via UART (Serial)
 *
 *  RELAY PINS (Active LOW — DO NOT CHANGE):
 *    IN1 → D3  (Floor 1 White Light)
 *    IN2 → D4  (Floor 2 White Light)
 *    IN3 → D5  (Floor 3 White Light)
 *    IN4 → D6  (Floor 4 White Light)
 *    IN5 → D7  (Floor 1 Red Light)
 *    IN6 → D8  (Floor 2 Red Light)
 *    IN7 → D9  (Floor 3 Red Light)
 *    IN8 → D10 (Floor 4 Red Light)
 *
 *  PCA9685 SERVO DRIVER (I2C — DO NOT CHANGE):
 *    VCC → 5V
 *    GND → GND
 *    SDA → A4
 *    SCL → A5
 *    V+  → External 5V–6V  (servo power, separate supply)
 *    OE  → GND             (always enabled)
 *
 *    Channel 5 → Floor 2 servo  (GRANTED= 30°, DENIED=180°)
 *    Channel 6 → Floor 3 servo  (GRANTED= 50°, DENIED=180°)
 *    Channel 7 → Floor 4 servo  (GRANTED=100°, DENIED=180°)
 *    (Floor 1 has no servo — bypass rule always grants access)
 *
 *  UART FROM ESP32-S3:
 *    Nano RX (D0) ← ESP32-S3 TX1 (GPIO17) — via 1kΩ resistor
 *    Nano TX (D1) → ESP32-S3 RX1 (GPIO18)
 *    GND          ↔ GND (common ground REQUIRED)
 *
 *  COMMAND PROTOCOL (1 byte):
 *    'A' = Floor 1 Normal  (White ON,  Red OFF, no servo)
 *    'B' = Floor 2 Normal  (White ON,  Red OFF, servo OPEN  ← right card)
 *    'C' = Floor 3 Normal  (White ON,  Red OFF, servo OPEN  ← right card)
 *    'D' = Floor 4 Normal  (White ON,  Red OFF, servo OPEN  ← right card)
 *    'E' = Floor 1 Alert   (White OFF, Red ON 5s, servo unchanged)
 *    'F' = Floor 2 Alert   (White OFF, Red ON 5s, servo unchanged ← wrong card)
 *    'G' = Floor 3 Alert   (White OFF, Red ON 5s, servo unchanged ← wrong card)
 *    'H' = Floor 4 Alert   (White OFF, Red ON 5s, servo unchanged ← wrong card)
 *    'I' = All Reset       (White ON,  Red OFF, all servos LOCKED ← boot/init)
 *    'J' = Floor 1 Reset   (White ON,  Red OFF, no servo)
 *    'K' = Floor 2 Reset   (White ON,  Red OFF, servo LOCKED ← after grant expires)
 *    'L' = Floor 3 Reset   (White ON,  Red OFF, servo LOCKED ← after grant expires)
 *    'M' = Floor 4 Reset   (White ON,  Red OFF, servo LOCKED ← after grant expires)
 *    'N' = Emergency ON     (All servos OPEN, all lights blink red↔white @1 Hz nonstop)
 *    'O' = Emergency OFF    (All Reset — same as 'I')
 *
 *  DEFAULT BEHAVIOUR:
 *    On boot: White lights (D3–D6) are ON, Red lights (D7–D10) are OFF.
 *    Red lights stay on for exactly RED_DURATION_MS (5 seconds), then
 *    automatically turn off and restore white — no reset command needed.
 *
 *  NOTE: Relay module is Active LOW
 *        LOW  = relay coil energized = light ON
 *        HIGH = relay coil off       = light OFF
 * ================================================================
 */

#include <Wire.h>
#include <Adafruit_PWMServoDriver.h>

// ── Red-light auto-off duration ──────────────────────────────
#define RED_DURATION_MS  5000UL   // 5 seconds

// ── PCA9685 Servo Driver ──────────────────────────────────────
Adafruit_PWMServoDriver pwm = Adafruit_PWMServoDriver(); // default I2C addr 0x40

#define SERVOMIN  110   // DO NOT CHANGE — calibrated pulse min
#define SERVOMAX  510   // DO NOT CHANGE — calibrated pulse max

// Servo channel per floor (index = floor-1, -1 = no servo)
const int servoChannel[4] = { -1, 5, 6, 7 };

// Angles: [floor-1][0] = GRANTED position, [floor-1][1] = DENIED/LOCKED position
const int servoAngle[4][2] = {
  {  -1,  -1 },   // Floor 1: no servo
  {   30, 180 },  // Floor 2: OPEN= 30°, LOCKED=180°
  {   50, 180 },  // Floor 3: OPEN= 50°, LOCKED=180°
  {  100, 180 },  // Floor 4: OPEN=100°, LOCKED=180°
};

int angleToPulse(int angle) {
  return map(angle, 0, 180, SERVOMIN, SERVOMAX);
}

void setServo(int floor, bool granted) {
  int ch = servoChannel[floor - 1];
  if (ch < 0) return;  // no servo on this floor
  int angle = granted ? servoAngle[floor - 1][0] : servoAngle[floor - 1][1];
  pwm.setPWM(ch, 0, angleToPulse(angle));
}

// ── Relay pin assignments (DO NOT CHANGE) ────────────────────
const int relayPins[8] = { 3, 4, 5, 6, 7, 8, 9, 10 };
//  Index:                   0  1  2  3  4  5  6   7
//  Function:               W1 W2 W3 W4 R1 R2 R3  R4
//  (W=White D3-D6, R=Red D7-D10, number=floor)

#define WHITE(floor)  ((floor) - 1)      // white relay index for floor 1-4
#define RED(floor)    ((floor) - 1 + 4)  // red relay index for floor 1-4

// ── Red-light timers (one per floor, 0 = not active) ─────────
unsigned long redTimer[4] = { 0, 0, 0, 0 };  // indexed [floor-1]

// ── Emergency Mode ────────────────────────────────────────────
bool          emergencyMode      = false;
unsigned long emergencyBlinkTimer = 0;
bool          emergencyBlinkState = false;  // false = red phase, true = white phase
#define EMERGENCY_BLINK_MS 500UL            // 500 ms per phase → 1 Hz full cycle

// ─────────────────────────────────────────────────────────────
//  Relay Helpers  (Active LOW)
// ─────────────────────────────────────────────────────────────
void relayOn(int index) {
  digitalWrite(relayPins[index], LOW);   // energize = ON
}

void relayOff(int index) {
  digitalWrite(relayPins[index], HIGH);  // de-energize = OFF
}

// ─────────────────────────────────────────────────────────────
//  Floor State Setters
// ─────────────────────────────────────────────────────────────

// Normal: White ON, Red OFF, servo OPEN (right card scanned)
void setFloorNormal(int floor) {
  redTimer[floor - 1] = 0;       // cancel any pending red timer
  relayOn(WHITE(floor));         // White ON
  relayOff(RED(floor));          // Red OFF
  setServo(floor, true);         // Servo → OPEN
}

// Alert: White OFF, Red ON — auto-resets to white after RED_DURATION_MS
void setFloorAlert(int floor) {
  relayOff(WHITE(floor));                    // White OFF
  relayOn(RED(floor));                       // Red ON
  redTimer[floor - 1] = millis();            // start 5-second countdown
  // Servo stays in current position (locked — wrong card)
}

// Reset: White ON, Red OFF, servo LOCKED — used at boot and after grant expires
void setFloorReset(int floor) {
  redTimer[floor - 1] = 0;       // cancel any pending red timer
  relayOn(WHITE(floor));         // White ON
  relayOff(RED(floor));          // Red OFF
  setServo(floor, false);        // Servo → LOCKED
}

void setAllReset() {
  for (int f = 1; f <= 4; f++) setFloorReset(f);
}

// ─────────────────────────────────────────────────────────────
//  Red-light Auto-off Checker  (call every loop)
//  Skipped during emergency mode — blinking loop takes over.
// ─────────────────────────────────────────────────────────────
void checkRedTimers() {
  if (emergencyMode) return;   // emergency blink loop owns the lights
  unsigned long now = millis();
  for (int f = 1; f <= 4; f++) {
    if (redTimer[f - 1] != 0 && (now - redTimer[f - 1]) >= RED_DURATION_MS) {
      redTimer[f - 1] = 0;      // clear timer
      relayOn(WHITE(f));         // restore white light
      relayOff(RED(f));          // turn red off
    }
  }
}

// ─────────────────────────────────────────────────────────────
//  Emergency Mode Helpers
// ─────────────────────────────────────────────────────────────

// Enter emergency: open all servos, cancel all timers, start blink
void setEmergencyOn() {
  emergencyMode      = true;
  emergencyBlinkState = false;
  emergencyBlinkTimer = millis();
  // Cancel all normal timers
  for (int f = 1; f <= 4; f++) redTimer[f - 1] = 0;
  // Unlock all servos immediately
  for (int f = 2; f <= 4; f++) setServo(f, true);   // Floor 1 has no servo
  // Start in red phase
  for (int f = 1; f <= 4; f++) {
    relayOff(WHITE(f));
    relayOn(RED(f));
  }
}

// Exit emergency: restore all floors to normal (white on, red off, servos locked)
void setEmergencyOff() {
  emergencyMode = false;
  setAllReset();
}

// Non-blocking blink stepper — call every loop() while emergencyMode == true
void stepEmergencyBlink() {
  unsigned long now = millis();
  if (now - emergencyBlinkTimer < EMERGENCY_BLINK_MS) return;
  emergencyBlinkTimer = now;
  emergencyBlinkState = !emergencyBlinkState;
  for (int f = 1; f <= 4; f++) {
    if (emergencyBlinkState) {
      relayOn(WHITE(f));   relayOff(RED(f));    // white phase
    } else {
      relayOff(WHITE(f));  relayOn(RED(f));     // red phase
    }
  }
}

// ─────────────────────────────────────────────────────────────
//  Command Handler
// ─────────────────────────────────────────────────────────────
void handleCommand(char cmd) {
  // Ignore normal floor commands while emergency mode is active
  // (emergency mode owns all lights and servos until explicitly cleared)
  if (emergencyMode && cmd != 'N' && cmd != 'O') return;

  switch (cmd) {
    case 'A': setFloorNormal(1); break;
    case 'B': setFloorNormal(2); break;
    case 'C': setFloorNormal(3); break;
    case 'D': setFloorNormal(4); break;
    case 'E': setFloorAlert(1);  break;
    case 'F': setFloorAlert(2);  break;
    case 'G': setFloorAlert(3);  break;
    case 'H': setFloorAlert(4);  break;
    case 'I': setAllReset();     break;
    case 'J': setFloorReset(1);  break;
    case 'K': setFloorReset(2);  break;
    case 'L': setFloorReset(3);  break;
    case 'M': setFloorReset(4);  break;
    case 'N': setEmergencyOn();  break;  // Emergency ON  — blink all, unlock all
    case 'O': setEmergencyOff(); break;  // Emergency OFF — restore normal
    default:  /* ignore unknown */ break;
  }
}

// ─────────────────────────────────────────────────────────────
//  Setup
// ─────────────────────────────────────────────────────────────
void setup() {
  // Init relay pins — all HIGH (OFF) first
  for (int i = 0; i < 8; i++) {
    pinMode(relayPins[i], OUTPUT);
    relayOff(i);
  }

  // Init PCA9685
  pwm.begin();
  pwm.setPWMFreq(50);
  delay(10);

  // Default state: White lights ON (D3-D6), Red lights OFF (D7-D10), servos LOCKED
  setAllReset();

  // UART from ESP32-S3
  // Note: Serial (D0/D1) is shared with USB on Nano.
  // Disconnect USB after uploading, or use SoftwareSerial on other
  // pins if you need USB debug at the same time.
  Serial.begin(9600);
}

// ─────────────────────────────────────────────────────────────
//  Loop
// ─────────────────────────────────────────────────────────────
void loop() {
  // Check and auto-turn off red lights after 5 seconds (skipped in emergency)
  checkRedTimers();

  // Emergency blink stepper (non-blocking, runs only in emergency mode)
  if (emergencyMode) {
    stepEmergencyBlink();
  }

  // Handle incoming command from ESP32-S3
  if (Serial.available() > 0) {
    char cmd = (char)Serial.read();
    handleCommand(cmd);
  }
}
