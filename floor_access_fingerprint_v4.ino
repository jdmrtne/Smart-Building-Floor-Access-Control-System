/*
 * ================================================================
 *  ESP32-S3-N16R8  —  RFID Reader + Fingerprint + Raspberry Pi USB
 *  v4: FP exit enforces RFID exit order
 *      FP gate OUT is DENIED unless:
 *        (a) All upper-floor RFID readers show OUT for this person
 *        (b) Floor-1 RFID reader has been tapped OUT (returned to lobby)
 *      Skipping any step → DENIED-ExitOrderViolation → CRITICAL alert on Pi
 *
 *  ACCESS FLOW:
 *    ENTER:  FP scan → fpBuildingInside = true  → door opens
 *            RFID F1 tap → lobby exit (toward stairs)
 *            RFID Fn tap → floor IN
 *    EXIT:   RFID Fn tap → floor OUT
 *            RFID F1 tap → lobby re-enter
 *            FP scan → fpBuildingInside = false → door opens
 *
 *  SECURITY: If a registered RFID card is tapped but the person's FP record
 *            shows they have NOT done FP sign-in, access is DENIED and an
 *            alert fires. The Pi receives result "DENIED-NoFPSignIn" and
 *            logs it as a CRITICAL anomaly (NO FP SIGN-IN).
 *
 *  FP-RFID LINK: Linked by matching name string (case-insensitive).
 *                Enroll both with the EXACT same name.
 *
 * ================================================================
 *
 *  Board: "ESP32S3 Dev Module" in Arduino IDE
 *  Flash: 16MB, PSRAM: OPI PSRAM (8MB)
 *  Required library: Adafruit Fingerprint Sensor Library
 *
 * ================================================================
 *
 *  RFID READERS (MFRC522) — Shared SPI bus, individual SS pins
 *    SCK  → GPIO 36
 *    MISO → GPIO 37
 *    MOSI → GPIO 35
 *    RST  → GPIO 8  (shared)
 *    SS1  → GPIO 4  (Floor 1 reader)
 *    SS2  → GPIO 5  (Floor 2 reader)
 *    SS3  → GPIO 6  (Floor 3 reader)
 *    SS4  → GPIO 7  (Floor 4 reader)
 *    SS5  → GPIO 15 (5th reader, unused in floor logic)
 *
 *  FINGERPRINT SENSOR (R307S)
 *    Red   → 5V
 *    Black → GND
 *    Yellow (TX) → GPIO 16 (ESP32 RX2)
 *    Green  (RX) → GPIO 19 (ESP32 TX2)
 *    White (Wakeup/Touch IRQ) → GPIO 20
 *    Blue  (3.3V out) → Leave unconnected
 *
 *  UART TO ARDUINO NANO
 *    ESP32-S3 TX1 (GPIO 17) → Nano RX (D0)
 *    ESP32-S3 RX1 (GPIO 18) ← Nano TX (D1) — via 1kΩ resistor
 *    GND                    ↔ GND (common ground REQUIRED)
 *
 *  USB TO RASPBERRY PI
 *    ESP32-S3 USB (Serial/Serial0) ↔ Raspberry Pi USB port
 *    Baud: 115200
 *
 * ================================================================
 *  PI → ESP32 COMMANDS  (newline-terminated text):
 *
 *    MODE:0               Normal operation
 *    MODE:1               Auto Enroll  (scan → auto-save to that floor)
 *    MODE:2               Manual Enroll (scan → capture UID, assign via ADD)
 *
 *    ADD:<uid>,<floor>,<n>   Add or update a card
 *    DEL:<uid>               Delete a card by UID
 *    LIST_CARDS              Reply with JSON array of all cards
 *
 *    SENSOR:<floor>,<0|1>       Disable (0) or enable (1) a reader
 *    LIGHT:<floor>,<normal|alert>   Manual light override
 *    LIGHT_RELEASE:<floor>          Release manual light lock
 *
 *    TIME:<epoch>               Set software RTC (Unix seconds)
 *    GET_LOG                    Reply with JSON array of access log entries
 *    CLEAR_LOG                  Clear access log
 *    RESET_PRESENCE:<uid>,<floor>,<inside>
 *
 *    FP_ENROLL:<id>,<floor>,<name>   Start fingerprint enrollment (id 1–127)
 *    FP_DELETE:<id>                  Delete fingerprint by ID
 *    FP_LIST                         Reply with JSON array of fingerprint records
 *    FP_CLEAR                        Erase all fingerprints from sensor
 *    FP_CANCEL                       Cancel ongoing enrollment
 *
 * ================================================================
 *  ESP32 → PI EVENTS  (newline-terminated JSON):
 *
 *    {"event":"scan","floor":1,"uid":"AA BB CC DD","result":"GRANTED",
 *     "name":"Juan","dir":"IN","time":"2025-01-01 08:00:00"}
 *
 *    {"event":"fp_scan","floor":2,"uid":"FP:001","fp_id":1,
 *     "confidence":250,"result":"GRANTED","name":"Juan",
 *     "dir":"IN","time":"2025-01-01 08:00:00"}
 *
 *    {"event":"fp_status","status":"ready","count":3}
 *    {"event":"fp_status","status":"finger_detected"}
 *    {"event":"fp_status","status":"no_match"}
 *    {"event":"fp_status","status":"sensor_offline"}
 *    {"event":"fp_status","status":"enroll_place","id":1}
 *    {"event":"fp_status","status":"enroll_remove","id":1}
 *    {"event":"fp_status","status":"enroll_done","id":1,"name":"...","floor":2}
 *    {"event":"fp_status","status":"enroll_failed","msg":"..."}
 *    {"event":"fp_status","status":"enroll_cancelled"}
 *    {"event":"fp_records","data":[{"id":1,"name":"Juan","floor":2},...]}
 *
 *    {"event":"enrolled","uid":"AA BB CC DD","floor":2}
 *    {"event":"captured","uid":"AA BB CC DD"}
 *    {"event":"cards","data":[...]}
 *    {"event":"log","data":[...]}
 *    {"event":"ack","msg":"..."}
 *    {"event":"err","msg":"..."}
 *    {"event":"boot","msg":"Ready"}
 *
 * ================================================================
 *  NANO COMMAND PROTOCOL:
 *    'A'–'D' = Floor 1–4 Normal  (white ON, red OFF, servo OPEN)
 *    'E'–'H' = Floor 1–4 Alert   (white OFF, red ON)
 *    'I'     = All Reset
 *    'J'–'M' = Floor 1–4 Reset   (white ON, red OFF, servo LOCKED)
 *    'N'     = Emergency ON       (all servos OPEN, all lights blink red↔white nonstop)
 *    'O'     = Emergency OFF      (All Reset)
 * ================================================================
 */

#include <SPI.h>
#include <MFRC522.h>
#include <Preferences.h>
#include <Adafruit_Fingerprint.h>

// ── RFID Pins ─────────────────────────────────────────────────
#define SCK_PIN  36
#define MISO_PIN 37
#define MOSI_PIN 35
#define RST_PIN  8
#define SS1 4
#define SS2 5
#define SS3 6
#define SS4 7
#define SS5 15

MFRC522 rfid1(SS1, RST_PIN);
MFRC522 rfid2(SS2, RST_PIN);
MFRC522 rfid3(SS3, RST_PIN);
MFRC522 rfid4(SS4, RST_PIN);
MFRC522 rfid5(SS5, RST_PIN);

MFRC522* readers[]  = { &rfid1, &rfid2, &rfid3, &rfid4, &rfid5 };
const int ssPins[]  = { SS1, SS2, SS3, SS4, SS5 };
const int NUM_READERS = 5;

// ── Fingerprint Sensor Pins ────────────────────────────────────
#define FP_TX_PIN   19    // ESP32 TX → R307S green (RX)
#define FP_RX_PIN   16    // ESP32 RX ← R307S yellow (TX)
#define FP_WAKEUP   20    // R307S white (touch IRQ)
#define FP_BAUD     57600
#define MAX_FP_RECORDS 20

HardwareSerial fpSerial(2);          // UART2
Adafruit_Fingerprint finger(&fpSerial);

bool fpSensorOk = false;

struct FpRecord {
  uint8_t id;
  char    name[32];
  int     floor;
};
FpRecord fpRecords[MAX_FP_RECORDS];
int      fpCount = 0;
// Tracks whether each FP-enrolled person is currently inside the building.
// Index matches fpRecords[]. FP sensor = building entrance gate.
bool     fpBuildingInside[MAX_FP_RECORDS];

// Enrollment state machine (non-blocking)
// 0=idle 1=waiting_first_touch 2=waiting_lift 3=waiting_second_touch
int      fpEnrollState   = 0;
uint8_t  fpEnrollId      = 0;
int      fpEnrollFloor   = 0;
char     fpEnrollName[32] = "";
unsigned long fpEnrollTimeout = 0;
#define FP_ENROLL_TIMEOUT_MS 30000UL

// Active polling state
bool          fpFingerWasPresent = false;   // true while finger is on sensor
unsigned long fpLastMatch        = 0;
unsigned long fpLastPoll         = 0;
#define FP_MATCH_DEBOUNCE_MS 2500UL  // min ms between successful matches
#define FP_POLL_INTERVAL_MS    80UL  // how often to call getImage() when idle

// ── USB Serial (Raspberry Pi) ──────────────────────────────────
#define PI_SERIAL   Serial
#define PI_BAUD     115200

// ── UART to Nano ───────────────────────────────────────────────
#define NANO_SERIAL  Serial1
#define NANO_TX_PIN  17
#define NANO_RX_PIN  18
#define NANO_BAUD    9600

const char cmdNormal[4] = {'A','B','C','D'};
const char cmdAlert[4]  = {'E','F','G','H'};
const char cmdReset[4]  = {'J','K','L','M'};

// ── Card Database ──────────────────────────────────────────────
#define MAX_CARDS 50
struct CardRecord {
  char uid[30];
  char name[32];
  int  floor;
};
CardRecord cards[MAX_CARDS];
int        cardCount = 0;
Preferences prefs;

// ── Floor Status ──────────────────────────────────────────────
#define ALERT_DURATION_MS 5000
#define GRANT_DURATION_MS 5000

struct FloorStatus {
  String        lastUID;
  String        lastResult;
  bool          alertActive;
  unsigned long alertStartTime;
  bool          grantActive;
  unsigned long grantStartTime;
};
FloorStatus floorStatus[4];

// ── Manual Overrides ─────────────────────────────────────────
bool manualLightLock[4] = {false, false, false, false};
bool sensorEnabled[4]   = {true, true, true, true};

// ── Enroll State (RFID) ──────────────────────────────────────
int    enrollMode       = 0;
String manualPendingUID = "";

// ── Software RTC ─────────────────────────────────────────────
unsigned long rtcBaseEpoch   = 0;
unsigned long rtcBaseMsAtSet = 0;
bool          rtcSet         = false;

unsigned long nowEpoch() {
  if (!rtcSet) return 0;
  return rtcBaseEpoch + (millis() - rtcBaseMsAtSet) / 1000UL;
}

void setRTC(unsigned long epoch) {
  rtcBaseEpoch   = epoch;
  rtcBaseMsAtSet = millis();
  rtcSet         = true;
}

String formatEpoch(unsigned long epoch) {
  if (epoch == 0) return "Time not set";
  unsigned long s  = epoch % 60; epoch /= 60;
  unsigned long mn = epoch % 60; epoch /= 60;
  unsigned long h  = epoch % 24; epoch /= 24;
  unsigned long days = epoch;
  unsigned long y = 1970;
  while (true) {
    bool leap = (y%4==0 && (y%100!=0 || y%400==0));
    unsigned long diy = leap ? 366 : 365;
    if (days < diy) break;
    days -= diy; y++;
  }
  const uint8_t dim[] = {31,28,31,30,31,30,31,31,30,31,30,31};
  bool leap = (y%4==0 && (y%100!=0 || y%400==0));
  unsigned long mo = 1;
  for (; mo <= 12; mo++) {
    unsigned long d = dim[mo-1] + (mo==2 && leap ? 1 : 0);
    if (days < d) break;
    days -= d;
  }
  char buf[22];
  snprintf(buf, sizeof(buf), "%04lu-%02lu-%02lu %02lu:%02lu:%02lu",
           y, mo, days+1, h, mn, s);
  return String(buf);
}

// ── Access Log ───────────────────────────────────────────────
#define MAX_LOG_ENTRIES 100
struct LogEntry {
  char uid[30];
  char name[32];
  int  floor;
  bool isEntry;
  bool granted;
  char reason[40];
  unsigned long epochSec;
};
LogEntry accessLog[MAX_LOG_ENTRIES];
int logCount = 0;
int logHead  = 0;

// ── Presence Tracking ────────────────────────────────────────
struct PresenceEntry {
  char uid[30];
  bool insideFloor[4];
};
#define MAX_PRESENCE 50
PresenceEntry presence[MAX_PRESENCE];
int presenceCount = 0;

int findPresence(const String& uid) {
  for (int i = 0; i < presenceCount; i++)
    if (String(presence[i].uid) == uid) return i;
  return -1;
}

// ── Pi Serial Command Buffer ─────────────────────────────────
String piBuffer = "";

// ─────────────────────────────────────────────────────────────
//  JSON Helpers
// ─────────────────────────────────────────────────────────────
String jsonStr(const String& s) {
  String out = "\"";
  for (int i = 0; i < (int)s.length(); i++) {
    char c = s[i];
    if (c == '"')       out += "\\\"";
    else if (c == '\\') out += "\\\\";
    else if (c == '\n') out += "\\n";
    else if (c == '\r') out += "\\r";
    else out += c;
  }
  out += "\"";
  return out;
}

void piSend(const String& json) { PI_SERIAL.println(json); }
void piAck(const String& msg)   { piSend("{\"event\":\"ack\",\"msg\":"  + jsonStr(msg) + "}"); }
void piErr(const String& msg)   { piSend("{\"event\":\"err\",\"msg\":"  + jsonStr(msg) + "}"); }

void fpStatus(const String& status, const String& extra = "") {
  String out = "{\"event\":\"fp_status\",\"status\":" + jsonStr(status);
  if (extra.length() > 0) out += "," + extra;
  out += "}";
  piSend(out);
}

// ─────────────────────────────────────────────────────────────
//  Utilities
// ─────────────────────────────────────────────────────────────
String uidToString(MFRC522* r) {
  String s = "";
  for (byte j = 0; j < r->uid.size; j++) {
    if (j > 0) s += " ";
    if (r->uid.uidByte[j] < 0x10) s += "0";
    s += String(r->uid.uidByte[j], HEX);
  }
  s.toUpperCase();
  return s;
}

String normalizeUID(String uid) {
  uid.trim(); uid.toUpperCase();
  String out = "";
  bool lastWasSpace = false;
  for (int i = 0; i < (int)uid.length(); i++) {
    char c = uid[i];
    if (c == ' ') {
      if (!lastWasSpace && out.length() > 0) { out += ' '; lastWasSpace = true; }
    } else {
      out += c; lastWasSpace = false;
    }
  }
  return out;
}

void sendToNano(char cmd) { NANO_SERIAL.write(cmd); }

// ─────────────────────────────────────────────────────────────
//  Floor Control
// ─────────────────────────────────────────────────────────────
void setFloorNormal(int floor) {
  floorStatus[floor-1].alertActive    = false;
  floorStatus[floor-1].alertStartTime = 0;
  floorStatus[floor-1].grantActive    = true;
  floorStatus[floor-1].grantStartTime = millis();
  sendToNano(cmdNormal[floor-1]);
}

void setFloorRevert(int floor) {
  floorStatus[floor-1].grantActive    = false;
  floorStatus[floor-1].grantStartTime = 0;
  sendToNano(cmdReset[floor-1]);
}

void setFloorAlert(int floor) {
  floorStatus[floor-1].alertActive    = true;
  floorStatus[floor-1].alertStartTime = millis();
  floorStatus[floor-1].grantActive    = false;
  floorStatus[floor-1].grantStartTime = 0;
  sendToNano(cmdAlert[floor-1]);
}

void initAllNormal() {
  sendToNano('I');
  for (int i = 0; i < 4; i++) {
    floorStatus[i].alertActive    = false;
    floorStatus[i].alertStartTime = 0;
    floorStatus[i].grantActive    = false;
    floorStatus[i].grantStartTime = 0;
  }
}

// ─────────────────────────────────────────────────────────────
//  Card Database
// ─────────────────────────────────────────────────────────────
int findCard(const String& uid) {
  String normUid = uid; normUid.trim(); normUid.toUpperCase();
  for (int i = 0; i < cardCount; i++) {
    String stored = String(cards[i].uid); stored.trim(); stored.toUpperCase();
    if (stored == normUid) return i;
  }
  return -1;
}

void saveCards() {
  prefs.begin("cards", false);
  prefs.putInt("count", cardCount);
  for (int i = 0; i < cardCount; i++) {
    prefs.putString(("uid"+String(i)).c_str(), cards[i].uid);
    prefs.putInt(("fl"+String(i)).c_str(), cards[i].floor);
    prefs.putString(("nm"+String(i)).c_str(), cards[i].name);
  }
  prefs.end();
}

void loadCards() {
  prefs.begin("cards", true);
  cardCount = prefs.getInt("count", 0);
  for (int i = 0; i < cardCount; i++) {
    String u = prefs.getString(("uid"+String(i)).c_str(), "");
    u.toCharArray(cards[i].uid, 30);
    cards[i].floor = prefs.getInt(("fl"+String(i)).c_str(), 0);
    String n = prefs.getString(("nm"+String(i)).c_str(), "");
    n.toCharArray(cards[i].name, 32);
  }
  prefs.end();
}

bool addOrUpdateCard(const String& uid, int floor, const String& name = "") {
  int idx = findCard(uid);
  if (idx >= 0) {
    cards[idx].floor = floor;
    if (name.length() > 0) name.toCharArray(cards[idx].name, 32);
    saveCards();
    return true;
  }
  if (cardCount >= MAX_CARDS) return false;
  uid.toCharArray(cards[cardCount].uid, 30);
  cards[cardCount].floor = floor;
  name.toCharArray(cards[cardCount].name, 32);
  cardCount++;
  saveCards();
  return true;
}

void deleteCard(const String& uid) {
  int idx = findCard(uid);
  if (idx < 0) return;
  for (int i = idx; i < cardCount-1; i++) cards[i] = cards[i+1];
  cardCount--;
  saveCards();
}

// ─────────────────────────────────────────────────────────────
//  Fingerprint Record Database (NVS)
// ─────────────────────────────────────────────────────────────
int findFpRecord(uint8_t id) {
  for (int i = 0; i < fpCount; i++)
    if (fpRecords[i].id == id) return i;
  return -1;
}

void saveFpRecords() {
  prefs.begin("fprec", false);
  prefs.putInt("count", fpCount);
  for (int i = 0; i < fpCount; i++) {
    prefs.putUChar(("fi"+String(i)).c_str(), fpRecords[i].id);
    prefs.putInt(("ff"+String(i)).c_str(), fpRecords[i].floor);
    prefs.putString(("fn"+String(i)).c_str(), fpRecords[i].name);
  }
  prefs.end();
}

void loadFpRecords() {
  prefs.begin("fprec", true);
  fpCount = prefs.getInt("count", 0);
  if (fpCount > MAX_FP_RECORDS) fpCount = MAX_FP_RECORDS;
  for (int i = 0; i < fpCount; i++) {
    fpRecords[i].id    = prefs.getUChar(("fi"+String(i)).c_str(), 0);
    fpRecords[i].floor = prefs.getInt(("ff"+String(i)).c_str(), 1);
    String n = prefs.getString(("fn"+String(i)).c_str(), "");
    n.toCharArray(fpRecords[i].name, 32);
  }
  prefs.end();
}

bool addOrUpdateFpRecord(uint8_t id, int floor, const String& name) {
  int idx = findFpRecord(id);
  if (idx >= 0) {
    fpRecords[idx].floor = floor;
    name.toCharArray(fpRecords[idx].name, 32);
    saveFpRecords();
    return true;
  }
  if (fpCount >= MAX_FP_RECORDS) return false;
  fpRecords[fpCount].id    = id;
  fpRecords[fpCount].floor = floor;
  name.toCharArray(fpRecords[fpCount].name, 32);
  fpCount++;
  saveFpRecords();
  return true;
}

void deleteFpRecord(uint8_t id) {
  int idx = findFpRecord(id);
  if (idx < 0) return;
  for (int i = idx; i < fpCount-1; i++) fpRecords[i] = fpRecords[i+1];
  fpCount--;
  saveFpRecords();
}

// ─────────────────────────────────────────────────────────────
//  Access Log
// ─────────────────────────────────────────────────────────────
String addLog(const String& uid, const String& ownerName, int floor,
              bool granted, const char* reason) {
  String dir = "";
  if (granted) {
    int floorIdx = floor - 1;
    int p = findPresence(uid);
    if (p < 0 && presenceCount < MAX_PRESENCE) {
      uid.toCharArray(presence[presenceCount].uid, 30);
      memset(presence[presenceCount].insideFloor, 0, 4);
      p = presenceCount++;
    }
    if (p >= 0) {
      bool nowInside = !presence[p].insideFloor[floorIdx];
      presence[p].insideFloor[floorIdx] = nowInside;
      dir = nowInside ? "IN" : "OUT";
    }
  }
  int slot = logHead % MAX_LOG_ENTRIES;
  uid.toCharArray(accessLog[slot].uid, 30);
  ownerName.toCharArray(accessLog[slot].name, 32);
  accessLog[slot].floor   = floor;
  // FIX: denied scans are always attempted entries — dir was "" so isEntry was
  // always false (OUT) for denied scans, making GET_LOG send "OUT" for them.
  // Use the toggle direction for granted, or true (IN) for all denied attempts.
  accessLog[slot].isEntry = granted ? (dir == "IN") : true;
  accessLog[slot].granted = granted;
  strncpy(accessLog[slot].reason, reason, 39);
  accessLog[slot].reason[39] = '\0';
  accessLog[slot].epochSec = nowEpoch();
  logHead = (logHead + 1) % MAX_LOG_ENTRIES;
  if (logCount < MAX_LOG_ENTRIES) logCount++;
  return dir;
}

// ─────────────────────────────────────────────────────────────
//  Scan Handler  (RFID)
// ─────────────────────────────────────────────────────────────
void handleScan(int readerIndex, const String& uid) {
  if (readerIndex >= 4) return;
  int floor = readerIndex + 1;

  if (!sensorEnabled[readerIndex]) return;

  floorStatus[readerIndex].lastUID = uid;

  if (enrollMode == 1) {
    addOrUpdateCard(uid, floor);
    floorStatus[readerIndex].lastResult = "AUTO-ENROLLED → Floor " + String(floor);
    piSend("{\"event\":\"enrolled\",\"uid\":" + jsonStr(uid) +
           ",\"floor\":" + String(floor) + "}");
    return;
  }

  if (enrollMode == 2) {
    manualPendingUID = uid;
    floorStatus[readerIndex].lastResult = "CAPTURED";
    piSend("{\"event\":\"captured\",\"uid\":" + jsonStr(uid) + "}");
    return;
  }

  int idx = findCard(uid);
  String ownerName = (idx >= 0 && strlen(cards[idx].name) > 0)
                     ? String(cards[idx].name) : "Unknown";
  String result, dir;
  bool granted = false;

  if (idx < 0 || cards[idx].floor == 0) {
    setFloorAlert(floor);
    result = "DENIED-Unregistered";
    dir    = "IN";   // FIX: denied scans never set dir; always "IN" for entry attempts
    floorStatus[readerIndex].lastResult = "DENIED — Unregistered Card";
    addLog(uid, ownerName, floor, false, "DENIED-Unregistered");
  } else {
    // ── CRITICAL SECURITY CHECK: FP sign-in required ────────
    // Every registered card must have a fingerprint record with the same name.
    // If the FP record exists but the person has NOT done FP sign-in at the
    // building entrance, deny RFID access and flag as unusual activity.
    bool hasFpRecord    = false;
    bool fpSignedIn     = false;
    for (int fi = 0; fi < fpCount; fi++) {
      if (strcasecmp(fpRecords[fi].name, cards[idx].name) == 0) {
        hasFpRecord = true;
        fpSignedIn  = fpBuildingInside[fi];
        break;
      }
    }
    if (hasFpRecord && !fpSignedIn) {
      // Person has an FP record but hasn't scanned FP at building entrance → CRITICAL
      setFloorAlert(floor);
      result  = "DENIED-NoFPSignIn";
      granted = false;
      floorStatus[readerIndex].lastResult =
          "DENIED — No FP sign-in (" + ownerName + ")";
      addLog(uid, ownerName, floor, false, "DENIED-NoFPSignIn");
      String evt2 = "{\"event\":\"scan\",\"floor\":" + String(floor) +
                    ",\"uid\":" + jsonStr(uid) +
                    ",\"result\":" + jsonStr(result) +
                    ",\"name\":" + jsonStr(ownerName) +
                    ",\"dir\":\"IN\"" +
                    ",\"time\":" + jsonStr(formatEpoch(nowEpoch())) + "}";
      piSend(evt2);
      return;
    }
    // ── Normal floor-access logic ────────────────────────────
    if (cards[idx].floor == floor) {
      setFloorNormal(floor);
      dir = addLog(uid, ownerName, floor, true, "GRANTED");
      result = "GRANTED";
      granted = true;
      floorStatus[readerIndex].lastResult = "GRANTED (" + dir + ") — " + ownerName;
    } else if (floor == 1 && cards[idx].floor >= 2 && cards[idx].floor <= 4) {
      setFloorNormal(floor);
      int assignedFloor = cards[idx].floor;

      int p = findPresence(uid);
      if (p < 0 && presenceCount < MAX_PRESENCE) {
        uid.toCharArray(presence[presenceCount].uid, 30);
        memset(presence[presenceCount].insideFloor, 0, 4);
        p = presenceCount++;
      }

      bool nowInside = false;
      if (p >= 0) {
        nowInside = !presence[p].insideFloor[0];
        presence[p].insideFloor[0] = nowInside;
      }
      dir = nowInside ? "IN" : "OUT";

      String reasonStr = "GRANTED (Floor " + String(assignedFloor) + " card)";
      int slot = logHead % MAX_LOG_ENTRIES;
      uid.toCharArray(accessLog[slot].uid, 30);
      ownerName.toCharArray(accessLog[slot].name, 32);
      accessLog[slot].floor   = 1;
      accessLog[slot].isEntry = nowInside;
      accessLog[slot].granted = true;
      strncpy(accessLog[slot].reason, reasonStr.c_str(), 39);
      accessLog[slot].reason[39] = '\0';
      accessLog[slot].epochSec = nowEpoch();
      logHead = (logHead + 1) % MAX_LOG_ENTRIES;
      if (logCount < MAX_LOG_ENTRIES) logCount++;

      result  = reasonStr;
      granted = true;
      floorStatus[readerIndex].lastResult = "GRANTED (" + dir + ") — " + ownerName
                                          + " [F" + String(assignedFloor) + " card]";
    } else {
      setFloorAlert(floor);
      result = "DENIED-WrongFloor";
      dir    = "IN";   // FIX: denied scans never set dir; always "IN" for entry attempts
      floorStatus[readerIndex].lastResult = "DENIED — Wrong Floor";
      addLog(uid, ownerName, floor, false, result.c_str());
    }
  }  // end outer else (registered card path)

  String evt = "{\"event\":\"scan\",\"floor\":" + String(floor) +
               ",\"uid\":" + jsonStr(uid) +
               ",\"result\":" + jsonStr(result) +
               ",\"name\":" + jsonStr(ownerName) +
               ",\"dir\":" + jsonStr(dir) +
               ",\"time\":" + jsonStr(formatEpoch(nowEpoch())) + "}";
  piSend(evt);
}
// ─────────────────────────────────────────────────────────────
//  Fingerprint Match Handler  — BUILDING GATE
//
//  The R307S fingerprint sensor is the building entrance gate.
//  It is NOT a floor reader. Floor=0 in the event means "building gate".
//
//  ENTRY SEQUENCE:
//    FP IN  → fpBuildingInside = true  → building door opens (Floor-1 output)
//    RFID F1 tap  → lobby exit toward upper floor
//    RFID Fn tap  → floor IN
//  EXIT SEQUENCE (reverse):
//    RFID Fn tap  → floor OUT
//    RFID F1 tap  → lobby re-entry
//    FP OUT → fpBuildingInside = false → building door opens
// ─────────────────────────────────────────────────────────────
void handleFpMatch(uint8_t fpId, uint16_t confidence) {
  char uidBuf[16];
  snprintf(uidBuf, sizeof(uidBuf), "FP:%03d", fpId);
  String uid = String(uidBuf);

  int recIdx = findFpRecord(fpId);
  if (recIdx < 0) {
    fpStatus("no_match", "\"reason\":\"FP ID not in database\"");
    return;
  }

  String ownerName = String(fpRecords[recIdx].name);
  if (ownerName.length() == 0) ownerName = uid;

  // Determine what direction this tap would be
  bool wouldBeInside = !fpBuildingInside[recIdx];   // true = entering, false = exiting
  String dir = wouldBeInside ? "IN" : "OUT";

  // ═══════════════════════════════════════════════════════════
  //  EXIT ORDER ENFORCEMENT
  //  Before the gate opens for EXIT, verify the person has
  //  completed the full RFID exit sequence:
  //    1. Tapped out of their assigned floor (insideFloor[n-1] = false)
  //    2. Tapped out through Floor-1 reader (insideFloor[0]   = false)
  //
  //  If they skipped any RFID tap → DENY, alert, send CRITICAL event.
  //  Exception: if no presence record exists they never used any RFID
  //             reader after FP entry (still in outer lobby) → allow exit.
  // ═══════════════════════════════════════════════════════════
  if (!wouldBeInside && fpBuildingInside[recIdx]) {

    // Find their linked RFID card by name match
    int cardIdx = -1;
    for (int ci = 0; ci < cardCount; ci++) {
      if (strcasecmp(cards[ci].name, ownerName.c_str()) == 0) {
        cardIdx = ci;
        break;
      }
    }

    if (cardIdx >= 0) {
      String rfidUid = normalizeUID(String(cards[cardIdx].uid));
      int presIdx    = findPresence(rfidUid);

      if (presIdx >= 0) {
        // Check upper floors first (floors 2-4 = indices 1-3)
        String stuckFloor = "";
        for (int f = 1; f <= 3; f++) {
          if (presence[presIdx].insideFloor[f]) {
            stuckFloor = "Floor " + String(f + 1);
            break;
          }
        }

        // Check Floor-1 RFID reader (index 0)
        bool notSignedOutF1 = presence[presIdx].insideFloor[0];

        if (stuckFloor.length() > 0 || notSignedOutF1) {
          // ── DENY FP EXIT ──────────────────────────────────
          String reason = stuckFloor.length() > 0
            ? "Still checked into " + stuckFloor + " — exit that floor first"
            : "Must tap Floor-1 RFID reader before exiting building";

          setFloorAlert(1);   // flash alert on building entrance
          floorStatus[0].lastUID    = uid;
          floorStatus[0].lastResult = "FP EXIT DENIED — " + ownerName;

          // Log the denial
          int slot = logHead % MAX_LOG_ENTRIES;
          uid.toCharArray(accessLog[slot].uid, 30);
          ownerName.toCharArray(accessLog[slot].name, 32);
          accessLog[slot].floor    = 0;
          accessLog[slot].isEntry  = false;
          accessLog[slot].granted  = false;
          strncpy(accessLog[slot].reason, "DENIED-ExitOrderViolation", 39);
          accessLog[slot].epochSec = nowEpoch();
          logHead = (logHead + 1) % MAX_LOG_ENTRIES;
          if (logCount < MAX_LOG_ENTRIES) logCount++;

          // Send CRITICAL event to Pi
          String evt = "{\"event\":\"fp_scan\",\"floor\":0"
                       ",\"uid\":" + jsonStr(uid) +
                       ",\"fp_id\":" + String(fpId) +
                       ",\"confidence\":" + String(confidence) +
                       ",\"result\":\"DENIED-ExitOrderViolation\"" +
                       ",\"name\":" + jsonStr(ownerName) +
                       ",\"dir\":\"OUT\"" +
                       ",\"gate\":true" +
                       ",\"deny_reason\":" + jsonStr(reason) +
                       ",\"time\":" + jsonStr(formatEpoch(nowEpoch())) + "}";
          piSend(evt);
          return;   // gate stays LOCKED
        }
        // All RFID checks passed — fall through to grant
      }
      // No presence record → person in outer lobby only, allow exit
    }
    // No RFID card found → can't check, allow exit (FP-only edge case)
  }

  // ── GRANT: toggle building state and open gate ─────────────
  fpBuildingInside[recIdx] = wouldBeInside;

  setFloorNormal(1);    // open building entrance door

  // Log granted gate event (floor=0)
  int slot = logHead % MAX_LOG_ENTRIES;
  uid.toCharArray(accessLog[slot].uid, 30);
  ownerName.toCharArray(accessLog[slot].name, 32);
  accessLog[slot].floor    = 0;
  accessLog[slot].isEntry  = wouldBeInside;
  accessLog[slot].granted  = true;
  strncpy(accessLog[slot].reason,
          wouldBeInside ? "FP-BUILDING-IN" : "FP-BUILDING-OUT", 39);
  accessLog[slot].epochSec = nowEpoch();
  logHead = (logHead + 1) % MAX_LOG_ENTRIES;
  if (logCount < MAX_LOG_ENTRIES) logCount++;

  floorStatus[0].lastUID    = uid;
  floorStatus[0].lastResult = "FP GATE " + dir + " — " + ownerName;

  String evt = "{\"event\":\"fp_scan\",\"floor\":0"
               ",\"uid\":" + jsonStr(uid) +
               ",\"fp_id\":" + String(fpId) +
               ",\"confidence\":" + String(confidence) +
               ",\"result\":\"GRANTED\"" +
               ",\"name\":" + jsonStr(ownerName) +
               ",\"dir\":" + jsonStr(dir) +
               ",\"gate\":true" +
               ",\"time\":" + jsonStr(formatEpoch(nowEpoch())) + "}";
  piSend(evt);
}

// tryFingerprintMatch() removed — logic now inlined in loop() as active polling.

// ─────────────────────────────────────────────────────────────
//  Fingerprint Enrollment — Non-blocking State Machine
//  Called every loop() iteration when fpEnrollState != 0.
// ─────────────────────────────────────────────────────────────
void handleFpEnrollStep() {
  if (!fpSensorOk) {
    fpStatus("enroll_failed", "\"msg\":\"Sensor offline\"");
    fpEnrollState = 0;
    return;
  }

  // Global timeout check
  if (millis() - fpEnrollTimeout > FP_ENROLL_TIMEOUT_MS) {
    fpStatus("enroll_failed", "\"msg\":\"Timeout waiting for finger\"");
    fpEnrollState = 0;
    return;
  }

  uint8_t r;

  if (fpEnrollState == 1) {
    // ── Waiting for first finger placement ─────────────────
    r = finger.getImage();
    if (r == FINGERPRINT_NOFINGER) return;   // still waiting — non-blocking
    if (r != FINGERPRINT_OK) {
      fpStatus("enroll_failed", "\"msg\":\"Image capture failed (step 1)\"");
      fpEnrollState = 0;
      return;
    }
    r = finger.image2Tz(1);
    if (r != FINGERPRINT_OK) {
      fpStatus("enroll_failed", "\"msg\":\"Image conversion failed (step 1)\"");
      fpEnrollState = 0;
      return;
    }
    fpEnrollState = 2;
    fpStatus("enroll_remove", "\"id\":" + String(fpEnrollId));
    fpEnrollTimeout = millis();  // reset timeout for next step

  } else if (fpEnrollState == 2) {
    // ── Waiting for finger lift ────────────────────────────
    r = finger.getImage();
    if (r == FINGERPRINT_NOFINGER) {
      // Finger lifted — proceed to second scan
      fpEnrollState = 3;
      fpEnrollTimeout = millis();
    }
    // Otherwise still touching — keep waiting

  } else if (fpEnrollState == 3) {
    // ── Waiting for second finger placement ────────────────
    r = finger.getImage();
    if (r == FINGERPRINT_NOFINGER) return;   // still waiting
    if (r != FINGERPRINT_OK) {
      fpStatus("enroll_failed", "\"msg\":\"Image capture failed (step 2)\"");
      fpEnrollState = 0;
      return;
    }
    r = finger.image2Tz(2);
    if (r != FINGERPRINT_OK) {
      fpStatus("enroll_failed", "\"msg\":\"Image conversion failed (step 2)\"");
      fpEnrollState = 0;
      return;
    }
    r = finger.createModel();
    if (r != FINGERPRINT_OK) {
      fpStatus("enroll_failed", "\"msg\":\"Fingerprints did not match — try again\"");
      fpEnrollState = 0;
      return;
    }
    r = finger.storeModel(fpEnrollId);
    if (r != FINGERPRINT_OK) {
      fpStatus("enroll_failed", "\"msg\":\"Failed to store fingerprint in sensor\"");
      fpEnrollState = 0;
      return;
    }

    // Save record to NVS
    addOrUpdateFpRecord(fpEnrollId, fpEnrollFloor, String(fpEnrollName));

    fpStatus("enroll_done",
             "\"id\":" + String(fpEnrollId) +
             ",\"name\":" + jsonStr(String(fpEnrollName)) +
             ",\"floor\":" + String(fpEnrollFloor));
    fpEnrollState = 0;
  }
}

// ─────────────────────────────────────────────────────────────
//  Timer Checks (RFID)
// ─────────────────────────────────────────────────────────────
void checkAlertTimers() {
  unsigned long now = millis();
  for (int i = 0; i < 4; i++) {
    if (floorStatus[i].alertActive && floorStatus[i].alertStartTime > 0) {
      if (manualLightLock[i]) continue;
      if (now - floorStatus[i].alertStartTime >= ALERT_DURATION_MS) {
        floorStatus[i].alertActive    = false;
        floorStatus[i].alertStartTime = 0;
        sendToNano(cmdReset[i]);
      }
    }
    if (floorStatus[i].grantActive && floorStatus[i].grantStartTime > 0) {
      if (now - floorStatus[i].grantStartTime >= GRANT_DURATION_MS) {
        setFloorRevert(i+1);
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────
//  Pi Command Dispatcher
// ─────────────────────────────────────────────────────────────
void handlePiCommand(const String& raw) {
  String line = raw;
  line.trim();
  if (line.length() == 0) return;

  // ── MODE ──────────────────────────────────────────────────
  if (line.startsWith("MODE:")) {
    int m = line.substring(5).toInt();
    if (m < 0 || m > 2) { piErr("Invalid mode (0-2)"); return; }
    enrollMode = m;
    const char* modeNames[] = {"Normal","AutoEnroll","ManualEnroll"};
    piAck(String("Mode set to ") + modeNames[m]);

  // ── ADD ───────────────────────────────────────────────────
  } else if (line.startsWith("ADD:")) {
    String rest = line.substring(4);
    int lastComma = rest.lastIndexOf(',');
    if (lastComma < 0) { piErr("ADD format: ADD:<uid>,<floor>,<n>"); return; }
    String name = rest.substring(lastComma + 1); name.trim();
    String left = rest.substring(0, lastComma);
    int midComma = left.lastIndexOf(',');
    if (midComma < 0) { piErr("ADD format: ADD:<uid>,<floor>,<n>"); return; }
    int floor = left.substring(midComma + 1).toInt();
    String uid = normalizeUID(left.substring(0, midComma));
    if (floor < 1 || floor > 4) { piErr("Floor must be 1-4"); return; }
    if (uid.length() == 0) { piErr("Empty UID"); return; }
    bool ok = addOrUpdateCard(uid, floor, name);
    if (ok) piAck("Card saved: " + uid + " Floor " + String(floor) + " " + name);
    else    piErr("Card database full (max 50)");

  // ── DEL ───────────────────────────────────────────────────
  } else if (line.startsWith("DEL:")) {
    String uid = normalizeUID(line.substring(4));
    int idx = findCard(uid);
    if (idx < 0) { piErr("Card not found: " + uid); return; }
    deleteCard(uid);
    piAck("Deleted: " + uid);

  // ── LIST_CARDS ────────────────────────────────────────────
  } else if (line == "LIST_CARDS") {
    String out = "{\"event\":\"cards\",\"data\":[";
    for (int i = 0; i < cardCount; i++) {
      if (i > 0) out += ",";
      out += "{\"uid\":" + jsonStr(String(cards[i].uid)) +
             ",\"name\":" + jsonStr(String(cards[i].name)) +
             ",\"floor\":" + String(cards[i].floor) + "}";
    }
    out += "]}";
    piSend(out);

  // ── SENSOR ────────────────────────────────────────────────
  } else if (line.startsWith("SENSOR:")) {
    String rest = line.substring(7);
    int comma = rest.indexOf(',');
    if (comma < 0) { piErr("SENSOR format: SENSOR:<floor>,<0|1>"); return; }
    int floor = rest.substring(0, comma).toInt();
    bool en   = rest.substring(comma + 1).toInt() != 0;
    if (floor < 1 || floor > 4) { piErr("Floor 1-4 only"); return; }
    sensorEnabled[floor - 1] = en;
    piAck("Floor " + String(floor) + " sensor " + (en ? "ENABLED" : "DISABLED"));

  // ── LIGHT ─────────────────────────────────────────────────
  } else if (line.startsWith("LIGHT:")) {
    String rest = line.substring(6);
    int comma = rest.indexOf(',');
    if (comma < 0) { piErr("LIGHT format: LIGHT:<floor>,<normal|alert>"); return; }
    int floor = rest.substring(0, comma).toInt();
    String state = rest.substring(comma + 1); state.trim();
    if (floor < 1 || floor > 4) { piErr("Floor 1-4 only"); return; }
    manualLightLock[floor - 1] = true;
    if (state == "normal") {
      sendToNano(cmdNormal[floor - 1]);
      floorStatus[floor-1].alertActive = false;
      piAck("Floor " + String(floor) + " White ON (manual)");
    } else if (state == "alert") {
      floorStatus[floor-1].alertActive    = true;
      floorStatus[floor-1].alertStartTime = 0;
      sendToNano(cmdAlert[floor - 1]);
      piAck("Floor " + String(floor) + " Red ON (manual)");
    } else {
      piErr("State must be 'normal' or 'alert'");
    }

  // ── LIGHT_RELEASE ─────────────────────────────────────────
  } else if (line.startsWith("LIGHT_RELEASE:")) {
    int floor = line.substring(14).toInt();
    if (floor < 1 || floor > 4) { piErr("Floor 1-4 only"); return; }
    manualLightLock[floor - 1] = false;
    sendToNano(cmdReset[floor - 1]);
    floorStatus[floor-1].alertActive = false;
    piAck("Floor " + String(floor) + " manual lock released");

  // ── TIME ──────────────────────────────────────────────────
  } else if (line.startsWith("TIME:")) {
    unsigned long epoch = strtoul(line.substring(5).c_str(), nullptr, 10);
    if (epoch < 1000000000UL) { piErr("Invalid epoch"); return; }
    setRTC(epoch);
    piAck("RTC set: " + formatEpoch(epoch));

  // ── GET_LOG ───────────────────────────────────────────────
  } else if (line == "GET_LOG") {
    String out = "{\"event\":\"log\",\"data\":[";
    int count = min(logCount, MAX_LOG_ENTRIES);
    bool first = true;
    int start = (logCount >= MAX_LOG_ENTRIES) ? logHead : 0;
    for (int n = 0; n < count; n++) {
      int slot = (start + n) % MAX_LOG_ENTRIES;
      if (!first) out += ",";
      first = false;
      out += "{\"uid\":" + jsonStr(String(accessLog[slot].uid)) +
             ",\"name\":" + jsonStr(String(accessLog[slot].name)) +
             ",\"floor\":" + String(accessLog[slot].floor) +
             ",\"granted\":" + (accessLog[slot].granted ? "true" : "false") +
             ",\"dir\":" + jsonStr(accessLog[slot].isEntry ? "IN" : "OUT") +
             ",\"reason\":" + jsonStr(String(accessLog[slot].reason)) +
             ",\"time\":" + jsonStr(formatEpoch(accessLog[slot].epochSec)) + "}";
    }
    out += "]}";
    piSend(out);

  // ── CLEAR_LOG ─────────────────────────────────────────────
  } else if (line == "CLEAR_LOG") {
    logCount = 0; logHead = 0; presenceCount = 0;
    piAck("Access log cleared");

  // ── RESET_PRESENCE ────────────────────────────────────────
  } else if (line.startsWith("RESET_PRESENCE:")) {
    String rest = line.substring(15);
    int lastComma = rest.lastIndexOf(',');
    if (lastComma < 0) { piErr("RESET_PRESENCE format error"); return; }
    int insideVal = rest.substring(lastComma + 1).toInt();
    String left2 = rest.substring(0, lastComma);
    int midComma = left2.lastIndexOf(',');
    if (midComma < 0) { piErr("RESET_PRESENCE format error"); return; }
    int floorNum = left2.substring(midComma + 1).toInt();
    String uid2  = normalizeUID(left2.substring(0, midComma));
    if (floorNum < 1 || floorNum > 4) { piErr("Floor must be 1-4"); return; }
    int bitIdx = floorNum - 1;
    int p = findPresence(uid2);
    if (p < 0) {
      if (presenceCount < MAX_PRESENCE) {
        uid2.toCharArray(presence[presenceCount].uid, 30);
        memset(presence[presenceCount].insideFloor, 0, 4);
        p = presenceCount++;
      }
    }
    if (p >= 0) {
      presence[p].insideFloor[bitIdx] = (insideVal != 0);
      piAck("Presence reset: " + uid2 + " F" + String(floorNum) +
            " -> " + (insideVal ? "INSIDE" : "OUTSIDE"));
    } else {
      piErr("Presence table full");
    }

  // ── FP_ENROLL ─────────────────────────────────────────────
  // Format: FP_ENROLL:<id>,<floor>,<name>
  } else if (line.startsWith("FP_ENROLL:")) {
    if (!fpSensorOk) { piErr("Fingerprint sensor offline"); return; }
    if (fpEnrollState != 0) { piErr("Enrollment already in progress — FP_CANCEL first"); return; }
    String rest = line.substring(10);
    int c1 = rest.indexOf(',');
    if (c1 < 0) { piErr("FP_ENROLL format: FP_ENROLL:<id>,<floor>,<name>"); return; }
    int c2 = rest.indexOf(',', c1 + 1);
    if (c2 < 0) { piErr("FP_ENROLL format: FP_ENROLL:<id>,<floor>,<name>"); return; }
    uint8_t id  = (uint8_t)rest.substring(0, c1).toInt();
    int     fl  = rest.substring(c1 + 1, c2).toInt();
    String  nm  = rest.substring(c2 + 1); nm.trim();
    if (id < 1 || id > 127) { piErr("FP ID must be 1–127"); return; }
    if (fl < 1 || fl > 4)   { piErr("Floor must be 1-4");   return; }
    fpEnrollId    = id;
    fpEnrollFloor = fl;
    nm.toCharArray(fpEnrollName, 32);
    fpEnrollState   = 1;
    fpEnrollTimeout = millis();
    fpStatus("enroll_place", "\"id\":" + String(id));
    piAck("FP enrollment started — ID:" + String(id) + " Floor:" + String(fl) + " (" + nm + ")");

  // ── FP_CANCEL ─────────────────────────────────────────────
  } else if (line == "FP_CANCEL") {
    if (fpEnrollState == 0) { piAck("No enrollment in progress"); return; }
    fpEnrollState = 0;
    fpStatus("enroll_cancelled");
    piAck("Fingerprint enrollment cancelled");

  // ── FP_DELETE ─────────────────────────────────────────────
  } else if (line.startsWith("FP_DELETE:")) {
    if (!fpSensorOk) { piErr("Fingerprint sensor offline"); return; }
    uint8_t id = (uint8_t)line.substring(10).toInt();
    if (id < 1 || id > 127) { piErr("FP ID must be 1–127"); return; }
    uint8_t r = finger.deleteModel(id);
    if (r == FINGERPRINT_OK) {
      deleteFpRecord(id);
      piAck("Fingerprint deleted: ID " + String(id));
    } else {
      piErr("Failed to delete FP ID " + String(id) + " from sensor");
    }

  // ── FP_LIST ───────────────────────────────────────────────
  } else if (line == "FP_LIST") {
    String out = "{\"event\":\"fp_records\",\"data\":[";
    for (int i = 0; i < fpCount; i++) {
      if (i > 0) out += ",";
      out += "{\"id\":" + String(fpRecords[i].id) +
             ",\"name\":" + jsonStr(String(fpRecords[i].name)) +
             ",\"floor\":" + String(fpRecords[i].floor) + "}";
    }
    out += "],\"sensor_ok\":" + String(fpSensorOk ? "true" : "false") +
           ",\"sensor_count\":" + String(fpSensorOk ? finger.templateCount : 0) + "}";
    piSend(out);

  // ── FP_CLEAR ──────────────────────────────────────────────
  } else if (line == "FP_CLEAR") {
    if (!fpSensorOk) { piErr("Fingerprint sensor offline"); return; }
    uint8_t r = finger.emptyDatabase();
    if (r == FINGERPRINT_OK) {
      fpCount = 0;
      saveFpRecords();
      piAck("All fingerprints cleared from sensor and database");
    } else {
      piErr("Failed to clear fingerprint sensor database");
    }

  // ── GRANT_FLOOR ───────────────────────────────────────────
  // Format: GRANT_FLOOR:<floor>
  // Sent by the Pi when Python-side logic (e.g. approved temp access)
  // overrides a DENIED-WrongFloor decision made by the ESP32.
  // Calls setFloorNormal() which opens the door for GRANT_DURATION_MS (5s)
  // and then auto-reverts — identical to a normal RFID grant.
  } else if (line.startsWith("GRANT_FLOOR:")) {
    int fl = line.substring(12).toInt();
    if (fl < 1 || fl > 4) { piErr("GRANT_FLOOR floor must be 1-4"); return; }
    setFloorNormal(fl);
    piAck("GRANT_FLOOR: Floor " + String(fl) + " door opened by Pi override");

  // ── EMERGENCY:ON ──────────────────────────────────────────
  // Activate emergency mode: blink all lights red↔white, unlock all doors.
  // The Nano handles the blinking loop autonomously once command 'N' is sent.
  } else if (line == "EMERGENCY:ON") {
    sendToNano('N');
    piAck("EMERGENCY MODE ON — all lights blinking, all doors unlocked");

  // ── EMERGENCY:OFF ─────────────────────────────────────────
  } else if (line == "EMERGENCY:OFF") {
    sendToNano('O');
    // Re-initialise ESP32 floor state to match Nano 'O' (all reset)
    initAllNormal();
    piAck("EMERGENCY MODE OFF — system restored to normal");

  } else {
    piErr("Unknown command: " + line);
  }
}

// ─────────────────────────────────────────────────────────────
//  Read Pi Serial (non-blocking, line-buffered)
// ─────────────────────────────────────────────────────────────
void readPiSerial() {
  while (PI_SERIAL.available()) {
    char c = (char)PI_SERIAL.read();
    if (c == '\n' || c == '\r') {
      if (piBuffer.length() > 0) {
        handlePiCommand(piBuffer);
        piBuffer = "";
      }
    } else {
      if (piBuffer.length() < 256) piBuffer += c;
    }
  }
}

// ─────────────────────────────────────────────────────────────
//  Setup
// ─────────────────────────────────────────────────────────────
void setup() {
  // USB Serial ↔ Raspberry Pi (also visible in Arduino Serial Monitor)
  PI_SERIAL.begin(PI_BAUD);
  delay(200);

  // UART to Nano
  NANO_SERIAL.begin(NANO_BAUD, SERIAL_8N1, NANO_RX_PIN, NANO_TX_PIN);
  delay(500);
  initAllNormal();

  // RFID SPI bus
  for (int i = 0; i < NUM_READERS; i++) {
    pinMode(ssPins[i], OUTPUT);
    digitalWrite(ssPins[i], HIGH);
  }
  SPI.begin(SCK_PIN, MISO_PIN, MOSI_PIN);
  for (int i = 0; i < NUM_READERS; i++) {
    readers[i]->PCD_Init();
    delay(50);
  }

  // Fingerprint sensor — active polling mode (no wakeup pin required)
  fpSerial.begin(FP_BAUD, SERIAL_8N1, FP_RX_PIN, FP_TX_PIN);
  finger.begin(FP_BAUD);
  delay(200);

  if (finger.verifyPassword()) {
    fpSensorOk = true;
    finger.getTemplateCount();
    PI_SERIAL.println("[FP] Sensor OK — " + String(finger.templateCount) + " templates stored");
  } else {
    fpSensorOk = false;
    PI_SERIAL.println("[FP] Sensor not found — check wiring");
  }

  // Load databases from NVS
  loadCards();
  loadFpRecords();
  memset(fpBuildingInside, 0, sizeof(fpBuildingInside));  // everyone starts outside

  // Normalize stored UIDs
  for (int i = 0; i < cardCount; i++) {
    String u = normalizeUID(String(cards[i].uid));
    u.toCharArray(cards[i].uid, 30);
  }

  // Boot event to Pi
  String bootMsg = "{\"event\":\"boot\",\"msg\":\"Ready\",\"cards\":" + String(cardCount) +
                   ",\"fp_ok\":" + (fpSensorOk ? "true" : "false") +
                   ",\"fp_count\":" + String(fpCount) + "}";
  piSend(bootMsg);

  // Fingerprint sensor status
  if (fpSensorOk) {
    fpStatus("ready", "\"count\":" + String(fpCount));
  } else {
    fpStatus("sensor_offline");
  }
}

// ─────────────────────────────────────────────────────────────
//  Main Loop
// ─────────────────────────────────────────────────────────────
void loop() {
  readPiSerial();
  checkAlertTimers();

  // ── Fingerprint Enrollment State Machine ──────────────────
  if (fpEnrollState != 0) {
    handleFpEnrollStep();
    // During enrollment: skip RFID scanning to avoid SPI contention
    // and keep state machine responsive
    return;
  }

  // ── Fingerprint Active Polling ────────────────────────────
  // Poll getImage() every FP_POLL_INTERVAL_MS instead of relying on
  // the wakeup/touch IRQ pin (which can be unreliable on some modules).
  if (fpSensorOk) {
    unsigned long now = millis();
    if (now - fpLastPoll >= FP_POLL_INTERVAL_MS) {
      fpLastPoll = now;
      uint8_t imgResult = finger.getImage();
      if (imgResult == FINGERPRINT_OK) {
        // Finger is present and image captured
        if (!fpFingerWasPresent && (now - fpLastMatch > FP_MATCH_DEBOUNCE_MS)) {
          fpFingerWasPresent = true;
          fpStatus("finger_detected");
          // Convert and search
          if (finger.image2Tz() == FINGERPRINT_OK) {
            if (finger.fingerSearch() == FINGERPRINT_OK) {
              handleFpMatch(finger.fingerID, finger.confidence);
              fpLastMatch = millis();
            } else {
              fpStatus("no_match");
              fpLastMatch = millis();   // debounce so we don't spam no_match
            }
          }
        }
      } else if (imgResult == FINGERPRINT_NOFINGER) {
        fpFingerWasPresent = false;   // finger lifted — allow next scan
      }
      // Other error codes: ignore silently
    }
  }

  // ── RFID Scanning ─────────────────────────────────────────
  for (int i = 0; i < NUM_READERS; i++) {
    if (!readers[i]->PICC_IsNewCardPresent()) continue;
    if (!readers[i]->PICC_ReadCardSerial())   continue;

    String uid = normalizeUID(uidToString(readers[i]));
    handleScan(i, uid);

    readers[i]->PICC_HaltA();
    readers[i]->PCD_StopCrypto1();
  }
}
