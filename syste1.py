#!/usr/bin/env python3
"""
Floor Access Control -- Raspberry Pi GUI  v10
FINAL FIXED VERSION:
  - TEMP ACCESS fully respected
  - ALL dialogs now open reliably (safe grab_set after window is viewable)
  - Camera dashboard is fully scrollable
"""

import contextlib
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
import serial
import serial.tools.list_ports
import threading
import json
import time
import queue
import os
import sqlite3
from datetime import datetime as dt, timezone

# --- Camera / Face Recognition Imports ---
import cv2
import numpy as np
from PIL import Image, ImageTk
import pickle
import logging

try:
    import face_recognition
    FACE_RECOG_AVAILABLE = True
except ImportError:
    FACE_RECOG_AVAILABLE = False
    logging.warning("face_recognition not available – face detection disabled.")

try:
    from picamera2 import Picamera2
    PICAMERA_AVAILABLE = True
except ImportError:
    PICAMERA_AVAILABLE = False
    logging.warning("picamera2 not available – cameras will show offline.")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("security_system.log"),
              logging.StreamHandler()])

CAPTURE_DIR = "captured_faces"
os.makedirs(CAPTURE_DIR, exist_ok=True)

try:
    with open("encodings.pickle", "rb") as _f:
        _data = pickle.loads(_f.read())
    known_face_encodings = _data["encodings"]
    known_face_names     = _data["names"]
    logging.info(f"Loaded {len(known_face_encodings)} face encodings.")
except FileNotFoundError:
    logging.warning("encodings.pickle not found – using empty encodings.")
    known_face_encodings = []
    known_face_names     = []
except Exception as _e:
    logging.error(f"Error loading encodings: {_e}")
    known_face_encodings = []
    known_face_names     = []

CV_SCALER       = 3
CAPTURE_COOLDOWN = 5
_last_capture_time: dict = {}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

C_BG        = "#080D12"
C_PANEL     = "#0F1A24"
C_PANEL2    = "#162030"
C_SIDEBAR   = "#0A1520"
C_BORDER    = "#1A4A6A"
C_ACCENT    = "#00D4FF"
C_ACCENT2   = "#007A9F"
C_GREEN     = "#00E87A"
C_RED       = "#FF3B5C"
C_YELLOW    = "#FFD60A"
C_ORANGE    = "#FF8C00"
C_PURPLE    = "#CF6CF7"
C_TEXT      = "#DCF0FC"
C_TEXT_DIM  = "#8ABCD4"
C_TEXT_MUTE = "#5A8AAE"
C_NAV_HOVER = "#1E3448"
C_NAV_SEL   = "#0E3A5A"
C_FP        = "#CF6CF7"

FONT_TITLE   = ("Courier New", 20, "bold")
FONT_HEAD    = ("Courier New", 14, "bold")
FONT_BODY    = ("Courier New", 12)
FONT_SMALL   = ("Courier New", 12)
FONT_MONO    = ("Courier New", 11)
FONT_NAV     = ("Courier New", 12, "bold")
FONT_MICRO   = ("Courier New", 10)
FONT_MICRO_B = ("Courier New", 10, "bold")

FLOOR_COLORS = ["#00D4FF", "#00E87A", "#FFD60A", "#CF6CF7"]
FLOOR_NAMES  = ["FLOOR 1", "FLOOR 2", "FLOOR 3", "FLOOR 4"]

BAUD          = 115200
SCAN_INTERVAL = 3

ANOMALY_FLOOR1_BYPASS      = "FLOOR-1 BYPASS"
ANOMALY_OUT_OF_ORDER       = "OUT-OF-ORDER EXIT"
ANOMALY_MULTI_IN           = "MULTI-FLOOR IN"
ANOMALY_ORPHAN_OUT         = "ORPHAN OUT"
ANOMALY_FLOOR_SKIP         = "FLOOR SKIP"
ANOMALY_UNKNOWN_CARD       = "UNKNOWN CARD"
ANOMALY_UNAUTHORIZED_FLOOR = "UNAUTHORIZED FLOOR"
ANOMALY_RAPID_REENTRY      = "RAPID RE-ENTRY"
ANOMALY_NO_FP_SIGNIN       = "NO FP SIGN-IN"
ANOMALY_FP_EXIT_DENIED     = "FP EXIT ORDER VIOLATION"

SEV_COLORS = {"CRITICAL":"#FF2D55","HIGH":"#FF6B00","MEDIUM":"#FFD60A","LOW":"#00D4FF"}
SEV_BG     = {"CRITICAL":"#200008","HIGH":"#1A0A00","MEDIUM":"#1A1500","LOW":"#001525"}

# ---------------------------------------------------------------------------
# ANOMALY SEVERITY HIERARCHY  (real-world building security rationale)
#
# CRITICAL — Active physical security breach / identity fraud risk.
#   Requires IMMEDIATE interception. System cannot trust this person's presence.
#   • UNKNOWN CARD        — Unregistered card = no identity, potential intruder
#   • NO FP SIGN-IN       — RFID used without fingerprint = card theft / tailgate
#   • FP EXIT ORDER VIO.  — Left without completing RFID sequence = unaccounted exit
#
# HIGH — Rule violation with clear intent or significant risk.
#   Requires swift action. Entry should be blocked / person escorted out.
#   • UNAUTHORIZED FLOOR  — Registered employee deliberately trying a wrong floor
#   • FLOOR-1 BYPASS      — Skipped mandatory lobby entry (tailgate or back-door)
#
# MEDIUM — Sequencing / state error, often procedural rather than malicious.
#   Should be investigated; could be operator error, sensor miss, or door held open.
#   • OUT-OF-ORDER EXIT   — Exiting floor out of sequence (forgot to scan out above)
#   • ORPHAN OUT          — Exit scan with no matching entry (data gap or tailgate exit)
#   • MULTI-FLOOR IN      — Checked in on more than one floor simultaneously
#
# LOW — Edge-case / nuisance event; worth logging but rarely dangerous.
#   No immediate action required; review in batch.
#   • FLOOR SKIP          — Jumped a floor (possible with temp access; low risk)
#   • RAPID RE-ENTRY      — Same card scanned IN twice quickly (double-tap, reader bounce)
# ---------------------------------------------------------------------------
ANOMALY_SEVERITIES = {
    ANOMALY_UNKNOWN_CARD:       "CRITICAL",
    ANOMALY_NO_FP_SIGNIN:       "CRITICAL",
    ANOMALY_FP_EXIT_DENIED:     "CRITICAL",
    ANOMALY_UNAUTHORIZED_FLOOR: "HIGH",
    ANOMALY_FLOOR1_BYPASS:      "HIGH",
    ANOMALY_OUT_OF_ORDER:       "MEDIUM",
    ANOMALY_ORPHAN_OUT:         "MEDIUM",
    ANOMALY_MULTI_IN:           "MEDIUM",
    ANOMALY_FLOOR_SKIP:         "LOW",
    ANOMALY_RAPID_REENTRY:      "LOW",
}

ACTION_REQUIRED = {
    ANOMALY_UNKNOWN_CARD:       "CONFISCATE CARD — No identity on record; detain if possible",
    ANOMALY_NO_FP_SIGNIN:       "INTERCEPT NOW — Likely tailgate or stolen card; check FP gate CCTV",
    ANOMALY_FP_EXIT_DENIED:     "INTERCEPT NOW — Unaccounted exit; locate person immediately",
    ANOMALY_UNAUTHORIZED_FLOOR: "ESCORT OUT — Verify clearance; report to floor manager",
    ANOMALY_FLOOR1_BYPASS:      "CHECK ENTRY POINT — Possible back-door entry; review camera",
    ANOMALY_OUT_OF_ORDER:       "Remind employee of correct exit sequence; clear state if confirmed",
    ANOMALY_ORPHAN_OUT:         "Review entry log — missed scan or door held open for someone else",
    ANOMALY_MULTI_IN:           "Verify occupancy — confirm person physically on only one floor",
    ANOMALY_FLOOR_SKIP:         "Verify floor compliance — may be temp access related; low urgency",
    ANOMALY_RAPID_REENTRY:      "Check for card sharing or reader double-read; low urgency",
}


# ─────────────────────────────────────────────────────────────────────────────
# AUDIO MANAGER
# Priority-based, non-overlapping WAV playback via aplay (Raspberry Pi native).
# Priorities (lower number = higher urgency):
#   1 = CRITICAL anomaly   2 = DENY   3 = HIGH anomaly   4 = GRANT
# A higher-priority sound preempts whatever is playing.
# Equal-or-lower priority sounds are dropped while something is already playing.
# ─────────────────────────────────────────────────────────────────────────────
import subprocess as _subprocess

_AUDIO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audios")

# Priority constants — lower number = higher urgency, preempts anything playing
SND_EMERGENCY = 0   # evacuation alarm — preempts absolutely everything
SND_CRITICAL  = 1   # active breach / identity fraud
SND_DENY      = 2   # access blocked (specific cause)
SND_HIGH      = 3   # rule violation / warning
SND_GRANT     = 4   # clean access granted

# Anomaly-type → (wav_filename, priority)
# violation.wav plays as a general violation tone layered on top of specific alerts.
# deny.wav plays on any access block. grant.wav plays on any clean grant (IN only).
ANOMALY_SOUNDS: dict = {
    # CRITICAL — active breach, plays over everything except emergency
    ANOMALY_NO_FP_SIGNIN:       ("alert_fp_missing.wav",   SND_CRITICAL),  # missing biometric
    ANOMALY_UNAUTHORIZED_FLOOR: ("alert_intercept.wav",    SND_CRITICAL),  # wrong floor — intercept now
    # DENY — access blocked
    ANOMALY_FP_EXIT_DENIED:     ("deny_sequence.wav",      SND_DENY),      # exit sequence violation
    ANOMALY_UNKNOWN_CARD:       ("deny_unknown_card.wav",  SND_DENY),      # unregistered card
    # HIGH — rule violation
    ANOMALY_FLOOR1_BYPASS:      ("alert_bypass.wav",       SND_HIGH),      # skipped lobby
    ANOMALY_OUT_OF_ORDER:       ("alert_out_of_order.wav", SND_HIGH),      # wrong exit sequence
    ANOMALY_ORPHAN_OUT:         ("alert_out_of_order.wav", SND_HIGH),      # exit with no entry
    ANOMALY_MULTI_IN:           ("alert_multi_floor.wav",  SND_HIGH),      # simultaneous multi-floor
    ANOMALY_FLOOR_SKIP:         ("alert_floor_skip.wav",   SND_HIGH),      # jumped a floor
    ANOMALY_RAPID_REENTRY:      ("alert_floor_skip.wav",   SND_HIGH),      # double-tap
}


class AudioManager:
    """Thread-safe, priority-aware WAV player using aplay."""

    def __init__(self):
        self._lock            = threading.Lock()
        self._proc: _subprocess.Popen | None = None
        self._current_priority: int = 99   # nothing playing
        self._loop_active: bool = False     # set False to stop a loop

    # ── public API ────────────────────────────────────────────────────────────

    def play(self, filename: str, priority: int = SND_GRANT) -> None:
        """Play *filename* (basename inside audios/) at *priority*.

        If a sound with equal-or-higher urgency is already playing, this call
        is silently dropped.  A higher-urgency sound kills the current one.
        """
        path = os.path.join(_AUDIO_DIR, filename)
        if not os.path.isfile(path):
            logging.warning(f"AudioManager: file not found: {path}")
            return
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                # Something is currently playing
                if priority >= self._current_priority:
                    # Current sound has equal or higher urgency — drop new sound
                    return
                # New sound has higher urgency — kill current
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._current_priority = priority
            try:
                self._proc = _subprocess.Popen(
                    ["aplay", "-q", path],
                    stdout=_subprocess.DEVNULL,
                    stderr=_subprocess.DEVNULL)
            except FileNotFoundError:
                # aplay not available (dev machine) — log and skip
                logging.warning("AudioManager: aplay not found; audio disabled.")
            except Exception as e:
                logging.error(f"AudioManager: playback error: {e}")

    def play_anomalies(self, anomalies: list) -> None:
        """Select the highest-urgency sound from a list of anomaly dicts."""
        best_file, best_pri = None, 99
        for a in anomalies:
            atype = a.get("type", "")
            if atype in ANOMALY_SOUNDS:
                fname, pri = ANOMALY_SOUNDS[atype]
                if pri < best_pri:
                    best_file, best_pri = fname, pri
        if best_file:
            self.play(best_file, best_pri)

    def play_sequence(self, files: list, priority: int = SND_GRANT) -> None:
        """Play a list of wav files back-to-back at *priority*.

        If something with equal-or-higher urgency is already playing, the whole
        sequence is dropped.  A higher-urgency call kills the current sound and
        starts its own sequence.  Each file in the sequence waits for the
        previous one to finish before starting.
        """
        if not files:
            return
        # Validate files exist first so we don't start a partial sequence
        paths = []
        for f in files:
            p = os.path.join(_AUDIO_DIR, f)
            if not os.path.isfile(p):
                logging.warning(f"AudioManager: file not found: {p}")
                # Still add None so the sequence slot is preserved; skip below
            paths.append(p if os.path.isfile(p) else None)
        paths = [p for p in paths if p]   # drop missing files
        if not paths:
            return

        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                if priority >= self._current_priority:
                    return          # drop — lower urgency
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._current_priority = priority
            self._proc = None      # will be set by the thread

        def _run():
            for path in paths:
                with self._lock:
                    # Abort if a higher-priority sound has taken over
                    if self._current_priority < priority:
                        return
                    try:
                        proc = _subprocess.Popen(
                            ["aplay", "-q", path],
                            stdout=_subprocess.DEVNULL,
                            stderr=_subprocess.DEVNULL)
                        self._proc = proc
                    except Exception as e:
                        logging.error(f"AudioManager: playback error: {e}")
                        return
                proc.wait()   # block until this clip finishes
            with self._lock:
                if self._current_priority == priority:
                    self._current_priority = 99   # sequence finished cleanly

        threading.Thread(target=_run, daemon=True).start()

    def play_loop(self, filename: str, priority: int = SND_GRANT) -> None:
        """Loop *filename* nonstop at *priority* until stop() is called.

        Starts a background thread that replays the file immediately after
        each playback finishes.  A call to stop() sets _loop_active=False,
        kills the current aplay process, and the thread exits cleanly.
        """
        path = os.path.join(_AUDIO_DIR, filename)
        if not os.path.isfile(path):
            logging.warning(f"AudioManager: loop file not found: {path}")
            return

        def _loop_worker():
            while True:
                with self._lock:
                    if not self._loop_active:
                        break
                    if self._current_priority < priority:
                        # A higher-urgency sound is playing — keep looping flag
                        # but don't spawn a new process; retry after a short sleep
                        pass
                    else:
                        # Kill anything currently playing
                        if self._proc and self._proc.poll() is None:
                            try:
                                self._proc.kill()
                            except Exception:
                                pass
                        try:
                            self._proc = _subprocess.Popen(
                                ["aplay", "-q", path],
                                stdout=_subprocess.DEVNULL,
                                stderr=_subprocess.DEVNULL)
                            self._current_priority = priority
                        except FileNotFoundError:
                            logging.warning("AudioManager: aplay not found; loop disabled.")
                            self._loop_active = False
                            break
                        except Exception as e:
                            logging.error(f"AudioManager: loop playback error: {e}")
                            self._loop_active = False
                            break

                # Wait for this iteration to finish (or for stop() to kill proc)
                proc_snap = None
                with self._lock:
                    proc_snap = self._proc
                if proc_snap:
                    proc_snap.wait()

                # Check if stop() was called while we were waiting
                with self._lock:
                    if not self._loop_active:
                        break

        # Atomically stop any existing loop/sound and start the new one
        with self._lock:
            self._loop_active = False    # signal any old loop thread to exit
            if self._proc and self._proc.poll() is None:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
            self._current_priority = 99
            self._loop_active = True

        t = threading.Thread(target=_loop_worker, daemon=True)
        t.start()

    def stop(self) -> None:
        """Kill any currently playing sound and stop any active loop."""
        with self._lock:
            self._loop_active = False
            if self._proc and self._proc.poll() is None:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
            self._current_priority = 99


# Singleton — imported once, used everywhere
_audio = AudioManager()

def play_sound(filename: str, priority: int = SND_GRANT) -> None:
    """Module-level shortcut."""
    _audio.play(filename, priority)

def play_anomaly_sounds(anomalies: list) -> None:
    """Module-level shortcut for anomaly lists."""
    _audio.play_anomalies(anomalies)

# --- Database ---
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "floor_access.db")

class DatabaseManager:
    def __init__(self, path=DB_PATH):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # RLock allows re-entrant acquisition from the same thread, preventing
        # deadlocks when DB methods call each other (e.g. expiry update inside
        # has_approved_temp_access).
        self._lock = threading.RLock()
        self._create_tables()

    def _create_tables(self):
        with self._conn:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS access_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL, floor INTEGER, uid TEXT,
                    name TEXT, direction TEXT, result TEXT,
                    granted INTEGER DEFAULT 0, injected INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS anomaly_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL, atype TEXT, severity TEXT,
                    uid TEXT, name TEXT, floor INTEGER,
                    direction TEXT, description TEXT);
                CREATE TABLE IF NOT EXISTS card_state (
                    uid TEXT PRIMARY KEY, floor1_entered INTEGER DEFAULT 0,
                    in_lobby INTEGER DEFAULT 0, active_ins TEXT DEFAULT '{}',
                    restricted INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS temp_access (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    visitor_name TEXT,
                    floor INTEGER,
                    purpose TEXT,
                    duration_hours REAL,
                    host TEXT,
                    notes TEXT,
                    status TEXT DEFAULT 'PENDING',
                    granted_ts TEXT,
                    request_type TEXT DEFAULT 'VISITOR');
            """)

            try:
                self._conn.execute("ALTER TABLE temp_access ADD COLUMN request_type TEXT DEFAULT 'VISITOR'")
            except sqlite3.OperationalError:
                pass

    def insert_access_log(self, ts, floor, uid, name, direction,
                          result, granted, injected=False):
        with self._lock:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO access_log "
                    "(timestamp,floor,uid,name,direction,result,granted,injected) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (ts, floor, uid, name, direction, result,
                     1 if granted else 0, 1 if injected else 0))

    def get_access_log(self, limit=500):
        with self._lock:
            return [dict(r) for r in self._conn.execute(
                "SELECT * FROM access_log ORDER BY timestamp DESC LIMIT ?", (limit,))]

    def clear_access_log(self):
        with self._lock:
            with self._conn:
                self._conn.execute("DELETE FROM access_log")

    def insert_anomaly(self, a):
        with self._lock:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO anomaly_log "
                    "(timestamp,atype,severity,uid,name,floor,direction,description) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (a.get("timestamp"), a.get("type"), a.get("severity"),
                     a.get("uid"), a.get("name"), a.get("floor"),
                     a.get("direction"), a.get("description")))

    def get_anomaly_log(self, limit=500):
        with self._lock:
            return [dict(r) for r in self._conn.execute(
                "SELECT * FROM anomaly_log ORDER BY timestamp DESC LIMIT ?", (limit,))]

    def get_anomaly_log_for_uid(self, uid: str, limit=50):
        with self._lock:
            return [dict(r) for r in self._conn.execute(
                "SELECT * FROM anomaly_log WHERE uid=? ORDER BY timestamp DESC LIMIT ?",
                (uid, limit))]

    def clear_anomaly_log(self):
        with self._lock:
            with self._conn:
                self._conn.execute("DELETE FROM anomaly_log")

    def save_card_state(self, uid, state):
        with self._lock:
            with self._conn:
                self._conn.execute("""
                    INSERT INTO card_state
                        (uid,floor1_entered,in_lobby,active_ins,restricted)
                    VALUES (?,?,?,?,?)
                    ON CONFLICT(uid) DO UPDATE SET
                        floor1_entered=excluded.floor1_entered,
                        in_lobby=excluded.in_lobby,
                        active_ins=excluded.active_ins,
                        restricted=excluded.restricted""",
                    (uid,
                     1 if state.get("floor1_entered") else 0,
                     1 if state.get("in_lobby") else 0,
                     json.dumps({str(k): v for k, v in state.get("active_ins", {}).items()}),
                     1 if state.get("restricted") else 0))

    def load_card_states(self):
        with self._lock:
            result = {}
            for row in self._conn.execute("SELECT * FROM card_state"):
                try:
                    ai = json.loads(row["active_ins"] or "{}")
                except Exception:
                    ai = {}
                result[row["uid"]] = {
                    "floor1_entered": bool(row["floor1_entered"]),
                    "in_lobby":       bool(row["in_lobby"]),
                    "active_ins":     {int(k): v for k, v in ai.items()},
                    "restricted":     bool(row["restricted"]),
                }
            return result

    def delete_card_state(self, uid):
        with self._lock:
            with self._conn:
                self._conn.execute("DELETE FROM card_state WHERE uid=?", (uid,))

    def clear_card_states(self):
        with self._lock:
            with self._conn:
                self._conn.execute("DELETE FROM card_state")

    def insert_temp_request(self, ts, visitor_name, floor, purpose, duration_hours, host, notes, request_type="VISITOR"):
        with self._lock:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO temp_access (timestamp,visitor_name,floor,purpose,duration_hours,host,notes,status,request_type) "
                    "VALUES (?,?,?,?,?,?,?,'PENDING',?)",
                    (ts, visitor_name, floor, purpose, duration_hours, host, notes, request_type))

    def get_temp_requests(self, limit=200, request_type=None):
        with self._lock:
            if request_type:
                return [dict(r) for r in self._conn.execute(
                    "SELECT * FROM temp_access WHERE (request_type=? OR request_type IS NULL) ORDER BY timestamp DESC LIMIT ?",
                    (request_type, limit))]
            return [dict(r) for r in self._conn.execute(
                "SELECT * FROM temp_access ORDER BY timestamp DESC LIMIT ?", (limit,))]

    def update_temp_status(self, req_id, new_status, granted_ts=None):
        with self._lock:
            with self._conn:
                self._conn.execute(
                    "UPDATE temp_access SET status=?, granted_ts=? WHERE id=?",
                    (new_status, granted_ts, req_id))

    def has_approved_temp_access(self, name: str, floor: int) -> bool:
        name = name.strip()
        # Hold the RLock for the entire read-check-update sequence so no other
        # thread can modify the same row between the read and the expiry write.
        with self._lock:
            row = self._conn.execute(
                """SELECT id, granted_ts, duration_hours FROM temp_access
                   WHERE LOWER(TRIM(visitor_name)) = LOWER(?)
                   AND floor = ? AND status = 'APPROVED' LIMIT 1""",
                (name, floor)
            ).fetchone()
            if not row:
                return False
            if row["granted_ts"]:
                try:
                    entry_dt  = dt.strptime(row["granted_ts"], "%Y-%m-%d %H:%M:%S")
                    elapsed_h = (dt.now() - entry_dt).total_seconds() / 3600.0
                    if elapsed_h > row["duration_hours"]:
                        # Still inside the lock — safe with RLock (same thread)
                        with self._conn:
                            self._conn.execute(
                                "UPDATE temp_access SET status='EXPIRED' WHERE id=?",
                                (row["id"],))
                        return False
                except Exception:
                    pass
            return True

    def update_temp_entry_time(self, name: str, floor: int, entry_ts: str):
        name = name.strip()
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """UPDATE temp_access SET granted_ts=?
                       WHERE LOWER(TRIM(visitor_name))=LOWER(?)
                       AND floor=? AND status='APPROVED'
                       AND (granted_ts IS NULL OR granted_ts='')""",
                    (entry_ts, name, floor))

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass

# --- Behavior Analyzer ---
class BehaviorAnalyzer:
    def __init__(self, db=None):
        self._state = {}
        self.strict_mode = False
        self._db = db
        self._fp_building: dict[str, bool] = {}
        # Protects _state and _fp_building from concurrent access between the
        # main event-loop thread (writes) and the camera background thread (reads).
        self._lock = threading.RLock()
        if db:
            self._state = db.load_card_states()

    def fp_building_signin(self, name: str, inside: bool):
        with self._lock:
            self._fp_building[name.strip().lower()] = inside

    def is_fp_signed_in(self, name: str) -> bool:
        with self._lock:
            return self._fp_building.get(name.strip().lower(), False)

    def fp_building_state(self) -> dict:
        with self._lock:
            return dict(self._fp_building)

    def get_state_snapshot(self, uid: str) -> dict:
        """Thread-safe snapshot of a single UID's state (for camera thread)."""
        with self._lock:
            st = self._state.get(uid, {})
            return {
                "floor1_entered": st.get("floor1_entered", False),
                "in_lobby":       st.get("in_lobby", False),
                "active_ins":     dict(st.get("active_ins", {})),
                "restricted":     st.get("restricted", False),
            }

    def reset_card(self, uid):
        with self._lock:
            self._state.pop(uid, None)
        if self._db:
            self._db.delete_card_state(uid)

    def reset_all(self):
        with self._lock:
            self._state.clear()
        if self._db:
            self._db.clear_card_states()

    def is_restricted(self, uid):
        with self._lock:
            return self._state.get(uid, {}).get("restricted", False)

    def process(self, uid, floor, direction, name, timestamp,
                is_lobby_passthrough=False):
        anomalies, deny_now, deny_reason = [], False, ""
        direction = (direction or "").lower().strip()
        # Acquire lock for the entire state mutation so the camera thread always
        # sees a consistent snapshot via get_state_snapshot().
        with self._lock:
            return self._process_locked(
                uid, floor, direction, name, timestamp, is_lobby_passthrough)

    def _process_locked(self, uid, floor, direction, name, timestamp,
                        is_lobby_passthrough=False):
        """Must be called with self._lock already held."""
        anomalies, deny_now, deny_reason = [], False, ""
        st = self._state.setdefault(uid, {
            "floor1_entered": False, "in_lobby": False,
            "active_ins": {}, "restricted": False})

        if is_lobby_passthrough:
            if direction == "in":
                if not self.is_fp_signed_in(name):
                    anomalies.append(self._make(
                        ANOMALY_NO_FP_SIGNIN, uid, name, floor, direction, timestamp,
                        "RFID lobby tap without fingerprint building sign-in.", "CRITICAL"))
                    deny_now    = True
                    deny_reason = "DENIED -- Fingerprint sign-in required before RFID access."
                    if self._db:
                        self._db.save_card_state(uid, st)
                    return anomalies, deny_now, deny_reason
                if st["in_lobby"]:
                    anomalies.append(self._make(
                        ANOMALY_FLOOR1_BYPASS, uid, name, floor, direction, timestamp,
                        "Card entered building again without exiting first.", "HIGH"))
                    if self.strict_mode:
                        deny_now, deny_reason = True, "DENIED -- Already inside building."
                st["in_lobby"] = True
                st["floor1_entered"] = True
            elif direction == "out":
                if not st["in_lobby"]:
                    anomalies.append(self._make(
                        ANOMALY_ORPHAN_OUT, uid, name, floor, direction, timestamp,
                        "Attempted to exit but not recorded as inside.", "HIGH"))
                    if self.strict_mode:
                        deny_now, deny_reason = True, "DENIED -- Not inside building."
                    if self._db:
                        self._db.save_card_state(uid, st)
                    return anomalies, deny_now, deny_reason
                still_in = sorted(st["active_ins"].keys())
                if still_in:
                    mef = ", ".join(f"Floor {f}" for f in still_in)
                    anomalies.append(self._make(
                        ANOMALY_OUT_OF_ORDER, uid, name, floor, direction, timestamp,
                        f"Cannot exit while still checked into {mef}.", "HIGH"))
                    deny_now, deny_reason = True, f"DENIED -- Must exit {mef} first."
                if not deny_now:
                    st["in_lobby"] = False
                    if not st["active_ins"]:
                        st["floor1_entered"] = False
            if anomalies and self.strict_mode and direction == "in":
                st["restricted"] = True
            if self._db:
                self._db.save_card_state(uid, st)
            return anomalies, deny_now, deny_reason

        if direction == "in" and not self.is_fp_signed_in(name):
            anomalies.append(self._make(
                ANOMALY_NO_FP_SIGNIN, uid, name, floor, direction, timestamp,
                f"RFID used without prior fingerprint building sign-in. "
                f"Possible tailgate, stolen card, or bypass attempt.", "CRITICAL"))
            deny_now    = True
            deny_reason = "DENIED -- Fingerprint sign-in required before RFID access."
            if self._db:
                self._db.save_card_state(uid, st)
            return anomalies, deny_now, deny_reason

        if direction == "in" and floor > 1 and not st["floor1_entered"]:
            anomalies.append(self._make(
                ANOMALY_FLOOR1_BYPASS, uid, name, floor, direction, timestamp,
                f"Accessed F{floor} without entering Floor 1 first.", "CRITICAL"))
            deny_now, deny_reason = True, f"DENIED -- Must enter Floor 1 before F{floor}."
        if direction == "in" and floor > 1 and st["active_ins"] and not deny_now:
            hi = max(st["active_ins"].keys())
            if floor - hi > 1:
                anomalies.append(self._make(
                    ANOMALY_FLOOR_SKIP, uid, name, floor, direction, timestamp,
                    f"Jumped from F{hi} to F{floor}.", "HIGH"))
                if self.strict_mode:
                    deny_now, deny_reason = True, "DENIED -- Cannot skip floors."
        if direction == "in" and st["active_ins"] and not deny_now:
            fins = sorted(st["active_ins"].keys())
            anomalies.append(self._make(
                ANOMALY_MULTI_IN, uid, name, floor, direction, timestamp,
                f"Already IN on: {', '.join(f'F{f}' for f in fins)}.", "HIGH"))
            if self.strict_mode:
                deny_now, deny_reason = True, "DENIED -- Already checked IN elsewhere."
        if direction == "in" and floor in st["active_ins"] and not deny_now:
            anomalies.append(self._make(
                ANOMALY_RAPID_REENTRY, uid, name, floor, direction, timestamp,
                f"Rapid re-entry to Floor {floor}.", "MEDIUM"))
        if direction == "out" and floor not in st["active_ins"] and not deny_now:
            anomalies.append(self._make(
                ANOMALY_ORPHAN_OUT, uid, name, floor, direction, timestamp,
                f"OUT on F{floor} with no matching IN record.", "HIGH"))
            if self.strict_mode:
                deny_now, deny_reason = True, f"DENIED -- No entry record for Floor {floor}."
        if direction == "out" and not deny_now:
            hf = sorted([f for f in st["active_ins"] if f > floor])
            if hf:
                mef = ", ".join(f"Floor {f}" for f in hf)
                anomalies.append(self._make(
                    ANOMALY_OUT_OF_ORDER, uid, name, floor, direction, timestamp,
                    f"Cannot exit F{floor} while IN on {mef}.", "HIGH"))
                if self.strict_mode:
                    deny_now, deny_reason = True, "DENIED -- Exit higher floors first."
        if not deny_now:
            if direction == "in":
                if floor == 1:
                    st["floor1_entered"] = True
                st["active_ins"][floor] = timestamp
            elif direction == "out":
                st["active_ins"].pop(floor, None)
                if not st["active_ins"] and not st["in_lobby"]:
                    st["floor1_entered"] = False
        if anomalies and self.strict_mode and direction == "in":
            st["restricted"] = True
        if self._db:
            self._db.save_card_state(uid, st)
        return anomalies, deny_now, deny_reason

    @staticmethod
    def _make(atype, uid, name, floor, direction, timestamp, description, severity=None):
        # Always derive severity from the canonical map; only fall back to passed value
        sev = ANOMALY_SEVERITIES.get(atype, severity or "MEDIUM")
        return {"type": atype, "uid": uid, "name": name or uid, "floor": floor,
                "direction": (direction.upper() if direction else "IN"),
                "timestamp": timestamp or dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                "description": description, "severity": sev}


def utc_to_local(s):
    try:
        u = dt.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return u.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return s


# --- LOG VIEWER ---
class LogViewer(ctk.CTkFrame):
    def __init__(self, parent, ctrl, feed, card_mgr=None, db=None, **kw):
        super().__init__(parent, fg_color="transparent", **kw)
        self.ctrl = ctrl
        self.feed = feed
        self.card_mgr = card_mgr
        self._db = db
        self._injected: list = []
        self._data: list = []

        bar = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=8)
        bar.pack(fill="x", pady=(0, 6))
        ctk.CTkButton(bar, text="FETCH LOG", width=120, height=30,
                      fg_color=C_ACCENT2, hover_color=C_ACCENT,
                      font=FONT_SMALL, text_color=C_BG,
                      command=self.fetch).pack(side="left", padx=8, pady=5)
        ctk.CTkButton(bar, text="CLEAR LOG", width=120, height=30,
                      fg_color="#3A0010", hover_color=C_RED,
                      font=FONT_SMALL, text_color=C_RED,
                      command=self.clear).pack(side="left", padx=4, pady=5)
        self._cnt_lbl = ctk.CTkLabel(bar, text="0 entries",
                                      font=FONT_SMALL, text_color=C_TEXT_DIM)
        self._cnt_lbl.pack(side="right", padx=12)

        hdr = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=5)
        hdr.pack(fill="x", pady=(0, 3))
        for label, w in [("TIMESTAMP", 170), ("STATUS", 95), ("NAME", 155),
                          ("FL", 52), ("DIR", 62), ("UID", 180),
                          ("RESULT / DETAILS", 350)]:
            ctk.CTkLabel(hdr, text=label, font=FONT_MICRO,
                         text_color=C_TEXT_MUTE, width=w, anchor="w"
                         ).pack(side="left", padx=(8, 0), pady=3)

        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color=C_BG, corner_radius=8,
            scrollbar_button_color=C_ACCENT2,
            scrollbar_button_hover_color=C_ACCENT)
        self._scroll.pack(fill="both", expand=True)

        if db:
            self._load_from_db()

    def _load_from_db(self):
        rows = self._db.get_access_log()
        for row in rows:
            rec = {
                "timestamp": row["timestamp"],
                "name":      row.get("name", ""),
                "floor":     row.get("floor", "?"),
                "direction": row.get("direction", ""),
                "uid":       row.get("uid", ""),
                "result":    row.get("result", ""),
                "granted":   bool(row.get("granted")),
                "injected":  bool(row.get("injected")),
            }
            self._data.append(rec)
            if rec["injected"]:
                self._injected.append({
                    "time":   rec["timestamp"], "floor": rec["floor"],
                    "uid":    rec["uid"],       "name":  rec["name"],
                    "dir":    rec["direction"], "reason": rec["result"],
                })
        self._rebuild()

    def fetch(self):
        self.ctrl.send_get_log()

    def inject_local_entry(self, entry: dict):
        rec = {
            "time":   entry.get("time",   dt.now().strftime("%Y-%m-%d %H:%M:%S")),
            "floor":  entry.get("floor",  "?"),
            "uid":    entry.get("uid",    ""),
            "name":   entry.get("name",   ""),
            "dir":    entry.get("dir",    ""),
            "reason": entry.get("reason", "DENIED -- Unusual Behaviour"),
            "granted": False,
        }
        self._injected.append(rec)
        if self._db:
            self._db.insert_access_log(
                rec["time"], rec["floor"], rec["uid"], rec["name"],
                rec["dir"], rec["reason"], granted=False, injected=True)
        data_rec = {
            "timestamp": rec["time"],    "name":      rec["name"],
            "floor":     rec["floor"],   "direction": rec["dir"],
            "uid":       rec["uid"],     "result":    rec["reason"],
            "granted":   False,          "injected":  True,
        }
        self._data.insert(0, data_rec)
        self._rebuild()

    def inject_granted_entry(self, entry: dict):
        rec = {
            "time":    entry.get("time",   dt.now().strftime("%Y-%m-%d %H:%M:%S")),
            "floor":   entry.get("floor",  "?"),
            "uid":     entry.get("uid",    ""),
            "name":    entry.get("name",   ""),
            "dir":     entry.get("dir",    "IN"),
            "reason":  entry.get("reason", "GRANTED (TEMP ACCESS)"),
            "granted": True,
        }
        self._injected.append(rec)
        if self._db:
            # BUG FIX: was injected=False, causing duplicate entries on log reload
            self._db.insert_access_log(
                rec["time"], rec["floor"], rec["uid"], rec["name"],
                rec["dir"], rec["reason"], granted=True, injected=True)
        data_rec = {
            "timestamp": rec["time"],   "name":      rec["name"],
            "floor":     rec["floor"],  "direction": rec["dir"],
            "uid":       rec["uid"],    "result":    rec["reason"],
            "granted":   True,          "injected":  True,
        }
        self._data.insert(0, data_rec)
        self._rebuild()

    def clear(self):
        if messagebox.askyesno("Confirm", "Clear all access log entries?",
                               parent=self.winfo_toplevel()):
            self.ctrl.send_clear_log()
            self._injected.clear()
            self._data.clear()
            self._rebuild()
            self.feed.add("Access log cleared", "WARN")
            if self._db:
                self._db.clear_access_log()

    def populate(self, entries: list):
        inj_keys = {
            (str(r["uid"]), str(r["floor"]), str(r["time"]))
            for r in self._injected
        }
        new_data = []
        for rec in self._injected:
            new_data.append({
                "timestamp": rec["time"],    "name":      rec["name"],
                "floor":     rec["floor"],   "direction": rec["dir"],
                "uid":       rec["uid"],     "result":    rec["reason"],
                "granted":   rec.get("granted", False),
                "injected":  True,
            })
        for e in entries:
            uid      = e.get("uid", "")
            floor    = e.get("floor", "")
            log_time = utc_to_local(e.get("time", ""))
            if (str(uid), str(floor), str(log_time)) in inj_keys:
                continue
            new_data.append({
                "timestamp": log_time,          "name":      e.get("name", ""),
                "floor":     floor,             "direction": e.get("dir", ""),
                "uid":       uid,               "result":    e.get("reason", ""),
                "granted":   e.get("granted", False), "injected": False,
            })
        new_data.sort(key=lambda r: r["timestamp"], reverse=True)
        self._data = new_data
        self._rebuild()

    def _rebuild(self):
        for w in self._scroll.winfo_children():
            w.destroy()
        for rec in self._data:
            self._pack_card(rec)
        self._cnt_lbl.configure(
            text=f"{len(self._data)} {'entry' if len(self._data)==1 else 'entries'}")

    def _pack_card(self, rec: dict):
        granted  = rec.get("granted", False)
        injected = rec.get("injected", False)
        accent   = C_GREEN if granted else C_RED
        bg       = "#0B1C0D" if granted else "#1A080E"
        border   = C_YELLOW if injected else accent
        floor    = rec.get("floor", "?")
        dir_str  = str(rec.get("direction", "")).upper() or "-"
        result   = str(rec.get("result", ""))
        uid_str  = str(rec.get("uid", ""))
        is_fp    = uid_str.startswith("FP:")
        if is_fp:
            bg = "#0D0A1F"; border = C_FP; accent = C_FP

        card = ctk.CTkFrame(self._scroll, fg_color=bg, corner_radius=6,
                            border_width=1, border_color=border)
        card.pack(fill="x", padx=3, pady=2)

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=5, pady=4)

        ctk.CTkFrame(row, width=3, fg_color=border, corner_radius=2
                     ).pack(side="left", fill="y", padx=(0, 7))

        ctk.CTkLabel(row, text=str(rec.get("timestamp", "")),
                     font=FONT_MICRO, text_color=C_TEXT_DIM,
                     width=170, anchor="w").pack(side="left", padx=(0, 6))

        badge_txt = ("GRANTED" if granted else "DENIED")
        badge_fg  = "#002A15" if granted else "#2A0010"
        if is_fp: badge_fg = "#1A0A2A"
        ctk.CTkLabel(row, text=badge_txt, font=FONT_MICRO_B,
                     text_color=accent, width=95, anchor="center",
                     fg_color=badge_fg, corner_radius=4
                     ).pack(side="left", padx=(0, 6))

        if is_fp:
            ctk.CTkLabel(row, text="FP", font=FONT_MICRO_B,
                         text_color=C_FP, fg_color="#12001A",
                         corner_radius=4, width=28
                         ).pack(side="left", padx=(0, 4))

        name = str(rec.get("name", ""))
        ctk.CTkLabel(row, text=(name[:20] if name else "-"),
                     font=FONT_MICRO_B, text_color=C_TEXT,
                     width=155, anchor="w").pack(side="left", padx=(0, 6))

        fl_idx  = int(floor) - 1 if str(floor).isdigit() and 1 <= int(floor) <= 4 else -1
        fl_col  = FLOOR_COLORS[fl_idx] if fl_idx >= 0 else C_TEXT_DIM
        fl_str  = f"F{floor}" if str(floor).isdigit() else str(floor or "?")
        ctk.CTkLabel(row, text=fl_str, font=FONT_MICRO_B,
                     text_color=fl_col, width=52, anchor="center"
                     ).pack(side="left", padx=(0, 6))

        dir_col = C_ACCENT if dir_str == "IN" else C_PURPLE
        ctk.CTkLabel(row, text=dir_str, font=FONT_MICRO_B,
                     text_color=dir_col, width=62, anchor="center"
                     ).pack(side="left", padx=(0, 6))

        ctk.CTkLabel(row, text=uid_str[:20],
                     font=FONT_MICRO, text_color=C_TEXT_MUTE,
                     width=180, anchor="w").pack(side="left", padx=(0, 6))

        result_col = C_GREEN if granted else C_RED
        if is_fp: result_col = C_FP if granted else C_RED
        ctk.CTkLabel(row, text=result, font=FONT_MICRO,
                     text_color=result_col, anchor="w", wraplength=480
                     ).pack(side="left", fill="x", expand=True, padx=(0, 4))

        if injected:
            ctk.CTkLabel(row, text="LOCAL", font=FONT_MICRO_B,
                         text_color=C_YELLOW, fg_color="#2A2000",
                         corner_radius=4, width=46
                         ).pack(side="right", padx=4)


# --- UNUSUAL ACTIVITY TABLE ---
class UnusualActivityTable(ctk.CTkFrame):
    def __init__(self, parent, db=None, analyzer=None, feed=None, ctrl=None, **kw):
        super().__init__(parent, fg_color="transparent", **kw)
        self._db       = db
        self._analyzer = analyzer
        self._feed     = feed
        self._ctrl     = ctrl
        self._data: list = []

        bar = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=8)
        bar.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(bar, text="UNUSUAL ACTIVITY LOG",
                     font=FONT_HEAD, text_color=C_RED
                     ).pack(side="left", padx=12, pady=8)
        self._cnt_lbl = ctk.CTkLabel(bar, text="0 anomalies",
                                      font=FONT_SMALL, text_color=C_TEXT_DIM)
        self._cnt_lbl.pack(side="right", padx=12)
        ctk.CTkButton(bar, text="CLEAR", width=80, height=28,
                      fg_color="#3A0010", hover_color=C_RED,
                      font=FONT_SMALL, text_color=C_RED,
                      command=self._clear).pack(side="right", padx=4, pady=6)

        hdr = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=5)
        hdr.pack(fill="x", pady=(0, 3))
        for label, w in [("TIMESTAMP", 170), ("SEV", 85), ("TYPE", 185),
                          ("NAME", 135), ("FL", 50), ("DIR", 58), ("UID", 155),
                          ("VIOLATION", 240), ("ACTION REQUIRED", 205)]:
            ctk.CTkLabel(hdr, text=label, font=FONT_MICRO,
                         text_color=C_TEXT_MUTE, width=w, anchor="w"
                         ).pack(side="left", padx=(8, 0), pady=3)

        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color=C_BG, corner_radius=8,
            scrollbar_button_color=C_ACCENT2,
            scrollbar_button_hover_color=C_ACCENT)
        self._scroll.pack(fill="both", expand=True)

        if db:
            self._load_from_db()

    def _load_from_db(self):
        rows = self._db.get_anomaly_log()
        for row in rows:
            self._data.append({
                "timestamp":   row["timestamp"],
                "type":        row["atype"],
                "severity":    row["severity"],
                "uid":         row["uid"],
                "name":        row["name"],
                "floor":       row["floor"],
                "direction":   row["direction"],
                "description": row["description"],
            })
        self._rebuild()

    def add_anomaly(self, anomaly: dict, save_db=True):
        if save_db and self._db:
            self._db.insert_anomaly(anomaly)
        self._data.insert(0, anomaly)
        self._rebuild()

    def _clear(self):
        # BUG FIX: was missing confirmation dialog (unlike LogViewer.clear)
        if not messagebox.askyesno("Confirm Clear",
                                   "Clear ALL anomaly records?\n\nThis cannot be undone.",
                                   parent=self.winfo_toplevel()):
            return
        self._data.clear()
        self._rebuild()
        if self._db:
            self._db.clear_anomaly_log()

    def _rebuild(self):
        for w in self._scroll.winfo_children():
            w.destroy()
        for anomaly in self._data:
            self._pack_card(anomaly)
        n = len(self._data)
        self._cnt_lbl.configure(
            text=f"{n} anomal{'y' if n == 1 else 'ies'}")

    def _pack_card(self, anomaly: dict):
        sev       = anomaly.get("severity", "MEDIUM")
        atype     = anomaly.get("type", "")
        color     = SEV_COLORS.get(sev, C_YELLOW)
        bg        = SEV_BG.get(sev, C_PANEL)
        action    = ACTION_REQUIRED.get(atype, "Investigate immediately")
        floor     = anomaly.get("floor", "?")
        fl_str    = f"F{floor}" if floor else "?"
        fl_idx    = int(floor) - 1 if str(floor).isdigit() and 1 <= int(floor) <= 4 else -1
        fl_col    = FLOOR_COLORS[fl_idx] if fl_idx >= 0 else C_TEXT_DIM
        direction = str(anomaly.get("direction", "")).upper()
        dir_col   = C_ACCENT if direction == "IN" else C_PURPLE
        desc      = str(anomaly.get("description", ""))

        card = ctk.CTkFrame(self._scroll, fg_color=bg, corner_radius=6,
                            border_width=1, border_color=color)
        card.pack(fill="x", padx=3, pady=2)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=5, pady=(5, 2))

        actions_frame = ctk.CTkFrame(top, fg_color="transparent")
        actions_frame.pack(side="right", padx=(10, 5), pady=2)

        uid  = str(anomaly.get("uid",  "")).strip()
        aname = str(anomaly.get("name", "")).strip()
        # No reset buttons here — use Building Activity page for card management

        ctk.CTkFrame(top, width=4, fg_color=color, corner_radius=2
                     ).pack(side="left", fill="y", padx=(0, 7))
        ctk.CTkLabel(top, text=str(anomaly.get("timestamp", "")),
                     font=FONT_MICRO, text_color=C_TEXT_DIM,
                     width=170, anchor="w").pack(side="left", padx=(0, 6))
        ctk.CTkLabel(top, text=sev, font=FONT_MICRO_B,
                     text_color=color, width=85, anchor="center",
                     fg_color=bg, corner_radius=4
                     ).pack(side="left", padx=(0, 6))
        ctk.CTkLabel(top, text=atype[:25], font=FONT_MICRO_B,
                     text_color=color, width=185, anchor="w"
                     ).pack(side="left", padx=(0, 6))
        ctk.CTkLabel(top, text=str(anomaly.get("name", ""))[:18],
                     font=FONT_MICRO_B, text_color=C_TEXT,
                     width=135, anchor="w").pack(side="left", padx=(0, 6))
        ctk.CTkLabel(top, text=fl_str, font=FONT_MICRO_B,
                     text_color=fl_col, width=50, anchor="center"
                     ).pack(side="left", padx=(0, 6))
        ctk.CTkLabel(top, text=direction if direction else "-",
                     font=FONT_MICRO_B, text_color=dir_col,
                     width=58, anchor="center").pack(side="left", padx=(0, 6))
        ctk.CTkLabel(top, text=str(anomaly.get("uid", ""))[:18],
                     font=FONT_MICRO, text_color=C_TEXT_MUTE,
                     width=155, anchor="w").pack(side="left", padx=(0, 6))
        ctk.CTkLabel(top, text=desc, font=FONT_MICRO,
                     text_color=C_TEXT_DIM, width=240, anchor="w",
                     wraplength=240, justify="left"
                     ).pack(side="left", padx=(0, 6))
        ctk.CTkLabel(top, text=f"{action}", font=FONT_MICRO_B,
                     text_color=C_YELLOW, anchor="w",
                     wraplength=240, justify="left"
                     ).pack(side="left", fill="x", expand=True, padx=(0, 4))

        if len(desc) > 60:
            bot = ctk.CTkFrame(card, fg_color="transparent")
            bot.pack(fill="x", padx=18, pady=(0, 5))
            ctk.CTkLabel(bot, text=f"{desc}", font=FONT_MICRO,
                         text_color=C_TEXT_DIM, anchor="w",
                         wraplength=900, justify="left"
                         ).pack(side="left")


# ─────────────────────────────────────────────────────────────────────────────
# BUILDING ACTIVITY PAGE
# One expandable employee card per registered employee.
# Each card shows: current location, FP status, restriction flag,
# their full violation history (from DB), and per-violation undo buttons.
# Undo here does NOT require the employee to return to the FP gate.
# ─────────────────────────────────────────────────────────────────────────────
class BuildingActivityPage(ctk.CTkFrame):
    def __init__(self, parent, analyzer=None, db=None, feed=None,
                 ctrl=None, personnel_mgr=None, **kw):
        super().__init__(parent, fg_color="transparent", **kw)
        self._analyzer      = analyzer
        self._db            = db
        self._feed          = feed
        self._ctrl          = ctrl
        self._personnel_mgr = personnel_mgr
        self._expanded: set = set()          # uids with expanded violation list

        # ── toolbar ──────────────────────────────────────────────────────────
        bar = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=8)
        bar.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(bar, text="BUILDING ACTIVITY",
                     font=FONT_HEAD, text_color=C_ACCENT
                     ).pack(side="left", padx=12, pady=8)
        self._summary_lbl = ctk.CTkLabel(bar, text="",
                                          font=FONT_SMALL, text_color=C_TEXT_DIM)
        self._summary_lbl.pack(side="left", padx=10)
        ctk.CTkButton(bar, text="REFRESH", width=84, height=28,
                      fg_color=C_ACCENT2, hover_color=C_ACCENT,
                      font=FONT_SMALL, text_color=C_BG,
                      command=self.refresh).pack(side="right", padx=8, pady=6)

        # ── legend ───────────────────────────────────────────────────────────
        leg = ctk.CTkFrame(self, fg_color=C_PANEL, corner_radius=6)
        leg.pack(fill="x", pady=(0, 6))
        for txt, col in [("● INSIDE", C_GREEN), ("🏢 LOBBY", C_ACCENT),
                         ("⛔ RESTRICTED", C_RED), ("○ OUT", C_TEXT_MUTE)]:
            ctk.CTkLabel(leg, text=txt, font=FONT_MICRO_B,
                         text_color=col).pack(side="left", padx=14, pady=5)
        ctk.CTkLabel(leg,
                     text="Click VIOLATIONS to expand  |  Undo individual violations without FP gate",
                     font=FONT_MICRO, text_color=C_TEXT_MUTE
                     ).pack(side="right", padx=14)

        # ── scrollable card list ──────────────────────────────────────────────
        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color=C_BG, corner_radius=8,
            scrollbar_button_color=C_ACCENT2,
            scrollbar_button_hover_color=C_ACCENT)
        self._scroll.pack(fill="both", expand=True)

        self.refresh()

    # ── public ────────────────────────────────────────────────────────────────
    def refresh(self):
        for w in self._scroll.winfo_children():
            w.destroy()

        known: dict = {}   # uid -> {name, reg_floor}
        if self._personnel_mgr:
            for rec in self._personnel_mgr._personnel.values():
                uid = rec.get("rfid_uid", "").strip().upper()
                if uid:
                    known[uid] = {
                        "name":      rec.get("name", uid),
                        "reg_floor": rec.get("floor", "?"),
                    }
        if self._analyzer:
            for uid in self._analyzer._state:
                if uid not in known:
                    known[uid] = {"name": uid, "reg_floor": "?"}

        inside_n = restricted_n = 0
        for uid, info in sorted(known.items(),
                                key=lambda x: x[1].get("name", "").lower()):
            st         = {}
            if self._analyzer:
                st = self._analyzer._state.get(uid, {})
            active_ins  = dict(st.get("active_ins", {}))
            restricted  = st.get("restricted", False)
            floor1_in   = st.get("floor1_entered", False)
            in_lobby    = st.get("in_lobby", False)
            fp_ok       = (self._analyzer.is_fp_signed_in(info["name"])
                           if self._analyzer else False)
            any_inside  = bool(active_ins) or in_lobby

            if any_inside: inside_n += 1
            if restricted: restricted_n += 1

            self._build_employee_card(uid, info, active_ins, restricted,
                                      floor1_in, in_lobby, fp_ok, any_inside)

        total = len(known)
        self._summary_lbl.configure(
            text=f"{total} employees  |  {inside_n} inside  "
                 + (f"|  {restricted_n} restricted" if restricted_n else ""))

    # ── per-employee card ─────────────────────────────────────────────────────
    def _build_employee_card(self, uid, info, active_ins, restricted,
                             floor1_in, in_lobby, fp_ok, any_inside):
        name      = info["name"]
        reg_floor = info["reg_floor"]

        if restricted:
            border_c = C_RED;    bg = "#150005"
        elif active_ins:
            border_c = C_GREEN;  bg = "#051208"
        elif in_lobby:
            border_c = C_ACCENT; bg = "#030E18"
        else:
            border_c = C_BORDER; bg = C_PANEL

        violations = self._db.get_anomaly_log_for_uid(uid) if self._db else []
        v_count    = len(violations)
        v_col = (C_RED    if any(a.get("severity") == "CRITICAL" for a in violations) else
                 C_ORANGE if any(a.get("severity") == "HIGH"     for a in violations) else
                 C_YELLOW if violations else C_TEXT_MUTE)

        outer = ctk.CTkFrame(self._scroll, fg_color=bg, corner_radius=7,
                             border_width=1, border_color=border_c)
        outer.pack(fill="x", padx=4, pady=2)

        # ── single compact row ────────────────────────────────────────────────
        row = ctk.CTkFrame(outer, fg_color="transparent")
        row.pack(fill="x", padx=6, pady=4)

        # accent bar
        ctk.CTkFrame(row, width=3, fg_color=border_c, corner_radius=2
                     ).pack(side="left", fill="y", padx=(0, 8))

        # name + floor + uid (fixed width column)
        name_col = ctk.CTkFrame(row, fg_color="transparent", width=220)
        name_col.pack(side="left", fill="y")
        name_col.pack_propagate(False)
        ctk.CTkLabel(name_col, text=name[:24], font=FONT_SMALL,
                     text_color=C_TEXT, anchor="w").pack(anchor="w")
        reg_col = (FLOOR_COLORS[int(reg_floor)-1]
                   if str(reg_floor).isdigit() and 1 <= int(reg_floor) <= 4
                   else C_TEXT_MUTE)
        ctk.CTkLabel(name_col,
                     text=f"F{reg_floor}  {uid[:16]}",
                     font=FONT_MICRO, text_color=C_TEXT_MUTE, anchor="w"
                     ).pack(anchor="w")

        # ── state chips (inline) ──────────────────────────────────────────────
        chips = ctk.CTkFrame(row, fg_color="transparent")
        chips.pack(side="left", padx=(0, 6))

        if restricted:
            ch = ctk.CTkFrame(chips, fg_color="#2A0010", corner_radius=4,
                              border_width=1, border_color=C_RED)
            ch.pack(side="left", padx=2)
            ctk.CTkLabel(ch, text=" ⛔ RESTRICTED ",
                         font=FONT_MICRO_B, text_color=C_RED
                         ).pack(side="left", pady=2)
            ctk.CTkButton(ch, text="LIFT", width=36, height=20,
                          corner_radius=3,
                          fg_color="transparent", hover_color="#003020",
                          text_color=C_GREEN, font=FONT_MICRO_B,
                          command=lambda u=uid, n=name: self._lift_restriction(u, n)
                          ).pack(side="left", padx=(0, 2))

        if active_ins:
            for fl, ts_val in sorted(active_ins.items()):
                fl_col = FLOOR_COLORS[fl-1] if 1 <= fl <= 4 else C_TEXT_DIM
                ch = ctk.CTkFrame(chips, fg_color="#001A05", corner_radius=4,
                                  border_width=1, border_color=fl_col)
                ch.pack(side="left", padx=2)
                ctk.CTkLabel(ch, text=f" F{fl} ",
                             font=FONT_MICRO_B, text_color=fl_col
                             ).pack(side="left", pady=2)
                ctk.CTkLabel(ch, text=f"{ts_val[-8:]} ",
                             font=FONT_MICRO, text_color=C_TEXT_MUTE
                             ).pack(side="left")
                ctk.CTkButton(ch, text="✕", width=20, height=20,
                              corner_radius=3,
                              fg_color="transparent", hover_color=C_RED,
                              text_color=C_RED, font=FONT_MICRO_B,
                              command=lambda u=uid, n=name, f=fl:
                                  self._undo_floor_checkin(u, n, f)
                              ).pack(side="left", padx=(0, 1))
        elif in_lobby:
            ctk.CTkLabel(chips, text=" 🏢 LOBBY ", font=FONT_MICRO_B,
                         text_color=C_ACCENT, fg_color="#030E18",
                         corner_radius=4).pack(side="left", padx=2)
        elif not restricted:
            ctk.CTkLabel(chips, text=" OUT ", font=FONT_MICRO_B,
                         text_color=C_TEXT_MUTE, fg_color=C_PANEL2,
                         corner_radius=4).pack(side="left", padx=2)

        if fp_ok:
            ctk.CTkLabel(chips, text=" FP✓ ", font=FONT_MICRO_B,
                         text_color=C_FP, fg_color="#0D0020",
                         corner_radius=4).pack(side="left", padx=2)

        # ── right-side buttons ────────────────────────────────────────────────
        rbtn = ctk.CTkFrame(row, fg_color="transparent")
        rbtn.pack(side="right")

        # CLEAR ALL STATE (only if there's something to clear)
        if any_inside or restricted:
            ctk.CTkButton(
                rbtn, text="CLEAR ALL", width=80, height=24,
                corner_radius=4,
                fg_color="#2A0010" if restricted else "#003020",
                hover_color=C_RED if restricted else C_GREEN,
                text_color=C_RED if restricted else C_GREEN,
                font=FONT_MICRO_B,
                command=lambda u=uid, n=name: self._full_state_clear(u, n)
            ).pack(side="right", padx=2)

        # violations toggle
        if violations:
            is_exp     = uid in self._expanded
            vbtn_label = f"{'▼' if is_exp else '▶'} {v_count} violation{'s' if v_count != 1 else ''}"
            ctk.CTkButton(
                rbtn, text=vbtn_label, width=120, height=24,
                corner_radius=4,
                fg_color="#1A0800" if any(a["severity"] in ("CRITICAL","HIGH") for a in violations) else "#1A1400",
                hover_color=C_PANEL2,
                text_color=v_col, font=FONT_MICRO_B,
                command=lambda u=uid, o=outer: self._toggle_violations(u, o)
            ).pack(side="right", padx=2)
        else:
            ctk.CTkLabel(rbtn, text="✓ clean", font=FONT_MICRO_B,
                         text_color=C_GREEN).pack(side="right", padx=6)

        # ── violations section (hidden by default) ────────────────────────────
        viol_frame = ctk.CTkFrame(outer, fg_color="transparent")
        outer._viol_frame = viol_frame
        outer._viol_data  = violations
        outer._uid        = uid

        if uid in self._expanded:
            self._build_violations_list(viol_frame, uid, violations)
            viol_frame.pack(fill="x", padx=8, pady=(0, 6))

    # ── violations list ───────────────────────────────────────────────────────
    def _build_violations_list(self, parent, uid, violations):
        for w in parent.winfo_children():
            w.destroy()
        if not violations:
            ctk.CTkLabel(parent, text="No violations on record.",
                         font=FONT_MICRO, text_color=C_TEXT_MUTE
                         ).pack(padx=14, pady=6)
            return

        ctk.CTkFrame(parent, height=1, fg_color=C_BORDER).pack(fill="x", pady=(4, 6))
        ctk.CTkLabel(parent, text="VIOLATION HISTORY  (newest first — click ✕ to undo individually)",
                     font=FONT_MICRO_B, text_color=C_TEXT_MUTE
                     ).pack(anchor="w", padx=4, pady=(0, 4))

        for a in violations:
            sev    = a.get("severity", "MEDIUM")
            atype  = a.get("atype") or a.get("type", "")
            color  = SEV_COLORS.get(sev, C_YELLOW)
            bg     = SEV_BG.get(sev, C_PANEL)
            action = ACTION_REQUIRED.get(atype, "Investigate")
            ts     = a.get("timestamp", "")
            desc   = a.get("description", "")
            fl     = a.get("floor", "")
            dirn   = str(a.get("direction", "")).upper()

            vrow = ctk.CTkFrame(parent, fg_color=bg, corner_radius=6,
                                border_width=1, border_color=color)
            vrow.pack(fill="x", padx=4, pady=2)

            inner = ctk.CTkFrame(vrow, fg_color="transparent")
            inner.pack(fill="x", padx=8, pady=5)

            ctk.CTkFrame(inner, width=3, fg_color=color, corner_radius=2
                         ).pack(side="left", fill="y", padx=(0, 8))

            # severity badge
            ctk.CTkLabel(inner, text=sev, font=FONT_MICRO_B,
                         text_color=color, width=72, anchor="center",
                         fg_color=bg, corner_radius=4
                         ).pack(side="left", padx=(0, 6))

            # type
            ctk.CTkLabel(inner, text=atype[:22], font=FONT_MICRO_B,
                         text_color=color, width=185, anchor="w"
                         ).pack(side="left", padx=(0, 6))

            # floor + dir
            fl_col = (FLOOR_COLORS[int(fl)-1]
                      if str(fl).isdigit() and 1 <= int(fl) <= 4
                      else C_TEXT_DIM)
            ctk.CTkLabel(inner, text=f"F{fl}" if fl else "-",
                         font=FONT_MICRO_B, text_color=fl_col,
                         width=38, anchor="center").pack(side="left", padx=(0, 4))
            dir_col = C_ACCENT if dirn == "IN" else C_PURPLE
            ctk.CTkLabel(inner, text=dirn or "-", font=FONT_MICRO_B,
                         text_color=dir_col, width=40, anchor="center"
                         ).pack(side="left", padx=(0, 6))

            # timestamp
            ctk.CTkLabel(inner, text=ts[-19:], font=FONT_MICRO,
                         text_color=C_TEXT_MUTE, width=145, anchor="w"
                         ).pack(side="left", padx=(0, 6))

            # description (truncated)
            ctk.CTkLabel(inner, text=desc[:60] + ("…" if len(desc) > 60 else ""),
                         font=FONT_MICRO, text_color=C_TEXT_DIM,
                         anchor="w", wraplength=340, justify="left"
                         ).pack(side="left", fill="x", expand=True, padx=(0, 6))

            # Action buttons per violation type
            a_id  = a.get("id")
            aname = str(a.get("name", "")).strip()
            can_undo = (sev in ("MEDIUM", "LOW") and
                        atype in (ANOMALY_OUT_OF_ORDER, ANOMALY_ORPHAN_OUT,
                                  ANOMALY_MULTI_IN, ANOMALY_FLOOR_SKIP,
                                  ANOMALY_RAPID_REENTRY) and fl)
            is_no_fp = (atype == ANOMALY_NO_FP_SIGNIN)

            if can_undo:
                ctk.CTkButton(inner, text="✕ UNDO", width=70, height=22,
                              corner_radius=4,
                              fg_color="#003020", hover_color=C_GREEN,
                              text_color=C_GREEN, font=FONT_MICRO_B,
                              command=lambda _id=a_id, _fl=fl, _uid=uid,
                                             _type=atype:
                                  self._undo_violation(_id, _uid, _fl, _type)
                              ).pack(side="right", padx=2)
            elif is_no_fp:
                # Allow operator to manually mark the employee as FP-signed-in
                # (e.g. they did sign in at the gate but the system didn't catch it,
                # or they've since signed in and the card should now be unblocked).
                ctk.CTkButton(inner, text="CLEAR FP BLOCK", width=110, height=22,
                              corner_radius=4,
                              fg_color="#1A0A2A", hover_color=C_FP,
                              text_color=C_FP, font=FONT_MICRO_B,
                              command=lambda _uid=uid, _name=aname:
                                  self._clear_fp_block(_uid, _name)
                              ).pack(side="right", padx=2)
            else:
                # Non-undoable: show dismiss (removes from view, keeps in DB for audit)
                ctk.CTkButton(inner, text="ACK", width=48, height=22,
                              corner_radius=4,
                              fg_color=C_PANEL2, hover_color=C_BORDER,
                              text_color=C_TEXT_MUTE, font=FONT_MICRO_B,
                              command=lambda r=vrow: r.pack_forget()
                              ).pack(side="right", padx=2)

    # ── toggle violations ─────────────────────────────────────────────────────
    def _toggle_violations(self, uid, outer):
        if uid in self._expanded:
            self._expanded.discard(uid)
            outer._viol_frame.pack_forget()
        else:
            self._expanded.add(uid)
            self._build_violations_list(outer._viol_frame, uid, outer._viol_data)
            outer._viol_frame.pack(fill="x", padx=10, pady=(4, 8))
        # Update button text
        self.after(30, self.refresh)

    # ── undo individual floor check-in (✕ chip button) ───────────────────────
    def _undo_floor_checkin(self, uid, name, floor):
        if not self._analyzer:
            return
        # Resolve UID case
        actual_uid = uid
        with self._analyzer._lock:
            for k in self._analyzer._state:
                if k.upper() == uid.upper():
                    actual_uid = k
                    break
            st = self._analyzer._state.get(actual_uid, {})
            if floor not in st.get("active_ins", {}):
                self.refresh(); return
            ts_in = st["active_ins"].get(floor, "")
        # Show dialog outside the lock (dialogs can take arbitrary time)
        if not messagebox.askyesno(
            "Undo Floor Check-In",
            f"Remove F{floor} check-in for {name}?\n\n"
            f"Entered at: {ts_in}\n\n"
            f"This will allow them to re-enter F{floor} normally.\n"
            f"No FP gate visit required.",
            parent=self.winfo_toplevel()
        ):
            return
        with self._analyzer._lock:
            st = self._analyzer._state.get(actual_uid, {})
            st.get("active_ins", {}).pop(floor, None)
            if not st.get("active_ins") and not st.get("in_lobby"):
                st["floor1_entered"] = False
        if self._analyzer._db:
            self._analyzer._db.save_card_state(actual_uid, st)
        if self._ctrl:
            self._ctrl.send_reset_presence(actual_uid, floor, False)
        if self._feed:
            self._feed.add(
                f"UNDO CHECK-IN → {name} ({actual_uid}) F{floor} cleared | no FP gate required",
                "WARN")
        self.refresh()

    # ── lift restriction only ─────────────────────────────────────────────────
    def _lift_restriction(self, uid, name):
        if not self._analyzer:
            return
        actual_uid = uid
        with self._analyzer._lock:
            for k in self._analyzer._state:
                if k.upper() == uid.upper():
                    actual_uid = k
                    break
            st = self._analyzer._state.get(actual_uid)
        if st is None or not st.get("restricted", False):
            messagebox.showinfo("Nothing to do",
                                f"{name} is not currently restricted.",
                                parent=self.winfo_toplevel())
            self.refresh()
            return
        if not messagebox.askyesno(
            "Lift Restriction",
            f"Remove access restriction for {name}?\n\n"
            f"Their floor check-ins will NOT be changed.\n"
            f"No FP gate visit required.",
            parent=self.winfo_toplevel()
        ):
            return
        with self._analyzer._lock:
            st = self._analyzer._state.get(actual_uid, {})
            st["restricted"] = False
        if self._analyzer._db:
            self._analyzer._db.save_card_state(actual_uid, st)
        if self._feed:
            self._feed.add(
                f"RESTRICTION LIFTED → {name} ({actual_uid}) | no FP gate required",
                "WARN")
        self.refresh()

    # ── undo specific violation (clears matching floor state, removes anomaly from DB) ─
    def _undo_violation(self, anomaly_id, uid, floor, atype):
        try:
            fl = int(floor)
        except (TypeError, ValueError):
            fl = None
        if not messagebox.askyesno(
            "Undo Violation",
            f"Undo this violation?\n\nType: {atype}\nFloor: F{floor}\n\n"
            f"This will clear the floor state for F{floor} if active.\n"
            f"The violation record stays in the audit log.\n"
            f"No FP gate visit required.",
            parent=self.winfo_toplevel()
        ):
            return
        if fl and self._analyzer:
            with self._analyzer._lock:
                st = self._analyzer._state.get(uid, {})
                if fl in st.get("active_ins", {}):
                    st["active_ins"].pop(fl, None)
            if self._analyzer._db:
                self._analyzer._db.save_card_state(uid, st)
            if self._ctrl:
                self._ctrl.send_reset_presence(uid, fl, False)
        if self._feed:
            self._feed.add(
                f"VIOLATION UNDO → {atype} F{floor} ({uid}) | state cleared | "
                f"no FP gate required", "WARN")
        self.refresh()

    # ── clear FP sign-in block (for NO FP SIGN-IN violations) ──────────────
    def _clear_fp_block(self, uid, name):
        if not self._analyzer:
            return
        # Resolve name from personnel if blank
        display_name = name
        if not display_name and self._personnel_mgr:
            for rec in self._personnel_mgr._personnel.values():
                if rec.get("rfid_uid", "").strip().upper() == uid.upper():
                    display_name = rec.get("name", uid)
                    break
        if not display_name:
            display_name = uid

        if not messagebox.askyesno(
            "Clear FP Sign-In Block",
            f"Mark {display_name} as FP-signed-in?\n\n"
            f"This clears the 'NO FP SIGN-IN' block so their RFID card\n"
            f"will be accepted on the next scan.\n\n"
            f"Use this when they have signed in at the FP gate but the\n"
            f"system still shows them as blocked.",
            parent=self.winfo_toplevel()
        ):
            return

        self._analyzer.fp_building_signin(display_name, True)

        # Also clear the card's restricted flag and reset floor1_entered so the
        # next RFID tap goes through the normal flow cleanly.
        actual_uid = uid
        with self._analyzer._lock:
            for k in self._analyzer._state:
                if k.upper() == uid.upper():
                    actual_uid = k
                    break
            st = self._analyzer._state.get(actual_uid, {})
            st["restricted"] = False
            # Reset floor entry state so the next tap is treated as a fresh entry
            st["floor1_entered"] = False
            st["in_lobby"]       = False
            st["active_ins"]     = {}
        if self._analyzer._db:
            self._analyzer._db.save_card_state(actual_uid, st)
        if self._ctrl:
            # Tell ESP32 to clear presence so relay/LED state is consistent
            for fl in range(1, 5):
                self._ctrl.send_reset_presence(actual_uid, fl, False)

        if self._feed:
            self._feed.add(
                f"FP BLOCK CLEARED → {display_name} ({actual_uid}) | "
                f"marked as FP-signed-in | card unblocked", "FP")
        self.refresh()

    # ── full state clear (clears everything, still no FP gate) ───────────────
    def _full_state_clear(self, uid, name):
        actual_uid = uid
        with self._analyzer._lock if self._analyzer else contextlib.nullcontext():
            for k in (self._analyzer._state if self._analyzer else {}):
                if k.upper() == uid.upper():
                    actual_uid = k
                    break
            st         = (self._analyzer._state.get(actual_uid, {})
                          if self._analyzer else {})
            active_ins = dict(st.get("active_ins", {}))
            restricted = st.get("restricted", False)
            in_lobby   = st.get("in_lobby", False)

        parts = []
        if active_ins:
            parts.append(f"Clear floor check-ins: {', '.join(f'F{f}' for f in sorted(active_ins))}")
        if restricted:
            parts.append("Remove access restriction")
        if in_lobby:
            parts.append("Clear lobby / Floor-1 state")
        if not parts:
            return

        if not messagebox.askyesno(
            "Clear All State",
            f"Clear all active state for {name}?\n\n"
            + "\n".join(f"• {p}" for p in parts)
            + "\n\nNo FP gate visit required.",
            parent=self.winfo_toplevel()
        ):
            return

        if self._ctrl:
            for fl in sorted(active_ins.keys()):
                self._ctrl.send_reset_presence(actual_uid, fl, False)
        if self._analyzer and actual_uid in self._analyzer._state:
            with self._analyzer._lock:
                self._analyzer._state[actual_uid].update({
                    "restricted": False, "active_ins": {},
                    "floor1_entered": False, "in_lobby": False})
            if self._analyzer._db:
                self._analyzer._db.save_card_state(
                    actual_uid, self._analyzer._state[actual_uid])
        if self._feed:
            self._feed.add(
                f"STATE CLEARED → {name} ({actual_uid}) | {', '.join(parts)} | "
                f"no FP gate required", "WARN")
        self.refresh()


# --- EMPLOYEE STATUS PANEL (legacy shim – kept for any internal references) ---
EmployeeStatusPanel = BuildingActivityPage


# --- ESP32 Controller ---
class ESP32Controller:
    def __init__(self, eq):
        self.eq = eq
        self._ser = None
        self._port = None
        self._running = False
        self._thread = None
        self._lock = threading.Lock()
        # Guards connect()/disconnect() so that two auto-scan threads cannot race
        # to open the serial port simultaneously.
        self._connect_lock = threading.Lock()
        self._connecting = False
        # Heartbeat: timestamp of the last JSON event received from ESP32.
        # Used by the watchdog to detect silent hardware failures.
        self.last_rx_time: float = 0.0

    def connect(self, port):
        # Bail out immediately if another thread is already connecting
        with self._connect_lock:
            if self._connecting:
                return False
            self._connecting = True
        try:
            self.disconnect()
            try:
                self._ser = serial.Serial(port, BAUD, timeout=1)
                self._port = port
                self._running = True
                self.last_rx_time = time.time()
                self._thread = threading.Thread(target=self._reader, daemon=True)
                self._thread.start()
                time.sleep(0.8)
                self._raw_send(f"TIME:{int(time.time())}")
                self._raw_send("LIST_CARDS")
                self._raw_send("FP_LIST")
                self._push({"event": "_connected", "port": port})
                return True
            except (serial.SerialException, OSError) as e:
                self._push({"event": "_connect_error", "msg": str(e)})
                return False
        finally:
            with self._connect_lock:
                self._connecting = False

    def disconnect(self):
        self._running = False
        # Close the serial port first so any blocking readline() in _reader
        # immediately raises SerialException and the thread can exit cleanly.
        ser = self._ser
        self._ser  = None
        self._port = None
        try:
            if ser and ser.is_open:
                ser.close()
        except Exception:
            pass

    @property
    def connected(self):
        return self._ser is not None and self._ser.is_open

    @property
    def port(self):
        return self._port

    def _reader(self):
        while self._running:
            # Snapshot self._ser into a local reference BEFORE using it.
            # disconnect() may null self._ser at any time from another thread;
            # a local ref means we either have a valid object or None — we
            # never call readline() on a half-nulled object.
            ser = self._ser
            if ser is None:
                break
            try:
                raw = ser.readline()
                if not raw:
                    continue
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                # Update heartbeat for every message received
                self.last_rx_time = time.time()
                if line.startswith("[FP]"):
                    self._push({"event": "_raw", "msg": line})
                    continue
                try:
                    self._push(json.loads(line))
                except json.JSONDecodeError:
                    self._push({"event": "_raw", "msg": line})
            except (serial.SerialException, OSError, TypeError, AttributeError):
                # TypeError/AttributeError: ser.fd became None inside pyserial
                # (race between our disconnect() and a blocking read).
                if self._running:
                    self._push({"event": "_disconnected"})
                    self._running = False
                    self._ser = None
                break

    def _push(self, e):
        self.eq.put_nowait(e)

    def _raw_send(self, line):
        with self._lock:
            if self._ser and self._ser.is_open:
                try:
                    self._ser.write((line + "\n").encode("utf-8"))
                except Exception:
                    pass

    def send_grant_floor(self, floor):
        self._raw_send(f"GRANT_FLOOR:{floor}")
    def send_mode(self, m):               self._raw_send(f"MODE:{m}")
    def send_add(self, uid, floor, name): self._raw_send(f"ADD:{uid},{floor},{name}")
    def send_del(self, uid):              self._raw_send(f"DEL:{uid}")
    def send_list_cards(self):            self._raw_send("LIST_CARDS")
    def send_sensor(self, floor, en):     self._raw_send(f"SENSOR:{floor},{1 if en else 0}")
    def send_light(self, floor, state):   self._raw_send(f"LIGHT:{floor},{state}")
    def send_light_release(self, floor):  self._raw_send(f"LIGHT_RELEASE:{floor}")
    def send_get_log(self):               self._raw_send("GET_LOG")
    def send_clear_log(self):             self._raw_send("CLEAR_LOG")
    def send_time(self):                  self._raw_send(f"TIME:{int(time.time())}")
    def send_reset_presence(self, uid, floor, inside):
        self._raw_send(f"RESET_PRESENCE:{uid},{floor},{1 if inside else 0}")

    def send_fp_enroll(self, fp_id, floor, name):
        self._raw_send(f"FP_ENROLL:{fp_id},{floor},{name}")
    def send_fp_delete(self, fp_id):
        self._raw_send(f"FP_DELETE:{fp_id}")
    def send_fp_list(self):
        self._raw_send("FP_LIST")
    def send_fp_clear(self):
        self._raw_send("FP_CLEAR")
    def send_fp_cancel(self):
        self._raw_send("FP_CANCEL")


ESP32_KEYWORDS = ["cp210", "ch340", "ftdi", "esp", "silicon labs", "usb serial"]

def find_esp32_ports():
    found = []
    for p in serial.tools.list_ports.comports():
        desc = (p.description or "").lower()
        mfr  = (p.manufacturer or "").lower()
        if any(k in desc or k in mfr for k in ESP32_KEYWORDS):
            found.append(p.device)
    return found


# --- Status Orb ---
class StatusOrb(tk.Canvas):
    def __init__(self, parent, size=18, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=C_BG, highlightthickness=0, **kw)
        self._size  = size
        self._color = C_RED
        self._alpha = 1.0
        self._dir   = -1
        self._orb   = None
        self._draw()
        self._animate()

    def _draw(self):
        s, p = self._size, 2
        self.delete("all")
        self.create_oval(p, p, s-p, s-p, outline=self._color, width=1, fill="")
        self._orb = self.create_oval(p+3, p+3, s-p-3, s-p-3,
                                     fill=self._color, outline="")

    def _animate(self):
        self._alpha += self._dir * 0.06
        if self._alpha <= 0.2:
            self._dir = 1
        elif self._alpha >= 1.0:
            self._dir = -1
        h = self._color.lstrip("#")
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        dim = f"#{int(r*self._alpha):02x}{int(g*self._alpha):02x}{int(b*self._alpha):02x}"
        if self._orb:
            self.itemconfig(self._orb, fill=dim)
        self.after(50, self._animate)

    def set_color(self, c):
        self._color = c
        self._draw()


# --- Event Feed ---
class EventFeed(ctk.CTkFrame):
    def __init__(self, parent, **kw):
        super().__init__(parent, fg_color=C_PANEL, corner_radius=8, **kw)
        self._t = tk.Text(self, bg=C_BG, fg=C_TEXT, font=FONT_MONO,
                          insertbackground=C_ACCENT, relief="flat", bd=0,
                          state="disabled", wrap="word",
                          selectbackground=C_BORDER, selectforeground=C_TEXT)
        sby = ctk.CTkScrollbar(self, command=self._t.yview,
                               fg_color=C_PANEL, button_color=C_ACCENT2)
        sbx = ctk.CTkScrollbar(self, command=self._t.xview,
                               orientation="horizontal",
                               fg_color=C_PANEL, button_color=C_ACCENT2)
        self._t.configure(yscrollcommand=sby.set, xscrollcommand=sbx.set)
        sby.pack(side="right", fill="y")
        sbx.pack(side="bottom", fill="x")
        self._t.pack(fill="both", expand=True, padx=4, pady=4)
        for tag, col in [("GRANTED", C_GREEN), ("DENIED", C_RED),
                         ("WARN", C_YELLOW), ("INFO", C_ACCENT),
                         ("DIM", C_TEXT_DIM), ("SYS", C_PURPLE),
                         ("FP", C_FP)]:
            self._t.tag_config(tag, foreground=col)

    def add(self, msg, tag="INFO"):
        ts = dt.now().strftime("%H:%M:%S")
        self._t.configure(state="normal")
        self._t.insert("end", f"[{ts}] ", "DIM")
        self._t.insert("end", msg + "\n", tag)
        self._t.see("end")
        self._t.configure(state="disabled")

    def clear(self):
        self._t.configure(state="normal")
        self._t.delete("1.0", "end")
        self._t.configure(state="disabled")


# --- FINGERPRINT STATUS WIDGET ---
class FingerprintStatusWidget(ctk.CTkFrame):
    STATUS_LABELS = {
        "ready":             ("READY",          C_GREEN),
        "finger_detected":   ("DETECTING",       C_YELLOW),
        "no_match":          ("NO MATCH",         C_RED),
        "sensor_offline":    ("OFFLINE",          C_TEXT_MUTE),
        "enroll_place":      ("PLACE FINGER",    C_YELLOW),
        "enroll_remove":     ("REMOVE FINGER",   C_ACCENT),
        "enroll_done":       ("ENROLLED",         C_GREEN),
        "enroll_failed":     ("ENROLL FAILED",    C_RED),
        "enroll_cancelled":  ("CANCELLED",        C_TEXT_DIM),
    }

    def __init__(self, parent, **kw):
        super().__init__(parent, fg_color=C_PANEL, corner_radius=10,
                         border_width=1, border_color=C_BORDER, **kw)

        hdr = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=8)
        hdr.pack(fill="x", padx=1, pady=(1, 0))
        ctk.CTkLabel(hdr, text="FINGERPRINT SENSOR  R307S",
                     font=FONT_MICRO_B, text_color=C_FP
                     ).pack(side="left", padx=10, pady=6)
        self._orb = StatusOrb(hdr, size=12)
        self._orb.pack(side="right", padx=8)
        self._orb.set_color(C_TEXT_MUTE)

        sr = ctk.CTkFrame(self, fg_color="transparent")
        sr.pack(fill="x", padx=10, pady=(6, 2))
        ctk.CTkLabel(sr, text="STATUS:", font=FONT_MICRO,
                     text_color=C_TEXT_MUTE, width=65, anchor="w"
                     ).pack(side="left")
        self._status_lbl = ctk.CTkLabel(sr, text="OFFLINE",
                                         font=FONT_MICRO_B,
                                         text_color=C_TEXT_MUTE)
        self._status_lbl.pack(side="left", padx=6)

        lr = ctk.CTkFrame(self, fg_color="transparent")
        lr.pack(fill="x", padx=10, pady=(0, 2))
        ctk.CTkLabel(lr, text="LAST:", font=FONT_MICRO,
                     text_color=C_TEXT_MUTE, width=65, anchor="w"
                     ).pack(side="left")
        self._last_lbl = ctk.CTkLabel(lr, text="-",
                                       font=FONT_MICRO, text_color=C_TEXT_DIM)
        self._last_lbl.pack(side="left", padx=6)

        cr = ctk.CTkFrame(self, fg_color="transparent")
        cr.pack(fill="x", padx=10, pady=(0, 6))
        ctk.CTkLabel(cr, text="INFO:", font=FONT_MICRO,
                     text_color=C_TEXT_MUTE, width=65, anchor="w"
                     ).pack(side="left")
        self._info_lbl = ctk.CTkLabel(cr, text="Sensor initializing...",
                                       font=FONT_MICRO, text_color=C_TEXT_MUTE)
        self._info_lbl.pack(side="left", padx=6)

    def update_status(self, status: str, extra: dict = None):
        extra = extra or {}
        label, color = self.STATUS_LABELS.get(status, (status.upper(), C_TEXT_DIM))
        self._status_lbl.configure(text=label, text_color=color)
        self._orb.set_color(color)

        ts = dt.now().strftime("%H:%M:%S")
        if status == "ready":
            cnt = extra.get("count", "?")
            self._info_lbl.configure(
                text=f"{cnt} fingerprints enrolled in sensor", text_color=C_TEXT_DIM)
            self._last_lbl.configure(text=f"Boot  {ts}", text_color=C_TEXT_DIM)
        elif status == "no_match":
            reason = extra.get("reason", "")
            self._last_lbl.configure(text=f"No match  {ts}", text_color=C_RED)
            self._info_lbl.configure(text=reason if reason else "Unknown fingerprint",
                                      text_color=C_TEXT_DIM)
        elif status == "finger_detected":
            self._last_lbl.configure(text=f"Finger detected  {ts}", text_color=C_YELLOW)
        elif status == "enroll_place":
            fid = extra.get("id", "?")
            self._info_lbl.configure(text=f"Enrolling ID:{fid} - place finger on sensor",
                                      text_color=C_YELLOW)
            self._last_lbl.configure(text=f"Enrolling  {ts}", text_color=C_YELLOW)
        elif status == "enroll_remove":
            fid = extra.get("id", "?")
            self._info_lbl.configure(text=f"ID:{fid} - remove finger, then place again",
                                      text_color=C_ACCENT)
        elif status == "enroll_done":
            fid  = extra.get("id", "?")
            name = extra.get("name", "")
            fl   = extra.get("floor", "?")
            self._last_lbl.configure(text=f"Enrolled  {ts}", text_color=C_GREEN)
            self._info_lbl.configure(
                text=f"ID:{fid}  {name}  Floor {fl}", text_color=C_GREEN)
        elif status == "enroll_failed":
            msg = extra.get("msg", "")
            self._last_lbl.configure(text=f"Failed  {ts}", text_color=C_RED)
            self._info_lbl.configure(text=msg if msg else "Enrollment failed",
                                      text_color=C_TEXT_DIM)
        elif status == "sensor_offline":
            self._info_lbl.configure(text="Check wiring: Red->5V  Blk->GND  Ylw->G16  Grn->G19",
                                      text_color=C_TEXT_MUTE)
            self._last_lbl.configure(text="Offline", text_color=C_TEXT_MUTE)

        if status in ("finger_detected", "no_match"):
            self.after(3000, lambda: self._soft_reset())

    def update_from_fp_scan(self, name: str, fp_id: int, confidence: int,
                             granted: bool, direction: str):
        ts = dt.now().strftime("%H:%M:%S")
        res_color = C_GREEN if granted else C_RED
        res_text  = "GRANTED" if granted else "DENIED"
        self._status_lbl.configure(text=res_text,
                                    text_color=res_color)
        self._orb.set_color(res_color)
        self._last_lbl.configure(text=f"{name}  {direction.upper()}  {ts}",
                                  text_color=res_color)
        self._info_lbl.configure(
            text=f"ID:{fp_id}  Confidence: {confidence}/300",
            text_color=C_TEXT_DIM)
        self.after(4000, lambda: self._soft_reset())

    def _soft_reset(self):
        self._status_lbl.configure(text="READY", text_color=C_GREEN)
        self._orb.set_color(C_GREEN)


# --- Face Capture + Model Training ---
def _run_model_training(log_cb=None):
    try:
        from imutils import paths as imutils_paths
    except ImportError:
        msg = "imutils not installed – run: pip install imutils"
        if log_cb: log_cb(msg)
        return False, msg

    if not FACE_RECOG_AVAILABLE:
        msg = "face_recognition not available – cannot train."
        if log_cb: log_cb(msg)
        return False, msg

    dataset_dir = "dataset"
    if not os.path.isdir(dataset_dir):
        msg = f"Dataset folder '{dataset_dir}' not found."
        if log_cb: log_cb(msg)
        return False, msg

    image_paths = list(imutils_paths.list_images(dataset_dir))
    if not image_paths:
        msg = "No images found in dataset/."
        if log_cb: log_cb(msg)
        return False, msg

    if log_cb: log_cb(f"Training on {len(image_paths)} image(s)…")

    known_encodings, known_names = [], []
    for i, img_path in enumerate(image_paths, 1):
        person_name = img_path.split(os.path.sep)[-2]
        if log_cb: log_cb(f"  [{i}/{len(image_paths)}]  {person_name}  ← {os.path.basename(img_path)}")
        img = cv2.imread(img_path)
        if img is None:
            if log_cb: log_cb(f"    ⚠ Could not read image, skipping.")
            continue
        rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        boxes     = face_recognition.face_locations(rgb, model="hog")
        encodings = face_recognition.face_encodings(rgb, boxes)
        for enc in encodings:
            known_encodings.append(enc)
            known_names.append(person_name)

    if not known_encodings:
        msg = "No faces found in any dataset image – training aborted."
        if log_cb: log_cb(msg)
        return False, msg

    data = {"encodings": known_encodings, "names": known_names}
    try:
        with open("encodings.pickle", "wb") as fh:
            fh.write(pickle.dumps(data))
    except Exception as e:
        msg = f"Failed to save encodings.pickle: {e}"
        if log_cb: log_cb(msg)
        return False, msg

    global known_face_encodings, known_face_names
    known_face_encodings = known_encodings
    known_face_names     = known_names

    msg = (f"✔ Training complete — {len(known_encodings)} encoding(s) "
           f"for {len(set(known_names))} person(s) saved to encodings.pickle")
    if log_cb: log_cb(msg)
    return True, msg


class FaceCaptureDialog:
    DATASET_DIR = "dataset"

    def __init__(self, parent, person_name: str, feed=None):
        self._name        = person_name.strip()
        self._feed        = feed
        self._running     = False
        self._photo_count = 0
        self._picam: "Picamera2 | None" = None
        self._cam_active  = False
        self._closing     = False

        self._win = ctk.CTkToplevel(parent)
        self._win.title(f"Face Capture  –  {self._name}")
        self._win.geometry("780x680")
        self._win.configure(fg_color=C_BG)
        self._win.protocol("WM_DELETE_WINDOW", self._on_close)
        self._win.after(150, self._safe_grab)

        hdr = ctk.CTkFrame(self._win, fg_color=C_PANEL2, corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text=f"FACE CAPTURE  —  {self._name.upper()}",
                     font=FONT_HEAD, text_color=C_ACCENT).pack(side="left", padx=16, pady=10)
        self._count_lbl = ctk.CTkLabel(hdr, text="Photos: 0",
                                        font=FONT_SMALL, text_color=C_GREEN)
        self._count_lbl.pack(side="right", padx=16)

        ctrl = ctk.CTkFrame(self._win, fg_color=C_PANEL2, corner_radius=0, height=52)
        ctrl.pack(side="bottom", fill="x")
        ctrl.pack_propagate(False)

        ctk.CTkButton(ctrl, text="📷  CAPTURE  (SPACE)", width=200, height=36,
                      fg_color="#003A1A", hover_color=C_GREEN,
                      font=FONT_HEAD, text_color=C_GREEN,
                      command=self._capture).pack(side="left", padx=14, pady=8)

        ctk.CTkButton(ctrl, text="✔  DONE + TRAIN", width=180, height=36,
                      fg_color=C_ACCENT2, hover_color=C_ACCENT,
                      font=FONT_HEAD, text_color=C_BG,
                      command=self._on_close).pack(side="left", padx=4, pady=8)

        ctk.CTkLabel(ctrl,
                     text="SPACE = capture  |  Close / Done = save & train",
                     font=FONT_SMALL, text_color=C_TEXT_MUTE
                     ).pack(side="right", padx=16)

        self._cam_label = ctk.CTkLabel(self._win,
                                        text="Starting camera…",
                                        font=FONT_HEAD, text_color=C_TEXT_DIM,
                                        fg_color=C_PANEL, corner_radius=8)
        self._cam_label.pack(fill="both", expand=True, padx=14, pady=8)

        self._win.bind("<space>", lambda e: self._capture())

        self._log_frame = ctk.CTkFrame(self._win, fg_color=C_PANEL, corner_radius=8)
        self._log_box = ctk.CTkTextbox(self._log_frame, font=FONT_MONO,
                                        text_color=C_TEXT_DIM, fg_color=C_BG,
                                        state="disabled", height=200)
        self._log_box.pack(fill="both", expand=True, padx=8, pady=8)

        self._ensure_dataset_folder()
        self._init_camera()

    def _safe_grab(self):
        try:
            self._win.lift()
            self._win.focus_force()
            self._win.grab_set()
        except tk.TclError:
            self._win.after(150, self._safe_grab)

    def _ensure_dataset_folder(self):
        person_dir = os.path.join(self.DATASET_DIR, self._name)
        os.makedirs(person_dir, exist_ok=True)
        self._save_dir = person_dir

    def _init_camera(self):
        if not PICAMERA_AVAILABLE:
            self._cam_label.configure(
                text="picamera2 not available.\nCannot capture photos.")
            return
        # Run in background so the dialog renders immediately; retry once if
        # the Camera surveillance page was just using the hardware.
        threading.Thread(target=self._init_camera_bg, daemon=True).start()

    def _init_camera_bg(self):
        """Background thread: open camera 0 with one automatic retry."""
        def _try_open():
            cam = Picamera2(0)
            cfg = cam.create_preview_configuration(
                main={"format": "XRGB8888", "size": (640, 480)})
            cam.configure(cfg)
            cam.start()
            return cam

        cam = None
        for attempt in range(2):
            try:
                cam = _try_open()
                logging.info("Initialization successful.")
                logging.info("Camera now open.")
                break
            except Exception as e:
                logging.error(f"FaceCaptureDialog camera error (attempt {attempt+1}): {e}")
                if attempt == 0:
                    logging.info("Retrying camera open in 2 s...")
                    time.sleep(2.0)

        if cam is None:
            try:
                self._win.after(0, lambda: self._cam_label.configure(
                    text="Camera unavailable.\n\n"
                         "The surveillance camera page may still be using it.\n"
                         "Navigate away from the Camera page first,\n"
                         "then reopen Face Capture."))
            except Exception:
                pass
            return

        self._picam = cam
        self._cam_active = True
        self._running = True
        threading.Thread(target=self._feed_loop, daemon=True).start()

    def _feed_loop(self):
        while self._running:
            try:
                frame = self._picam.capture_array()
                frame = cv2.cvtColor(frame, cv2.COLOR_RGBA2RGB)
                frame = cv2.flip(frame, 1)

                h, w = frame.shape[:2]
                cx, cy = w // 2, h // 2
                cv2.ellipse(frame, (cx, cy), (110, 145), 0, 0, 360,
                            (0, 255, 180), 2, cv2.LINE_AA)
                cv2.putText(frame, f"Photos taken: {self._photo_count}",
                            (12, h - 14), cv2.FONT_HERSHEY_SIMPLEX,
                            0.65, (0, 230, 130), 2)

                rgb      = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                pil_img  = Image.fromarray(rgb)
                img      = ImageTk.PhotoImage(pil_img)
                try:
                    self._cam_label.configure(image=img, text="")
                    self._cam_label.image = img
                except tk.TclError:
                    break
                time.sleep(0.033)
            except Exception as e:
                logging.error(f"FaceCapture feed loop: {e}")
                time.sleep(0.5)

    def _capture(self):
        if not self._cam_active or not self._picam:
            return
        try:
            frame = self._picam.capture_array()
            frame = cv2.cvtColor(frame, cv2.COLOR_RGBA2RGB)
            frame = cv2.flip(frame, 1)
            self._photo_count += 1
            ts       = dt.now().strftime("%Y%m%d_%H%M%S_%f")
            filename = f"{self._name}_{ts}.jpg"
            filepath = os.path.join(self._save_dir, filename)
            cv2.imwrite(filepath, frame)
            self._count_lbl.configure(text=f"Photos: {self._photo_count}")
            logging.info(f"Face photo saved: {filepath}")
        except Exception as e:
            logging.error(f"Face capture error: {e}")

    def _on_close(self):
        if self._closing:
            return
        self._closing = True
        self._running = False

        if self._picam:
            try:
                self._picam.stop()
                self._picam.close()
            except Exception:
                pass
            self._picam = None

        if self._photo_count == 0:
            self._win.destroy()
            return

        self._cam_label.pack_forget()
        self._log_frame.pack(fill="both", expand=True, padx=14, pady=8)
        self._log("─" * 50)
        self._log(f"Captured {self._photo_count} photo(s) for '{self._name}'.")
        self._log("Starting model training…")

        if self._feed:
            self._feed.add(
                f"Face capture done: {self._photo_count} photo(s) for "
                f"{self._name}. Training model…", "INFO")

        self._win.protocol("WM_DELETE_WINDOW", lambda: None)

        threading.Thread(target=self._train_bg, daemon=True).start()

    def _train_bg(self):
        ok, msg = _run_model_training(log_cb=self._log)
        if self._feed:
            self._feed.add(f"Model training: {msg}", "INFO" if ok else "WARN")
        self._win.after(0, self._add_close_btn)

    def _add_close_btn(self):
        self._win.protocol("WM_DELETE_WINDOW", self._win.destroy)
        ctk.CTkButton(self._log_frame, text="✔  CLOSE", width=140, height=34,
                      fg_color=C_ACCENT2, hover_color=C_ACCENT,
                      font=FONT_HEAD, text_color=C_BG,
                      command=self._win.destroy
                      ).pack(pady=(0, 10))

    def _log(self, text: str):
        def _do():
            try:
                self._log_box.configure(state="normal")
                self._log_box.insert("end", text + "\n")
                self._log_box.see("end")
                self._log_box.configure(state="disabled")
            except tk.TclError:
                pass
        try:
            self._win.after(0, _do)
        except Exception:
            pass


# --- PERSONNEL MANAGER (ALL DIALOGS FIXED) ---
class PersonnelManager(ctk.CTkFrame):
    def __init__(self, parent, ctrl, feed, **kw):
        super().__init__(parent, fg_color="transparent", **kw)
        self.ctrl  = ctrl
        self.feed  = feed
        self._personnel: dict = {}
        self._cards: list     = []
        self._fp_records: list = []
        self._awaiting_rfid_for: str = ""
        self._build()

    def _build(self):
        bar = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=8)
        bar.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(bar, text="PERSONNEL",
                     font=FONT_HEAD, text_color=C_ACCENT
                     ).pack(side="left", padx=12, pady=8)
        ctk.CTkButton(bar, text="+ ADD EMPLOYEE", width=140, height=32,
                      fg_color="#003A1A", hover_color=C_GREEN,
                      font=FONT_SMALL, text_color=C_GREEN,
                      command=self._add_dialog
                      ).pack(side="left", padx=6, pady=6)
        ctk.CTkButton(bar, text="REFRESH", width=90, height=32,
                      fg_color=C_ACCENT2, hover_color=C_ACCENT,
                      font=FONT_SMALL, text_color=C_BG,
                      command=self.refresh
                      ).pack(side="left", padx=4, pady=6)
        ctk.CTkButton(bar, text="FP CANCEL", width=100, height=32,
                      fg_color="#2A1A00", hover_color=C_YELLOW,
                      font=FONT_SMALL, text_color=C_YELLOW,
                      command=lambda: self.ctrl.send_fp_cancel()
                      ).pack(side="left", padx=4, pady=6)
        ctk.CTkButton(bar, text="🧠 TRAIN MODEL", width=130, height=32,
                      fg_color="#1A0A2A", hover_color=C_PURPLE,
                      font=FONT_SMALL, text_color=C_PURPLE,
                      command=self._train_model_dialog
                      ).pack(side="left", padx=4, pady=6)

        self._mode_var = tk.StringVar(value="Normal")
        ctk.CTkLabel(bar, text="RFID MODE:", font=FONT_SMALL,
                     text_color=C_TEXT_DIM).pack(side="right", padx=(0, 4), pady=6)
        ctk.CTkOptionMenu(bar, variable=self._mode_var,
                          values=["Normal", "Manual Capture"],
                          width=155, height=32, font=FONT_SMALL,
                          fg_color=C_PANEL, button_color=C_ACCENT2,
                          button_hover_color=C_ACCENT, text_color=C_TEXT,
                          command=self._set_mode
                          ).pack(side="right", padx=8, pady=6)

        leg = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=6)
        leg.pack(fill="x", pady=(0, 4))
        for txt, col in [
            ("Enrolled", C_GREEN),
            ("Missing - access BLOCKED", C_RED),
            ("Incomplete employee", C_YELLOW),
            ("READY = full access enabled", C_ACCENT),
        ]:
            ctk.CTkLabel(leg, text=txt, font=FONT_MICRO,
                         text_color=col).pack(side="left", padx=12, pady=5)
        self._count_lbl = ctk.CTkLabel(leg, text="0 employees",
                                        font=FONT_SMALL, text_color=C_TEXT_DIM)
        self._count_lbl.pack(side="right", padx=12)

        hdr = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=5)
        hdr.pack(fill="x", pady=(0, 2))
        for lbl_txt, w in [("NAME", 195), ("FL", 55), ("RFID CARD", 230),
                            ("FINGERPRINT", 200), ("ACTIONS", 330)]:
            ctk.CTkLabel(hdr, text=lbl_txt, font=FONT_MICRO,
                         text_color=C_TEXT_MUTE, width=w, anchor="w"
                         ).pack(side="left", padx=(8, 0), pady=4)

        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color=C_BG, corner_radius=8,
            scrollbar_button_color=C_ACCENT2,
            scrollbar_button_hover_color=C_ACCENT)
        self._scroll.pack(fill="both", expand=True)

    def _set_mode(self, choice):
        m = {"Normal": 0, "Manual Capture": 2}.get(choice, 0)
        self.ctrl.send_mode(m)
        self.feed.add(f"RFID mode -> {choice}", "INFO")

    def refresh(self):
        self.ctrl.send_list_cards()
        self.ctrl.send_fp_list()

    def populate(self, cards: list):
        self._cards = cards
        for c in cards:
            name = (c.get("name") or "").strip()
            if not name:
                continue
            key = name.lower()
            rec = self._personnel.setdefault(key, {
                "name": name, "floor": 1, "rfid_uid": "", "fp_id": None})
            rec["rfid_uid"] = c.get("uid", "").strip().upper()
            rec["floor"]    = int(c.get("floor", rec.get("floor", 1)))
        self._rebuild()

    def populate_fp(self, records: list):
        self._fp_records = records
        for r in records:
            name = (r.get("name") or "").strip()
            if not name:
                continue
            key = name.lower()
            rec = self._personnel.setdefault(key, {
                "name": name, "floor": 1, "rfid_uid": "", "fp_id": None})
            rec["fp_id"] = r.get("id")
            rec["floor"] = int(r.get("floor", rec.get("floor", 1)))
        self._rebuild()

    def show_captured(self, uid: str):
        uid = uid.strip().upper()
        if self._awaiting_rfid_for:
            self._do_assign_rfid(self._awaiting_rfid_for, uid)
            self._awaiting_rfid_for = ""
            self._mode_var.set("Normal")
            self.ctrl.send_mode(0)
        else:
            self._assign_uid_dialog(uid)

    def _do_assign_rfid(self, name: str, uid: str):
        key   = name.lower()
        floor = self._personnel.get(key, {}).get("floor", 1)
        self.ctrl.send_add(uid, floor, name)
        if key in self._personnel:
            self._personnel[key]["rfid_uid"] = uid
        self.feed.add(f"RFID -> {name}  (Floor {floor}): {uid}", "INFO")
        self.after(700, self.refresh)

    def _assign_uid_dialog(self, uid: str):
        d = ctk.CTkToplevel(self.winfo_toplevel())
        d.title("Assign Captured RFID")
        d.geometry("460x320")
        d.configure(fg_color=C_PANEL)
        # FIXED: safe grab
        d.after(100, lambda: (d.lift(), d.grab_set(), d.focus_force()))

        ctk.CTkLabel(d, text="ASSIGN RFID CARD",
                     font=FONT_HEAD, text_color=C_ACCENT).pack(pady=(18, 4))
        ctk.CTkLabel(d, text=f"Captured UID:  {uid}",
                     font=FONT_MONO, text_color=C_YELLOW).pack(pady=(0, 10))
        ctk.CTkLabel(d, text="Select employee to assign this card to:",
                     font=FONT_SMALL, text_color=C_TEXT_DIM).pack()
        names = [p["name"] for p in self._personnel.values()
                 if not p.get("rfid_uid")]
        if not names:
            names = [p["name"] for p in self._personnel.values()]
        if not names:
            messagebox.showinfo("No Employees",
                                "Add employees first, then scan RFID.",
                                parent=d)
            d.destroy()
            return
        sel_var = tk.StringVar(value=names[0])
        ctk.CTkOptionMenu(d, variable=sel_var, values=names,
                          width=300, font=FONT_MONO,
                          fg_color=C_BG, button_color=C_ACCENT2,
                          text_color=C_TEXT).pack(pady=14)

        def do_assign():
            self._do_assign_rfid(sel_var.get(), uid)
            self._mode_var.set("Normal")
            self.ctrl.send_mode(0)
            d.destroy()

        br = ctk.CTkFrame(d, fg_color="transparent")
        br.pack(pady=10)
        ctk.CTkButton(br, text="ASSIGN", width=110,
                      fg_color=C_ACCENT2, hover_color=C_ACCENT,
                      text_color=C_BG, font=FONT_HEAD,
                      command=do_assign).pack(side="left", padx=8)
        ctk.CTkButton(br, text="CANCEL", width=90,
                      fg_color=C_PANEL2, hover_color=C_BORDER,
                      text_color=C_TEXT_DIM, font=FONT_HEAD,
                      command=d.destroy).pack(side="left", padx=8)

    def _add_dialog(self):
        d = ctk.CTkToplevel(self.winfo_toplevel())
        d.title("Add Employee")
        d.geometry("480x360")
        d.configure(fg_color=C_PANEL)
        # FIXED: safe grab
        d.after(100, lambda: (d.lift(), d.grab_set(), d.focus_force()))

        ctk.CTkLabel(d, text="ADD NEW EMPLOYEE",
                     font=FONT_HEAD, text_color=C_ACCENT).pack(pady=(18, 4))
        ctk.CTkLabel(d,
                     text="Use the EXACT same name when enrolling RFID and FP.\n"
                          "Name is how the system links them together.",
                     font=FONT_SMALL, text_color=C_YELLOW, justify="center"
                     ).pack(pady=(0, 14))
        form = ctk.CTkFrame(d, fg_color="transparent")
        form.pack(padx=30, fill="x")

        ctk.CTkLabel(form, text="Full Name:", font=FONT_SMALL,
                     text_color=C_TEXT_DIM, anchor="w"
                     ).grid(row=0, column=0, sticky="w", pady=4)
        name_e = ctk.CTkEntry(form, font=FONT_MONO, fg_color=C_BG,
                               border_color=C_ACCENT2, text_color=C_TEXT, width=300)
        name_e.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        name_e.focus()

        ctk.CTkLabel(form, text="Assigned Floor (1-4):", font=FONT_SMALL,
                     text_color=C_TEXT_DIM, anchor="w"
                     ).grid(row=2, column=0, sticky="w", pady=4)
        fv = tk.StringVar(value="2")
        ctk.CTkOptionMenu(form, variable=fv, values=["1", "2", "3", "4"],
                          fg_color=C_BG, button_color=C_ACCENT2,
                          text_color=C_TEXT, font=FONT_MONO, width=80
                          ).grid(row=3, column=0, sticky="w")

        def do_add():
            name  = name_e.get().strip()
            floor = int(fv.get())
            if not name:
                messagebox.showwarning("Missing", "Name is required.", parent=d)
                return
            key = name.lower()
            if key in self._personnel:
                messagebox.showwarning("Duplicate",
                                       f"'{name}' already exists.", parent=d)
                return
            self._personnel[key] = {
                "name": name, "floor": floor, "rfid_uid": "", "fp_id": None}
            self._rebuild()
            self.feed.add(
                f"Employee added: {name}  Floor {floor}  - now assign RFID and FP",
                "INFO")
            d.destroy()

        br = ctk.CTkFrame(d, fg_color="transparent")
        br.pack(pady=16)
        ctk.CTkButton(br, text="ADD", width=100,
                      fg_color=C_ACCENT2, hover_color=C_ACCENT,
                      text_color=C_BG, font=FONT_HEAD,
                      command=do_add).pack(side="left", padx=8)
        ctk.CTkButton(br, text="CANCEL", width=100,
                      fg_color=C_PANEL2, hover_color=C_BORDER,
                      text_color=C_TEXT_DIM, font=FONT_HEAD,
                      command=d.destroy).pack(side="left", padx=8)

    def _delete_person(self, key: str):
        rec = self._personnel.get(key)
        if not rec:
            return
        if not messagebox.askyesno(
            "Confirm Delete",
            f"Delete {rec['name']}?\n\n"
            "This removes their RFID card AND fingerprint from the sensor.",
            parent=self.winfo_toplevel()):
            return
        if rec.get("rfid_uid"):
            self.ctrl.send_del(rec["rfid_uid"])
        if rec.get("fp_id") is not None:
            self.ctrl.send_fp_delete(rec["fp_id"])
        del self._personnel[key]
        self.feed.add(f"Employee deleted: {rec['name']}", "WARN")
        self.after(700, self.refresh)
        self._rebuild()

    def _start_rfid_capture(self, name: str):
        self._awaiting_rfid_for = name
        self._mode_var.set("Manual Capture")
        self.ctrl.send_mode(2)
        self.feed.add(f"Waiting for RFID scan for: {name}", "WARN")
        messagebox.showinfo(
            "Scan RFID Card",
            f"Place the RFID card for:\n\n  {name}\n\non any floor reader now.",
            parent=self.winfo_toplevel())

    def _start_fp_enroll(self, name: str, floor: int):
        used_ids = {r.get("id") for r in self._fp_records
                    if r.get("id") is not None}
        fp_id = next((i for i in range(1, 128) if i not in used_ids), None)
        if fp_id is None:
            messagebox.showerror("Full",
                                  "Fingerprint sensor is full (127 templates max).",
                                  parent=self.winfo_toplevel())
            return
        self.ctrl.send_fp_enroll(fp_id, floor, name)
        self.feed.add(
            f"FP enrollment: ID:{fp_id}  {name}  Floor {floor} - place finger on sensor",
            "FP")
        messagebox.showinfo(
            "Enroll Fingerprint",
            f"Enrolling fingerprint for:\n\n  {name}  (Floor {floor})\n  FP Slot: {fp_id}\n\n"
            "1. Place finger on sensor\n"
            "2. Remove when prompted\n"
            "3. Place finger again to confirm",
            parent=self.winfo_toplevel())

    def _open_face_capture(self, name: str):
        # Stop surveillance cameras first (they hold the hardware), then open
        # the dialog.  stop() does a blocking thread-join so we run it in a
        # worker thread and open the dialog on the Tk event loop afterwards.
        app = self.winfo_toplevel()
        camera_page = getattr(app, '_camera_page', None)

        def _do_open():
            if camera_page:
                try:
                    camera_page.stop()   # releases Picamera2 objects
                except Exception:
                    pass
                time.sleep(0.3)          # let libcamera driver fully settle
            # Marshal dialog creation back to the main thread
            try:
                self.after(0, lambda: FaceCaptureDialog(
                    self.winfo_toplevel(), person_name=name, feed=self.feed))
            except Exception:
                pass

        threading.Thread(target=_do_open, daemon=True).start()

    def _train_model_dialog(self):
        d = ctk.CTkToplevel(self.winfo_toplevel())
        d.title("Train Face Recognition Model")
        d.geometry("620x420")
        d.configure(fg_color=C_BG)
        # FIXED: safe grab
        d.after(100, lambda: (d.lift(), d.grab_set(), d.focus_force()))

        ctk.CTkLabel(d, text="🧠  TRAIN FACE RECOGNITION MODEL",
                     font=FONT_HEAD, text_color=C_PURPLE).pack(pady=(18, 6))
        ctk.CTkLabel(d, text="Reads all images in dataset/ and rebuilds encodings.pickle",
                     font=FONT_SMALL, text_color=C_TEXT_DIM).pack(pady=(0, 12))

        log_box = ctk.CTkTextbox(d, font=FONT_MONO, text_color=C_TEXT_DIM,
                                  fg_color=C_PANEL, state="disabled", height=260)
        log_box.pack(fill="both", expand=True, padx=16, pady=4)

        btn_row = ctk.CTkFrame(d, fg_color="transparent")
        btn_row.pack(pady=10)
        start_btn = ctk.CTkButton(btn_row, text="START TRAINING", width=160, height=34,
                                   fg_color="#1A0A2A", hover_color=C_PURPLE,
                                   font=FONT_HEAD, text_color=C_PURPLE)
        start_btn.pack(side="left", padx=8)
        ctk.CTkButton(btn_row, text="CLOSE", width=100, height=34,
                      fg_color=C_PANEL2, hover_color=C_BORDER,
                      font=FONT_HEAD, text_color=C_TEXT_DIM,
                      command=d.destroy).pack(side="left", padx=8)

        def _log(text):
            def _do():
                try:
                    log_box.configure(state="normal")
                    log_box.insert("end", text + "\n")
                    log_box.see("end")
                    log_box.configure(state="disabled")
                except tk.TclError:
                    pass
            try: d.after(0, _do)
            except Exception: pass

        def _start():
            start_btn.configure(state="disabled", text="Training…")
            _log("─" * 50)
            _log("Starting training…")
            self.feed.add("Manual model training started.", "INFO")
            def _bg():
                ok, msg = _run_model_training(log_cb=_log)
                tag = "INFO" if ok else "WARN"
                self.feed.add(f"Training: {msg}", tag)
                try:
                    d.after(0, lambda: start_btn.configure(
                        state="normal", text="TRAIN AGAIN"))
                except Exception:
                    pass
            threading.Thread(target=_bg, daemon=True).start()

        start_btn.configure(command=_start)

    def _rebuild(self):
        for w in self._scroll.winfo_children():
            w.destroy()
        for key, rec in sorted(self._personnel.items()):
            self._pack_row(key, rec)
        n = len(self._personnel)
        self._count_lbl.configure(
            text=f"{n} employee{'s' if n != 1 else ''}")

    def _pack_row(self, key: str, rec: dict):
        has_rfid = bool(rec.get("rfid_uid"))
        has_fp   = rec.get("fp_id") is not None
        complete = has_rfid and has_fp
        row_bg   = C_PANEL if complete else "#0F0900"
        border   = (FLOOR_COLORS[min(int(rec.get("floor", 1))-1, 3)]
                    if complete else C_RED)

        row = ctk.CTkFrame(self._scroll, fg_color=row_bg, corner_radius=7,
                           border_width=1, border_color=border)
        row.pack(fill="x", padx=4, pady=3)

        ctk.CTkLabel(row, text=rec["name"][:24], font=FONT_SMALL,
                     text_color=C_TEXT, width=195, anchor="w"
                     ).pack(side="left", padx=(10, 0), pady=10)

        fi   = max(0, min(3, int(rec.get("floor", 1)) - 1))
        fcol = FLOOR_COLORS[fi]
        ctk.CTkLabel(row, text=f"F{rec.get('floor', '?')}",
                     font=(FONT_BODY[0], FONT_BODY[1], "bold"),
                     text_color=fcol, width=55, anchor="center"
                     ).pack(side="left", padx=4, pady=10)

        if has_rfid:
            rtxt = f"OK  {rec['rfid_uid'][:18]}"
            rcol = C_GREEN
        else:
            rtxt = "Not assigned"
            rcol = C_RED
        ctk.CTkLabel(row, text=rtxt, font=FONT_MONO,
                     text_color=rcol, width=230, anchor="w"
                     ).pack(side="left", padx=4, pady=10)

        if has_fp:
            ftxt  = f"OK  Slot {rec['fp_id']}"
            fcol2 = C_FP
        else:
            ftxt  = "Not enrolled"
            fcol2 = C_RED
        ctk.CTkLabel(row, text=ftxt, font=FONT_MONO,
                     text_color=fcol2, width=200, anchor="w"
                     ).pack(side="left", padx=4, pady=10)

        act = ctk.CTkFrame(row, fg_color="transparent")
        act.pack(side="left", padx=6, pady=6)

        rfid_lbl = "RE-SCAN RFID" if has_rfid else "SCAN RFID"
        rfid_col = C_PANEL2 if has_rfid else C_ACCENT2
        rfid_tc  = C_TEXT_DIM if has_rfid else C_BG
        ctk.CTkButton(act, text=rfid_lbl, width=110, height=28,
                      fg_color=rfid_col, hover_color=C_ACCENT,
                      font=FONT_MICRO_B, text_color=rfid_tc,
                      command=lambda n=rec["name"]: self._start_rfid_capture(n)
                      ).pack(side="left", padx=2)

        fp_lbl = "RE-ENROLL FP" if has_fp else "ENROLL FP"
        fp_col = C_PANEL2 if has_fp else "#1A0A2A"
        fp_tc  = C_TEXT_DIM if has_fp else C_FP
        ctk.CTkButton(act, text=fp_lbl, width=110, height=28,
                      fg_color=fp_col, hover_color=C_FP,
                      font=FONT_MICRO_B, text_color=fp_tc,
                      command=lambda n=rec["name"], f=rec.get("floor", 1):
                          self._start_fp_enroll(n, f)
                      ).pack(side="left", padx=2)

        ctk.CTkButton(act, text="DELETE", width=72, height=28,
                      fg_color="#3A0010", hover_color=C_RED,
                      font=FONT_MICRO_B, text_color=C_RED,
                      command=lambda k=key: self._delete_person(k)
                      ).pack(side="left", padx=2)

        ctk.CTkButton(act, text="📷 FACE DATA", width=110, height=28,
                      fg_color="#0A1A2A", hover_color="#1A3A5A",
                      font=FONT_MICRO_B, text_color=C_ACCENT,
                      command=lambda n=rec["name"]: self._open_face_capture(n)
                      ).pack(side="left", padx=2)

        if complete:
            ctk.CTkLabel(row, text="READY", font=FONT_MICRO_B,
                         text_color=C_GREEN, fg_color="#001A08",
                         corner_radius=4, width=72
                         ).pack(side="right", padx=10, pady=10)
        else:
            missing = []
            if not has_rfid: missing.append("RFID")
            if not has_fp:   missing.append("FP")
            ctk.CTkLabel(row, text=f"NEEDS {'+'.join(missing)}",
                         font=FONT_MICRO_B, text_color=C_YELLOW,
                         fg_color="#1A1000", corner_radius=4, width=130
                         ).pack(side="right", padx=10, pady=10)


# --- VISITORS MANAGER ---
class VisitorAccessManager(ctk.CTkFrame):
    def __init__(self, parent, db=None, feed=None, personnel_mgr=None, **kw):
        super().__init__(parent, fg_color="transparent", **kw)
        self._db = db
        self.feed = feed
        self._personnel_mgr = personnel_mgr
        self._data: list = []
        self._build()

    def _build(self):
        bar = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=8)
        bar.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(bar, text="VISITORS",
                     font=FONT_HEAD, text_color=C_ORANGE
                     ).pack(side="left", padx=12, pady=8)
        ctk.CTkButton(bar, text="+ NEW VISITOR", width=160, height=32,
                      fg_color="#3A2A00", hover_color=C_YELLOW,
                      font=FONT_SMALL, text_color=C_YELLOW,
                      command=self._new_visitor_dialog
                      ).pack(side="left", padx=6, pady=6)
        ctk.CTkButton(bar, text="REFRESH", width=90, height=32,
                      fg_color=C_ACCENT2, hover_color=C_ACCENT,
                      font=FONT_SMALL, text_color=C_BG,
                      command=self.refresh
                      ).pack(side="left", padx=4, pady=6)

        hdr = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=5)
        hdr.pack(fill="x", pady=(0, 2))
        for label, w in [("TIMESTAMP", 170), ("VISITOR", 160), ("FLOOR", 60),
                         ("PURPOSE", 130), ("HOST", 140), ("DURATION", 80),
                         ("STATUS", 90), ("ACTIONS", 140)]:
            ctk.CTkLabel(hdr, text=label, font=FONT_MICRO,
                         text_color=C_TEXT_MUTE, width=w, anchor="w"
                         ).pack(side="left", padx=(8, 0), pady=3)

        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color=C_BG, corner_radius=8,
            scrollbar_button_color=C_ACCENT2,
            scrollbar_button_hover_color=C_ACCENT)
        self._scroll.pack(fill="both", expand=True)

        if self._db:
            self.refresh()

    def _new_visitor_dialog(self):
        d = ctk.CTkToplevel(self.winfo_toplevel())
        d.title("New Visitor Entry Request")
        d.geometry("540x520")
        d.configure(fg_color=C_PANEL)
        # FIXED: safe grab
        d.after(100, lambda: (d.lift(), d.grab_set(), d.focus_force()))

        ctk.CTkLabel(d, text="NEW VISITOR ENTRY REQUEST",
                     font=FONT_HEAD, text_color=C_ORANGE).pack(pady=(20, 10))

        form = ctk.CTkFrame(d, fg_color="transparent")
        form.pack(padx=40, fill="x")

        ctk.CTkLabel(form, text="Visitor Name:", font=FONT_SMALL,
                     text_color=C_TEXT_DIM).grid(row=0, column=0, sticky="w", pady=4)
        name_e = ctk.CTkEntry(form, font=FONT_MONO, fg_color=C_BG,
                               border_color=C_ACCENT2, text_color=C_TEXT, width=320)
        name_e.grid(row=1, column=0, sticky="ew", pady=(0, 12))

        ctk.CTkLabel(form, text="Host Employee:", font=FONT_SMALL,
                     text_color=C_TEXT_DIM).grid(row=2, column=0, sticky="w", pady=4)
        hosts = ["(No Host)"] + sorted([p["name"] for p in (self._personnel_mgr._personnel.values() if self._personnel_mgr else [])])
        host_var = tk.StringVar(value=hosts[0])
        ctk.CTkOptionMenu(form, variable=host_var, values=hosts,
                          fg_color=C_BG, button_color=C_ACCENT2,
                          text_color=C_TEXT, font=FONT_MONO, width=320
                          ).grid(row=3, column=0, sticky="w", pady=(0, 12))

        ctk.CTkLabel(form, text="Floor to Visit:", font=FONT_SMALL,
                     text_color=C_TEXT_DIM).grid(row=4, column=0, sticky="w", pady=4)
        floor_var = tk.StringVar(value="2")
        ctk.CTkOptionMenu(form, variable=floor_var, values=["1","2","3","4"],
                          fg_color=C_BG, button_color=C_ACCENT2,
                          text_color=C_TEXT, font=FONT_MONO, width=80
                          ).grid(row=5, column=0, sticky="w", pady=(0, 12))

        ctk.CTkLabel(form, text="Reason for Visit:", font=FONT_SMALL,
                     text_color=C_TEXT_DIM).grid(row=6, column=0, sticky="w", pady=4)
        reason_e = ctk.CTkEntry(form, font=FONT_MONO, fg_color=C_BG,
                                border_color=C_ACCENT2, text_color=C_TEXT, width=320,
                                placeholder_text="Meeting, Delivery, Maintenance, etc.")
        reason_e.grid(row=7, column=0, sticky="ew", pady=(0, 12))

        ctk.CTkLabel(form, text="Duration (hours):", font=FONT_SMALL,
                     text_color=C_TEXT_DIM).grid(row=8, column=0, sticky="w", pady=4)
        dur_var = tk.StringVar(value="2")
        dur_e = ctk.CTkEntry(form, textvariable=dur_var, font=FONT_MONO,
                             fg_color=C_BG, border_color=C_ACCENT2,
                             text_color=C_TEXT, width=80)
        dur_e.grid(row=9, column=0, sticky="w", pady=(0, 20))

        def do_submit():
            name = name_e.get().strip()
            if not name:
                messagebox.showwarning("Missing", "Visitor name is required.", parent=d)
                return
            try:
                dur = float(dur_var.get())
            except:
                dur = 2.0
            ts = dt.now().strftime("%Y-%m-%d %H:%M:%S")
            host = host_var.get() if host_var.get() != "(No Host)" else ""
            if self._db:
                self._db.insert_temp_request(
                    ts, name, int(floor_var.get()),
                    reason_e.get().strip() or "Visitor",
                    dur, host, "", request_type="VISITOR")
            if self.feed:
                self.feed.add(f"Visitor request submitted: {name} → Floor {floor_var.get()}", "INFO")
            self.refresh()
            d.destroy()

        br = ctk.CTkFrame(d, fg_color="transparent")
        br.pack(pady=20)
        ctk.CTkButton(br, text="SUBMIT VISITOR REQUEST", width=200,
                      fg_color=C_ORANGE, hover_color="#FFAA00",
                      text_color=C_BG, font=FONT_HEAD,
                      command=do_submit).pack(side="left", padx=8)
        ctk.CTkButton(br, text="CANCEL", width=100,
                      fg_color=C_PANEL2, hover_color=C_BORDER,
                      text_color=C_TEXT_DIM, font=FONT_HEAD,
                      command=d.destroy).pack(side="left", padx=8)

    def refresh(self):
        if self._db:
            self._data = self._db.get_temp_requests(request_type="VISITOR")
        self._rebuild()

    def _rebuild(self):
        for w in self._scroll.winfo_children():
            w.destroy()
        for req in self._data:
            self._pack_row(req)

    def _pack_row(self, req: dict):
        ts = req.get("timestamp", "")
        name = req.get("visitor_name", "")
        fl = req.get("floor", "?")
        purp = req.get("purpose", "")
        dur = req.get("duration_hours", "?")
        host = req.get("host", "") or "-"
        status = req.get("status", "PENDING")
        rid = req.get("id")

        row = ctk.CTkFrame(self._scroll, fg_color=C_PANEL, corner_radius=6,
                           border_width=1, border_color=C_YELLOW if status=="APPROVED" else C_TEXT_MUTE)
        row.pack(fill="x", padx=4, pady=3)

        ctk.CTkLabel(row, text=ts[:16], font=FONT_MICRO,
                     text_color=C_TEXT_DIM, width=170, anchor="w").pack(side="left", padx=(10,0), pady=8)
        ctk.CTkLabel(row, text=name[:22], font=FONT_SMALL,
                     text_color=C_TEXT, width=160, anchor="w").pack(side="left", padx=4, pady=8)
        ctk.CTkLabel(row, text=f"F{fl}", font=FONT_MICRO_B,
                     text_color=FLOOR_COLORS[int(fl)-1] if str(fl).isdigit() else C_TEXT_DIM,
                     width=60, anchor="center").pack(side="left", padx=4, pady=8)
        ctk.CTkLabel(row, text=purp[:15], font=FONT_SMALL,
                     text_color=C_YELLOW, width=130, anchor="w").pack(side="left", padx=4, pady=8)
        ctk.CTkLabel(row, text=host[:22], font=FONT_SMALL,
                     text_color=C_TEXT_DIM, width=140, anchor="w").pack(side="left", padx=4, pady=8)
        ctk.CTkLabel(row, text=f"{dur}h", font=FONT_SMALL,
                     text_color=C_TEXT_DIM, width=80, anchor="center").pack(side="left", padx=4, pady=8)

        col = C_GREEN if status == "APPROVED" else C_YELLOW if status == "PENDING" else C_RED
        ctk.CTkLabel(row, text=status, font=FONT_MICRO_B,
                     text_color=col, width=90, anchor="center").pack(side="left", padx=4, pady=8)

        act = ctk.CTkFrame(row, fg_color="transparent")
        act.pack(side="right", padx=6, pady=6)

        if status == "PENDING":
            ctk.CTkButton(act, text="APPROVE", width=72, height=24,
                          fg_color=C_GREEN, hover_color="#00C060",
                          font=FONT_MICRO_B, text_color=C_BG,
                          command=lambda r=rid: self._approve(r)).pack(side="left", padx=2)
            ctk.CTkButton(act, text="DENY", width=60, height=24,
                          fg_color=C_RED, hover_color="#FF4040",
                          font=FONT_MICRO_B, text_color=C_BG,
                          command=lambda r=rid: self._deny(r)).pack(side="left", padx=2)
        else:
            ctk.CTkButton(act, text="REVOKE", width=72, height=24,
                          fg_color="#3A0010", hover_color=C_RED,
                          font=FONT_MICRO_B, text_color=C_RED,
                          command=lambda r=rid: self._revoke(r)).pack(side="left", padx=2)

    def _approve(self, req_id):
        if messagebox.askyesno("Approve Request", "Approve this visitor access?", parent=self.winfo_toplevel()):
            ts = dt.now().strftime("%Y-%m-%d %H:%M:%S")
            if self._db:
                self._db.update_temp_status(req_id, "APPROVED", ts)
            self.feed.add(f"Visitor access APPROVED (ID:{req_id})", "INFO")
            self.refresh()

    def _deny(self, req_id):
        if messagebox.askyesno("Deny Request", "Deny this visitor access?", parent=self.winfo_toplevel()):
            if self._db:
                self._db.update_temp_status(req_id, "DENIED")
            self.feed.add(f"Visitor access DENIED (ID:{req_id})", "WARN")
            self.refresh()

    def _revoke(self, req_id):
        if messagebox.askyesno("Revoke Access", "Revoke this visitor access?", parent=self.winfo_toplevel()):
            if self._db:
                self._db.update_temp_status(req_id, "REVOKED")
            self.feed.add(f"Visitor access REVOKED (ID:{req_id})", "WARN")
            self.refresh()


# --- TEMP ACCESS MANAGER ---
class TemporaryFloorAccessManager(ctk.CTkFrame):
    def __init__(self, parent, db=None, feed=None, personnel_mgr=None, **kw):
        super().__init__(parent, fg_color="transparent", **kw)
        self._db = db
        self.feed = feed
        self._personnel_mgr = personnel_mgr
        self._data: list = []
        self._build()

    def _build(self):
        bar = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=8)
        bar.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(bar, text="TEMP ACCESS",
                     font=FONT_HEAD, text_color=C_YELLOW
                     ).pack(side="left", padx=12, pady=8)
        ctk.CTkButton(bar, text="+ NEW EMPLOYEE REQUEST", width=200, height=32,
                      fg_color="#3A2A00", hover_color=C_YELLOW,
                      font=FONT_SMALL, text_color=C_YELLOW,
                      command=self._new_request_dialog
                      ).pack(side="left", padx=6, pady=6)
        ctk.CTkButton(bar, text="REFRESH", width=90, height=32,
                      fg_color=C_ACCENT2, hover_color=C_ACCENT,
                      font=FONT_SMALL, text_color=C_BG,
                      command=self.refresh
                      ).pack(side="left", padx=4, pady=6)

        hdr = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=5)
        hdr.pack(fill="x", pady=(0, 2))
        for label, w in [("TIMESTAMP", 170), ("EMPLOYEE", 180), ("TARGET FLOOR", 90),
                         ("PURPOSE", 140), ("DURATION", 80), ("STATUS", 90), ("ACTIONS", 140)]:
            ctk.CTkLabel(hdr, text=label, font=FONT_MICRO,
                         text_color=C_TEXT_MUTE, width=w, anchor="w"
                         ).pack(side="left", padx=(8, 0), pady=3)

        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color=C_BG, corner_radius=8,
            scrollbar_button_color=C_ACCENT2,
            scrollbar_button_hover_color=C_ACCENT)
        self._scroll.pack(fill="both", expand=True)

        if self._db:
            self.refresh()
        self.after(30000, self._auto_refresh)

    def _auto_refresh(self):
        self.refresh()
        self.after(30000, self._auto_refresh)

    def _new_request_dialog(self):
        d = ctk.CTkToplevel(self.winfo_toplevel())
        d.title("New Temporary Floor Access Request")
        d.geometry("520x460")
        d.configure(fg_color=C_PANEL)
        # FIXED: safe grab
        d.after(100, lambda: (d.lift(), d.grab_set(), d.focus_force()))

        ctk.CTkLabel(d, text="NEW EMPLOYEE TEMPORARY FLOOR ACCESS",
                     font=FONT_HEAD, text_color=C_YELLOW).pack(pady=(20, 10))

        form = ctk.CTkFrame(d, fg_color="transparent")
        form.pack(padx=40, fill="x")

        ctk.CTkLabel(form, text="Employee:", font=FONT_SMALL,
                     text_color=C_TEXT_DIM).grid(row=0, column=0, sticky="w", pady=4)
        employees = sorted([p["name"] for p in (self._personnel_mgr._personnel.values() if self._personnel_mgr else [])])
        if not employees:
            employees = ["No employees registered"]
        emp_var = tk.StringVar(value=employees[0])
        ctk.CTkOptionMenu(form, variable=emp_var, values=employees,
                          fg_color=C_BG, button_color=C_ACCENT2,
                          text_color=C_TEXT, font=FONT_MONO, width=320
                          ).grid(row=1, column=0, sticky="w", pady=(0, 12))

        ctk.CTkLabel(form, text="Requested Floor:", font=FONT_SMALL,
                     text_color=C_TEXT_DIM).grid(row=2, column=0, sticky="w", pady=4)
        floor_var = tk.StringVar(value="2")
        ctk.CTkOptionMenu(form, variable=floor_var, values=["1","2","3","4"],
                          fg_color=C_BG, button_color=C_ACCENT2,
                          text_color=C_TEXT, font=FONT_MONO, width=80
                          ).grid(row=3, column=0, sticky="w", pady=(0, 12))

        ctk.CTkLabel(form, text="Purpose:", font=FONT_SMALL,
                     text_color=C_TEXT_DIM).grid(row=4, column=0, sticky="w", pady=4)
        purpose_var = tk.StringVar(value="Errands")
        ctk.CTkOptionMenu(form, variable=purpose_var,
                          values=["Errands", "Maintenance", "Meeting", "Training", "Other"],
                          fg_color=C_BG, button_color=C_ACCENT2,
                          text_color=C_TEXT, font=FONT_MONO, width=180
                          ).grid(row=5, column=0, sticky="w", pady=(0, 12))

        ctk.CTkLabel(form, text="Duration (hours):", font=FONT_SMALL,
                     text_color=C_TEXT_DIM).grid(row=6, column=0, sticky="w", pady=4)
        dur_var = tk.StringVar(value="1")
        dur_e = ctk.CTkEntry(form, textvariable=dur_var, font=FONT_MONO,
                             fg_color=C_BG, border_color=C_ACCENT2,
                             text_color=C_TEXT, width=80)
        dur_e.grid(row=7, column=0, sticky="w", pady=(0, 20))

        def do_submit():
            name = emp_var.get()
            if name == "No employees registered":
                messagebox.showwarning("Missing", "No employees registered.", parent=d)
                return
            try:
                dur = float(dur_var.get())
            except:
                dur = 1.0
            ts = dt.now().strftime("%Y-%m-%d %H:%M:%S")
            if self._db:
                self._db.insert_temp_request(
                    ts, name, int(floor_var.get()),
                    purpose_var.get(), dur, "", "Employee temporary floor access request",
                    request_type="EMPLOYEE_TEMP")
            if self.feed:
                self.feed.add(f"Temp floor request submitted for {name} → Floor {floor_var.get()}", "INFO")
            self.refresh()
            d.destroy()

        br = ctk.CTkFrame(d, fg_color="transparent")
        br.pack(pady=20)
        ctk.CTkButton(br, text="SUBMIT REQUEST", width=160,
                      fg_color=C_YELLOW, hover_color="#FFAA00",
                      text_color=C_BG, font=FONT_HEAD,
                      command=do_submit).pack(side="left", padx=8)
        ctk.CTkButton(br, text="CANCEL", width=100,
                      fg_color=C_PANEL2, hover_color=C_BORDER,
                      text_color=C_TEXT_DIM, font=FONT_HEAD,
                      command=d.destroy).pack(side="left", padx=8)

    def refresh(self):
        if self._db:
            self._data = self._db.get_temp_requests(request_type="EMPLOYEE_TEMP")
        self._rebuild()

    def _rebuild(self):
        for w in self._scroll.winfo_children():
            w.destroy()
        for req in self._data:
            self._pack_row(req)

    def _remaining_str(self, granted_ts_str, duration_hours):
        if not granted_ts_str:
            return "not started"
        try:
            entry_dt = dt.strptime(granted_ts_str, "%Y-%m-%d %H:%M:%S")
            expiry   = entry_dt + dt.timedelta(hours=float(duration_hours))
            remaining = expiry - dt.now()
            total_sec = int(remaining.total_seconds())
            if total_sec <= 0:
                return "EXPIRED"
            h, rem = divmod(total_sec, 3600)
            m = rem // 60
            if h > 0:
                return f"{h}h {m}m left"
            return f"{m}m left"
        except Exception:
            return ""

    def _pack_row(self, req: dict):
        ts          = req.get("timestamp", "")
        name        = req.get("visitor_name", "")
        fl          = req.get("floor", "?")
        purp        = req.get("purpose", "")
        dur         = req.get("duration_hours", "?")
        status      = req.get("status", "PENDING")
        rid         = req.get("id")
        granted_ts  = req.get("granted_ts") or ""

        countdown_str = self._remaining_str(granted_ts, dur) if status == "APPROVED" else ""
        is_expired    = countdown_str == "EXPIRED"

        row = ctk.CTkFrame(self._scroll, fg_color=C_PANEL, corner_radius=6,
                           border_width=1, border_color=C_RED if is_expired else
                           (C_YELLOW if status == "APPROVED" else C_TEXT_MUTE))
        row.pack(fill="x", padx=4, pady=3)

        ctk.CTkLabel(row, text=ts[:16], font=FONT_MICRO,
                     text_color=C_TEXT_DIM, width=170, anchor="w").pack(side="left", padx=(10,0), pady=8)
        ctk.CTkLabel(row, text=name[:25], font=FONT_SMALL,
                     text_color=C_TEXT, width=180, anchor="w").pack(side="left", padx=4, pady=8)
        ctk.CTkLabel(row, text=f"F{fl}", font=FONT_MICRO_B,
                     text_color=FLOOR_COLORS[int(fl)-1] if str(fl).isdigit() else C_TEXT_DIM,
                     width=90, anchor="center").pack(side="left", padx=4, pady=8)
        ctk.CTkLabel(row, text=purp[:20], font=FONT_SMALL,
                     text_color=C_YELLOW, width=140, anchor="w").pack(side="left", padx=4, pady=8)
        ctk.CTkLabel(row, text=f"{dur}h", font=FONT_SMALL,
                     text_color=C_TEXT_DIM, width=60, anchor="center").pack(side="left", padx=4, pady=8)

        cd_col = C_RED if is_expired else (C_GREEN if countdown_str and countdown_str != "not started" else C_TEXT_DIM)
        ctk.CTkLabel(row, text=countdown_str, font=FONT_MICRO_B,
                     text_color=cd_col, width=90, anchor="center").pack(side="left", padx=4, pady=8)

        col = C_RED if (status == "EXPIRED" or is_expired) else (
              C_GREEN if status == "APPROVED" else
              C_YELLOW if status == "PENDING" else C_RED)
        status_txt = "EXPIRED" if is_expired else status
        ctk.CTkLabel(row, text=status_txt, font=FONT_MICRO_B,
                     text_color=col, width=80, anchor="center").pack(side="left", padx=4, pady=8)

        act = ctk.CTkFrame(row, fg_color="transparent")
        act.pack(side="right", padx=6, pady=6)

        if status == "PENDING":
            ctk.CTkButton(act, text="APPROVE", width=72, height=24,
                          fg_color=C_GREEN, hover_color="#00C060",
                          font=FONT_MICRO_B, text_color=C_BG,
                          command=lambda r=rid: self._approve(r)).pack(side="left", padx=2)
            ctk.CTkButton(act, text="DENY", width=60, height=24,
                          fg_color=C_RED, hover_color="#FF4040",
                          font=FONT_MICRO_B, text_color=C_BG,
                          command=lambda r=rid: self._deny(r)).pack(side="left", padx=2)
        else:
            ctk.CTkButton(act, text="REVOKE", width=72, height=24,
                          fg_color="#3A0010", hover_color=C_RED,
                          font=FONT_MICRO_B, text_color=C_RED,
                          command=lambda r=rid: self._revoke(r)).pack(side="left", padx=2)

    def _approve(self, req_id):
        if messagebox.askyesno("Approve Request", "Approve this temporary floor access for employee?", parent=self.winfo_toplevel()):
            ts = dt.now().strftime("%Y-%m-%d %H:%M:%S")
            if self._db:
                self._db.update_temp_status(req_id, "APPROVED", ts)
            self.feed.add(f"TEMP FLOOR ACCESS APPROVED (ID:{req_id})", "INFO")
            self.refresh()

    def _deny(self, req_id):
        if messagebox.askyesno("Deny Request", "Deny this temporary floor access?", parent=self.winfo_toplevel()):
            if self._db:
                self._db.update_temp_status(req_id, "DENIED")
            self.feed.add(f"TEMP FLOOR ACCESS DENIED (ID:{req_id})", "WARN")
            self.refresh()

    def _revoke(self, req_id):
        if messagebox.askyesno("Revoke Access", "Revoke this temporary floor access?", parent=self.winfo_toplevel()):
            if self._db:
                self._db.update_temp_status(req_id, "REVOKED")
            self.feed.add(f"TEMP FLOOR ACCESS REVOKED (ID:{req_id})", "WARN")
            self.refresh()


# --- Occupancy Dashboard ---
class OccupancyDashboard(ctk.CTkFrame):
    def __init__(self, parent, ctrl=None, **kw):
        super().__init__(parent, fg_color="transparent", **kw)
        self._ctrl = ctrl
        self._fs = [
            {"count": 0, "last_uid": "--", "last_name": "--",
             "last_action": "STANDBY", "granted": None}
            for _ in range(4)
        ]
        self._building_count = 0

        self._build()

    def _build(self):
        sf = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=10)
        sf.pack(fill="x", pady=(0, 14))
        sf.columnconfigure((0, 1, 2, 3), weight=1)
        self._total_lbl = ctk.CTkLabel(sf, text="0  IN BUILDING",
                                        font=("Courier New", 18, "bold"),
                                        text_color=C_ACCENT)
        self._total_lbl.grid(row=0, column=0, padx=20, pady=12, sticky="w")
        ctk.CTkLabel(sf, text="FLOOR OCCUPANCY OVERVIEW",
                     font=FONT_HEAD, text_color=C_TEXT_DIM
                     ).grid(row=0, column=1, columnspan=2, pady=12)
        self._alert_lbl = ctk.CTkLabel(sf, text="ALL CLEAR",
                                        font=FONT_BODY, text_color=C_GREEN)
        self._alert_lbl.grid(row=0, column=3, padx=20, pady=12, sticky="e")

        tf = ctk.CTkFrame(self, fg_color="transparent")
        tf.pack(fill="x", pady=(0, 14))
        tf.columnconfigure((0, 1, 2, 3), weight=1)

        self._tiles = []
        for i in range(4):
            col = FLOOR_COLORS[i]
            tile = ctk.CTkFrame(tf, fg_color=C_PANEL, corner_radius=12,
                                border_width=2, border_color=C_BORDER)
            tile.grid(row=0, column=i, padx=6, sticky="nsew")

            hdr = ctk.CTkFrame(tile, fg_color=C_PANEL2, corner_radius=0, height=36)
            hdr.pack(fill="x"); hdr.pack_propagate(False)
            ctk.CTkLabel(hdr, text=FLOOR_NAMES[i], font=FONT_HEAD,
                         text_color=col).pack(side="left", padx=12)
            dot = StatusOrb(hdr, size=12)
            dot.pack(side="right", padx=10)
            dot.set_color(C_TEXT_MUTE)

            cnt = ctk.CTkLabel(tile, text="0",
                               font=("Courier New", 38, "bold"),
                               text_color=C_TEXT_MUTE)
            cnt.pack(pady=(8, 0))
            ctk.CTkLabel(tile,
                         text="in lobby (FP gate)" if i == 0 else "present on floor",
                         font=FONT_SMALL, text_color=C_TEXT_DIM).pack()

            ctk.CTkFrame(tile, height=1, fg_color=C_BORDER
                         ).pack(fill="x", padx=10, pady=(6, 4))

            stl = ctk.CTkLabel(tile, text="STANDBY",
                               font=FONT_BODY, text_color=C_TEXT_DIM)
            stl.pack(pady=(0, 2))
            ull = ctk.CTkLabel(tile, text="--",
                               font=FONT_SMALL, text_color=C_TEXT_DIM,
                               wraplength=160)
            ull.pack(pady=(0, 6))

            ctk.CTkFrame(tile, height=1, fg_color=C_BORDER
                         ).pack(fill="x", padx=10, pady=(0, 6))

            ctk.CTkLabel(tile, text="LIGHT CONTROL",
                         font=("Courier New", 9, "bold"),
                         text_color=C_TEXT_MUTE).pack(anchor="w", padx=12)
            lr = ctk.CTkFrame(tile, fg_color="transparent")
            lr.pack(fill="x", padx=10, pady=(2, 4))
            lr.columnconfigure((0, 1), weight=1)

            fi = i
            ctk.CTkButton(
                lr, text="WHITE", height=26, fg_color=C_ACCENT2,
                hover_color=C_ACCENT, font=FONT_SMALL, text_color=C_BG,
                command=lambda f=fi: self._ctrl and self._ctrl.send_light(f+1, "normal")
            ).grid(row=0, column=0, padx=(0, 3), sticky="ew")
            ctk.CTkButton(
                lr, text="ALERT", height=26, fg_color="#3A000E",
                hover_color=C_RED, font=FONT_SMALL, text_color=C_RED,
                command=lambda f=fi: self._ctrl and self._ctrl.send_light(f+1, "alert")
            ).grid(row=0, column=1, padx=(3, 0), sticky="ew")
            ctk.CTkButton(
                tile, text="RELEASE LOCK", height=26,
                fg_color=C_PANEL2, hover_color=C_BORDER,
                font=FONT_SMALL, text_color=C_TEXT_DIM,
                command=lambda f=fi: self._ctrl and self._ctrl.send_light_release(f+1)
            ).pack(fill="x", padx=10, pady=(0, 6))

            sr = ctk.CTkFrame(tile, fg_color="transparent")
            sr.pack(fill="x", padx=12, pady=(0, 10))
            ctk.CTkLabel(sr, text="SENSOR",
                         font=("Courier New", 9, "bold"),
                         text_color=C_TEXT_MUTE).pack(side="left")
            sv = tk.BooleanVar(value=True)
            ctk.CTkSwitch(
                sr, text="", variable=sv, onvalue=True, offvalue=False,
                progress_color=C_GREEN, fg_color=C_BORDER,
                button_color=C_ACCENT, width=40, height=18,
                command=lambda f=fi, v=sv: (
                    self._ctrl and self._ctrl.send_sensor(f+1, v.get()))
            ).pack(side="right")

            self._tiles.append({
                "tile": tile, "dot": dot, "count": cnt,
                "status": stl, "uid": ull, "color": col,
            })

        bot = ctk.CTkFrame(self, fg_color="transparent")
        bot.pack(fill="both", expand=True)
        bot.columnconfigure(0, weight=3)
        bot.columnconfigure(1, weight=2)
        bot.columnconfigure(2, weight=2)

        ef = ctk.CTkFrame(bot, fg_color=C_PANEL, corner_radius=10)
        ef.grid(row=0, column=0, padx=(0, 6), sticky="nsew")
        ctk.CTkLabel(ef, text="RECENT ACCESS EVENTS",
                     font=FONT_HEAD, text_color=C_TEXT_DIM
                     ).pack(anchor="w", padx=6, pady=(8, 4))
        ctk.CTkFrame(ef, height=1, fg_color=C_BORDER).pack(fill="x", padx=6)
        self._mf = tk.Text(ef, bg=C_PANEL, fg=C_TEXT,
                           font=("Courier New", 10), relief="flat", bd=0,
                           state="disabled", height=8, wrap="word",
                           selectbackground=C_BORDER, selectforeground=C_TEXT)
        self._mf.tag_config("G", foreground=C_GREEN)
        self._mf.tag_config("D", foreground=C_RED)
        self._mf.tag_config("F", foreground=C_FP)
        self._mf.pack(fill="both", expand=True, padx=6, pady=6)

        sf2 = ctk.CTkFrame(bot, fg_color=C_PANEL, corner_radius=10)
        sf2.grid(row=0, column=1, padx=(0, 6), sticky="nsew")
        ctk.CTkLabel(sf2, text="FLOOR STATISTICS",
                     font=FONT_HEAD, text_color=C_TEXT_DIM
                     ).pack(anchor="w", padx=6, pady=(8, 4))
        ctk.CTkFrame(sf2, height=1, fg_color=C_BORDER).pack(fill="x", padx=6)

        self._stat_labels = []
        for i in range(4):
            rf = ctk.CTkFrame(sf2, fg_color="transparent")
            rf.pack(fill="x", padx=12, pady=4)
            ctk.CTkLabel(rf, text=FLOOR_NAMES[i], font=FONT_SMALL,
                         text_color=FLOOR_COLORS[i], width=70, anchor="w"
                         ).pack(side="left")
            lbl2 = ctk.CTkLabel(rf, text="FP GATE" if i == 0 else "VACANT",
                               font=FONT_SMALL, text_color=C_TEXT_DIM)
            lbl2.pack(side="left", padx=8)
            self._stat_labels.append(lbl2)

        self.fp_widget = FingerprintStatusWidget(bot)
        self.fp_widget.grid(row=0, column=2, sticky="nsew")

    def update_fp_gate(self, name: str, uid: str, inside: bool, ts: str):
        si = 0
        st = self._fs[si]
        st["last_uid"]  = uid
        st["last_name"] = name
        st["granted"]   = True
        gate_str = "ENTERED" if inside else "EXITED"
        st["last_action"] = f"FP GATE {gate_str}: {name}"

        if inside:
            self._building_count += 1
            st["count"] = st.get("count", 0) + 1
        else:
            self._building_count = max(0, self._building_count - 1)
            st["count"] = max(0, st.get("count", 0) - 1)

        self._rt_gate(si)
        self._rs()

        sym = "ENTER" if inside else "EXIT"
        msg = f"[{ts[-8:]}] GATE {sym} FP {name} ({uid[:10]})\n"
        self._mf.configure(state="normal")
        self._mf.insert("1.0", msg, "F")
        lines = int(self._mf.index("end-1c").split(".")[0])
        if lines > 100:
            self._mf.delete("101.0", "end")
        self._mf.configure(state="disabled")

    def update_floor_scan(self, scan_floor, uid, name, granted,
                          direction, registered_floor=None, is_fp=False):
        si  = scan_floor - 1
        ri  = (registered_floor - 1) if registered_floor is not None else None
        st  = self._fs[si]
        st["last_uid"]    = uid
        st["last_name"]   = name
        st["granted"]     = granted
        fp_tag = " FP" if is_fp else ""
        st["last_action"] = (f"OK {name} {direction.upper()}{fp_tag}"
                             if granted else "DENIED")

        if granted and scan_floor == 1:
            lobby_st = self._fs[0]
            if direction.upper() == "IN":
                # RFID F1 IN = employee walked through lobby -> going up (lobby count decreases)
                lobby_st["count"] = max(0, lobby_st.get("count", 0) - 1)
            elif direction.upper() == "OUT":
                # RFID F1 OUT = employee returning to lobby from F1 area
                lobby_st["count"] = lobby_st.get("count", 0) + 1
            self._rt_gate(0)

        if granted and si > 0:
            if direction.upper() == "IN":
                self._fs[si]["count"] += 1
            elif direction.upper() == "OUT":
                self._fs[si]["count"] = max(0, self._fs[si]["count"] - 1)
            self._rt(si)

        if si != 0:
            self._rt(si)

        self._rs()

        ts  = dt.now().strftime("%H:%M:%S")
        sym = "OK" if granted else "DENIED"
        fp_prefix = "FP:" if is_fp else ""
        msg = f"[{ts}] F{scan_floor} {sym} {fp_prefix}{name} ({uid[:10]}) {direction.upper()}\n"
        tag = "F" if is_fp else ("G" if granted else "D")
        self._mf.configure(state="normal")
        self._mf.insert("1.0", msg, tag)
        lines = int(self._mf.index("end-1c").split(".")[0])
        if lines > 100:
            self._mf.delete("101.0", "end")
        self._mf.configure(state="disabled")

    def _rt_gate(self, i):
        st, t = self._fs[i], self._tiles[i]
        col = self._tiles[i]["color"]
        cnt = st.get("count", 0)
        t["dot"].set_color(C_FP if cnt > 0 else C_TEXT_MUTE)
        t["tile"].configure(border_color=col)
        t["status"].configure(text=st["last_action"], text_color=C_FP)
        t["count"].configure(
            text=str(cnt), text_color=C_FP if cnt > 0 else C_TEXT_MUTE)
        t["uid"].configure(
            text=f"Last: {st['last_name']} ({st['last_uid'][:12]})",
            text_color=C_TEXT_DIM)
        self._stat_labels[0].configure(
            text=f"{cnt} in lobby" if cnt > 0 else "LOBBY EMPTY",
            text_color=C_FP if cnt > 0 else C_TEXT_DIM)

    def _rs(self):
        total = self._building_count
        if total == 0:
            self._total_lbl.configure(text="0  IN BUILDING", text_color=C_TEXT_MUTE)
        elif total == 1:
            self._total_lbl.configure(text="1  PERSON IN BUILDING", text_color=C_ACCENT)
        else:
            self._total_lbl.configure(text=f"{total}  IN BUILDING", text_color=C_ACCENT)

        if any(s["granted"] is False for s in self._fs):
            self._alert_lbl.configure(text="ALERT ACTIVE", text_color=C_RED)
            # BUG FIX: was always resetting to ALL CLEAR after 6s even if denials persist
            self.after(6000, self._maybe_clear_alert)

    def _maybe_clear_alert(self):
        """Only reset alert banner if no denial states remain active."""
        if not any(s["granted"] is False for s in self._fs):
            self._alert_lbl.configure(text="ALL CLEAR", text_color=C_GREEN)

    def _rt(self, i):
        st, t, col = self._fs[i], self._tiles[i], self._tiles[i]["color"]
        if i == 0:
            t["uid"].configure(
                text=f"Last RFID: {st['last_name']} ({st['last_uid'][:12]})",
                text_color=C_TEXT_DIM)
            if st["granted"] is True:
                t["status"].configure(text=st["last_action"], text_color=C_GREEN)
            elif st["granted"] is False:
                t["status"].configure(text=st["last_action"], text_color=C_RED)
            return
        if st["granted"] is True:
            t["dot"].set_color(C_GREEN)
            t["status"].configure(text=st["last_action"], text_color=C_GREEN)
            t["tile"].configure(border_color=col)
        elif st["granted"] is False:
            t["dot"].set_color(C_RED)
            t["status"].configure(text=st["last_action"], text_color=C_RED)
            t["tile"].configure(border_color=C_RED)
            self.after(5000, lambda idx=i: (
                self._tiles[idx]["tile"].configure(border_color=C_BORDER),
                self._tiles[idx]["dot"].set_color(C_TEXT_MUTE)))
        else:
            t["dot"].set_color(C_TEXT_MUTE)
            t["status"].configure(text="STANDBY", text_color=C_TEXT_DIM)
        t["uid"].configure(
            text=f"Last: {st['last_name']} ({st['last_uid'][:12]})",
            text_color=C_TEXT_DIM)
        cnt = st["count"]
        t["count"].configure(text=str(cnt),
                             text_color=col if cnt > 0 else C_TEXT_MUTE)
        self._stat_labels[i].configure(
            text=f"{cnt} present" if cnt > 0 else "VACANT",
            text_color=col if cnt > 0 else C_TEXT_DIM)


# --- Camera Feed Page (SCROLLABLE) ---
class CameraFeedPage(ctk.CTkFrame):
    CAM1_FLOOR = 2
    CAM2_FLOOR = 3

    def __init__(self, parent, personnel_mgr=None, analyzer=None, ctrl=None, audio=None, **kw):
        super().__init__(parent, fg_color="transparent", **kw)

        self._personnel_mgr = personnel_mgr
        self._analyzer      = analyzer
        self._ctrl          = ctrl
        self._audio         = audio   # AudioManager for camera violation sounds
        self._alert_cooldown: dict = {}
        self._alert_cooldown_secs = 10
        self._stop_event  = threading.Event()
        self._video_thread: threading.Thread | None = None
        self._running     = False
        self._picam1      = None
        self._picam2      = None
        self._cam1_active = False
        self._cam2_active = False

        hdr = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=8)
        hdr.pack(fill="x", padx=0, pady=(0, 8))
        ctk.CTkLabel(hdr, text="SURVEILLANCE  –  LIVE CAMERA FEED",
                     font=FONT_HEAD, text_color=C_ACCENT).pack(side="left", padx=12, pady=8)
        self._status_lbl = ctk.CTkLabel(hdr, text="● INITIALISING",
                                         font=FONT_SMALL, text_color=C_YELLOW)
        self._status_lbl.pack(side="right", padx=12)

        btn_frame = ctk.CTkFrame(hdr, fg_color="transparent")
        btn_frame.pack(side="right", padx=4)
        ctk.CTkButton(btn_frame, text="RESTART CAMERAS", width=150, height=28,
                      fg_color=C_ACCENT2, hover_color=C_ACCENT,
                      font=FONT_SMALL, text_color=C_BG,
                      command=self.restart_cameras).pack(padx=4, pady=6)

        # Plain frame so the video label fills and the grid scales to fit the
        # window — no scroll bar, no fixed dimensions.
        self._cam_container = ctk.CTkFrame(
            self, fg_color=C_BG, corner_radius=8)
        self._cam_container.pack(fill="both", expand=True, padx=14, pady=8)

        self._video_label = ctk.CTkLabel(
            self._cam_container,
            text="Loading camera feed\u2026",
            font=FONT_HEAD, text_color=C_TEXT_DIM,
            fg_color=C_PANEL, corner_radius=12)
        self._video_label.pack(fill="both", expand=True, padx=4, pady=4)

        # Track the CONTAINER frame's live pixel size, NOT the label's.
        # Binding <Configure> on the label creates a feedback loop:
        #   set image → label resizes → Configure fires → smaller dims →
        #   smaller image → label shrinks → repeat until zero.
        # The container is driven by the window geometry and stays stable.
        self._display_w = 1100
        self._display_h = 800

        def _on_container_resize(event):
            self._display_w = max(event.width  - 8, 200)
            self._display_h = max(event.height - 8, 150)

        self._cam_container.bind("<Configure>", _on_container_resize)

    def start(self):
        self._initialize_cameras()
        self._stop_event.clear()
        self._running = True
        self._video_thread = threading.Thread(target=self._feed_loop, daemon=True)
        self._video_thread.start()
        self._set_status("LIVE", C_GREEN)

    def stop(self):
        self._running = False
        self._stop_event.set()
        if self._video_thread and self._video_thread.is_alive():
            self._video_thread.join(timeout=2.0)
        self._video_thread = None
        # Always release the hardware when stopping so other callers
        # (e.g. FaceCaptureDialog) can open the cameras immediately.
        self._close_cameras()
        self._set_status("STANDBY", C_TEXT_DIM)

    def restart_cameras(self):
        self.stop()
        # Schedule start on the Tkinter event loop after a short delay instead of
        # blocking the main thread with time.sleep() which freezes the UI.
        self.after(350, self.start)

    def destroy(self):
        self.stop()
        self._close_cameras()
        super().destroy()

    def _initialize_cameras(self):
        self._close_cameras()
        if not PICAMERA_AVAILABLE:
            return
        try:
            self._picam1 = Picamera2(0)
            self._picam1.configure(self._picam1.create_preview_configuration(
                main={"format": "XRGB8888", "size": (640, 480)}))
            self._picam1.start()
            self._cam1_active = True
        except Exception as e:
            logging.error(f"Camera 1 init failed: {e}")
            self._picam1 = None
            self._cam1_active = False

        try:
            self._picam2 = Picamera2(1)
            self._picam2.configure(self._picam2.create_preview_configuration(
                main={"format": "XRGB8888", "size": (640, 480)}))
            self._picam2.start()
            self._cam2_active = True
        except Exception as e:
            logging.error(f"Camera 2 init failed: {e}")
            self._picam2 = None
            self._cam2_active = False

    def _close_cameras(self):
        for cam in (self._picam1, self._picam2):
            if cam is not None:
                try:
                    cam.close()
                except Exception:
                    pass
        self._picam1 = self._picam2 = None
        self._cam1_active = self._cam2_active = False

    def _feed_loop(self):
        offline = np.zeros((480, 640, 3), dtype=np.uint8)
        cv2.putText(offline, "Camera Offline", (120, 240),
                    cv2.FONT_HERSHEY_SIMPLEX, 1.4, (0, 0, 255), 3, cv2.LINE_AA)

        last1  = offline.copy()
        last2  = offline.copy()
        frame_n = 0
        loc1, names1 = [], []
        loc2, names2 = [], []

        while not self._stop_event.is_set() and self._running:
            try:
                frame_n += 1

                # ── Compute tile size to fit the grid inside the label ────────
                # The grid is 2 columns × 2 rows.  We derive the tile size from
                # the label's current pixel dimensions (updated by <Configure>),
                # then clamp to 4:3 so frames are never stretched.
                avail_w = self._display_w
                avail_h = self._display_h
                # Largest tile that fits both axes at 4:3
                tw_from_w = avail_w // 2
                th_from_w = tw_from_w * 3 // 4
                th_from_h = avail_h // 2
                tw_from_h = th_from_h * 4 // 3
                if th_from_w <= avail_h // 2:
                    TW, TH = tw_from_w, th_from_w
                else:
                    TW, TH = tw_from_h, th_from_h
                TW = max(TW, 100)
                TH = max(TH, 75)
                # ────────────────────────────────────────────────────────────

                if self._cam1_active and self._picam1:
                    try:
                        f1 = self._picam1.capture_array()
                        f1 = cv2.cvtColor(f1, cv2.COLOR_RGBA2RGB)
                        f1 = cv2.flip(f1, 1)
                        last1 = f1.copy()
                    except Exception:
                        f1 = last1
                else:
                    f1 = offline.copy()

                if self._cam2_active and self._picam2:
                    try:
                        f2 = self._picam2.capture_array()
                        f2 = cv2.cvtColor(f2, cv2.COLOR_RGBA2RGB)
                        f2 = cv2.flip(f2, 1)
                        last2 = f2.copy()
                    except Exception:
                        f2 = last2
                else:
                    f2 = offline.copy()

                if frame_n % 3 == 0:
                    if not np.array_equal(f1, offline):
                        loc1, names1 = self._process_frame(f1)
                        self._capture_faces(f1, loc1, names1, 1)
                    else:
                        loc1, names1 = [], []
                    if not np.array_equal(f2, offline):
                        loc2, names2 = self._process_frame(f2)
                        self._capture_faces(f2, loc2, names2, 2)
                    else:
                        loc2, names2 = [], []

                set1 = {n for n in names1 if n != "Unknown"}
                set2 = {n for n in names2 if n != "Unknown"}
                multi_floor_names = set1 & set2

                for mf_name in multi_floor_names:
                    self._trigger_floor_alert(self.CAM1_FLOOR, "MULTI-FLOOR DETECTED")
                    self._trigger_floor_alert(self.CAM2_FLOOR, "MULTI-FLOOR DETECTED")
                    logging.warning(
                        f"Multi-floor face detected: {mf_name} on "
                        f"F{self.CAM1_FLOOR} and F{self.CAM2_FLOOR} simultaneously")

                f1 = self._draw_results(f1, loc1, names1, 1, multi_floor_names)
                f2 = self._draw_results(f2, loc2, names2, 2, multi_floor_names)

                f1r = cv2.resize(f1, (TW, TH))
                f2r = cv2.resize(f2, (TW, TH))

                floor1 = cv2.resize(offline.copy(), (TW, TH))
                floor4 = cv2.resize(offline.copy(), (TW, TH))

                top    = np.hstack((floor1, f1r))
                bottom = np.hstack((f2r, floor4))
                grid   = np.vstack((top, bottom))

                cv2.line(grid, (TW, 0),    (TW, grid.shape[0]),    (255, 255, 255), 2)
                cv2.line(grid, (0,  TH),   (grid.shape[1], TH),    (255, 255, 255), 2)

                labels    = ["1st Floor", "2nd Floor", "3rd Floor", "4th Floor"]
                positions = [(10, 30), (TW + 10, 30),
                             (10, TH + 30), (TW + 10, TH + 30)]
                for lbl, (x, y) in zip(labels, positions):
                    cv2.putText(grid, lbl, (x, y),
                                cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2, cv2.LINE_AA)

                ts = time.strftime("%Y-%m-%d  %H:%M:%S")
                cv2.putText(grid, ts, (20, grid.shape[0] - 16),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.75, (255, 255, 0), 2)

                rgb     = cv2.cvtColor(grid, cv2.COLOR_BGR2RGB)
                pil_img = Image.fromarray(rgb)
                img     = ImageTk.PhotoImage(pil_img)

                if self._running:
                    # CRITICAL: Tkinter is NOT thread-safe.  All widget updates
                    # must be marshalled back to the main thread via after(0,…).
                    # Holding a reference to `img` inside the closure prevents
                    # garbage-collection before the callback fires.
                    _img = img
                    def _update_ui(i=_img):
                        try:
                            self._video_label.configure(image=i, text="")
                            self._video_label.image = i   # keep GC reference
                        except tk.TclError:
                            # Widget was destroyed (page switched) — stop loop
                            self._running = False
                            self._stop_event.set()
                    try:
                        self._video_label.after(0, _update_ui)
                    except tk.TclError:
                        break

                time.sleep(0.033)

            except Exception as e:
                logging.error(f"Camera feed error: {e}")
                time.sleep(1)

    def _process_frame(self, frame):
        if not FACE_RECOG_AVAILABLE:
            return [], []
        try:
            small  = cv2.resize(frame, (0, 0), fx=1/CV_SCALER, fy=1/CV_SCALER)
            rgb_sm = cv2.cvtColor(small, cv2.COLOR_BGR2RGB)
            locs   = face_recognition.face_locations(rgb_sm, model="hog")
            if not locs:
                return [], []
            encs   = face_recognition.face_encodings(rgb_sm, locs)
            names  = []
            for enc in encs:
                name = "Unknown"
                if known_face_encodings:
                    matches   = face_recognition.compare_faces(known_face_encodings, enc, tolerance=0.5)
                    dists     = face_recognition.face_distance(known_face_encodings, enc)
                    best      = int(np.argmin(dists))
                    if matches[best]:
                        name = known_face_names[best]
                names.append(name)
            return locs, names
        except Exception as e:
            logging.error(f"process_frame: {e}")
            return [], []

    def _check_authorization(self, name: str, cam_num: int,
                             multi_floor_names: set = None):
        cam_floor = self.CAM1_FLOOR if cam_num == 1 else self.CAM2_FLOOR

        if name == "Unknown":
            return False, "UNKNOWN PERSON"

        if not self._personnel_mgr:
            return False, "UNAUTHORIZED"

        rec = self._personnel_mgr._personnel.get(name.lower())
        if not rec:
            return False, "NOT REGISTERED"

        assigned_floor = int(rec.get("floor", -1))
        if assigned_floor != cam_floor:
            return False, f"WRONG FLOOR (F{assigned_floor})"

        if self._analyzer and not self._analyzer.is_fp_signed_in(name):
            return False, "NO FP SIGN-IN"

        if self._analyzer:
            uid   = rec.get("rfid_uid", "")
            # Use the thread-safe snapshot so we never read a partially-updated dict
            state      = self._analyzer.get_state_snapshot(uid)
            active_ins = state.get("active_ins", {})

            if len(active_ins) > 1:
                floors = ", ".join(f"F{f}" for f in sorted(active_ins.keys()))
                return False, f"MULTI-FLOOR ({floors})"

            if assigned_floor not in active_ins:
                return False, "NOT CHECKED IN"

        if multi_floor_names and name in multi_floor_names:
            return False, "MULTI-FLOOR DETECTED"

        return True, "AUTHORIZED"

    def _is_authorized(self, name: str, cam_num: int) -> bool:
        auth, _ = self._check_authorization(name, cam_num)
        return auth

    def _trigger_floor_alert(self, floor: int, reason: str = "UNAUTHORIZED"):
        now = time.time()
        if now - self._alert_cooldown.get(floor, 0) < self._alert_cooldown_secs:
            return
        self._alert_cooldown[floor] = now

        if self._ctrl:
            try:
                self._ctrl.send_light(floor, "alert")
                logging.info(f"Camera violation alert: red light triggered on F{floor} ({reason})")
            except Exception as e:
                logging.error(f"Alert light error F{floor}: {e}")

        # Play sounds based on what the camera detected.
        # Always plays violation.wav as the base camera-violation tone, then
        # layered with a specific clip chosen by reason — the highest-urgency
        # candidate wins via the AudioManager priority system.
        if self._audio:
            try:
                reason_up = reason.upper()
                # Always: general violation tone for any camera detection
                self._audio.play("violation.wav", SND_HIGH)

                # Then attempt to play a more specific clip at higher priority
                if "UNKNOWN" in reason_up:
                    pass  # violation.wav already covers unknown face — no extra clip
                elif "MULTI" in reason_up or "MULTI-FLOOR" in reason_up:
                    self._audio.play("alert_multi_floor.wav", SND_HIGH)
                elif "WRONG FLOOR" in reason_up or "NOT REGISTERED" in reason_up:
                    self._audio.play("alert_intercept.wav", SND_CRITICAL)
                elif "NO FP" in reason_up or "FP SIGN" in reason_up:
                    self._audio.play("alert_fp_missing.wav", SND_CRITICAL)
                elif "NOT CHECKED IN" in reason_up:
                    self._audio.play("alert_bypass.wav", SND_HIGH)
                # else: violation.wav alone is sufficient for generic cases
            except Exception as e:
                logging.error(f"Camera alert sound error: {e}")

    def _draw_results(self, frame, locs, names, cam_num,
                      multi_floor_names: set = None):
        cam_floor = self.CAM1_FLOOR if cam_num == 1 else self.CAM2_FLOOR
        worst_reason = None   # track most severe violation reason for sound

        for (top, right, bottom, left), name in zip(locs, names):
            top    *= CV_SCALER;  right  *= CV_SCALER
            bottom *= CV_SCALER;  left   *= CV_SCALER

            authorized, reason = self._check_authorization(
                name, cam_num, multi_floor_names)

            if not authorized:
                # Prioritise reason for sound: unknown > wrong floor > others
                if worst_reason is None:
                    worst_reason = reason
                elif "UNKNOWN" in reason.upper() and "UNKNOWN" not in worst_reason.upper():
                    worst_reason = reason

            color = (0, 255, 0) if authorized else (0, 0, 255)

            cv2.rectangle(frame, (left, top), (right, bottom), color, 2)
            cv2.rectangle(frame, (left, bottom - 36), (right, bottom), color, cv2.FILLED)
            cv2.putText(frame, name,   (left + 6, bottom - 21),
                        cv2.FONT_HERSHEY_DUPLEX, 0.6, (255, 255, 255), 1)
            cv2.putText(frame, reason, (left + 6, bottom - 6),
                        cv2.FONT_HERSHEY_DUPLEX, 0.48, (255, 255, 255), 1)

            if not authorized:
                banner_y = max(top - 6, 18)
                cv2.rectangle(frame, (left, banner_y - 16), (right, banner_y + 2),
                              (0, 0, 200), cv2.FILLED)
                cv2.putText(frame, f"VIOLATION – F{cam_floor}",
                            (left + 4, banner_y),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 60, 60), 1)

        if worst_reason is not None:
            self._trigger_floor_alert(cam_floor, worst_reason)

        return frame

    def _capture_faces(self, frame, locs, names, cam_id):
        now = time.time()
        for (top, right, bottom, left), name in zip(locs, names):
            top    *= CV_SCALER;  right  *= CV_SCALER
            bottom *= CV_SCALER;  left   *= CV_SCALER
            key = f"{name}_{cam_id}"
            if now - _last_capture_time.get(key, 0) < CAPTURE_COOLDOWN:
                continue
            _last_capture_time[key] = now
            margin = 30
            y0, y1 = max(0, top - margin),  min(frame.shape[0], bottom + margin)
            x0, x1 = max(0, left - margin), min(frame.shape[1], right + margin)
            face_img = frame[y0:y1, x0:x1]
            status   = "auth" if self._is_authorized(name, cam_id) else "unauth"
            ts_str   = dt.now().strftime("%Y%m%d_%H%M%S")
            fname    = f"{name}_{status}_cam{cam_id}_{ts_str}.jpg"
            try:
                cv2.imwrite(os.path.join(CAPTURE_DIR, fname), face_img)
            except Exception as e:
                logging.error(f"Face capture save error: {e}")

    def _set_status(self, text, color=C_TEXT_DIM):
        try:
            self._status_lbl.configure(text=f"● {text}", text_color=color)
        except Exception:
            pass


# --- Main Application ---
class FloorAccessApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("FLOOR ACCESS CONTROL SYSTEM")
        self.geometry("1440x880")
        self.minsize(1100, 680)
        self.configure(fg_color=C_BG)

        self._eq        = queue.Queue()
        self._ctrl      = ESP32Controller(self._eq)
        self._connected = False
        self._scan_timer = None
        self._db        = DatabaseManager()
        self._analyzer  = BehaviorAnalyzer(db=self._db)

        # ── Real-building safety features ────────────────────────────────────
        # Emergency / evacuation mode: all doors grant access, no anomaly checks.
        self._audio         = _audio      # module-level AudioManager singleton
        self._emergency_mode = False
        # Heartbeat watchdog: if ESP32 sends no data for this many seconds while
        # we think we're connected, treat it as a silent disconnect.
        self._HEARTBEAT_TIMEOUT = 30
        # Stale-state sweep: persons marked "inside" for longer than this are
        # flagged so security can verify they haven't silently left.
        self._STALE_HOURS = 24

        self._build_ui()
        self._start_event_loop()
        self._schedule_port_scan()
        # Heartbeat watchdog disabled — no automatic disconnect
        self._schedule_stale_state_check()

    def _build_ui(self):
        tb = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=0, height=54)
        tb.pack(fill="x"); tb.pack_propagate(False)
        lf = ctk.CTkFrame(tb, fg_color="transparent")
        lf.pack(side="left", padx=16)
        ctk.CTkLabel(lf, text="FLOOR ACCESS CONTROL",
                     font=FONT_TITLE, text_color=C_TEXT).pack(side="left")

        cf = ctk.CTkFrame(tb, fg_color="transparent")
        cf.pack(side="right", padx=16, pady=10)
        self._orb = StatusOrb(cf, size=14)
        self._orb.pack(side="right", padx=(6, 0))
        self._conn_lbl = ctk.CTkLabel(cf, text="OFFLINE  scanning...",
                                       font=FONT_SMALL, text_color=C_RED)
        self._conn_lbl.pack(side="right", padx=(0, 8))
        self._port_var = tk.StringVar(value="AUTO")
        self._port_menu = ctk.CTkOptionMenu(
            cf, variable=self._port_var, values=["AUTO"],
            width=130, height=26, font=FONT_SMALL,
            fg_color=C_PANEL, button_color=C_ACCENT2,
            button_hover_color=C_ACCENT, text_color=C_TEXT,
            command=self._on_port_selected)
        self._port_menu.pack(side="right", padx=6)
        ctk.CTkLabel(cf, text="PORT:", font=FONT_SMALL,
                     text_color=C_TEXT_DIM).pack(side="right")
        self._clock_lbl = ctk.CTkLabel(tb, text="", font=FONT_BODY,
                                        text_color=C_TEXT_DIM)
        self._clock_lbl.pack(side="right", padx=30)
        self._tick_clock()

        sb = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=0, height=26)
        sb.pack(fill="x", side="bottom"); sb.pack_propagate(False)
        self._status_bar_lbl = ctk.CTkLabel(
            sb, text="Ready  no ESP32 detected",
            font=FONT_SMALL, text_color=C_TEXT_DIM)
        self._status_bar_lbl.pack(side="left", padx=12)
        self._page_indicator = ctk.CTkLabel(sb, text="DASHBOARD",
                                             font=FONT_SMALL,
                                             text_color=C_ACCENT2)
        self._page_indicator.pack(side="right", padx=12)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)
        self._sidebar = ctk.CTkFrame(body, width=200, fg_color=C_SIDEBAR,
                                      corner_radius=0)
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)
        self._build_sidebar()
        ctk.CTkFrame(body, width=1, fg_color=C_BORDER).pack(side="left", fill="y")
        self._ca = ctk.CTkFrame(body, fg_color="transparent")
        self._ca.pack(side="left", fill="both", expand=True)

        self._pages: dict = {}
        self._active_page = ""
        self._build_pages()
        # Wire personnel manager into building activity page now that both exist
        try:
            self._building_activity._personnel_mgr = self._card_mgr
        except Exception:
            pass
        # Legacy shim removed – no emp_status_panel
        self._show_page("DASHBOARD")

    def _build_sidebar(self):
        self._nav_buttons: dict = {}
        ctk.CTkLabel(self._sidebar, text="NAVIGATION",
                     font=("Courier New", 9, "bold"),
                     text_color=C_TEXT_MUTE
                     ).pack(anchor="w", padx=16, pady=(16, 4))
        for pid, sub in [
            ("DASHBOARD",          "Floor Occupancy"),
            ("LIVE FEED",          "Real-time Events"),
            ("CAMERA",             "Surveillance Cameras"),
            ("PERSONNEL",          "Employee Management"),
            ("ACCESS LOG",         "Access History"),
            ("BUILDING ACTIVITY",  "Employee Location & State"),
            ("ANOMALY LOG",        "Security Violations"),
            ("VISITORS",           "External Visitors"),
            ("TEMP ACCESS",        "Employee Temp Floor Access"),
            ("SYSTEM",             "Settings"),
        ]:
            self._make_nav_btn(self._sidebar, pid, sub)

    def _make_nav_btn(self, parent, page_id, subtitle):
        bf = ctk.CTkFrame(parent, fg_color="transparent", cursor="hand2")
        bf.pack(fill="x", padx=6, pady=2)
        inner = ctk.CTkFrame(bf, fg_color="transparent", corner_radius=8,
                              cursor="hand2")
        inner.pack(fill="x")
        tc = ctk.CTkFrame(inner, fg_color="transparent")
        tc.pack(fill="x", pady=6)
        nl = ctk.CTkLabel(tc, text=page_id, font=FONT_NAV,
                           text_color=C_TEXT_DIM, anchor="center")
        nl.pack(fill="x", pady=(0, 1))
        sl = ctk.CTkLabel(tc, text=subtitle,
                           font=("Courier New", 9), text_color=C_TEXT_MUTE,
                           anchor="center")
        sl.pack(fill="x")

        def on_enter(e, f=inner):
            if self._active_page != page_id:
                f.configure(fg_color=C_NAV_HOVER)

        def on_leave(e, f=inner):
            if self._active_page != page_id:
                f.configure(fg_color="transparent")

        def on_click(pid=page_id):
            self._show_page(pid)

        for w in (inner, nl, sl, tc):
            w.bind("<Enter>", on_enter)
            w.bind("<Leave>", on_leave)
            w.bind("<Button-1>", lambda e, pid=page_id: on_click(pid))

        self._nav_buttons[page_id] = {"frame": inner, "name": nl}

    def _set_nav_active(self, page_id):
        for pid, w in self._nav_buttons.items():
            if pid == page_id:
                w["frame"].configure(fg_color=C_NAV_SEL)
                w["name"].configure(text_color=C_ACCENT)
            else:
                w["frame"].configure(fg_color="transparent")
                w["name"].configure(text_color=C_TEXT_DIM)

    def _build_pages(self):
        ca = self._ca

        dp = ctk.CTkFrame(ca, fg_color="transparent")
        self._pages["DASHBOARD"] = dp
        self._dashboard = OccupancyDashboard(dp, ctrl=self._ctrl)
        self._dashboard.pack(fill="both", expand=True, padx=14, pady=12)

        fp = ctk.CTkFrame(ca, fg_color="transparent")
        self._pages["LIVE FEED"] = fp
        self._phdr(fp, "LIVE FEED", "Real-time scan events")
        self._feed = EventFeed(fp)
        self._feed.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        self._feed.add("System started. Scanning for ESP32...", "SYS")
        self._feed.add("Fingerprint sensor R307S: GPIO 16(RX)  19(TX)  20(Wake)", "FP")

        cam_p = ctk.CTkFrame(ca, fg_color="transparent")
        self._pages["CAMERA"] = cam_p
        self._phdr(cam_p, "CAMERA FEED", "Live surveillance – face recognition enabled")

        cp = ctk.CTkFrame(ca, fg_color="transparent")
        self._pages["PERSONNEL"] = cp
        self._phdr(cp, "PERSONNEL MANAGEMENT",
                   "1 RFID + 1 Fingerprint per employee")
        self._card_mgr = PersonnelManager(cp, self._ctrl, self._feed)
        self._card_mgr.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        self._camera_page = CameraFeedPage(cam_p, personnel_mgr=self._card_mgr,
                                           analyzer=self._analyzer,
                                           ctrl=self._ctrl,
                                           audio=self._audio)
        self._camera_page.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        lp = ctk.CTkFrame(ca, fg_color="transparent")
        self._pages["ACCESS LOG"] = lp
        self._phdr(lp, "ACCESS LOG",
                   "Full access history - RFID and fingerprint, newest first")
        self._log_viewer = LogViewer(lp, self._ctrl, self._feed,
                                     card_mgr=self._card_mgr, db=self._db)
        self._log_viewer.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        # ── BUILDING ACTIVITY page ────────────────────────────────────────────
        bap = ctk.CTkFrame(ca, fg_color="transparent")
        self._pages["BUILDING ACTIVITY"] = bap
        self._phdr(bap, "BUILDING ACTIVITY",
                   "Live employee location, state & violations — undo without FP gate")
        self._building_activity = BuildingActivityPage(
            bap, analyzer=self._analyzer, db=self._db,
            feed=self._feed, ctrl=self._ctrl, personnel_mgr=None)
        self._building_activity.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        # ── ANOMALY LOG page ──────────────────────────────────────────────────
        alp = ctk.CTkFrame(ca, fg_color="transparent")
        self._pages["ANOMALY LOG"] = alp
        self._phdr(alp, "ANOMALY LOG",
                   "Security violation history — go to Building Activity to manage state")
        self._build_anomaly_content(alp)

        vp = ctk.CTkFrame(ca, fg_color="transparent")
        self._pages["VISITORS"] = vp
        self._phdr(vp, "VISITORS", "External Visitor Entry Requests")
        self._visitor_mgr = VisitorAccessManager(
            vp, db=self._db, feed=self._feed, personnel_mgr=self._card_mgr)
        self._visitor_mgr.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        tp = ctk.CTkFrame(ca, fg_color="transparent")
        self._pages["TEMP ACCESS"] = tp
        self._phdr(tp, "TEMP ACCESS", "Employee Temporary Floor Access Requests")
        self._temp_mgr = TemporaryFloorAccessManager(
            tp, db=self._db, feed=self._feed, personnel_mgr=self._card_mgr)
        self._temp_mgr.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        syp = ctk.CTkFrame(ca, fg_color="transparent")
        self._pages["SYSTEM"] = syp
        self._phdr(syp, "SYSTEM SETTINGS",
                   "Connection, time sync and diagnostics")
        self._build_sys_content(syp)

    def _phdr(self, parent, title, subtitle):
        h = ctk.CTkFrame(parent, fg_color=C_PANEL2, corner_radius=0, height=52)
        h.pack(fill="x"); h.pack_propagate(False)
        ctk.CTkLabel(h, text=f"  {title}", font=FONT_HEAD,
                     text_color=C_TEXT).pack(side="left", pady=8)
        ctk.CTkLabel(h, text=subtitle, font=FONT_SMALL,
                     text_color=C_TEXT_DIM).pack(side="left", padx=16)
        ctk.CTkFrame(parent, height=1, fg_color=C_BORDER).pack(fill="x")

    def _show_page(self, page_id):
        if self._active_page == "CAMERA" and page_id != "CAMERA":
            try:
                self._camera_page.stop()
            except Exception:
                pass
        if self._active_page:
            self._pages[self._active_page].pack_forget()
        self._active_page = page_id
        self._pages[page_id].pack(fill="both", expand=True)
        self._set_nav_active(page_id)
        self._page_indicator.configure(text=page_id)
        if page_id == "CAMERA":
            try:
                self._camera_page.start()
            except Exception:
                pass

    def _build_anomaly_content(self, parent):
        top = ctk.CTkFrame(parent, fg_color="transparent")
        top.pack(fill="x", padx=14, pady=(8, 4))

        # Controls bar: strict mode + reset all
        cr = ctk.CTkFrame(top, fg_color=C_PANEL2, corner_radius=8)
        cr.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(cr, text="STRICT MODE:", font=FONT_SMALL,
                     text_color=C_TEXT_DIM).pack(side="left", padx=12, pady=8)
        self._strict_var = tk.BooleanVar(value=False)
        ctk.CTkSwitch(cr, text="Deny access on anomaly",
                      variable=self._strict_var, onvalue=True, offvalue=False,
                      progress_color=C_RED, fg_color=C_BORDER,
                      button_color=C_ACCENT, font=FONT_SMALL, text_color=C_TEXT,
                      command=self._toggle_strict_mode
                      ).pack(side="left", padx=6, pady=8)

        ctk.CTkLabel(cr, text="→ Use Building Activity page to manage individual cards",
                     font=FONT_MICRO, text_color=C_TEXT_MUTE
                     ).pack(side="left", padx=16)

        ctk.CTkButton(cr, text="RESET ALL CARDS", width=140, height=28,
                      fg_color="#3A0010", hover_color=C_RED,
                      font=FONT_SMALL, text_color=C_RED,
                      command=self._reset_all_tracking
                      ).pack(side="right", padx=12, pady=8)

        # Severity legend
        leg = ctk.CTkFrame(top, fg_color=C_PANEL, corner_radius=8)
        leg.pack(fill="x", pady=(0, 4))
        for txt, col, note in [
            ("CRITICAL", C_RED,    "Active breach – intercept now"),
            ("HIGH",     C_ORANGE, "Rule violation – swift action"),
            ("MEDIUM",   C_YELLOW, "Sequencing error – investigate"),
            ("LOW",      C_ACCENT, "Edge case – review in batch"),
        ]:
            ctk.CTkLabel(leg, text=f"{txt}", font=FONT_MICRO_B,
                         text_color=col).pack(side="left", padx=10, pady=6)
            ctk.CTkLabel(leg, text=f"({note})", font=FONT_MICRO,
                         text_color=C_TEXT_MUTE).pack(side="left", padx=(0, 10), pady=6)

        self._anomaly_table = UnusualActivityTable(
            parent, db=self._db, analyzer=self._analyzer,
            feed=self._feed, ctrl=self._ctrl)
        self._anomaly_table.pack(fill="both", expand=True, padx=14, pady=(0, 12))

    def _build_sys_content(self, parent):
        sc = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        sc.pack(fill="both", expand=True, padx=14, pady=8)

        # ── Emergency / Evacuation Mode ──────────────────────────────────────
        emg_frame = ctk.CTkFrame(sc, fg_color="#200008", corner_radius=8,
                                  border_width=2, border_color=C_RED)
        emg_frame.pack(fill="x", pady=(8, 4))
        ctk.CTkLabel(emg_frame, text="⚠  EMERGENCY / EVACUATION MODE",
                     font=FONT_HEAD, text_color=C_RED
                     ).pack(side="left", padx=16, pady=12)
        ctk.CTkLabel(emg_frame,
                     text="Grants ALL access unconditionally. Use during fire alarm or evacuation only.",
                     font=FONT_SMALL, text_color=C_TEXT_DIM
                     ).pack(side="left", padx=4)
        self._emergency_btn = ctk.CTkButton(
            emg_frame, text="EMERGENCY MODE", width=180, height=36,
            fg_color="#8B0000", hover_color=C_RED,
            font=FONT_HEAD, text_color=C_TEXT,
            command=self._toggle_emergency_mode)
        self._emergency_btn.pack(side="right", padx=16, pady=8)

        def section(t):
            ctk.CTkLabel(sc, text=t, font=FONT_HEAD,
                         text_color=C_ACCENT).pack(anchor="w", pady=(18, 4))
            ctk.CTkFrame(sc, height=1, fg_color=C_BORDER).pack(
                fill="x", pady=(0, 8))

        section("SOFTWARE CLOCK")
        rr = ctk.CTkFrame(sc, fg_color=C_PANEL, corner_radius=8)
        rr.pack(fill="x", pady=2)
        ctk.CTkLabel(rr, text="Sync Pi system time -> ESP32 RTC",
                     font=FONT_BODY, text_color=C_TEXT
                     ).pack(side="left", padx=12, pady=10)
        ctk.CTkButton(rr, text="SYNC TIME", width=110, height=30,
                      fg_color=C_ACCENT2, hover_color=C_ACCENT,
                      font=FONT_SMALL, text_color=C_BG,
                      command=self._sync_time
                      ).pack(side="right", padx=12, pady=10)

        section("FINGERPRINT SENSOR")
        fpr = ctk.CTkFrame(sc, fg_color=C_PANEL, corner_radius=8,
                            border_width=1, border_color=C_BORDER)
        fpr.pack(fill="x", pady=2)
        ctk.CTkLabel(fpr,
                     text="R307S  -  Red->5V  Black->GND  Yellow(TX)->GPIO16  Green(RX)->GPIO19  White(Wakeup)->GPIO20",
                     font=FONT_MONO, text_color=C_TEXT_DIM
                     ).pack(side="left", padx=12, pady=10)
        ctk.CTkButton(fpr, text="REFRESH FP LIST", width=140, height=30,
                      fg_color="#1A0A2A", hover_color=C_FP,
                      font=FONT_SMALL, text_color=C_FP,
                      command=lambda: self._ctrl.send_fp_list()
                      ).pack(side="right", padx=12, pady=10)

        section("CONNECTION")
        cr2 = ctk.CTkFrame(sc, fg_color=C_PANEL, corner_radius=8)
        cr2.pack(fill="x", pady=2)
        ctk.CTkButton(cr2, text="FORCE DISCONNECT", width=150, height=30,
                      fg_color="#3A0010", hover_color=C_RED,
                      font=FONT_SMALL, text_color=C_RED,
                      command=self._force_disconnect
                      ).pack(side="left", padx=12, pady=10)
        ctk.CTkButton(cr2, text="RESCAN PORTS", width=130, height=30,
                      fg_color=C_PANEL2, hover_color=C_BORDER,
                      font=FONT_SMALL, text_color=C_TEXT,
                      command=self._rescan_now
                      ).pack(side="left", padx=4, pady=10)

        section("ABOUT")
        ab = ctk.CTkFrame(sc, fg_color=C_PANEL, corner_radius=8)
        ab.pack(fill="x", pady=2)
        ctk.CTkLabel(ab,
                     text=("Floor Access Control System  v10\n"
                           "ESP32-S3 + Arduino Nano + MFRC522 RFID + R307S Fingerprint\n"
                           "Raspberry Pi Controller  --  USB Serial Interface\n"
                           "Protocol baud: 115200  |  Floors: 4  |  Max employees: 50  |  Max FP slots: 127"),
                     font=FONT_MONO, text_color=C_TEXT_DIM, justify="left"
                     ).pack(padx=12, pady=12)

    def _toggle_strict_mode(self):
        self._analyzer.strict_mode = self._strict_var.get()
        state = "ENABLED" if self._analyzer.strict_mode else "DISABLED"
        self._feed.add(f"Strict mode {state}.", "WARN")

    def _reset_all_tracking(self):
        with self._analyzer._lock:
            states = {uid: dict(st) for uid, st in self._analyzer._state.items()}
        for uid, st in states.items():
            for fl in st.get("active_ins", {}).keys():
                try:
                    self._ctrl.send_reset_presence(uid, fl, False)
                except Exception:
                    pass
        self._analyzer.reset_all()
        self._feed.add("All card tracking states reset (ESP32 presence cleared).", "INFO")

    def _handle_anomalies(self, anomalies, uid, name,
                          strict_denied=False, deny_reason=""):
        for a in anomalies:
            self._anomaly_table.add_anomaly(a)
            sev = a["severity"]
            tag = "DENIED" if sev in ("CRITICAL", "HIGH") else "WARN"
            self._feed.add(
                f"ANOMALY [{sev}] {a['type']} | {a['name']} ({a['uid']}) "
                f"F{a['floor']} {a['direction']} -- {a['description']}", tag)
        if strict_denied and deny_reason:
            self._feed.add(f"ACCESS BLOCKED -- {deny_reason}", "DENIED")
        if anomalies:
            a   = anomalies[0]
            sev = a["severity"]
            self._set_status(
                f"SECURITY ALERT [{sev}]: {a['type']} -- {a['name']} on F{a['floor']}",
                C_RED if sev in ("CRITICAL", "HIGH") else C_YELLOW)
            if sev == "CRITICAL":
                self._show_page("ANOMALY LOG")
        # Refresh building activity panel to reflect latest state
        try:
            self._building_activity.refresh()
        except Exception:
            pass

    def _tick_clock(self):
        self._clock_lbl.configure(text=dt.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _schedule_port_scan(self):
        self._scan_timer = self.after(SCAN_INTERVAL * 1000, self._auto_scan)



    # ── Stale-state sweep ─────────────────────────────────────────────────────
    def _schedule_stale_state_check(self):
        """Runs every hour; flags persons who have been marked 'inside' for more
        than _STALE_HOURS without a corresponding exit scan."""
        self._check_stale_states()

    def _check_stale_states(self):
        now = dt.now()
        with self._analyzer._lock:
            state_snapshot = {uid: dict(st) for uid, st in self._analyzer._state.items()}

        for uid, st in state_snapshot.items():
            active_ins: dict = st.get("active_ins", {})
            for floor, ts_str in active_ins.items():
                try:
                    ts_in  = dt.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    hours  = (now - ts_in).total_seconds() / 3600.0
                    if hours >= self._STALE_HOURS:
                        self._feed.add(
                            f"STALE STATE ALERT: UID {uid} has been marked IN on "
                            f"F{floor} for {hours:.1f}h since {ts_str} — "
                            f"verify physical presence or clear state in Building Activity.",
                            "WARN")
                        # Escalate to anomaly log so security sees it
                        anomaly = BehaviorAnalyzer._make(
                            ANOMALY_ORPHAN_OUT, uid, uid, floor, "IN", ts_str,
                            f"Person marked IN on F{floor} for {hours:.1f}h with no exit "
                            f"scan. Possible silent exit, tailgate, or sensor miss.", "MEDIUM")
                        try:
                            self._anomaly_table.add_anomaly(anomaly)
                        except Exception:
                            pass
                except Exception:
                    pass
        # Re-schedule once per hour
        self.after(3600 * 1000, self._check_stale_states)

    # ── Emergency / evacuation mode ───────────────────────────────────────────
    def _toggle_emergency_mode(self):
        self._emergency_mode = not self._emergency_mode
        if self._emergency_mode:
            self._feed.add(
                "⚠ EMERGENCY MODE ACTIVATED — All access granted, anomaly checks "
                "suspended. Use only during evacuation or fire alarm.", "WARN")
            self._set_status("⚠ EMERGENCY MODE ACTIVE — ALL DOORS OPEN", C_RED)
            try:
                self._emergency_btn.configure(
                    text="DEACTIVATE EMERGENCY", fg_color=C_RED)
            except Exception:
                pass
            # Tell the Nano to blink all lights red↔white and unlock all doors
            try:
                self._ctrl._raw_send("EMERGENCY:ON")
            except Exception:
                pass
            # Loop the emergency alarm at highest priority until deactivated
            self._audio.play_loop("emergency.wav", SND_EMERGENCY)
        else:
            self._feed.add("EMERGENCY MODE DEACTIVATED — Normal operation resumed.", "INFO")
            self._set_status("Emergency mode cleared — system normal", C_GREEN)
            try:
                self._emergency_btn.configure(
                    text="EMERGENCY MODE", fg_color="#8B0000")
            except Exception:
                pass
            # Tell the Nano to restore normal state (all reset)
            try:
                self._ctrl._raw_send("EMERGENCY:OFF")
            except Exception:
                pass
            # Stop the emergency alarm
            self._audio.stop()

    # ── Reconnect state resync ────────────────────────────────────────────────
    def _resync_esp32_state(self):
        """After reconnecting, push all known in-building presence flags back to
        the ESP32 so its hardware LED / relay state matches our software state.
        A real building system must reconcile hardware and software on every
        reconnect to prevent phantom 'access granted' on stale ESP32 state."""
        with self._analyzer._lock:
            state_copy = {uid: dict(st) for uid, st in self._analyzer._state.items()}
        pushed = 0
        for uid, st in state_copy.items():
            for floor in st.get("active_ins", {}).keys():
                try:
                    self._ctrl.send_reset_presence(uid, floor, True)
                    pushed += 1
                except Exception:
                    pass
        if pushed:
            self._feed.add(
                f"STATE RESYNC: Pushed {pushed} active presence flags to ESP32 after reconnect.",
                "INFO")


    def _auto_scan(self):
        if not self._connected:
            ports = find_esp32_ports()
            all_ports = list(dict.fromkeys(
                ["AUTO"] + ports +
                [p.device for p in serial.tools.list_ports.comports()]))
            self._port_menu.configure(values=all_ports)
            if ports:
                chosen = ports[0]
                if self._port_var.get() in ("AUTO", chosen):
                    self._set_status(f"ESP32 found on {chosen} -- connecting...",
                                     C_YELLOW)
                    threading.Thread(target=self._ctrl.connect,
                                     args=(chosen,), daemon=True).start()
            else:
                self._set_status("No ESP32 detected -- scanning...", C_RED)
        self._schedule_port_scan()

    def _rescan_now(self):
        if self._scan_timer:
            self.after_cancel(self._scan_timer)
        self._auto_scan()

    def _on_port_selected(self, choice):
        if choice == "AUTO" or self._connected:
            return
        self._set_status(f"Connecting to {choice}...", C_YELLOW)
        threading.Thread(target=self._ctrl.connect,
                         args=(choice,), daemon=True).start()

    def _start_event_loop(self):
        self._process_events()

    def _process_events(self):
        try:
            while True:
                evt = self._eq.get_nowait()
                self._handle_event(evt)
        except queue.Empty:
            pass
        self.after(50, self._process_events)

    def _trigger_alert_light(self, floor):
        self._ctrl.send_light(floor, "alert")
        self.after(5000, lambda f=floor: self._ctrl.send_light_release(f))

    def _handle_event(self, evt: dict):
        kind = evt.get("event", "")

        if kind == "_connected":
            port = evt.get("port", "")
            self._connected = True
            self._ctrl.last_rx_time = time.time()   # reset heartbeat on fresh connect
            self._orb.set_color(C_GREEN)
            self._conn_lbl.configure(text=f"ONLINE  {port}", text_color=C_GREEN)
            self._set_status(f"Connected to ESP32 on {port}", C_GREEN)
            self._feed.add(f"ESP32 connected on {port}", "SYS")
            self._sync_time()
            # Push any in-memory state back to the freshly connected ESP32
            self.after(1500, self._resync_esp32_state)

        elif kind == "_disconnected":
            self._on_disconnected()

        elif kind == "_connect_error":
            self._set_status(f"Connect failed: {evt.get('msg', '')}", C_RED)

        elif kind == "_raw":
            msg = evt.get("msg", "")
            tag = "FP" if msg.startswith("[FP]") else "DIM"
            self._feed.add(f"[RAW] {msg}", tag)

        elif kind == "boot":
            fp_ok  = evt.get("fp_ok", False)
            fp_cnt = evt.get("fp_count", 0)
            self._feed.add(
                f"ESP32 boot -- {evt.get('cards', '?')} RFID cards  |  "
                f"FP sensor: {'OK' if fp_ok else 'OFFLINE'}  "
                f"({fp_cnt} fingerprints)", "SYS")
            self._card_mgr.refresh()
            try:
                self._building_activity._personnel_mgr = self._card_mgr
                self._building_activity.refresh()
            except Exception:
                pass
            if not fp_ok:
                self._dashboard.fp_widget.update_status("sensor_offline")

        elif kind == "scan":
            self._handle_scan_event(evt, is_fp=False)

        elif kind == "fp_scan":
            fp_id      = evt.get("fp_id", 0)
            confidence = evt.get("confidence", 0)
            name       = evt.get("name", "") or "Unknown"
            granted    = "GRANTED" in evt.get("result", "").upper()
            direction  = (evt.get("dir", "") or "").strip().upper() or "IN"
            self._dashboard.fp_widget.update_from_fp_scan(
                name, fp_id, confidence, granted, direction)
            self._handle_scan_event(evt, is_fp=True)

        elif kind == "fp_status":
            status = evt.get("status", "")
            extra  = {k: v for k, v in evt.items() if k not in ("event", "status")}
            self._dashboard.fp_widget.update_status(status, extra)

            fp_feed_map = {
                "ready":             lambda e: f"FP sensor ready - {e.get('count', '?')} templates enrolled",
                "finger_detected":   lambda e: "FP: Finger detected - scanning...",
                "no_match":          lambda e: f"FP: No match ({e.get('reason', 'unknown fingerprint')})",
                "sensor_offline":    lambda e: "FP: Sensor OFFLINE - check wiring",
                "enroll_place":      lambda e: f"FP: Enroll ID:{e.get('id','?')} - PLACE FINGER on sensor",
                "enroll_remove":     lambda e: f"FP: Enroll ID:{e.get('id','?')} - REMOVE finger, then place again",
                "enroll_done":       lambda e: f"FP: Enrolled ID:{e.get('id','?')}  {e.get('name','')}  Floor {e.get('floor','?')}",
                "enroll_failed":     lambda e: f"FP: Enrollment FAILED - {e.get('msg','')}",
                "enroll_cancelled":  lambda e: "FP: Enrollment cancelled",
            }
            if status in fp_feed_map:
                msg = fp_feed_map[status](extra)
                feed_tag = ("WARN" if status in ("no_match", "enroll_failed", "sensor_offline")
                            else "FP")
                self._feed.add(msg, feed_tag)
                self._set_status(msg,
                    C_GREEN if status in ("ready", "enroll_done") else
                    C_RED   if status in ("no_match", "enroll_failed", "sensor_offline") else
                    C_YELLOW)

            # Unknown fingerprint → play deny tone
            if status == "no_match":
                play_sound("deny.wav", SND_DENY)

            if status == "enroll_done":
                self.after(500, self._ctrl.send_fp_list)

        elif kind == "fp_records":
            data       = evt.get("data", [])
            sensor_ok  = evt.get("sensor_ok", True)
            sensor_cnt = evt.get("sensor_count", len(data))
            self._card_mgr.populate_fp(data)
            self._feed.add(
                f"FP records loaded: {len(data)} in DB  |  "
                f"Sensor templates: {sensor_cnt}  |  Sensor: {'OK' if sensor_ok else 'OFFLINE'}",
                "FP")

        elif kind == "enrolled":
            self._feed.add(
                f"AUTO-ENROLLED: {evt.get('uid','')} -> Floor {evt.get('floor','')}",
                "INFO")
            self._card_mgr.refresh()

        elif kind == "captured":
            uid = evt.get("uid", "")
            self._feed.add(
                f"CAPTURED UID: {uid} -- assign in Personnel page", "WARN")
            self._card_mgr.show_captured(uid)
            self._show_page("PERSONNEL")

        elif kind == "ack":
            self._feed.add(evt.get("msg", ""), "INFO")
            self._set_status(evt.get("msg", ""), C_GREEN)

        elif kind == "err":
            self._feed.add(f"ERROR: {evt.get('msg', '')}", "DENIED")
            self._set_status(f"Error: {evt.get('msg', '')}", C_RED)

        elif kind == "cards":
            data = evt.get("data", [])
            self._card_mgr.populate(data)
            self._feed.add(f"Cards loaded: {len(data)}", "DIM")

        elif kind == "log":
            data = evt.get("data", [])
            self._log_viewer.populate(data)
            self._feed.add(f"Log fetched: {len(data)} entries", "DIM")

    def _handle_scan_event(self, evt: dict, is_fp: bool):
        floor        = int(evt.get("floor", 0))
        uid          = evt.get("uid", "").strip().upper()
        res          = evt.get("result", "")
        name         = evt.get("name", "") or "Unknown"
        dir_from_esp = (evt.get("dir", "") or "").strip().upper()
        ts           = evt.get("time", "")
        local_ts     = (utc_to_local(ts) if ts
                        else dt.now().strftime("%Y-%m-%d %H:%M:%S"))

        # ── Emergency / evacuation mode bypass ───────────────────────────────
        # In a real building, fire-alarm activation must never let the system
        # block egress.  If emergency mode is on, grant unconditionally and log.
        if self._emergency_mode and not is_fp:
            self._ctrl.send_grant_floor(floor)
            self._feed.add(
                f"[EMERGENCY] F{floor} GRANTED (override) | UID:{uid} | {name} "
                f"| DIR:{dir_from_esp} | {local_ts}", "WARN")
            if 1 <= floor <= 4:
                self._dashboard.update_floor_scan(
                    floor, uid, name, True, dir_from_esp,
                    registered_floor=None, is_fp=False)
            return

        if is_fp and floor == 0:
            granted    = "GRANTED" in res.upper()
            is_inside  = (dir_from_esp == "IN")
            deny_reason_str = evt.get("deny_reason", "")

            if not granted:
                anomaly = BehaviorAnalyzer._make(
                    ANOMALY_FP_EXIT_DENIED, uid, name, 0,
                    "OUT", local_ts,
                    f"{name} attempted to exit building via fingerprint without "
                    f"completing RFID exit sequence. "
                    + (f"Reason: {deny_reason_str}" if deny_reason_str else
                       "Must tap all floor readers OUT then Floor-1 reader before FP exit."),
                    "CRITICAL")
                self._handle_anomalies(
                    [anomaly], uid, name,
                    strict_denied=True,
                    deny_reason="FP exit blocked - RFID exit sequence incomplete")
                self._dashboard.fp_widget.update_from_fp_scan(
                    name, evt.get("fp_id", 0), evt.get("confidence", 0),
                    False, "OUT")
                self._feed.add(
                    f"FP GATE EXIT BLOCKED | {name} | {deny_reason_str or 'RFID exit sequence incomplete'} | {local_ts}",
                    "DENIED")
                self._db.insert_access_log(
                    local_ts, 0, uid, name, "OUT",
                    f"DENIED-ExitOrderViolation: {deny_reason_str}",
                    granted=False, injected=False)
                self._ctrl.send_get_log()
                # Audio: FP exit denied
                self._play_event_sound(
                    granted=False, is_fp=True, floor=0,
                    temp_allowed=False, dir_from_esp="OUT",
                    anomalies=[], anomaly_deny=True)
                return

            self._analyzer.fp_building_signin(name, is_inside)
            self._dashboard.update_fp_gate(name, uid, is_inside, local_ts)
            self._dashboard.fp_widget.update_from_fp_scan(
                name, evt.get("fp_id", 0), evt.get("confidence", 0),
                True, dir_from_esp)
            self._db.insert_access_log(
                local_ts, 0, uid, name,
                dir_from_esp, res, granted=True, injected=False)
            sym = "ENTERED" if is_inside else "EXITED"
            self._feed.add(
                f"FP GATE {sym} | {name} | UID:{uid} | {local_ts}", "FP")
            self._ctrl.send_get_log()
            # Audio: FP building sign-in granted
            self._play_event_sound(
                granted=True, is_fp=True, floor=0,
                temp_allowed=False, dir_from_esp=dir_from_esp,
                anomalies=[], anomaly_deny=False)
            return

        registered_floor = floor if is_fp else None
        card_name = name.strip()

        if not is_fp:
            for c in getattr(self._card_mgr, "_cards", []):
                if c.get("uid", "").strip().upper() == uid:
                    registered_floor = int(c.get("floor", 0))
                    card_name = c.get("name", name).strip() or name
                    break

        granted         = "GRANTED" in res.upper()
        original_granted = granted
        anomalies       = []
        anomaly_deny    = False
        anomaly_reason  = ""
        is_lobby_pt     = False
        display_dir     = dir_from_esp if dir_from_esp else "IN"

        temp_allowed = False
        if not is_fp and self._db and card_name:
            if self._db.has_approved_temp_access(card_name, floor):
                temp_allowed = True
                granted      = True

                uid_state = self._analyzer._state.setdefault(uid, {
                    "floor1_entered": False, "in_lobby": False,
                    "active_ins": {}, "restricted": False})

                already_inside = floor in uid_state.get("active_ins", {})

                if already_inside:
                    display_dir = "OUT"
                    higher_floors = sorted(
                        [f for f in uid_state.get("active_ins", {}) if f > floor])
                    if higher_floors:
                        granted      = False
                        anomaly_deny = True
                        dir_from_esp = "OUT"
                        mef          = ", ".join(f"F{f}" for f in higher_floors)
                        res          = f"DENIED -- Must exit {mef} before leaving F{floor}."
                        anomalies.append(BehaviorAnalyzer._make(
                            ANOMALY_OUT_OF_ORDER, uid, card_name, floor,
                            "OUT", local_ts,
                            f"Temp exit F{floor} blocked: still checked into {mef}.",
                            "HIGH"))
                        self._feed.add(
                            f"TEMP EXIT BLOCKED → {card_name} must exit "
                            f"{mef} before F{floor}", "DENIED")
                    else:
                        dir_from_esp = "OUT"
                        res = f"GRANTED (TEMP EXIT F{floor})"
                        uid_state["active_ins"].pop(floor, None)
                        if not uid_state["active_ins"]:
                            uid_state["in_lobby"] = True
                        if self._db:
                            self._db.save_card_state(uid, uid_state)
                        self._ctrl.send_reset_presence(uid, floor, False)
                        self._ctrl.send_grant_floor(floor)
                        self._feed.add(
                            f"TEMP EXIT → {card_name} left F{floor} | "
                            f"GRANT_FLOOR + RESET_PRESENCE(OUT) sent", "INFO")
                else:
                    display_dir  = "IN"
                    dir_from_esp = "IN"
                    other_active = sorted(uid_state.get("active_ins", {}).keys())
                    if floor > 1 and not uid_state.get("floor1_entered", False):
                        granted      = False
                        anomaly_deny = True
                        res          = "DENIED -- Must enter via Floor 1 first."
                        anomalies.append(BehaviorAnalyzer._make(
                            ANOMALY_FLOOR1_BYPASS, uid, card_name, floor,
                            "IN", local_ts,
                            f"Temp access F{floor} attempted without scanning "
                            f"through Floor 1 first. Possible tailgate or bypass.",
                            "CRITICAL"))
                        self._feed.add(
                            f"TEMP ENTRY BLOCKED → {card_name} skipped "
                            f"Floor 1 scanner before F{floor}", "DENIED")
                    elif self._analyzer.strict_mode and other_active:
                        granted      = False
                        anomaly_deny = True
                        mef          = ", ".join(f"F{f}" for f in other_active)
                        res          = f"DENIED -- Already checked into {mef}."
                        anomalies.append(BehaviorAnalyzer._make(
                            ANOMALY_MULTI_IN, uid, card_name, floor,
                            "IN", local_ts,
                            f"Temp entry F{floor} blocked (strict): already IN on {mef}.",
                            "HIGH"))
                        self._feed.add(
                            f"TEMP ENTRY BLOCKED (strict) → {card_name} "
                            f"already in {mef}", "DENIED")
                    else:
                        dir_from_esp = "IN"
                        res = f"GRANTED (TEMP ACCESS F{floor})"
                        uid_state["active_ins"][floor] = local_ts
                        uid_state["floor1_entered"] = True
                        uid_state["in_lobby"]        = True
                        if self._db:
                            self._db.save_card_state(uid, uid_state)
                        if not self._analyzer.is_fp_signed_in(card_name):
                            self._analyzer.fp_building_signin(card_name, True)
                        self._ctrl.send_reset_presence(uid, floor, True)
                        self._ctrl.send_grant_floor(floor)
                        self._db.update_temp_entry_time(card_name, floor, local_ts)
                        if hasattr(self, '_temp_mgr'):
                            self.after(200, self._temp_mgr.refresh)
                        self._feed.add(
                            f"TEMP ENTRY → {card_name} on F{floor} | "
                            f"GRANT_FLOOR + RESET_PRESENCE(IN) sent | countdown started",
                            "INFO")

        if not is_fp and "NOFPSIGNIN" in res.upper().replace("-", "").replace(" ", ""):
            granted      = False
            anomaly_deny = True
            res          = "DENIED -- No FP Sign-In"
            anomalies.append(BehaviorAnalyzer._make(
                ANOMALY_NO_FP_SIGNIN, uid, card_name, floor,
                display_dir, local_ts,
                f"{card_name} used RFID card without fingerprint sign-in at building "
                f"entrance. Possible tailgate, stolen card, or bypass.", "CRITICAL"))

        if not is_fp and not anomaly_deny:
            if not registered_floor and not temp_allowed:
                uid_state_chk  = self._analyzer._state.get(uid, {})
                still_active   = sorted(uid_state_chk.get("active_ins", {}).keys())
                if still_active:
                    granted = False; anomaly_deny = True
                    mef = ", ".join(f"F{f}" for f in still_active)
                    res = f"DENIED -- Must exit {mef} before leaving F{floor}."
                    anomalies.append(BehaviorAnalyzer._make(
                        ANOMALY_OUT_OF_ORDER, uid, card_name, floor,
                        display_dir, local_ts,
                        f"F{floor} scan blocked: still checked into {mef}. "
                        f"Exit temp floor first.", "HIGH"))
                else:
                    granted = False; anomaly_deny = True
                    res = "DENIED -- Unknown Card"
                    anomalies.append(BehaviorAnalyzer._make(
                        ANOMALY_UNKNOWN_CARD, uid, card_name, floor,
                        display_dir, local_ts,
                        "Card not registered in the system.", "CRITICAL"))
            else:
                if floor != 1 and floor != registered_floor and not temp_allowed:
                    granted = False; anomaly_deny = True
                    res = (f"DENIED -- Unauthorized Floor {floor} "
                           f"(registered F{registered_floor})")
                    display_dir = "IN"
                    state = self._analyzer._state.get(uid, {})
                    inside_own  = registered_floor in state.get("active_ins", {})
                    inside_bldg = (state.get("floor1_entered", False) or
                                   state.get("in_lobby", False))
                    sev  = "CRITICAL" if inside_own else (
                           "HIGH" if inside_bldg else "CRITICAL")
                    desc = (f"Still checked into Floor {registered_floor} "
                            f"but attempted Floor {floor}." if inside_own
                            else f"Card inside building but attempted "
                                 f"unauthorized Floor {floor}.")
                    anomalies.append(BehaviorAnalyzer._make(
                        ANOMALY_UNAUTHORIZED_FLOOR, uid, card_name, floor,
                        display_dir, local_ts, desc, sev))
                else:
                    is_lobby_pt = (floor == 1 and registered_floor is not None and
                                   registered_floor > 1)
                    if not temp_allowed:
                        anomalies, anomaly_deny, anomaly_reason = (
                            self._analyzer.process(
                                uid, floor, dir_from_esp, card_name, local_ts,
                                is_lobby_passthrough=is_lobby_pt))
                        if anomaly_deny:
                            granted = False
                            res = anomaly_reason

            if (granted and self._analyzer.is_restricted(uid)
                    and not anomaly_deny):
                granted = False
                res = "DENIED -- Card restricted due to prior anomaly."
                self._feed.add(f"STRICT DENY: {card_name} ({uid})", "DENIED")
                anomaly_deny = True

        if not is_fp and ((original_granted and not granted) or anomaly_deny):
            self._ctrl.send_reset_presence(uid, floor, dir_from_esp.lower() == "out")
            if 1 <= floor <= 4:
                self._trigger_alert_light(floor)

        tag   = "GRANTED" if granted else "DENIED"
        label = ("GRANTED" if granted else "DENIED") + (
            f" (F{registered_floor} card)" if is_lobby_pt and granted else "")
        if temp_allowed and granted:
            label = f"GRANTED (TEMP F{floor})"
        elif temp_allowed and not granted:
            label = "DENIED (TEMP)"
        fp_prefix = "FP " if is_fp else ""
        conf_str = ""
        if is_fp:
            conf_str = f" | Conf:{evt.get('confidence',0)}"
        self._feed.add(
            f"{fp_prefix}F{floor} | {label} | UID:{uid} | {card_name} "
            f"| DIR:{display_dir}{conf_str} | {local_ts}",
            "FP" if is_fp else tag)

        if 1 <= floor <= 4:
            self._dashboard.update_floor_scan(
                floor, uid, card_name, granted, display_dir,
                registered_floor=registered_floor, is_fp=is_fp)

        # Keep Building Activity page live after every scan
        try:
            self._building_activity.refresh()
        except Exception:
            pass

        if not is_fp and anomalies and (not temp_allowed or anomaly_deny):
            self._handle_anomalies(
                anomalies, uid, card_name,
                strict_denied=anomaly_deny and self._analyzer.strict_mode,
                deny_reason=anomaly_reason)

        if not is_fp:
            if temp_allowed and granted:
                self._log_viewer.inject_granted_entry({
                    "time":   local_ts,    "floor":  floor,
                    "uid":    uid,         "name":   card_name,
                    "dir":    display_dir, "reason": res,
                })
                self._ctrl.send_get_log()
            elif temp_allowed and not granted:
                self._log_viewer.inject_local_entry({
                    "time": local_ts, "floor": floor, "uid": uid,
                    "name": card_name, "dir": display_dir, "reason": res})
            elif not (anomaly_deny and self._analyzer.strict_mode):
                self._db.insert_access_log(
                    local_ts, floor, uid, card_name, display_dir, res,
                    granted=granted, injected=False)
                self._ctrl.send_get_log()
            else:
                self._log_viewer.inject_local_entry({
                    "time": local_ts, "floor": floor, "uid": uid,
                    "name": card_name, "dir": display_dir, "reason": res})
        else:
            self._db.insert_access_log(
                local_ts, floor, uid, card_name, display_dir, res,
                granted=granted, injected=False)
            self._ctrl.send_get_log()

        # ── Audio feedback for RFID scans ────────────────────────────────
        if not is_fp:
            self._play_event_sound(
                granted=granted,
                is_fp=False,
                floor=floor,
                temp_allowed=temp_allowed,
                dir_from_esp=dir_from_esp,
                anomalies=anomalies,
                anomaly_deny=anomaly_deny)

    # ── Audio event dispatcher ───────────────────────────────────────────────
    def _play_event_sound(self, *,
                          granted: bool,
                          is_fp: bool,
                          floor: int,
                          temp_allowed: bool,
                          dir_from_esp: str,
                          anomalies: list,
                          anomaly_deny: bool) -> None:
        """Play a two-part sound sequence for every access event.

        Every event plays a SHORT TONE first (grant.wav / deny.wav /
        violation.wav) immediately, then a SPECIFIC VOICE CLIP second.
        This gives instant audible feedback followed by informative context.

        Sequence rules:
          GRANT  IN  → grant.wav  then  <specific grant clip>
          GRANT  OUT → grant.wav  only  (silent voice, just the chime)
          DENY       → deny.wav   then  <specific deny/alert clip>
          VIOLATION  → violation.wav then <specific alert clip>

        Priority (lower = higher urgency, preempts current playback):
            SND_EMERGENCY = 0
            SND_CRITICAL  = 1
            SND_DENY      = 2
            SND_HIGH      = 3
            SND_GRANT     = 4
        """
        direction     = (dir_from_esp or "").upper()
        anomaly_types = {a.get("type", "") for a in anomalies}

        # ── GRANT ─────────────────────────────────────────────────────────────
        if granted and not anomaly_deny:
            if direction == "OUT":
                # Sign-out: just the chime, no voice
                self._audio.play_sequence(["grant.wav"], SND_GRANT)

            else:  # IN
                # Pick the most specific voice clip for this entry
                if is_fp and floor == 0:
                    voice = "grant_fp.wav"
                elif temp_allowed:
                    voice = "grant_temp.wav"
                elif floor == 1:
                    voice = "grant_floor1.wav"
                else:
                    voice = "grant_floor.wav"
                # Chime first, then voice
                self._audio.play_sequence(["grant.wav", voice], SND_GRANT)
            return

        # ── DENY ──────────────────────────────────────────────────────────────
        if not granted:
            # Pick the most specific deny/alert voice clip
            if ANOMALY_FP_EXIT_DENIED in anomaly_types:
                voice = "deny_sequence.wav"
                pri   = SND_DENY
            elif ANOMALY_UNKNOWN_CARD in anomaly_types:
                voice = "deny_unknown_card.wav"
                pri   = SND_DENY
            elif ANOMALY_NO_FP_SIGNIN in anomaly_types:
                voice = "deny_fp_required.wav"
                pri   = SND_CRITICAL
            elif ANOMALY_UNAUTHORIZED_FLOOR in anomaly_types:
                voice = "alert_intercept.wav"
                pri   = SND_CRITICAL
            elif ANOMALY_FLOOR1_BYPASS in anomaly_types:
                voice = "alert_bypass.wav"
                pri   = SND_HIGH
            elif ANOMALY_OUT_OF_ORDER in anomaly_types or ANOMALY_ORPHAN_OUT in anomaly_types:
                voice = "alert_out_of_order.wav"
                pri   = SND_HIGH
            elif ANOMALY_MULTI_IN in anomaly_types:
                voice = "alert_multi_floor.wav"
                pri   = SND_HIGH
            elif ANOMALY_FLOOR_SKIP in anomaly_types or ANOMALY_RAPID_REENTRY in anomaly_types:
                voice = "alert_floor_skip.wav"
                pri   = SND_HIGH
            elif is_fp and not granted and floor == 0:
                voice = "deny_sequence.wav"
                pri   = SND_DENY
            else:
                voice = "deny_unknown_card.wav"
                pri   = SND_DENY

            # deny.wav chime first, then the specific voice
            self._audio.play_sequence(["deny.wav", voice], pri)
            return

        # ── VIOLATION (granted but with anomalies — warn without blocking) ────
        if anomaly_types:
            # Pick best voice clip from anomalies present
            best_voice, best_pri = "violation.wav", SND_HIGH
            for atype in anomaly_types:
                if atype in ANOMALY_SOUNDS:
                    fname, pri = ANOMALY_SOUNDS[atype]
                    if pri < best_pri:
                        best_voice, best_pri = fname, pri
            self._audio.play_sequence(["violation.wav", best_voice], best_pri)

    def _on_disconnected(self):
        self._connected = False
        self._ctrl.disconnect()
        self._orb.set_color(C_RED)
        self._conn_lbl.configure(text="OFFLINE  scanning...", text_color=C_RED)
        self._set_status(
            "ESP32 disconnected -- auto-scanning for reconnection", C_RED)
        self._feed.add("ESP32 disconnected", "WARN")
        self._dashboard.fp_widget.update_status("sensor_offline")

    def _set_status(self, msg, color=C_TEXT_DIM):
        self._status_bar_lbl.configure(text=msg, text_color=color)

    def _sync_time(self):
        self._ctrl.send_time()
        self._feed.add(f"Time synced: {dt.now()}", "INFO")

    def _force_disconnect(self):
        self._ctrl.disconnect()
        self._on_disconnected()

    def on_close(self):
        try:
            self._camera_page.stop()
        except Exception:
            pass
        self._audio.stop()         # kill any playing sound before exit
        self._ctrl.disconnect()
        self._db.close()
        self.destroy()


if __name__ == "__main__":
    app = FloorAccessApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()