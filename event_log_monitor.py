"""
Windows Event Log Monitor
Monitors Security Event Logs in real-time for:
  - Event ID 4625: Failed Login Attempts
  - Event ID 4672: Privilege Escalation (Special Privileges Assigned)
  - Event ID 7045: New Service Installation

Alerts on high-frequency occurrences using configurable thresholds.

Requirements:
  pip install pywin32 winevt  (Windows only)
  Run as Administrator for Security log access.
"""

import sys
import time
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, Optional

# ── Windows-only imports ──────────────────────────────────────────────────────
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32security
    import winerror
    WINDOWS = True
except ImportError:
    WINDOWS = False
    print("[WARNING] pywin32 not found. Running in SIMULATION mode.\n")

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AlertThreshold:
    """How many events within window_seconds triggers an alert."""
    count: int
    window_seconds: int
    cooldown_seconds: int = 60   # silence repeat alerts for this long


THRESHOLDS: Dict[int, AlertThreshold] = {
    4625: AlertThreshold(count=5,  window_seconds=60,  cooldown_seconds=120),  # 5 failures / min
    4672: AlertThreshold(count=10, window_seconds=60,  cooldown_seconds=60),   # 10 privilege assigns / min
    7045: AlertThreshold(count=2,  window_seconds=300, cooldown_seconds=300),  # 2 new services / 5 min
}

EVENT_DESCRIPTIONS = {
    4625: "Failed Logon Attempt",
    4672: "Special Privileges Assigned (Privilege Escalation)",
    7045: "New Service Installed",
}

LOG_SOURCES = {
    4625: "Security",
    4672: "Security",
    7045: "System",
}

POLL_INTERVAL_SECONDS = 2   # how often to re-query the log
LOG_FILE = "event_monitor.log"

# ─────────────────────────────────────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
log = logging.getLogger("EventMonitor")

# ─────────────────────────────────────────────────────────────────────────────
# Event tracker
# ─────────────────────────────────────────────────────────────────────────────

class EventTracker:
    """Sliding-window counter per Event ID with alert cooldown."""

    def __init__(self):
        # deque of timestamps for each event_id
        self._timestamps: Dict[int, deque] = defaultdict(deque)
        # timestamp of last alert per event_id (to enforce cooldown)
        self._last_alert: Dict[int, Optional[datetime]] = defaultdict(lambda: None)
        self._lock = threading.Lock()

    def record(self, event_id: int, event_time: datetime) -> bool:
        """
        Record an event. Returns True if an alert should fire.
        """
        threshold = THRESHOLDS.get(event_id)
        if threshold is None:
            return False

        with self._lock:
            ts_queue = self._timestamps[event_id]
            ts_queue.append(event_time)

            # Drop events outside the sliding window
            cutoff = event_time - timedelta(seconds=threshold.window_seconds)
            while ts_queue and ts_queue[0] < cutoff:
                ts_queue.popleft()

            count_in_window = len(ts_queue)

            if count_in_window >= threshold.count:
                last = self._last_alert[event_id]
                now = datetime.now()
                if last is None or (now - last).total_seconds() >= threshold.cooldown_seconds:
                    self._last_alert[event_id] = now
                    return True   # fire alert

        return False

    def window_count(self, event_id: int) -> int:
        with self._lock:
            return len(self._timestamps[event_id])


tracker = EventTracker()

# ─────────────────────────────────────────────────────────────────────────────
# Alert handler
# ─────────────────────────────────────────────────────────────────────────────

def fire_alert(event_id: int, extra: dict):
    threshold = THRESHOLDS[event_id]
    count = tracker.window_count(event_id)
    desc  = EVENT_DESCRIPTIONS[event_id]

    msg = (
        f"\n{'='*70}\n"
        f"  🚨  ALERT  |  EventID {event_id}  |  {desc}\n"
        f"  Count in last {threshold.window_seconds}s : {count}  "
        f"(threshold: {threshold.count})\n"
    )
    if extra:
        for k, v in extra.items():
            msg += f"  {k:<20}: {v}\n"
    msg += f"{'='*70}"
    log.warning(msg)

    # ── Hook: send email / Slack / SIEM here ──────────────────────────────
    # send_slack_alert(event_id, desc, count, extra)
    # send_email_alert(event_id, desc, count, extra)
    # push_to_siem(event_id, desc, count, extra)


# ─────────────────────────────────────────────────────────────────────────────
# Event parsers  (extract useful fields per Event ID)
# ─────────────────────────────────────────────────────────────────────────────

def _safe_str(obj) -> str:
    try:
        return str(obj).strip()
    except Exception:
        return "<unknown>"


def parse_event(event_id: int, event) -> dict:
    """Extract human-readable fields from a raw win32evtlog event record."""
    extras = {}
    try:
        strings = event.StringInserts or []

        if event_id == 4625:
            # Index reference: https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
            extras = {
                "Subject Account": _safe_str(strings[1]) if len(strings) > 1 else "?",
                "Target Account" : _safe_str(strings[5]) if len(strings) > 5 else "?",
                "Workstation"    : _safe_str(strings[13]) if len(strings) > 13 else "?",
                "Source IP"      : _safe_str(strings[19]) if len(strings) > 19 else "?",
                "Logon Type"     : _safe_str(strings[10]) if len(strings) > 10 else "?",
                "Failure Reason" : _safe_str(strings[8])  if len(strings) > 8  else "?",
            }

        elif event_id == 4672:
            extras = {
                "Account Name"   : _safe_str(strings[1]) if len(strings) > 1 else "?",
                "Account Domain" : _safe_str(strings[2]) if len(strings) > 2 else "?",
                "Logon ID"       : _safe_str(strings[3]) if len(strings) > 3 else "?",
                "Privileges"     : _safe_str(strings[4]) if len(strings) > 4 else "?",
            }

        elif event_id == 7045:
            extras = {
                "Service Name"   : _safe_str(strings[0]) if len(strings) > 0 else "?",
                "Image Path"     : _safe_str(strings[1]) if len(strings) > 1 else "?",
                "Service Type"   : _safe_str(strings[2]) if len(strings) > 2 else "?",
                "Start Type"     : _safe_str(strings[3]) if len(strings) > 3 else "?",
                "Account"        : _safe_str(strings[4]) if len(strings) > 4 else "?",
            }
    except Exception as exc:
        extras["parse_error"] = str(exc)

    return extras


# ─────────────────────────────────────────────────────────────────────────────
# Real-time monitor  (Windows)
# ─────────────────────────────────────────────────────────────────────────────

def monitor_windows():
    """Open each log source and poll for new matching events."""

    # Open handles per unique log source
    handles = {}
    for event_id, source in LOG_SOURCES.items():
        if source not in handles:
            try:
                h = win32evtlog.OpenEventLog(None, source)
                handles[source] = h
                log.info(f"Opened event log: {source}")
            except Exception as exc:
                log.error(f"Cannot open '{source}' log (run as Administrator?): {exc}")
                sys.exit(1)

    # Remember the last record number we processed per source
    last_record: Dict[str, int] = {}
    for source, h in handles.items():
        total = win32evtlog.GetNumberOfEventLogRecords(h)
        last_record[source] = total   # skip historical events on startup

    log.info(f"Monitoring started. Watching Event IDs: {list(THRESHOLDS.keys())}")
    log.info(f"Polling every {POLL_INTERVAL_SECONDS}s  |  Log file: {LOG_FILE}\n")

    target_ids = set(THRESHOLDS.keys())

    while True:
        for source, h in handles.items():
            try:
                events = win32evtlog.ReadEventLog(
                    h,
                    win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                    0,
                )
                for evt in events:
                    if evt.RecordNumber <= last_record[source]:
                        continue
                    last_record[source] = evt.RecordNumber

                    eid = evt.EventID & 0xFFFF   # mask provider bits
                    if eid not in target_ids:
                        continue

                    evt_time = datetime(*evt.TimeGenerated.timetuple()[:6])
                    extras   = parse_event(eid, evt)

                    log.info(
                        f"Event {eid} ({EVENT_DESCRIPTIONS[eid]}) | "
                        + " | ".join(f"{k}={v}" for k, v in extras.items())
                    )

                    if tracker.record(eid, evt_time):
                        fire_alert(eid, extras)

            except Exception as exc:
                log.error(f"Error reading {source}: {exc}")

        time.sleep(POLL_INTERVAL_SECONDS)


# ─────────────────────────────────────────────────────────────────────────────
# Simulation mode  (non-Windows / demo)
# ─────────────────────────────────────────────────────────────────────────────

import random

SIMULATED_EVENTS = [
    (4625, {"Subject Account": "SYSTEM", "Target Account": "administrator",
            "Workstation": "WORKSTATION01", "Source IP": "192.168.1.55",
            "Logon Type": "3", "Failure Reason": "Unknown user name or bad password"}),
    (4672, {"Account Name": "svcBackup", "Account Domain": "CORP",
            "Logon ID": "0x3E7", "Privileges": "SeBackupPrivilege\nSeRestorePrivilege"}),
    (7045, {"Service Name": "EvilSvc", "Image Path": r"C:\Windows\Temp\evil.exe",
            "Service Type": "16", "Start Type": "2", "Account": "LocalSystem"}),
]


def simulate():
    """Replay synthetic events to demonstrate alerting logic."""
    log.info("=== SIMULATION MODE ===")
    log.info(f"Thresholds: { {k: f'{v.count}/{v.window_seconds}s' for k,v in THRESHOLDS.items()} }\n")

    scenario = [
        # Brute-force: 8 failed logins in 30 seconds
        *[(4625, 3) for _ in range(8)],
        # One privilege escalation burst
        *[(4672, 1) for _ in range(12)],
        # Suspicious service installs
        *[(7045, 5) for _ in range(3)],
    ]

    for event_id, delay in scenario:
        extras = dict(next(e for e in SIMULATED_EVENTS if e[0] == event_id)[1])
        now    = datetime.now()

        log.info(
            f"Event {event_id} ({EVENT_DESCRIPTIONS[event_id]}) | "
            + " | ".join(f"{k}={v}" for k, v in extras.items())
        )

        if tracker.record(event_id, now):
            fire_alert(event_id, extras)

        time.sleep(delay)

    log.info("\nSimulation complete.")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        if WINDOWS:
            monitor_windows()
        else:
            simulate()
    except KeyboardInterrupt:
        log.info("Monitor stopped by user.")