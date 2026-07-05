# windows-event-log-monitor
monitoring the windows log using python and powershell script

# 🔐 Windows Event Log Monitor

> Real-time Windows Security Event Log monitoring tool built with Python and PowerShell. Detects brute-force attacks, privilege escalation, and suspicious service installations — and fires alerts before damage is done.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell)
![Windows](https://img.shields.io/badge/Windows-10%2F11%2FServer-0078D6?style=for-the-badge&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Security](https://img.shields.io/badge/Category-Blue%20Team-blue?style=for-the-badge)

---

## 📌 Table of Contents

- [About The Project](#-about-the-project)
- [Event IDs Monitored](#-event-ids-monitored)
- [How It Works](#-how-it-works)
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Sample Output](#-sample-output)
- [Extending The Tool](#-extending-the-tool)
- [Project Structure](#-project-structure)
- [Use Cases](#-use-cases)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🧠 About The Project

Windows Event Logs are one of the most valuable sources of threat intelligence on any Windows machine — but only if someone is actively watching them. Most small teams and home labs lack a full SIEM (Security Information and Event Management) system to do this automatically.

This tool fills that gap. It monitors the Windows **Security** and **System** event logs in real time, counts suspicious events using a **sliding-window algorithm**, and fires an alert the moment activity crosses a defined threshold.

Built as a hands-on Blue Team / SOC learning project to understand:
- Windows Event Log structure and forensic value
- Threshold-based anomaly detection
- Real-time log parsing with Python and PowerShell

---

## 🎯 Event IDs Monitored

| Event ID | Log Source | Description | Why It Matters |
|----------|-----------|-------------|----------------|
| **4625** | Security | Failed Logon Attempt | Detects brute-force and password spray attacks |
| **4672** | Security | Special Privileges Assigned | Flags privilege escalation and suspicious account activity |
| **7045** | System | New Service Installed | Catches malware persistence via service installation |

---

## ⚙️ How It Works

```
Windows Event Log (Security / System)
          │
          ▼  poll every 2 seconds
  ┌───────────────────┐
  │   Event Poller    │  reads new records since last check
  └────────┬──────────┘
           │
           ▼
  ┌───────────────────┐
  │  Sliding Window   │  counts events within time window
  │     Counter       │  evicts old events automatically
  └────────┬──────────┘
           │
           ▼
  ┌───────────────────┐
  │ Threshold Checker │  compares count vs configured limit
  └────────┬──────────┘
           │
    threshold exceeded?
           │
     YES ──▼──────────────────────────────────────┐
  ┌───────────────────┐                           │
  │  Alert Dispatcher │  logs + prints alert      │
  │  (+ hooks for     │  cooldown timer starts    │
  │  Slack/Email/SIEM)│                           │
  └───────────────────┘                           │
                                                  │
     NO ───────────────────────────────────────── ┘
           │
           ▼
    wait 2 seconds → repeat
```

### Sliding Window Algorithm

Unlike simple counters that reset on a fixed schedule, this tool uses a **sliding window**. Every event is timestamped. On each check, events older than the window duration are evicted. This means:

- 4 failures at 00:59 + 2 failures at 01:01 = **6 failures in the last 60 seconds** ✅
- A fixed-window counter would reset at 01:00 and miss the pattern ❌

---

## ✅ Features

- 🔴 **Real-time monitoring** — polls every 2 seconds
- 📊 **Sliding-window detection** — accurate frequency tracking, no blind spots
- 🔕 **Alert cooldown** — suppresses repeat alerts to prevent notification fatigue
- 🧾 **Structured logging** — all events and alerts written to `event_monitor.log`
- 🔍 **Rich field extraction** — Source IP, Account Name, Logon Type, Privilege List, Service Path
- 🧪 **Simulation mode** — Python script runs on non-Windows systems for testing/demo
- 🔌 **Integration-ready** — stub hooks for Slack, Email, and SIEM integrations
- ⚡ **Two implementations** — Python (cross-platform, extensible) and PowerShell (zero install)

---

## 🖥️ Prerequisites

### For Python Script
- Windows 10 / 11 / Server 2016+
- Python 3.8 or higher
- Administrator privileges (required to read Security logs)

### For PowerShell Script
- Windows 10 / 11 / Server 2016+
- PowerShell 5.1 or higher (built into Windows)
- Administrator privileges

---

## 📦 Installation

### Clone the Repository

```bash
git clone https://github.com/AkishRaj/windows-event-log-monitor.git
cd windows-event-log-monitor
```

### Python Setup

```bash
# Install the required dependency
pip install pywin32

# Verify installation
python -c "import win32evtlog; print('pywin32 installed successfully')"
```

### PowerShell Setup

No installation needed. Just set the execution policy once:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 🚀 Usage

> ⚠️ **Important:** Both scripts must be run as Administrator to access Windows Security logs.

### Python Script

```bash
# Right-click VS Code or terminal → "Run as Administrator"
python event_log_monitor.py
```

### PowerShell Script

```powershell
# Right-click PowerShell → "Run as Administrator"
.\event_log_monitor.ps1
```

### Running Simulation Mode (Python only — no Windows required)

On a non-Windows machine, the Python script automatically enters simulation mode and replays synthetic events to demonstrate the alerting logic:

```bash
python event_log_monitor.py
# Output: === SIMULATION MODE ===
```

---

## 🔧 Configuration

All thresholds are configurable at the top of each script.

### Python (`event_log_monitor.py`)

```python
THRESHOLDS: Dict[int, AlertThreshold] = {
    4625: AlertThreshold(count=5,  window_seconds=60,  cooldown_seconds=120),
    4672: AlertThreshold(count=10, window_seconds=60,  cooldown_seconds=60),
    7045: AlertThreshold(count=2,  window_seconds=300, cooldown_seconds=300),
}
```

### PowerShell (`event_log_monitor.ps1`)

```powershell
$Config = @{
    PollIntervalSeconds = 2
    Thresholds = @{
        4625 = @{ Count = 5;  WindowSeconds = 60;  CooldownSeconds = 120 }
        4672 = @{ Count = 10; WindowSeconds = 60;  CooldownSeconds = 60  }
        7045 = @{ Count = 2;  WindowSeconds = 300; CooldownSeconds = 300 }
    }
}
```

### Configuration Reference

| Parameter | Description |
|-----------|-------------|
| `count` | Number of events needed to trigger an alert |
| `window_seconds` | Rolling time window to count events within |
| `cooldown_seconds` | Minimum time between repeat alerts for the same Event ID |
| `PollIntervalSeconds` | How often the log is checked (default: 2s) |

### Filtering SYSTEM Noise (PowerShell)

The `NT AUTHORITY\SYSTEM` account regularly triggers 4672 events as part of normal Windows operation. To filter these out:

```powershell
# Add inside the foreach ($rec in $records) loop
if ($rec.ReplacementStrings[1] -eq "SYSTEM") { continue }
```

---

## 📋 Sample Output

### Normal Event Log
```
2026-02-24 18:59:04  INFO      Event Log Monitor starting...
2026-02-24 18:59:04  INFO      Watching Event IDs: 4625, 4672, 7045
2026-02-24 18:59:04  INFO      Opened log 'Security' (latest record: 1143494)
2026-02-24 18:59:04  INFO      Opened log 'System'   (latest record: 68109)
2026-02-24 18:59:04  INFO      Monitoring active. Press Ctrl+C to stop.
```

### Alert Triggered (4672 — Privilege Escalation)
```
======================================================================
  *** ALERT  |  EventID 4672  |  Special Privileges Assigned
  Count in last 60s : 10  (threshold: 10)
  Account Name        : svcMalicious
  Account Domain      : WORKGROUP
  Logon ID            : 0x4A3F1
  Privileges          : SeDebugPrivilege
                        SeTakeOwnershipPrivilege
                        SeLoadDriverPrivilege
======================================================================
```

### Alert Triggered (4625 — Brute Force)
```
======================================================================
  *** ALERT  |  EventID 4625  |  Failed Logon Attempt
  Count in last 60s : 6  (threshold: 5)
  Target Account      : administrator
  Workstation         : WORKSTATION01
  Source IP           : 192.168.1.55
  Logon Type          : 3
  Failure Reason      : Unknown user name or bad password
======================================================================
```

---

## 🔌 Extending The Tool

### Add Slack Alerts (Python)

```python
import requests

def send_slack_alert(event_id, description, count, extras):
    webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    message = f"*ALERT* | EventID {event_id} | {description}\nCount: {count}\n"
    for k, v in extras.items():
        message += f"• {k}: {v}\n"
    requests.post(webhook_url, json={"text": message})

# Call inside fire_alert()
send_slack_alert(event_id, desc, count, extra)
```

### Add Email Alerts (Python)

```python
import smtplib
from email.mime.text import MIMEText

def send_email_alert(event_id, description, count):
    msg = MIMEText(f"ALERT: EventID {event_id} - {description}\nCount: {count}")
    msg["Subject"] = f"Security Alert: EventID {event_id}"
    msg["From"] = "monitor@yourdomain.com"
    msg["To"] = "security@yourdomain.com"
    with smtplib.SMTP("smtp.yourdomain.com") as server:
        server.send_message(msg)
```

### Push to SIEM / Splunk (Python)

```python
import requests

def push_to_splunk(event_id, description, count, extras):
    url = "https://your-splunk-instance:8088/services/collector"
    headers = {"Authorization": "Splunk YOUR-HEC-TOKEN"}
    payload = {"event": {"event_id": event_id, "description": description, "count": count, **extras}}
    requests.post(url, json=payload, headers=headers, verify=False)
```

---

## 📁 Project Structure

```
windows-event-log-monitor/
│
├── event_log_monitor.py      # Python implementation (recommended)
├── event_log_monitor.ps1     # PowerShell implementation
└── event_monitor.log         # Generated at runtime — all events logged here
```

---

## 🏢 Use Cases

| Scenario | How This Tool Helps |
|----------|-------------------|
| **Home Lab Security** | Monitor your own machine for unauthorized access attempts |
| **SOC Practice** | Hands-on experience with real Windows event data |
| **Small Business** | Lightweight alternative to expensive SIEM solutions |
| **CTF / DFIR** | Quick triage tool for suspicious activity on a host |
| **Malware Analysis Lab** | Watch for persistence mechanisms (7045) during malware runs |

---

## 🗺️ Roadmap

- [ ] Add email alert integration
- [ ] Add Slack / Teams webhook support
- [ ] Export alerts to JSON / CSV
- [ ] Add Event ID 4688 (Process Creation) monitoring
- [ ] Add Event ID 4720 (User Account Created) monitoring
- [ ] Build a simple web dashboard for live viewing
- [ ] Package as a Windows Service for always-on monitoring

---

## 🤝 Contributing

Contributions are welcome! If you have ideas to improve this tool:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/SlackAlerts`)
3. Commit your changes (`git commit -m "Add Slack alert integration"`)
4. Push to the branch (`git push origin feature/SlackAlerts`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## 👤 Author

**Your Name**
- LinkedIn: https://www.linkedin.com/in/akish-raj/


---

## ⭐ Show Your Support

If this project helped you learn or solve a problem, please give it a **star** ⭐ — it helps others find the project!

---

> **Disclaimer:** This tool is intended for educational purposes and authorized security monitoring only. Always obtain proper authorization before monitoring systems you do not own.
