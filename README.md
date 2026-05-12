# 🛡️ SOC Simulator | Real + Simulated IDS

A Security Operations Center (SOC) simulation platform for monitoring Windows telemetry, detecting suspicious activities, visualizing threats, and exporting forensic evidence bundles.

---

# 📌 Features

- Real-time SOC Dashboard
- HIDS + Simulated NIDS
- Windows Event Log Monitoring
- Alert Correlation Engine
- Forensic Bundle Export
- Threat Visualization Graphs
- SQLite-based Alert Storage
- Detection Rule Engine
- Analyst Investigation Workflow

---

# 🏗️ Technologies Used

| Component | Technology |
|---|---|
| GUI | CustomTkinter |
| Backend | Python |
| Database | SQLite |
| Visualization | Matplotlib |
| Monitoring | Watchdog |
| Event Logs | PyWin32 |
| Packet Analysis | Scapy |
| Encryption | Cryptography |

---

# 📂 Project Structure

```text
Dashboard_GUI/
│
├── app.py
├── backend.py
├── database.py
├── forensic_scanner.py
├── fim_monitor.py
├── correlation_engine.py
├── timeline_engine.py
├── rules.py
├── detection_rules.json
├── config.py
├── requirements.txt
│
├── forensics_exports/
├── raw_events/
└── screenshots/
```

---

# ⚙️ Installation Guide

## 1. Clone Repository

```bash
git clone <your-github-repository-url>
cd Dashboard_GUI
```

---

## 2. Create Virtual Environment (Recommended)

```bash
python -m venv venv
```

### Activate Virtual Environment

#### Windows

```bash
venv\Scripts\activate
```

---

## 3. Install Dependencies

### Online Installation

```bash
pip install -r requirements.txt
```

---

### Offline Installation

Download packages beforehand:

```bash
pip download -r requirements.txt -d offline_packages
```

Install offline:

```bash
pip install --no-index --find-links=offline_packages -r requirements.txt
```

---

## 4. Run Application

Run as Administrator:

```bash
python app.py
```

---

# 📦 Create Standalone EXE

## Install PyInstaller

```bash
pip install pyinstaller
```

## Build Executable

```bash
pyinstaller --onedir --windowed app.py
```

Generated executable:

```text
dist/app/app.exe
```

---

# 🖥️ Recommended Environment

- Windows 10 / 11
- Python 3.11+
- Administrator Privileges
- 8GB RAM minimum

---

# 🔐 Optional Windows Components

## Sysmon (Recommended)

Download:

https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

Install:

```bash
sysmon64.exe -i
```

---

## Npcap (For Packet Monitoring)

Download:

https://npcap.com/#download

---

# 🚀 Features Overview

## 🛡️ HIDS Detection

- Brute Force Detection
- Privilege Escalation Detection
- Security Log Clearing Detection
- Suspicious Process Monitoring
- Rapid Process Spawn Detection

---

## 🌐 Simulated NIDS

- Port Scan Detection
- SYN Flood Detection
- Reconnaissance Alerts

---

## 📊 Dashboard

- Alert Metrics
- Pie Chart Visualization
- Threat Category Graphs
- Timeline Analysis
- Alert Grouping

---

## 🔎 Forensics Export

Exports forensic evidence bundles including:

```text
alerts.csv
raw_logs.csv
case_metadata.json
pie_chart.png
threat_category_graph.png
```

---

# 📈 Workflow Architecture

```text
Windows Security Logs
          ↓
   Detection Engine
          ↓
 Correlation Engine
          ↓
    SQLite Storage
          ↓
    SOC Dashboard
          ↓
 Forensic Export System
```

---

# 📦 Offline Dependency Download

```bash
pip freeze > requirements.txt
```

Download all wheel packages:

```bash
pip download -r requirements.txt -d offline_packages
```

Install later without internet:

```bash
pip install --no-index --find-links=offline_packages -r requirements.txt
```

---

# 📜 License

Educational and research purposes only.

---

# 👨‍💻 Author

Pratyush Raj
