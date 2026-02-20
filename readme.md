# 🛡️ HIDS — Host-Based Intrusion Detection System

A Python-based **Host Intrusion Detection System** for Windows.  
Monitors system activity, compares it against a trusted **baseline**, applies heuristic correlation rules, and presents results in an interactive **Streamlit dashboard**.

> ⚠️ **Windows only.** Requires Python 3.10+ and Administrator privileges for full functionality.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Modular Sensors** | Collects data from Process, Network, Registry, Task Scheduler, and File system |
| **Baseline Filtering** | Instantly whitelists trusted files/processes via SHA256 hash (stored in `baseline.db`) |
| **Smart Correlation** | Detects attack chains: Suspicious Parent (Office → Shell), LOLBAS abuse, First-Seen executables |
| **JSON Configuration** | All rules, whitelists, and thresholds live in `config/config.json` — no code changes needed |
| **Streamlit Dashboard** | Interactive web UI for anomaly review and triage decisions |
| **Scheduled Scanning** | `run_scan_once.py` is designed for Windows Task Scheduler |

---

## 🏗️ Architecture

```
Sensors (Process, Network, Registry, Task, File)
        │
        ▼
BaselineManager  ──── baseline.db (SHA256 whitelist)
        │
   Unknown/Suspicious events only
        │
        ▼
AnomalyCorrelator  ─── applies Suspicious Parent, LOLBAS, First-Seen rules
        │
        ▼
DatabaseManager  ──── anomalies.db
        │
        ▼
Dashboard (Streamlit)  ──── Review & Triage
```

---

## 📂 Project Structure

```
HIDS_Project/
├── config/
│   ├── config.example.json   ← Copy this → config.json and customize
│   └── schema.json
│
├── core/
│   ├── anomaly.py            ← AnomalyEvent dataclass
│   ├── baseline_manager.py   ← Reads baseline.db
│   ├── config.py             ← Loads config.json into constants
│   ├── correlator.py         ← Correlation & prioritization logic
│   ├── database.py           ← Reads/writes anomalies.db
│   └── utils.py              ← get_sha256, normalize_path, parse_command_path
│
├── sensors/
│   ├── base.py               ← Abstract BaseSensor
│   ├── process.py            ← Running process monitoring
│   ├── network.py            ← Connections + DNS (tshark)
│   ├── registry.py           ← Registry autorun keys
│   ├── task.py               ← Scheduled tasks
│   └── file.py               ← Filesystem (suspicious new files)
│
├── dashboard/
│   └── dashboard.py          ← Streamlit web UI
│
├── launcher/
│   ├── baseline.py           ← Run ONCE (as Admin) to build baseline.db
│   └── scanner.py            ← Legacy CLI scanner (no dashboard)
│
├── data/                     ← Runtime databases (git-ignored)
│   └── .gitkeep
│
├── logs/                     ← Scan logs (git-ignored)
│   └── .gitkeep
│
├── run_scan_once.py          ← Entry point for Task Scheduler
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup & Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/HIDS_Project.git
cd HIDS_Project
```

### 2. Create a virtual environment

```bash
python -m venv .venv
.\.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Create your config file

```bash
copy config\config.example.json config\config.json
```

Then open `config/config.json` and adjust:

| Key | What to change |
|---|---|
| `paths.tshark` | Path to `tshark.exe` (Wireshark). Default: `C:\Program Files\Wireshark\tshark.exe` |
| `settings.network_interface` | Your active network adapter name (e.g., `"Wi-Fi"`, `"Ethernet"`) |
| `settings.days_to_keep_logs` | How many days to keep anomaly records (default: `7`) |

> **Find your network interface name:**
>
> ```powershell
> netsh interface show interface
> ```

### 5. Build the Baseline (run once, as Administrator)

This scans all running processes, autorun entries, and network listeners to create a whitelist:

```bash
# Open PowerShell as Administrator, then:
python launcher/baseline.py
```

This creates `data/baseline.db`. Takes 5–10 minutes.  
**Re-run after installing new software** to avoid false positives.

---

## 🚀 Running the System

### Option A — Streamlit Dashboard (recommended)

```bash
streamlit run dashboard/dashboard.py
```

Opens at `http://localhost:8501`. From the dashboard you can:

- View and filter anomalies
- Run a manual scan (Live tab)
- Perform triage (mark files as trusted)

### Option B — Headless / Task Scheduler

```bash
python run_scan_once.py
```

Schedule this with **Windows Task Scheduler** to run automatically (e.g., every 4 hours).  
Log is written to `logs/scanner_run.log`.

### Option C — CLI only

```bash
python launcher/scanner.py
```

---

## 🌍 Optional: GeoIP Support

The Network sensor can identify the country of remote IP addresses.

1. Register for a free account at [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/signup)
2. Download `GeoLite2-Country.mmdb`
3. Place it in `data/GeoLite2-Country.mmdb`

Without this file the sensor still works — country will show as `"Unknown"`.

---

## 🔧 Configuration Reference (`config/config.json`)

| Section | Purpose |
|---|---|
| `paths` | Paths to external tools (tshark) |
| `settings` | Scan duration, interface, log retention |
| `whitelists.trusted_ips` | IPs that are never flagged |
| `whitelists.trusted_domain_suffixes` | Domain suffixes (CDNs, etc.) allowed in DNS |
| `whitelists.process_trusted_ports` | Which ports are normal for each process |
| `blacklists.suspicious_ports` | Ports that always raise an alert |
| `blacklists.suspicious_tlds` | High-risk domain TLDs |
| `correlation_rules` | Rules for Suspicious Parent and LOLBAS detection |

---

## 📦 Dependencies

See `requirements.txt`. Key libraries:

| Library | Purpose |
|---|---|
| `streamlit` | Dashboard UI |
| `psutil` | Process and network data |
| `geoip2` | IP geolocation |
| `pandas` | Data display in dashboard |

---

## ⚡ Requirements

- **OS:** Windows 10/11
- **Python:** 3.10+
- **Admin rights:** Required for `baseline.py`, Registry sensor, and raw network access
- **Wireshark/tshark:** Optional — needed only for DNS monitoring

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
