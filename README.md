# 🛡️ Mini SIEM — Log Analyzer & Intrusion Detection System

A lightweight Python-based Security Information and Event Management (SIEM) tool that parses system logs, detects suspicious activity, and generates structured alert reports.

---

## 📌 Overview

This project simulates the core functionality of a real-world SIEM: ingesting raw log data, applying detection rules, and producing actionable security alerts. It was built as a practical introduction to defensive security concepts — log analysis, pattern recognition, and threat classification.

---

## ⚙️ Features

- **SSH log parsing** — extracts authentication events from `auth.log` (failed/accepted logins, source IPs, targeted usernames)
- **Apache log parsing** — processes HTTP requests from `access.log` in Common Log Format
- **Brute force detection** — flags IPs exceeding a configurable threshold of failed SSH login attempts
- **Web reconnaissance detection** — identifies IPs generating abnormal volumes of HTTP 4xx/5xx errors
- **Suspicious path detection** — alerts on access attempts to sensitive paths (`/etc/passwd`, `/wp-admin`, `/.env`, etc.)
- **HTML report generation** — produces a clean, severity-ranked alert report viewable in any browser
- **JSON export** — outputs structured alert data for further processing or integration

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- No external dependencies — standard library only

### Installation

```bash
git clone https://github.com/Ismail-elm/Mini-SIEM.git
cd mini-siem
```

### Usage

```bash
python mini_siem.py
```

This runs the analyzer on the built-in sample logs and generates two output files:

| File | Description |
|---|---|
| `report.html` | Visual alert report, open in a browser |
| `alerts.json` | Raw alert data in JSON format |

---

## 📊 Sample Output

```
[*] Parsing des logs SSH...
    8 événements SSH extraits
[*] Parsing des logs Apache...
    12 requêtes HTTP extraites
[*] Lancement de la détection...
    4 alerte(s) générée(s)
    [HIGH  ] SSH Brute Force — 192.168.1.100 — 6 tentatives échouées détectées
    [HIGH  ] Accès chemin suspect — 192.168.1.201 — Tentative d'accès à '/etc/passwd'
    [HIGH  ] Accès chemin suspect — 192.168.1.201 — Tentative d'accès à '/wp-admin'
    [MEDIUM] Web Scan / Reconnaissance — 192.168.1.201 — 10 erreurs HTTP
[+] Rapport généré : report.html
[+] Export JSON : alerts.json
```

---

## 🗂️ Project Structure

```
mini-siem/
├── mini_siem.py     # Main script — parsers, detection engine, report generator
├── report.html      # Generated HTML alert report (auto-created on run)
├── alerts.json      # Generated JSON alert export (auto-created on run)
└── README.md
```

---

## 🔍 Detection Rules

| Rule | Severity | Trigger |
|---|---|---|
| SSH Brute Force | HIGH | ≥ 5 failed login attempts from the same IP |
| Web Reconnaissance | MEDIUM | ≥ 10 HTTP 4xx/5xx errors from the same IP |
| Suspicious Path Access | HIGH | Request to `/etc/passwd`, `/wp-admin`, `/.env`, `/shell`, etc. |

Thresholds are configurable via constants at the top of `mini_siem.py`:

```python
BRUTE_FORCE_THRESHOLD = 5   # failed SSH attempts before alert
HTTP_ERROR_THRESHOLD  = 10  # HTTP errors per IP before alert
```

---

## 🛠️ Built With

- Python 3 — `re`, `json`, `collections`, `datetime`, `pathlib`
- No third-party libraries

---

## 👤 Author

**EL MAALLEM Ismail**  
1st-year Computer Science & Networks Engineering student — ENSISA, Mulhouse  
[LinkedIn](https://www.linkedin.com/in/ismail-el-maallem-580a4a37a/) · [GitHub](https://github.com/Ismail-elm)

---

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized log analysis only. Do not use it against systems you do not own or have explicit permission to analyze.
