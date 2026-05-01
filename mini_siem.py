import re
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 5   
HTTP_ERROR_THRESHOLD  = 10  

SAMPLE_SSH_LOG = """
Jan 10 10:00:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 10 10:00:03 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 10 10:00:05 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 10 10:00:07 server sshd[1234]: Failed password for user from 192.168.1.100 port 22 ssh2
Jan 10 10:00:09 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 10 10:00:11 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 10 10:01:00 server sshd[1234]: Accepted password for alice from 10.0.0.5 port 22 ssh2
Jan 10 10:02:00 server sshd[1234]: Failed password for root from 10.10.10.10 port 22 ssh2
"""

SAMPLE_APACHE_LOG = """
192.168.1.200 - - [10/Jan/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.1.201 - - [10/Jan/2024:10:00:02 +0000] "GET /admin HTTP/1.1" 403 512
192.168.1.201 - - [10/Jan/2024:10:00:03 +0000] "GET /admin HTTP/1.1" 403 512
192.168.1.201 - - [10/Jan/2024:10:00:04 +0000] "GET /passwd HTTP/1.1" 404 256
192.168.1.201 - - [10/Jan/2024:10:00:05 +0000] "GET /etc/passwd HTTP/1.1" 404 256
192.168.1.201 - - [10/Jan/2024:10:00:06 +0000] "POST /login HTTP/1.1" 401 128
192.168.1.201 - - [10/Jan/2024:10:00:07 +0000] "POST /login HTTP/1.1" 401 128
192.168.1.201 - - [10/Jan/2024:10:00:08 +0000] "GET /wp-admin HTTP/1.1" 404 256
192.168.1.201 - - [10/Jan/2024:10:00:09 +0000] "GET /shell.php HTTP/1.1" 404 256
192.168.1.201 - - [10/Jan/2024:10:00:10 +0000] "GET /admin HTTP/1.1" 403 512
192.168.1.201 - - [10/Jan/2024:10:00:11 +0000] "GET /admin HTTP/1.1" 403 512
192.168.1.100 - - [10/Jan/2024:10:00:12 +0000] "GET /page.html HTTP/1.1" 200 800
"""


# ─────────────────────────────────────────────
# 1. PARSERS
# ─────────────────────────────────────────────

def parse_ssh_logs(log_text: str) -> list[dict]:
    """Extrait les événements SSH (succès et échecs) depuis auth.log."""
    events = []
    pattern = re.compile(
        r'(?P<date>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[.*?\]:\s+'
        r'(?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>[\d.]+)'
    )
    for line in log_text.strip().splitlines():
        m = pattern.search(line)
        if m:
            events.append({
                "type"  : "ssh",
                "date"  : m.group("date"),
                "status": m.group("status"),
                "user"  : m.group("user"),
                "ip"    : m.group("ip"),
            })
    return events


def parse_apache_logs(log_text: str) -> list[dict]:
    """Extrait les requêtes HTTP depuis access.log (Common Log Format)."""
    events = []
    pattern = re.compile(
        r'(?P<ip>[\d.]+) .* \[(?P<date>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) HTTP/[\d.]+" '
        r'(?P<status>\d{3}) (?P<size>\d+)'
    )
    for line in log_text.strip().splitlines():
        m = pattern.search(line)
        if m:
            events.append({
                "type"  : "http",
                "date"  : m.group("date"),
                "ip"    : m.group("ip"),
                "method": m.group("method"),
                "path"  : m.group("path"),
                "status": int(m.group("status")),
            })
    return events


# ─────────────────────────────────────────────
# 2. MOTEUR DE DÉTECTION
# ─────────────────────────────────────────────

def detect_brute_force(ssh_events: list[dict]) -> list[dict]:
    """Détecte les attaques brute force SSH (trop d'échecs par IP)."""
    fails = defaultdict(int)
    for e in ssh_events:
        if e["status"] == "Failed":
            fails[e["ip"]] += 1

    alerts = []
    for ip, count in fails.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "severity" : "HIGH",
                "rule"     : "SSH Brute Force",
                "ip"       : ip,
                "detail"   : f"{count} tentatives échouées détectées",
            })
    return alerts


def detect_http_scan(http_events: list[dict]) -> list[dict]:
    """Détecte les scans web (trop d'erreurs 4xx/5xx par IP)."""
    errors = defaultdict(list)
    for e in http_events:
        if e["status"] >= 400:
            errors[e["ip"]].append(e["path"])

    alerts = []
    for ip, paths in errors.items():
        if len(paths) >= HTTP_ERROR_THRESHOLD:
            alerts.append({
                "severity" : "MEDIUM",
                "rule"     : "Web Scan / Reconnaissance",
                "ip"       : ip,
                "detail"   : f"{len(paths)} erreurs HTTP — chemins testés : {', '.join(set(paths[:5]))}...",
            })
    return alerts


def detect_suspicious_paths(http_events: list[dict]) -> list[dict]:
    """Détecte les accès à des chemins sensibles connus."""
    SUSPICIOUS = ["/etc/passwd", "/wp-admin", "/shell", "/.env", "/admin", "/phpmyadmin"]
    alerts = []
    for e in http_events:
        for pattern in SUSPICIOUS:
            if pattern in e["path"]:
                alerts.append({
                    "severity" : "HIGH",
                    "rule"     : "Accès chemin suspect",
                    "ip"       : e["ip"],
                    "detail"   : f"Tentative d'accès à '{e['path']}'",
                })
                break
    return alerts


def run_detection(ssh_events, http_events) -> list[dict]:
    alerts = []
    alerts += detect_brute_force(ssh_events)
    alerts += detect_http_scan(http_events)
    alerts += detect_suspicious_paths(http_events)
    # Tri : HIGH d'abord
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(alerts, key=lambda a: severity_order.get(a["severity"], 9))


# ─────────────────────────────────────────────
# 3. RAPPORT HTML
# ─────────────────────────────────────────────

SEVERITY_COLORS = {
    "HIGH"  : ("#fde8e8", "#c0392b"),
    "MEDIUM": ("#fef3cd", "#b7680a"),
    "LOW"   : ("#e8f4fd", "#1a6fa0"),
}

def generate_html_report(alerts: list[dict], output_path: str = "report.html") -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    high   = sum(1 for a in alerts if a["severity"] == "HIGH")
    medium = sum(1 for a in alerts if a["severity"] == "MEDIUM")

    rows = ""
    for a in alerts:
        bg, color = SEVERITY_COLORS.get(a["severity"], ("#fff", "#000"))
        rows += f"""
        <tr>
          <td><span style="background:{bg};color:{color};padding:3px 10px;border-radius:12px;font-weight:600;font-size:12px">{a['severity']}</span></td>
          <td>{a['rule']}</td>
          <td><code>{a['ip']}</code></td>
          <td>{a['detail']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Mini SIEM — Rapport d'alertes</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f4f6f8; color: #222; }}
    .header {{ background: #1a1a2e; color: #fff; padding: 24px 40px; }}
    .header h1 {{ margin: 0; font-size: 22px; }}
    .header p  {{ margin: 4px 0 0; opacity: .6; font-size: 13px; }}
    .stats {{ display: flex; gap: 16px; padding: 24px 40px; }}
    .stat {{ background: #fff; border-radius: 10px; padding: 16px 24px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
    .stat .val {{ font-size: 28px; font-weight: 700; }}
    .stat .lbl {{ font-size: 12px; color: #666; margin-top: 2px; }}
    .stat.high   .val {{ color: #c0392b; }}
    .stat.medium .val {{ color: #b7680a; }}
    table {{ width: calc(100% - 80px); margin: 0 40px 40px; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
    th {{ background: #f0f2f5; text-align: left; padding: 12px 16px; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: #555; }}
    td {{ padding: 12px 16px; border-top: 1px solid #eee; font-size: 14px; vertical-align: middle; }}
    code {{ background: #f0f2f5; padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
    .footer {{ text-align: center; padding: 16px; font-size: 12px; color: #999; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡 Mini SIEM — Rapport d'alertes</h1>
    <p>Généré le {timestamp} — {len(alerts)} alerte(s) détectée(s)</p>
  </div>
  <div class="stats">
    <div class="stat high">  <div class="val">{high}</div>  <div class="lbl">Alertes HIGH</div></div>
    <div class="stat medium"><div class="val">{medium}</div><div class="lbl">Alertes MEDIUM</div></div>
    <div class="stat">       <div class="val">{len(alerts)}</div><div class="lbl">Total</div></div>
  </div>
  <table>
    <thead><tr><th>Sévérité</th><th>Règle</th><th>IP source</th><th>Détail</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <div class="footer">Mini SIEM — Projet cybersécurité</div>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    print(f"[+] Rapport généré : {output_path}")
    return html


# ─────────────────────────────────────────────
# 4. MAIN
# ─────────────────────────────────────────────

def main():
    print("[*] Parsing des logs SSH...")
    ssh_events  = parse_ssh_logs(SAMPLE_SSH_LOG)
    print(f"    {len(ssh_events)} événements SSH extraits")

    print("[*] Parsing des logs Apache...")
    http_events = parse_apache_logs(SAMPLE_APACHE_LOG)
    print(f"    {len(http_events)} requêtes HTTP extraites")

    print("[*] Lancement de la détection...")
    alerts = run_detection(ssh_events, http_events)
    print(f"    {len(alerts)} alerte(s) générée(s)")

    for a in alerts:
        print(f"    [{a['severity']:6}] {a['rule']} — {a['ip']} — {a['detail']}")

    print("[*] Génération du rapport HTML...")
    generate_html_report(alerts, "report.html")

    # Export JSON 
    with open("alerts.json", "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2, ensure_ascii=False)
    print("[+] Export JSON : alerts.json")


if __name__ == "__main__":
    main()
