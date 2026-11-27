"""Response actions: alert notifications and a simulated IP blocklist."""
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BLOCKLIST_PATH = PROJECT_ROOT / "data" / "blocklist.json"
NOTIFIED_PATH = PROJECT_ROOT / "data" / "notified_alerts.json"
LEVELS = ["low", "medium", "high", "critical"]
MAX_REMEMBERED = 5000


def _read_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


# ---------------- simulated blocklist ----------------

def load_blocklist():
    data = _read_json(BLOCKLIST_PATH, {})
    return data if isinstance(data, dict) else {}


def block_ip(address, reason="manual"):
    # raises ValueError if invalid
    ip = str(ipaddress.ip_address(address.strip()))
    blocklist = load_blocklist()
    blocklist[ip] = {
        "reason": reason,
        "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    _write_json(BLOCKLIST_PATH, blocklist)
    return blocklist[ip]


def unblock_ip(address):
    ip = str(ipaddress.ip_address(address.strip()))
    blocklist = load_blocklist()
    removed = blocklist.pop(ip, None) is not None
    if removed:
        _write_json(BLOCKLIST_PATH, blocklist)
    return removed


def is_blocked(address):
    try:
        ip = str(ipaddress.ip_address(address.strip()))
    except (ValueError, AttributeError):
        return False
    return ip in load_blocklist()


# ---------------- notifications ----------------

def _level_rank(level):
    return LEVELS.index(level) if level in LEVELS else -1


def alert_key(alert):
    detection, event = alert["detection"], alert["event"]
    return f"{detection.get('rule_id')}|{event.get('source_ip')}|{event.get('timestamp')}"


def format_alert(alert):
    detection, event, risk = alert["detection"], alert["event"], alert["risk"]
    intel = alert.get("threat_intel") or {}
    mitre = detection.get("mitre")

    lines = [
        f"SENTRY {str(risk.get('risk_level', '?')).upper()} alert "
        f"({risk.get('risk_score')}/100)",
        f"Rule: {detection.get('rule_id')} - {detection.get('reason')}",
        f"Source IP: {event.get('source_ip') or 'n/a'}",
        f"Time: {event.get('timestamp')}",
    ]
    if mitre:
        lines.append(
            f"MITRE: {mitre['technique_id']} {mitre['technique']} ({mitre['tactic']})"
        )
    if intel.get("status") == "known_malicious":
        lines.append(f"Threat intel: known malicious ({intel.get('source')})")
    return "\n".join(lines)


def telegram_configured():
    return bool(os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"))


def send_telegram(text, timeout=10):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not (token and chat_id):
        return False
    body = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage", data=body
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError):
        return False  # never print the exception: the URL contains the token


def default_send(text):
    print("\n" + text + "\n")
    if telegram_configured():
        send_telegram(text)


def notify_new_alerts(alerts, min_level="high", max_per_run=5, send=None, state_path=None):
    """Notify once per alert at or above `min_level`. Returns the keys handled."""
    send = send or default_send
    state_path = state_path or NOTIFIED_PATH

    seen = _read_json(state_path, [])
    seen_set = set(seen)
    floor = _level_rank(min_level)

    new = [
        a for a in alerts
        if _level_rank(a["risk"].get("risk_level")) >= floor
        and alert_key(a) not in seen_set
    ]
    if not new:
        return []

    new.sort(key=lambda a: a["risk"].get("risk_score", 0), reverse=True)
    for alert in new[:max_per_run]:
        send(format_alert(alert))
    if len(new) > max_per_run:
        send(
            f"SENTRY: {len(new) - max_per_run} more alerts not shown individually.")

    keys = [alert_key(a) for a in new]
    _write_json(state_path, (seen + keys)[-MAX_REMEMBERED:])
    return keys
