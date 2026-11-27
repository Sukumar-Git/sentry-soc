from datetime import datetime

from app.detection_engine import detect_event
from app.honeypot import format_event, sanitize
from app.log_parser import parse_log

NOW = datetime(2026, 11, 27, 10, 0, 0)


def test_honeypot_line_is_parsed_and_detected():
    line = format_event("203.0.113.7", "SSH-2.0-libssh_0.9.6", now=NOW)
    event = parse_log(line)
    assert event["event_type"] == "honeypot_connection"
    assert event["source_ip"] == "203.0.113.7"

    result = detect_event(event)
    assert result["rule_id"] == "NET-005"
    assert result["mitre"]["technique_id"] == "T1595"


def test_log_injection_is_neutralized():
    evil = "x ip=9.9.9.9 username=root"
    event = parse_log(format_event("203.0.113.7", evil, now=NOW))
    assert event["source_ip"] == "203.0.113.7"
    assert event["username"] is None


def test_sanitize_handles_empty_input():
    assert sanitize("") == "none"
