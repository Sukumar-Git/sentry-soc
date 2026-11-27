from app import response
from app.response import (
    block_ip, format_alert, notify_new_alerts, send_telegram, unblock_ip,
)
import pytest


def make_alert(level="high", score=60, rule="AUTH-001", ip="1.2.3.4",
               ts="2026-11-27 10:00:00", mitre=None):
    return {
        "event": {"source_ip": ip, "timestamp": ts},
        "detection": {"rule_id": rule, "reason": "test reason", "mitre": mitre},
        "risk": {"risk_level": level, "risk_score": score},
        "threat_intel": {"status": "not_found"},
    }


def test_alert_is_notified_only_once(tmp_path):
    sent = []
    state = tmp_path / "state.json"
    alerts = [make_alert()]

    first = notify_new_alerts(alerts, send=sent.append, state_path=state)
    second = notify_new_alerts(alerts, send=sent.append, state_path=state)

    assert len(first) == 1
    assert second == []
    assert len(sent) == 1


def test_low_risk_alerts_are_ignored(tmp_path):
    sent = []
    keys = notify_new_alerts(
        [make_alert(level="low", score=10)],
        send=sent.append, state_path=tmp_path / "s.json",
    )
    assert keys == [] and sent == []


def test_flood_is_capped_with_summary(tmp_path):
    sent = []
    alerts = [make_alert(
        ts=f"2026-11-27 10:00:0{i}", score=50 + i) for i in range(7)]
    notify_new_alerts(alerts, max_per_run=5, send=sent.append,
                      state_path=tmp_path / "s.json")
    assert len(sent) == 6
    assert "2 more alerts" in sent[-1]


def test_block_and_unblock(monkeypatch, tmp_path):
    monkeypatch.setattr(response, "BLOCKLIST_PATH",
                        tmp_path / "blocklist.json")
    block_ip("203.0.113.5", "test")
    assert response.is_blocked("203.0.113.5")
    assert unblock_ip("203.0.113.5") is True
    assert not response.is_blocked("203.0.113.5")


def test_block_rejects_invalid_ip(monkeypatch, tmp_path):
    monkeypatch.setattr(response, "BLOCKLIST_PATH",
                        tmp_path / "blocklist.json")
    with pytest.raises(ValueError):
        block_ip("not-an-ip")


def test_format_alert_includes_mitre():
    mitre = {"technique_id": "T1046",
             "technique": "Network Service Discovery", "tactic": "Discovery"}
    text = format_alert(make_alert(mitre=mitre))
    assert "T1046" in text and "Discovery" in text and "1.2.3.4" in text


def test_telegram_not_configured_returns_false(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    assert send_telegram("hello") is False
