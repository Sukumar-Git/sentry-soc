import json

from app import threat_intel


def test_known_ip_is_flagged(monkeypatch):
    feed = {
        "203.0.113.50": {
            "category": "test_indicator",
            "description": "Synthetic test indicator.",
        }
    }

    monkeypatch.setattr(
        threat_intel,
        "load_threat_feed",
        lambda: feed,
    )

    result = threat_intel.enrich_ip("203.0.113.50")

    assert result["status"] == "known_malicious"
    assert result["category"] == "test_indicator"
    assert result["source"] == "local_feed"


def test_unknown_ip_is_not_marked_safe(monkeypatch):
    monkeypatch.setattr(
        threat_intel,
        "load_threat_feed",
        lambda: {},
    )

    result = threat_intel.enrich_ip("192.0.2.10")

    assert result["status"] == "not_found"
    assert "does not establish" in result["description"]


def test_invalid_ip_is_rejected():
    result = threat_intel.enrich_ip("not-an-ip")

    assert result["status"] == "invalid_ip"


def test_empty_ip_is_rejected():
    result = threat_intel.enrich_ip("")

    assert result["status"] == "invalid_ip"


def test_ip_address_is_normalized(monkeypatch):
    monkeypatch.setattr(
        threat_intel,
        "load_threat_feed",
        lambda: {},
    )

    result = threat_intel.enrich_ip(" 192.0.2.10 ")

    assert result["ip"] == "192.0.2.10"
    assert result["status"] == "not_found"


def test_feed_rejects_invalid_ip(monkeypatch, tmp_path):
    feed_path = tmp_path / "threat_feed.json"
    feed_path.write_text(
        json.dumps({
            "this-is-not-an-ip": {
                "category": "test"
            }
        }),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        threat_intel,
        "FEED_PATH",
        feed_path,
    )

    try:
        threat_intel.load_threat_feed()
        assert False, "Expected ValueError for invalid feed IP"
    except ValueError as exc:
        assert "Invalid IP address" in str(exc)