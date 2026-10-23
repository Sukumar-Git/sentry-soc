from app.risk_engine import calculate_risk


def test_authentication_failure_risk():
    event = {
        "event_type": "authentication_failure",
        "level": "WARNING"
    }

    detection = {
        "alert": True,
        "severity": "medium"
    }

    result = calculate_risk(event, detection)

    assert result["risk_score"] == 50
    assert result["risk_level"] == "high"


def test_network_event_risk():
    event = {
        "event_type": "suspicious_network_connection",
        "level": "WARNING"
    }

    detection = {
        "alert": True,
        "severity": "medium"
    }

    result = calculate_risk(event, detection)

    assert result["risk_score"] == 40
    assert result["risk_level"] == "high"


def test_no_alert_low_risk():
    event = {
        "event_type": "authentication_success",
        "level": "INFO"
    }

    detection = {
        "alert": False,
        "severity": "none"
    }

    result = calculate_risk(event, detection)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"


def test_high_severity_detection():
    event = {
        "event_type": "suspicious_destination",
        "level": "WARNING"
    }

    detection = {
        "alert": True,
        "severity": "high"
    }

    result = calculate_risk(event, detection)

    assert result["risk_score"] == 50
    assert result["risk_level"] == "high"


def test_risk_factors_are_explained():
    event = {
        "event_type": "suspicious_destination",
        "level": "WARNING"
    }

    detection = {
        "alert": True,
        "severity": "high"
    }

    result = calculate_risk(event, detection)

    reasons = [
        factor["reason"]
        for factor in result["factors"]
    ]

    assert "Detection rule matched" in reasons
    assert "High detection severity" in reasons
    assert "Warning-level event" in reasons


def test_critical_severity_detection():
    event = {
        "event_type": "suspicious_destination",
        "level": "WARNING"
    }

    detection = {
        "alert": True,
        "severity": "critical"
    }

    result = calculate_risk(event, detection)

    assert result["risk_score"] == 60
    assert result["risk_level"] == "critical"
