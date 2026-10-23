from app.pipeline import run_pipeline


def test_full_pipeline():
    results = run_pipeline()

    assert len(results["events"]) == 7
    assert len(results["alerts"]) == 5
    assert len(results["correlations"]) == 2
    assert len(results["incidents"]) == 2


def test_pipeline_incident_details():
    results = run_pipeline()

    incident = next(
        item
        for item in results["incidents"]
        if item["type"] == "possible_brute_force"
    )

    assert incident["incident_id"] == "INC-0001"
    assert incident["source_ip"] == "192.168.1.20"
    assert incident["username"] == "admin"
    assert incident["related_events"] == 3
    assert incident["risk_score"] == 50
    assert incident["risk_level"] == "high"
    assert incident["status"] == "open"


def test_successful_login_correlation_creates_incident():
    results = run_pipeline()

    incident = next(
        item
        for item in results["incidents"]
        if item["type"] == "successful_login_after_repeated_failures"
    )

    assert incident["incident_id"] == "INC-0002"
    assert incident["source_ip"] == "192.168.1.20"
    assert incident["username"] == "admin"
    assert incident["related_events"] == 4

    assert incident["timeline"] == [
        "2026-09-19 07:31:12",
        "2026-09-19 07:31:15",
        "2026-09-19 07:31:18",
        "2026-09-19 07:31:25",
    ]
