from app.pipeline import run_pipeline


def test_full_pipeline():
    results = run_pipeline()

    assert len(results["events"]) == 6
    assert len(results["alerts"]) == 5
    assert len(results["correlations"]) == 1
    assert len(results["incidents"]) == 1


def test_pipeline_incident_details():
    results = run_pipeline()

    incident = results["incidents"][0]

    assert incident["incident_id"] == "INC-0001"
    assert incident["type"] == "possible_brute_force"
    assert incident["source_ip"] == "192.168.1.20"
    assert incident["username"] == "admin"
    assert incident["related_events"] == 3
    assert incident["risk_score"] == 50
    assert incident["risk_level"] == "high"
    assert incident["status"] == "open"
