from app.mitre_summary import alerts_to_rows, count_by


def make_alert(rule, tactic=None):
    mitre = {"technique_id": "T1110", "technique": "Brute Force",
             "tactic": tactic} if tactic else None
    return {
        "event": {"timestamp": "2026-11-27 10:00:00", "source_ip": "1.2.3.4"},
        "detection": {"rule_id": rule, "severity": "high", "mitre": mitre},
        "risk": {"risk_score": 50},
    }


def test_rows_include_tactic_and_technique():
    rows = alerts_to_rows([make_alert("AUTH-001", "Credential Access")])
    assert rows[0]["tactic"] == "Credential Access"
    assert rows[0]["technique"] == "T1110 Brute Force"


def test_untagged_alert_is_labelled():
    rows = alerts_to_rows([make_alert("NET-001")])
    assert rows[0]["tactic"] == "Untagged"


def test_count_by_orders_most_common_first():
    rows = alerts_to_rows([
        make_alert("A", "Discovery"),
        make_alert("B", "Credential Access"),
        make_alert("C", "Credential Access"),
    ])
    assert list(count_by(rows, "tactic").items())[
        0] == ("Credential Access", 2)
