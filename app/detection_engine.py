from app.log_parser import parse_log
from rules.auth_rules import AUTH_RULES
from rules.network_rules import NETWORK_RULES

ALL_RULES = {**AUTH_RULES, **NETWORK_RULES}


def detect_event(event):
    """Evaluate a parsed security event against detection rules."""
    for rule_id, rule in ALL_RULES.items():
        if event["event_type"] != rule["event_type"]:
            continue

        return {
            "rule_id": rule_id,
            "alert": True,
            "severity": rule["severity"],
            "reason": rule["description"],
            "mitre": rule.get("mitre"),
            "evidence": {
                field: event.get(field) for field in rule["evidence_fields"]
            },
        }

    return {
        "rule_id": None,
        "alert": False,
        "severity": "none",
        "reason": "No detection rule matched",
        "mitre": None,
        "evidence": {},
    }


if __name__ == "__main__":
    test_logs = [
        "2026-09-19 07:31:12 WARNING Failed login username=admin ip=192.168.1.20",
        "2026-09-19 07:35:00 WARNING Suspicious network connection ip=10.0.0.25",
        "2026-09-19 07:40:12 WARNING Connection to suspicious destination ip=185.220.101.5",
        "2026-09-19 07:45:00 WARNING Port scan detected ip=203.0.113.9",
    ]

    for test_log in test_logs:
        parsed_event = parse_log(test_log)
        print(detect_event(parsed_event)
              if parsed_event else "Could not parse log.")
