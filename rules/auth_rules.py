AUTH_RULES = {
    "AUTH-001": {
        "name": "Authentication Failure",
        "description": "Detects a failed authentication attempt.",
        "event_type": "authentication_failure",
        "severity": "medium",
        "evidence_fields": ["username", "source_ip", "timestamp"],
        "mitre": {
            "technique_id": "T1110",
            "technique": "Brute Force",
            "tactic": "Credential Access",
        },
    },

    "AUTH-002": {
        "name": "Possible Brute Force",
        "description": (
            "Identifies a possible brute-force pattern when "
            "multiple authentication failures occur from "
            "the same source."
        ),
        "event_type": "authentication_failure",
        "severity": "high",
        "evidence_fields": ["username", "source_ip", "timestamp"],
        "mitre": {
            "technique_id": "T1110",
            "technique": "Brute Force",
            "tactic": "Credential Access",
        },
    },

    "AUTH-003": {
        "name": "Privilege Escalation Attempt",
        "description": "Detects a failed attempt to gain elevated privileges (sudo).",
        "event_type": "privilege_escalation_attempt",
        "severity": "high",
        "evidence_fields": ["username", "source_ip", "timestamp"],
        "mitre": {
            "technique_id": "T1548",
            "technique": "Abuse Elevation Control Mechanism",
            "tactic": "Privilege Escalation",
        },
    },

    "AUTH-004": {
        "name": "Account Lockout",
        "description": "Detects an account being locked after repeated failures.",
        "event_type": "account_lockout",
        "severity": "medium",
        "evidence_fields": ["username", "source_ip", "timestamp"],
        "mitre": {
            "technique_id": "T1110",
            "technique": "Brute Force",
            "tactic": "Credential Access",
        },
    },
}
