NETWORK_RULES = {
    "NET-001": {
        "name": "Suspicious Network Connection",
        "description": (
            "Detects a network connection event that "
            "may require investigation."
        ),
        "event_type": "suspicious_network_connection",
        "severity": "medium",
        "evidence_fields": ["source_ip", "timestamp"],
        "mitre": None,  # too generic to map to one technique
    },

    "NET-002": {
        "name": "Suspicious Destination",
        "description": (
            "Detects a connection attempt to a destination "
            "that has been identified as suspicious."
        ),
        "event_type": "suspicious_destination",
        "severity": "high",
        "evidence_fields": ["source_ip", "timestamp"],
        "mitre": {
            "technique_id": "T1071",
            "technique": "Application Layer Protocol",
            "tactic": "Command and Control",
        },
    },

    "NET-003": {
        "name": "Port Scan",
        "description": "Detects probing of multiple ports or services on a host.",
        "event_type": "port_scan",
        "severity": "medium",
        "evidence_fields": ["source_ip", "timestamp"],
        "mitre": {
            "technique_id": "T1046",
            "technique": "Network Service Discovery",
            "tactic": "Discovery",
        },
    },

    "NET-004": {
        "name": "Large Outbound Transfer",
        "description": "Detects an unusually large outbound data transfer.",
        "event_type": "data_exfiltration",
        "severity": "high",
        "evidence_fields": ["source_ip", "timestamp"],
        "mitre": {
            "technique_id": "T1048",
            "technique": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
        },
    },
    "NET-005": {
        "name": "Honeypot Contact",
        "description": (
            "Detects a connection to a decoy service. No legitimate "
            "user should ever touch it."
        ),
        "event_type": "honeypot_connection",
        "severity": "high",
        "evidence_fields": ["source_ip", "timestamp"],
        "mitre": {
            "technique_id": "T1595",
            "technique": "Active Scanning",
            "tactic": "Reconnaissance",
        },
    },
}
