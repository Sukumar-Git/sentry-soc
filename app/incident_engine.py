def create_incidents(alerts, correlations):
    """Create investigation incidents from correlated security events."""

    incidents = []

    for correlation in correlations:
        source_ip = correlation["source_ip"]

        related_alerts = [
            item
            for item in alerts
            if item["event"].get("source_ip") == source_ip
        ]

        if not related_alerts:
            continue

        highest_risk_alert = max(
            related_alerts,
            key=lambda item: item["risk"]["risk_score"],
        )

        username = correlation.get("username")

        if not username:
            username = next(
                (
                    item["event"].get("username")
                    for item in related_alerts
                    if item["event"].get("username")
                ),
                None,
            )

        # Preserve the full correlation timeline when available.
        timeline = correlation.get("timeline")

        if timeline is None:
            timeline = [
                item["event"]["timestamp"]
                for item in related_alerts
            ]

        timeline = sorted(timeline)

        # Collect threat-intelligence findings for this incident's IP.
        threat_findings = []

        for item in related_alerts:
            finding = item.get("threat_intel")

            if finding and finding not in threat_findings:
                threat_findings.append(finding)

        # Keep the existing evidence fields for dashboard compatibility.
        evidence = {
            "correlation_id": correlation["correlation_id"],
            "event_count": correlation["event_count"],
            "time_window_seconds": correlation["time_window_seconds"],
            "reason": correlation["reason"],
            "threat_intelligence": threat_findings,
        }

        incident = {
            "incident_id": f"INC-{len(incidents) + 1:04d}",
            "type": correlation["type"],
            "source_ip": source_ip,
            "username": username,
            "related_events": correlation["event_count"],
            "risk_score": highest_risk_alert["risk"]["risk_score"],
            "risk_level": highest_risk_alert["risk"]["risk_level"],
            "status": "open",
            "timeline": timeline,
            "evidence": evidence,
        }

        incidents.append(incident)

    return incidents