from app.log_collector import collect_logs
from app.log_parser import parse_log
from app.detection_engine import detect_event
from app.risk_engine import calculate_risk
from app.correlation_engine import correlate_events
from app.incident_engine import create_incidents
from app.threat_intel import enrich_ip


def run_pipeline():
    """Run the complete SENTRY security monitoring pipeline."""

    raw_logs = collect_logs()

    parsed_events = []
    alerts = []

    for raw_log in raw_logs:
        event = parse_log(raw_log)

        if event is None:
            continue

        parsed_events.append(event)

        detection = detect_event(event)

        if detection.get("alert"):
            risk = calculate_risk(event, detection)

            # Enrich the source IP using the local threat feed.
            source_ip = event.get("source_ip")

            if source_ip:
                threat_intel = enrich_ip(source_ip)
            else:
                threat_intel = {
                    "ip": None,
                    "status": "not_available",
                    "source": "local_feed",
                    "category": None,
                    "description": "The event has no source IP address.",
                }

            alerts.append({
                "event": event,
                "detection": detection,
                "risk": risk,
                "threat_intel": threat_intel,
            })

    correlations = correlate_events(parsed_events)

    incidents = create_incidents(
        alerts,
        correlations,
    )

    return {
        "events": parsed_events,
        "alerts": alerts,
        "correlations": correlations,
        "incidents": incidents,
    }


if __name__ == "__main__":
    results = run_pipeline()

    print("\n=== SENTRY PIPELINE RESULTS ===")
    print(f"\nEvents processed: {len(results['events'])}")
    print(f"Alerts generated: {len(results['alerts'])}")
    print(f"Correlations found: {len(results['correlations'])}")
    print(f"Incidents created: {len(results['incidents'])}")

    print("\n=== ALERTS ===")

    for alert in results["alerts"]:
        print(alert)

    print("\n=== CORRELATIONS ===")

    for correlation in results["correlations"]:
        print(correlation)

    print("\n=== INCIDENTS ===")

    for incident in results["incidents"]:
        print(incident)