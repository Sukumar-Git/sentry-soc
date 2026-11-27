from collections import Counter


def alerts_to_rows(alerts):
    """Flatten pipeline alerts into simple rows for tables and charts."""
    rows = []
    for alert in alerts:
        detection = alert.get("detection", {})
        event = alert.get("event", {})
        risk = alert.get("risk", {})
        mitre = detection.get("mitre") or {}

        rows.append({
            "time": event.get("timestamp"),
            "rule": detection.get("rule_id"),
            "severity": detection.get("severity"),
            "risk_score": risk.get("risk_score"),
            "source_ip": event.get("source_ip"),
            "tactic": mitre.get("tactic", "Untagged"),
            "technique": (
                f"{mitre['technique_id']} {mitre['technique']}"
                if mitre else "Untagged"
            ),
        })
    return rows


def count_by(rows, key):
    """Count rows per value of `key`, most common first."""
    return dict(Counter(row[key] for row in rows).most_common())
