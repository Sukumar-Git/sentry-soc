
SEVERITY_POINTS = {
    "low": 5,
    "medium": 10,
    "high": 20,
    "critical": 30,
}

RISK_THRESHOLDS = {
    "critical": 60,
    "high": 40,
    "medium": 20,
}


def classify_risk(score):
    """Classify a risk score into a consistent risk level."""
    if score >= RISK_THRESHOLDS["critical"]:
        return "critical"
    if score >= RISK_THRESHOLDS["high"]:
        return "high"
    if score >= RISK_THRESHOLDS["medium"]:
        return "medium"
    return "low"


def calculate_risk(event, detection):
    """
    Calculate a transparent risk score using detection severity
    and event characteristics.

    Returns:
        risk_score: Integer from 0 to 100.
        risk_level: low, medium, high, or critical.
        factors: List explaining the points added.
    """
    score = 0
    factors = []

    # Detection rule contribution
    if detection.get("alert"):
        score += 20
        factors.append({
            "points": 20,
            "reason": "Detection rule matched",
        })

        # Detection severity contribution
        severity = str(
            detection.get("severity", "none")
        ).lower()

        severity_points = SEVERITY_POINTS.get(severity, 0)

        if severity_points:
            score += severity_points
            factors.append({
                "points": severity_points,
                "reason": f"{severity.capitalize()} detection severity",
            })

    # Authentication failure contribution
    if event.get("event_type") == "authentication_failure":
        score += 10
        factors.append({
            "points": 10,
            "reason": "Authentication failure",
        })

    # Warning-level event contribution
    if str(event.get("level", "")).upper() == "WARNING":
        score += 10
        factors.append({
            "points": 10,
            "reason": "Warning-level event",
        })

    # Keep the score in the range 0–100
    score = min(max(score, 0), 100)

    return {
        "risk_score": score,
        "risk_level": classify_risk(score),
        "factors": factors,
    }
