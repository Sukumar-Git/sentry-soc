def calculate_risk(event, detection):
    """
    Calculate a transparent risk score using detection severity
    and event characteristics.
    """

    score = 0
    factors = []

    # --------------------------------------------------
    # Detection rule contribution
    # --------------------------------------------------

    if detection["alert"]:
        score += 20

        factors.append({
            "points": 20,
            "reason": "Detection rule matched"
        })

        # --------------------------------------------------
        # Detection severity contribution
        # --------------------------------------------------

        severity_points = {
            "low": 5,
            "medium": 10,
            "high": 20,
            "critical": 30
        }

        severity = detection.get("severity", "none").lower()
        points = severity_points.get(severity, 0)

        if points > 0:
            score += points

            factors.append({
                "points": points,
                "reason": f"{severity.capitalize()} detection severity"
            })

    # --------------------------------------------------
    # Authentication failure contribution
    # --------------------------------------------------

    if event["event_type"] == "authentication_failure":
        score += 10

        factors.append({
            "points": 10,
            "reason": "Authentication failure"
        })

    # --------------------------------------------------
    # Event level contribution
    # --------------------------------------------------

    if event["level"] == "WARNING":
        score += 10

        factors.append({
            "points": 10,
            "reason": "Warning-level event"
        })

    # --------------------------------------------------
    # Determine risk level
    # --------------------------------------------------

    if score >= 60:
        risk_level = "critical"
    elif score >= 40:
        risk_level = "high"
    elif score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "factors": factors
    }
