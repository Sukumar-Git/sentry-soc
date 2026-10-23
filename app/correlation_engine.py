from datetime import datetime


TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
CORRELATION_WINDOW_SECONDS = 60
FAILED_LOGIN_THRESHOLD = 3


def parse_timestamp(event):
    """Convert an event timestamp into a datetime object."""
    return datetime.strptime(event["timestamp"], TIME_FORMAT)


def correlate_events(events):
    """
    Correlate authentication failures and identify:
    1. Possible brute-force activity.
    2. Successful login following repeated failures.
    """

    correlations = []

    failed_events = [
        event
        for event in events
        if event["event_type"] == "authentication_failure"
    ]

    successful_events = [
        event
        for event in events
        if event["event_type"] == "authentication_success"
    ]

    # --------------------------------------------------
    # AUTH-CORR-001: Possible brute-force activity
    # --------------------------------------------------

    ip_groups = {}

    for event in failed_events:
        ip = event["source_ip"]
        ip_groups.setdefault(ip, []).append(event)

    for ip, ip_events in ip_groups.items():
        ip_events.sort(key=parse_timestamp)

        for index, first_event in enumerate(ip_events):
            start_time = parse_timestamp(first_event)

            window_events = [
                event
                for event in ip_events[index:]
                if (
                    parse_timestamp(event) - start_time
                ).total_seconds() <= CORRELATION_WINDOW_SECONDS
            ]

            if len(window_events) >= FAILED_LOGIN_THRESHOLD:
                correlations.append({
                    "correlation_id": "AUTH-CORR-001",
                    "type": "possible_brute_force",
                    "source_ip": ip,
                    "event_count": len(window_events),
                    "time_window_seconds": CORRELATION_WINDOW_SECONDS,
                    "reason": (
                        "Multiple authentication failures from the "
                        "same source IP within 60 seconds"
                    )
                })
                break

    # --------------------------------------------------
    # AUTH-CORR-002: Successful login after repeated failures
    # --------------------------------------------------

    for success in successful_events:
        success_time = parse_timestamp(success)
        username = success["username"]
        source_ip = success["source_ip"]

        matching_failures = [
            event
            for event in failed_events
            if (
                event["username"] == username
                and event["source_ip"] == source_ip
                and 0 <= (
                    success_time - parse_timestamp(event)
                ).total_seconds() <= CORRELATION_WINDOW_SECONDS
            )
        ]

        if len(matching_failures) >= FAILED_LOGIN_THRESHOLD:
            correlations.append({
                "correlation_id": "AUTH-CORR-002",
                "type": "successful_login_after_repeated_failures",
                "source_ip": source_ip,
                "username": username,
                "event_count": len(matching_failures) + 1,
                "time_window_seconds": CORRELATION_WINDOW_SECONDS,
                "reason": (
                    "A successful login followed at least three "
                    "failed login attempts for the same username "
                    "and source IP within 60 seconds"
                ),
                "timeline": sorted(
                    [
                        event["timestamp"]
                        for event in matching_failures
                    ] + [success["timestamp"]]
                )
            })

    return correlations
