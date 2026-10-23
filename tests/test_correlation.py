from app.correlation_engine import correlate_events


def make_event(timestamp, event_type, username="admin", source_ip="192.168.1.20"):
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
    }


def test_brute_force_correlation():
    events = [
        make_event("2026-09-19 07:31:12", "authentication_failure"),
        make_event("2026-09-19 07:31:15", "authentication_failure"),
        make_event("2026-09-19 07:31:18", "authentication_failure"),
    ]

    correlations = correlate_events(events)

    assert len(correlations) == 1
    assert correlations[0]["type"] == "possible_brute_force"
    assert correlations[0]["event_count"] == 3


def test_no_correlation_for_single_failure():
    events = [
        make_event("2026-09-19 07:31:12", "authentication_failure"),
    ]

    assert correlate_events(events) == []


def test_no_correlation_for_different_ips():
    events = [
        make_event("2026-09-19 07:31:12", "authentication_failure",
                   source_ip="192.168.1.20"),
        make_event("2026-09-19 07:31:15", "authentication_failure",
                   source_ip="192.168.1.21"),
        make_event("2026-09-19 07:31:18", "authentication_failure",
                   source_ip="192.168.1.22"),
    ]

    assert correlate_events(events) == []


def test_successful_login_after_repeated_failures():
    events = [
        make_event("2026-09-19 07:31:12", "authentication_failure"),
        make_event("2026-09-19 07:31:15", "authentication_failure"),
        make_event("2026-09-19 07:31:18", "authentication_failure"),
        make_event("2026-09-19 07:31:25", "authentication_success"),
    ]

    correlations = correlate_events(events)

    successful_login_correlations = [
        correlation
        for correlation in correlations
        if correlation["type"] == "successful_login_after_repeated_failures"
    ]

    assert len(successful_login_correlations) == 1

    correlation = successful_login_correlations[0]

    assert correlation["correlation_id"] == "AUTH-CORR-002"
    assert correlation["source_ip"] == "192.168.1.20"
    assert correlation["username"] == "admin"
    assert correlation["event_count"] == 4
    assert len(correlation["timeline"]) == 4


def test_successful_login_with_different_username_is_not_correlated():
    events = [
        make_event("2026-09-19 07:31:12",
                   "authentication_failure", username="admin"),
        make_event("2026-09-19 07:31:15",
                   "authentication_failure", username="admin"),
        make_event("2026-09-19 07:31:18",
                   "authentication_failure", username="admin"),
        make_event("2026-09-19 07:31:25",
                   "authentication_success", username="sukumar"),
    ]

    correlations = correlate_events(events)

    assert not any(
        correlation["type"] == "successful_login_after_repeated_failures"
        for correlation in correlations
    )
