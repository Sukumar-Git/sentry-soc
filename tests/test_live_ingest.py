from app.live_ingest import normalize
from app.log_parser import parse_log


def test_failed_ssh_login_is_normalized_and_parsed():
    raw = ("Nov 27 09:12:01 myhost sshd[1234]: Failed password for invalid user "
           "admin from 203.0.113.5 port 4444 ssh2")
    line = normalize(raw)
    event = parse_log(line)
    assert event["event_type"] == "authentication_failure"
    assert event["username"] == "admin"
    assert event["source_ip"] == "203.0.113.5"


def test_accepted_ssh_login():
    raw = ("Nov 27 09:13:10 myhost sshd[1234]: Accepted password for sukumar "
           "from 192.168.1.10 port 5555 ssh2")
    event = parse_log(normalize(raw))
    assert event["event_type"] == "authentication_success"


def test_unknown_line_is_skipped():
    assert normalize("Nov 27 09:00:00 myhost cron[1]: job done") is None
