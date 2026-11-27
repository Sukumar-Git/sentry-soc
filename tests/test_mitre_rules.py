import pytest

from app.detection_engine import detect_event
from app.log_parser import parse_log

CASES = [
    ("2026-11-27 10:00:00 WARNING Failed login username=admin ip=1.2.3.4",
     "AUTH-001", "T1110"),
    ("2026-11-27 10:00:00 WARNING Sudo authentication failure username=bob",
     "AUTH-003", "T1548"),
    ("2026-11-27 10:00:00 WARNING Account locked username=bob ip=1.2.3.4",
     "AUTH-004", "T1110"),
    ("2026-11-27 10:00:00 WARNING Port scan detected ip=203.0.113.9", "NET-003", "T1046"),
    ("2026-11-27 10:00:00 WARNING Large outbound transfer ip=192.168.1.30",
     "NET-004", "T1048"),
    ("2026-11-27 10:00:00 WARNING Connection to suspicious destination ip=185.220.101.5", "NET-002", "T1071"),
]


@pytest.mark.parametrize("line,rule_id,technique", CASES)
def test_rule_and_mitre_mapping(line, rule_id, technique):
    result = detect_event(parse_log(line))
    assert result["alert"] is True
    assert result["rule_id"] == rule_id
    assert result["mitre"]["technique_id"] == technique


def test_generic_network_rule_has_no_mitre_tag():
    line = "2026-11-27 10:00:00 WARNING Suspicious network connection ip=10.0.0.25"
    assert detect_event(parse_log(line))["mitre"] is None
