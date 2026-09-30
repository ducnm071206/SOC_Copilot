import pytest
from soc_copilot.features import (normalize_alert, compact_alert, build_query,
                                  extract_src_ip)

BASE = {"rule": {"id": "31103", "level": 7, "description": "SQL injection attempt",
                 "groups": ["web", "attack"], "mitre": {"id": ["T1190"]},
                 "gdpr": ["IV_35.7.d"], "pci_dss": ["6.5"]},
        "agent": {"name": "web01"},
        "data": {"srcip": "203.0.113.5", "url": "/index.php?id=1'--"},
        "full_log": "GET /index.php"}


def test_source_unwrapped():
    assert normalize_alert({"_id": "x", "_source": BASE})["rule"]["id"] == "31103"


def test_missing_rule_id():
    with pytest.raises(ValueError):
        normalize_alert({"rule": {}})
    with pytest.raises(ValueError):
        normalize_alert("not a dict")


def test_compact_drops_compliance_and_truncates():
    a = dict(BASE, full_log="x" * 5000 + "\x00\x07")
    c = compact_alert(a)
    assert len(c["log"]) == 800 and "\x00" not in c["log"]
    assert "gdpr" not in str(c) and "pci_dss" not in str(c)


def test_missing_mitre_and_srcip():
    a = {"rule": {"id": "1", "level": 3, "description": "d"}}
    assert compact_alert(a)["rule_id"] == "1"
    assert extract_src_ip(a) == (None, "none")


def test_query_includes_url():
    a2 = dict(BASE, data={"srcip": "1.1.1.1", "url": "/other"})
    assert build_query(BASE) != build_query(a2)


def test_ip_fallback_regex_and_invalid():
    a = {"rule": {"id": "1"}, "data": {"srcip": "?"},
         "full_log": "sshd: Failed password from 198.51.100.7 port 22"}
    assert extract_src_ip(a) == ("198.51.100.7", "regex:full_log")
    a = {"rule": {"id": "1"}, "data": {"srcip": "999.1.1.1"}, "full_log": "from 300.1.1.1"}
    assert extract_src_ip(a)[0] is None
