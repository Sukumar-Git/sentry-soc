from app import enrichment

LOCAL = {
    "ip": "8.8.8.8",
    "status": "not_found",
    "source": "local_feed",
    "category": None,
    "description": "Not in the local feed. This does not establish that the address is safe.",
}


def setup(monkeypatch, tmp_path, key="test-key", local=None):
    monkeypatch.setattr(enrichment, "enrich_ip",
                        lambda addr: dict(local or LOCAL))
    monkeypatch.setattr(enrichment, "CACHE_PATH", tmp_path / "cache.json")
    monkeypatch.setattr(enrichment, "_paused_until", 0.0)
    if key:
        monkeypatch.setenv("ABUSEIPDB_API_KEY", key)
    else:
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)


def test_high_score_becomes_known_malicious(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    monkeypatch.setattr(
        enrichment, "query_abuseipdb",
        lambda ip, key: {"abuseConfidenceScore": 90, "totalReports": 12},
    )
    result = enrichment.enrich_ip_live("8.8.8.8")
    assert result["status"] == "known_malicious"
    assert result["source"] == "abuseipdb"
    assert result["abuse_confidence_score"] == 90


def test_low_score_stays_not_found(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    monkeypatch.setattr(
        enrichment, "query_abuseipdb",
        lambda ip, key: {"abuseConfidenceScore": 0, "totalReports": 0},
    )
    result = enrichment.enrich_ip_live("8.8.8.8")
    assert result["status"] == "not_found"
    assert "does not establish" in result["description"]


def test_second_lookup_uses_cache(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    calls = []

    def fake_query(ip, key):
        calls.append(ip)
        return {"abuseConfidenceScore": 10, "totalReports": 1}

    monkeypatch.setattr(enrichment, "query_abuseipdb", fake_query)
    enrichment.enrich_ip_live("8.8.8.8")
    enrichment.enrich_ip_live("8.8.8.8")
    assert len(calls) == 1


def test_private_ip_is_never_queried(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path, local={**LOCAL, "ip": "192.168.1.5"})

    def boom(ip, key):
        raise AssertionError("must not be called")

    monkeypatch.setattr(enrichment, "query_abuseipdb", boom)
    result = enrichment.enrich_ip_live("192.168.1.5")
    assert result["status"] == "not_found"


def test_no_api_key_returns_local_result(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path, key=None)

    def boom(ip, key):
        raise AssertionError("must not be called")

    monkeypatch.setattr(enrichment, "query_abuseipdb", boom)
    assert enrichment.enrich_ip_live("8.8.8.8") == LOCAL


def test_api_error_does_not_break_enrichment(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)

    def fail(ip, key):
        raise TimeoutError()

    monkeypatch.setattr(enrichment, "query_abuseipdb", fail)
    result = enrichment.enrich_ip_live("8.8.8.8")
    assert result["status"] == "not_found"
    assert result["live_lookup_error"] == "TimeoutError"
