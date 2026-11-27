"""Live IP reputation via AbuseIPDB, layered on top of the local threat feed."""
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from app.threat_intel import enrich_ip

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CACHE_PATH = PROJECT_ROOT / "data" / "abuseipdb_cache.json"
API_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_TTL = 24 * 3600          # re-check an IP at most once a day
MALICIOUS_THRESHOLD = 50       # abuse confidence score treated as malicious

_paused_until = 0.0            # set when the API says we hit the rate limit


def _load_cache():
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(cache):
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def query_abuseipdb(ip, api_key, timeout=5):
    params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    request = urllib.request.Request(
        f"{API_URL}?{params}",
        headers={"Key": api_key, "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)["data"]


def _merge(local, data):
    score = data.get("abuseConfidenceScore", 0)
    reports = data.get("totalReports", 0)
    result = {
        **local,
        "abuse_confidence_score": score,
        "total_reports": reports,
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
    }
    if score >= MALICIOUS_THRESHOLD:
        result.update(
            status="known_malicious",
            source="abuseipdb",
            category="abuseipdb_high_confidence",
            description=(
                f"AbuseIPDB abuse confidence score {score}/100 from {reports} "
                "reports in the last 90 days. A community score is a signal, "
                "not proof."
            ),
        )
    return result


def enrich_ip_live(address):
    """Local feed first; AbuseIPDB only for public IPs the feed doesn't know."""
    global _paused_until

    local = enrich_ip(address)
    if local["status"] != "not_found":
        return local  # invalid, or already known from the local feed

    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    ip = local["ip"]
    if not api_key or not ipaddress.ip_address(ip).is_global:
        return local  # no key, or a private/reserved address

    cache = _load_cache()
    entry = cache.get(ip)
    if entry and time.time() - entry["fetched_at"] < CACHE_TTL:
        return _merge(local, entry["data"])

    if time.time() < _paused_until:
        return local

    try:
        data = query_abuseipdb(ip, api_key)
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            _paused_until = time.time() + 3600
        return {**local, "live_lookup_error": f"HTTP {exc.code}"}
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as exc:
        return {**local, "live_lookup_error": type(exc).__name__}

    cache[ip] = {"fetched_at": time.time(), "data": data}
    _save_cache(cache)
    return _merge(local, data)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    print(json.dumps(enrich_ip_live(target), indent=2))
