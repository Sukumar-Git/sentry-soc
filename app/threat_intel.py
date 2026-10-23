"""
SENTRY Threat Intelligence Engine

Provides offline IP reputation checks using a local threat feed.
An IP absent from the feed is unknown, not automatically safe.
"""

import ipaddress
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FEED_PATH = PROJECT_ROOT / "data" / "threat_feed.json"


def load_threat_feed():
    """
    Load the local threat feed.

    Returns an empty feed if the file does not exist.
    Raises ValueError if the feed is invalid.
    """
    if not FEED_PATH.exists():
        return {}

    try:
        with FEED_PATH.open("r", encoding="utf-8") as file:
            feed = json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError("Threat feed contains invalid JSON.") from exc

    if not isinstance(feed, dict):
        raise ValueError("Threat feed must be a JSON object.")

    normalized_feed = {}

    for address, details in feed.items():
        try:
            ip = str(ipaddress.ip_address(address))
        except ValueError as exc:
            raise ValueError(
                f"Invalid IP address in threat feed: {address}"
            ) from exc

        if not isinstance(details, dict):
            raise ValueError(
                f"Threat details for {ip} must be an object."
            )

        normalized_feed[ip] = details

    return normalized_feed


def enrich_ip(address):
    """
    Return local threat-intelligence context for an IP address.

    Status values:
        known_malicious: IP exists in the local threat feed.
        not_found: Valid IP is absent from the feed.
        invalid_ip: Input is not a valid IP address.

    This local implementation does not perform live reputation lookups.
    """
    if not isinstance(address, str) or not address.strip():
        return {
            "ip": address,
            "status": "invalid_ip",
            "source": "local_feed",
            "category": None,
            "description": "No valid IP address was provided.",
        }

    try:
        ip = str(ipaddress.ip_address(address.strip()))
    except ValueError:
        return {
            "ip": address,
            "status": "invalid_ip",
            "source": "local_feed",
            "category": None,
            "description": "The supplied value is not a valid IP address.",
        }

    feed = load_threat_feed()
    details = feed.get(ip)

    if details is None:
        return {
            "ip": ip,
            "status": "not_found",
            "source": "local_feed",
            "category": None,
            "description": (
                "No matching indicator exists in the local feed. "
                "This does not establish that the IP is safe."
            ),
        }

    return {
        "ip": ip,
        "status": "known_malicious",
        "source": "local_feed",
        "category": details.get("category", "unspecified"),
        "description": details.get(
            "description",
            "IP matched a local threat-intelligence indicator.",
        ),
    }