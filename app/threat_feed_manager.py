
"""Safe CRUD helpers for SENTRY's local offline threat-intelligence feed."""

import ipaddress
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FEED_PATH = PROJECT_ROOT / "data" / "threat_feed.json"


def normalize_ip(address):
    """Validate an IP address and return its canonical representation."""
    if not isinstance(address, str) or not address.strip():
        raise ValueError("Enter a valid IPv4 or IPv6 address.")

    try:
        return str(ipaddress.ip_address(address.strip()))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {address!r}") from exc


def load_feed():
    """Load and validate the local feed."""
    if not FEED_PATH.exists():
        return {}

    try:
        with FEED_PATH.open("r", encoding="utf-8") as file:
            feed = json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Threat feed contains invalid JSON; no changes were made."
        ) from exc
    except OSError as exc:
        raise ValueError(f"Could not read threat feed: {exc}") from exc

    if not isinstance(feed, dict):
        raise ValueError(
            "Threat feed must be a JSON object keyed by IP address."
        )

    normalized = {}

    for address, details in feed.items():
        ip = normalize_ip(address)

        if not isinstance(details, dict):
            raise ValueError(
                f"Threat details for {ip} must be a JSON object."
            )

        normalized[ip] = dict(details)

    return normalized


def _write_feed(feed):
    """Write the feed through a temporary file to reduce partial-write risk."""
    FEED_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = FEED_PATH.with_suffix(
        FEED_PATH.suffix + ".tmp"
    )

    try:
        with temporary_path.open(
            "w", encoding="utf-8", newline="\n"
        ) as file:
            json.dump(
                feed,
                file,
                indent=4,
                ensure_ascii=False,
                sort_keys=True,
            )
            file.write("\n")

        temporary_path.replace(FEED_PATH)

    except OSError as exc:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass

        raise ValueError(f"Could not save threat feed: {exc}") from exc


def add_indicator(address, category, description, overwrite=False):
    """Add an indicator; replacing an existing one requires explicit approval."""
    ip = normalize_ip(address)

    if not isinstance(category, str) or not category.strip():
        raise ValueError("Category cannot be empty.")

    if not isinstance(description, str) or not description.strip():
        raise ValueError("Description cannot be empty.")

    feed = load_feed()

    if ip in feed and not overwrite:
        raise ValueError(
            f"{ip} already exists in the feed. "
            "Enable replace-existing to update it."
        )

    feed[ip] = {
        "category": category.strip(),
        "description": description.strip(),
    }

    _write_feed(feed)
    return ip


def remove_indicator(address):
    """Remove an existing indicator from the local feed."""
    ip = normalize_ip(address)
    feed = load_feed()

    if ip not in feed:
        raise ValueError(f"{ip} does not exist in the local feed.")

    del feed[ip]
    _write_feed(feed)

    return ip
