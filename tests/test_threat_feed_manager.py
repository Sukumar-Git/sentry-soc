
import json

import pytest

from app import threat_feed_manager as manager


def use_temporary_feed(monkeypatch, tmp_path):
    feed_path = tmp_path / "data" / "threat_feed.json"
    monkeypatch.setattr(manager, "FEED_PATH", feed_path)
    return feed_path


def test_missing_feed_loads_as_empty(monkeypatch, tmp_path):
    use_temporary_feed(monkeypatch, tmp_path)

    assert manager.load_feed() == {}


def test_add_normalizes_ip_and_persists_indicator(
    monkeypatch, tmp_path
):
    feed_path = use_temporary_feed(monkeypatch, tmp_path)

    result = manager.add_indicator(
        " 203.0.113.60 ",
        "scanner",
        "Test indicator for unit tests.",
    )

    assert result == "203.0.113.60"

    assert manager.load_feed()[result] == {
        "category": "scanner",
        "description": "Test indicator for unit tests.",
    }

    saved_data = json.loads(
        feed_path.read_text(encoding="utf-8")
    )

    assert saved_data[result]["category"] == "scanner"


def test_duplicate_is_rejected_without_overwrite(
    monkeypatch, tmp_path
):
    use_temporary_feed(monkeypatch, tmp_path)

    manager.add_indicator(
        "203.0.113.60",
        "scanner",
        "Original description",
    )

    with pytest.raises(ValueError, match="already exists"):
        manager.add_indicator(
            "203.0.113.60",
            "malware",
            "Changed description",
        )

    assert (
        manager.load_feed()["203.0.113.60"]["category"]
        == "scanner"
    )


def test_existing_indicator_can_be_updated_explicitly(
    monkeypatch, tmp_path
):
    use_temporary_feed(monkeypatch, tmp_path)

    manager.add_indicator(
        "203.0.113.60",
        "scanner",
        "Original description",
    )

    manager.add_indicator(
        "203.0.113.60",
        "malware",
        "Updated description",
        overwrite=True,
    )

    assert manager.load_feed()["203.0.113.60"] == {
        "category": "malware",
        "description": "Updated description",
    }


def test_remove_indicator(monkeypatch, tmp_path):
    use_temporary_feed(monkeypatch, tmp_path)

    manager.add_indicator(
        "203.0.113.60",
        "scanner",
        "Test indicator",
    )

    assert manager.remove_indicator("203.0.113.60") == (
        "203.0.113.60"
    )

    assert manager.load_feed() == {}


def test_remove_missing_indicator_fails(monkeypatch, tmp_path):
    use_temporary_feed(monkeypatch, tmp_path)

    with pytest.raises(ValueError, match="does not exist"):
        manager.remove_indicator("203.0.113.60")


@pytest.mark.parametrize(
    "address",
    ["", "not-an-ip", "999.1.1.1"],
)
def test_invalid_ip_is_rejected(
    monkeypatch, tmp_path, address
):
    use_temporary_feed(monkeypatch, tmp_path)

    with pytest.raises(
        ValueError,
        match="valid IPv4 or IPv6|Invalid IP",
    ):
        manager.add_indicator(
            address,
            "malware",
            "Description",
        )


def test_empty_category_and_description_are_rejected(
    monkeypatch, tmp_path
):
    use_temporary_feed(monkeypatch, tmp_path)

    with pytest.raises(
        ValueError,
        match="Category cannot be empty",
    ):
        manager.add_indicator(
            "203.0.113.60",
            "  ",
            "Description",
        )

    with pytest.raises(
        ValueError,
        match="Description cannot be empty",
    ):
        manager.add_indicator(
            "203.0.113.60",
            "malware",
            "  ",
        )


def test_malformed_json_is_rejected_without_overwriting(
    monkeypatch, tmp_path
):
    feed_path = use_temporary_feed(monkeypatch, tmp_path)
    feed_path.parent.mkdir(parents=True)

    feed_path.write_text(
        "{bad json",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid JSON"):
        manager.add_indicator(
            "203.0.113.60",
            "malware",
            "Description",
        )

    assert feed_path.read_text(encoding="utf-8") == "{bad json"
