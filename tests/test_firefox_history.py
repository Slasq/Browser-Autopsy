import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from extractors.firefox import extract_history

_TS_2024 = 1_704_067_200_000_000   # 2024-01-01 00:00:00 UTC
_TS_JAN2 = 1_704_153_600_000_000   # 2024-01-02 00:00:00 UTC


def _make_firefox_places(directory: Path, visits: list[dict]) -> Path:
    """
    Create a minimal Firefox 'places.sqlite' with history tables.
    visits: list of dicts with keys: url, title, visit_count, visit_date, visit_type
    """
    db_path = directory / "places.sqlite"
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE moz_places (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT NOT NULL,
            title       TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 0
        );
        CREATE TABLE moz_historyvisits (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            place_id    INTEGER NOT NULL,
            visit_date  INTEGER NOT NULL,
            visit_type  INTEGER DEFAULT 0,
            FOREIGN KEY (place_id) REFERENCES moz_places(id)
        );
    """)
    for v in visits:
        conn.execute(
            "INSERT INTO moz_places (url, title, visit_count) VALUES (?, ?, ?)",
            (v["url"], v.get("title", ""), v.get("visit_count", 1)),
        )
        place_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO moz_historyvisits (place_id, visit_date, visit_type) VALUES (?, ?, ?)",
            (place_id, v["visit_date"], v.get("visit_type", 0)),
        )
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def tmp_profile(tmp_path):
    return tmp_path


class TestFirefoxExtractHistory:

    def test_returns_correct_number_of_entries(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://example.com", "visit_date": _TS_2024},
            {"url": "https://google.com",  "visit_date": _TS_JAN2},
        ])
        assert len(extract_history(tmp_profile)) == 2

    def test_timestamp_converted_to_utc(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://example.com", "visit_date": _TS_2024},
        ])
        assert extract_history(tmp_profile)[0].timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)

    def test_sorted_ascending_by_timestamp(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://later.com",   "visit_date": _TS_JAN2},
            {"url": "https://earlier.com", "visit_date": _TS_2024},
        ])
        entries = extract_history(tmp_profile)
        assert entries[0].url == "https://earlier.com"
        assert entries[1].url == "https://later.com"

    def test_url_title_visit_count_preserved(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://example.com", "title": "Example", "visit_count": 5, "visit_date": _TS_2024},
        ])
        e = extract_history(tmp_profile)[0]
        assert e.url == "https://example.com"
        assert e.title == "Example"
        assert e.visit_count == 5

    def test_empty_title_becomes_empty_string(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://notitle.com", "title": "", "visit_date": _TS_2024},
        ])
        assert extract_history(tmp_profile)[0].title == ""

    def test_zero_visit_date_returns_none_timestamp(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://example.com", "visit_date": 0},
        ])
        assert extract_history(tmp_profile)[0].timestamp is None

    def test_none_timestamp_sorted_last(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://no-time.com",  "visit_date": 0},
            {"url": "https://has-time.com", "visit_date": _TS_2024},
        ])
        entries = extract_history(tmp_profile)
        assert entries[0].url == "https://has-time.com"
        assert entries[1].url == "https://no-time.com"

    def test_sha256_present_and_consistent(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://example.com", "visit_date": _TS_2024},
            {"url": "https://other.com",   "visit_date": _TS_JAN2},
        ])
        entries = extract_history(tmp_profile)
        sha = entries[0].sha256
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)
        assert all(e.sha256 == sha for e in entries)

    def test_raises_when_places_sqlite_missing(self, tmp_profile):
        with pytest.raises(FileNotFoundError):
            extract_history(tmp_profile)

    def test_empty_database_returns_empty_list(self, tmp_profile):
        _make_firefox_places(tmp_profile, [])
        assert extract_history(tmp_profile) == []

    def test_visit_type_stored_as_transition(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://typed.com", "visit_date": _TS_2024, "visit_type": 1},
        ])
        assert extract_history(tmp_profile)[0].transition == 1

    def test_multiple_visits_same_url_produce_separate_entries(self, tmp_profile):
        """One URL visited twice = two separate VisitEntry."""
        _make_firefox_places(tmp_profile, [
            {"url": "https://example.com", "visit_date": _TS_2024},
            {"url": "https://example.com", "visit_date": _TS_JAN2},
        ])
        assert len(extract_history(tmp_profile)) == 2