import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from extractors.chrome import extract_history

# helpers

# 2024-01-01 00:00:00 UTC jako Chrome timestamp
_TS_2024 = 13_348_540_800_000_000
# 2024-06-15 12:30:00 UTC jako Chrome timestamp
_TS_JUNE = 13_364_655_000_000_000


def _make_chrome_history(directory: Path, visits: list[dict]) -> Path:
    """
    Create a minimal Chrome 'History' SQLite file with real schema.
    visits: list of dicts with keys: url, title, visit_count, visit_time, transition
    """
    db_path = directory / "History"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE urls (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            url             TEXT NOT NULL,
            title           TEXT DEFAULT '',
            visit_count     INTEGER DEFAULT 0,
            last_visit_time INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE visits (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         INTEGER NOT NULL,
            visit_time  INTEGER NOT NULL,
            transition  INTEGER DEFAULT 0,
            FOREIGN KEY (url) REFERENCES urls(id)
        );
        """
    )
    for v in visits:
        conn.execute(
            "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)",
            (v["url"], v.get("title", ""), v.get("visit_count", 1), v["visit_time"]),
        )
        url_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO visits (url, visit_time, transition) VALUES (?, ?, ?)",
            (url_id, v["visit_time"], v.get("transition", 0)),
        )
    conn.commit()
    conn.close()
    return db_path


# fixtures

@pytest.fixture
def tmp_profile(tmp_path):
    """Temporary directory acting as Chrome profile folder."""
    return tmp_path


# testy

class TestExtractHistory:

    def test_returns_correct_number_of_entries(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://example.com", "title": "Example", "visit_count": 1, "visit_time": _TS_2024},
            {"url": "https://google.com",  "title": "Google",  "visit_count": 3, "visit_time": _TS_JUNE},
        ])
        entries = extract_history(tmp_profile)
        assert len(entries) == 2

    def test_timestamp_converted_to_utc(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://example.com", "visit_time": _TS_2024},
        ])
        entries = extract_history(tmp_profile)
        assert entries[0].timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)

    def test_sorted_ascending_by_timestamp(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://later.com",  "visit_time": _TS_JUNE},
            {"url": "https://earlier.com","visit_time": _TS_2024},
        ])
        entries = extract_history(tmp_profile)
        assert entries[0].url == "https://earlier.com"
        assert entries[1].url == "https://later.com"

    def test_url_and_title_preserved(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://example.com", "title": "Example Domain", "visit_count": 5, "visit_time": _TS_2024},
        ])
        entry = extract_history(tmp_profile)[0]
        assert entry.url == "https://example.com"
        assert entry.title == "Example Domain"
        assert entry.visit_count == 5

    def test_empty_title_becomes_empty_string(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://notitle.com", "title": "", "visit_time": _TS_2024},
        ])
        entry = extract_history(tmp_profile)[0]
        assert entry.title == ""

    def test_zero_visit_time_returns_none_timestamp(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://example.com", "visit_time": 0},
        ])
        entry = extract_history(tmp_profile)[0]
        assert entry.timestamp is None

    def test_none_timestamp_entries_sorted_last(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://no-time.com", "visit_time": 0},
            {"url": "https://has-time.com","visit_time": _TS_2024},
        ])
        entries = extract_history(tmp_profile)
        assert entries[0].url == "https://has-time.com"
        assert entries[1].url == "https://no-time.com"

    def test_sha256_present_and_consistent(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://example.com", "visit_time": _TS_2024},
        ])
        entries = extract_history(tmp_profile)
        sha = entries[0].sha256
        assert len(sha) == 64          # SHA256 hex = 64 znaki
        assert all(c in "0123456789abcdef" for c in sha)
        # wszystkie wpisy z tego samego pliku mają ten sam hash
        assert all(e.sha256 == sha for e in entries)

    def test_raises_when_history_file_missing(self, tmp_profile):
        with pytest.raises(FileNotFoundError):
            extract_history(tmp_profile)

    def test_transition_value_preserved(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://typed.com", "visit_time": _TS_2024, "transition": 1},
        ])
        entry = extract_history(tmp_profile)[0]
        assert entry.transition == 1