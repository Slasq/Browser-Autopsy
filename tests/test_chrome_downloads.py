import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from extractors.chrome import DownloadEntry, extract_downloads

# timestamps

_TS_2024 = 13_348_540_800_000_000   # 2024-01-01 00:00:00 UTC
_TS_JUNE = 13_364_655_000_000_000   # 2024-06-15 12:30:00 UTC


# helpers

def _make_chrome_history_with_downloads(directory: Path, downloads: list[dict]) -> Path:
    """
    Create a minimal Chrome 'History' SQLite with downloads tables.
    Each dict in downloads may contain:
        url, target_path, start_time, end_time, total_bytes, state, danger_type
    chain_index=0 is always created for the main URL.
    Pass chain=[url1, url2] to simulate redirect chains (last = final URL).
    """
    db_path = directory / "History"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            title TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 0,
            last_visit_time INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            transition INTEGER DEFAULT 0
        );
        CREATE TABLE downloads (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            current_path    TEXT DEFAULT '',
            target_path     TEXT DEFAULT '',
            start_time      INTEGER NOT NULL DEFAULT 0,
            received_bytes  INTEGER DEFAULT 0,
            total_bytes     INTEGER DEFAULT -1,
            state           INTEGER DEFAULT 1,
            danger_type     INTEGER DEFAULT 0,
            interrupt_reason INTEGER DEFAULT 0,
            end_time        INTEGER DEFAULT 0,
            opened          INTEGER DEFAULT 0
        );
        CREATE TABLE downloads_url_chains (
            id          INTEGER NOT NULL,
            chain_index INTEGER NOT NULL,
            url         TEXT NOT NULL,
            PRIMARY KEY (id, chain_index)
        );
        """
    )
    for d in downloads:
        conn.execute(
            """INSERT INTO downloads
               (target_path, start_time, end_time, total_bytes, state, danger_type)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                d.get("target_path", ""),
                d.get("start_time", 0),
                d.get("end_time", 0),
                d.get("total_bytes", -1),
                d.get("state", 1),
                d.get("danger_type", 0),
            ),
        )
        dl_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        chain = d.get("chain", [d.get("url", "")])
        for i, url in enumerate(chain):
            conn.execute(
                "INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (?, ?, ?)",
                (dl_id, i, url),
            )
    conn.commit()
    conn.close()
    return db_path


# fixture

@pytest.fixture
def tmp_profile(tmp_path):
    return tmp_path


# testy

class TestExtractDownloads:

    def test_returns_correct_number_of_entries(self, tmp_profile):
        _make_chrome_history_with_downloads(tmp_profile, [
            {"url": "https://example.com/a.zip", "start_time": _TS_2024},
            {"url": "https://example.com/b.exe", "start_time": _TS_JUNE},
        ])
        entries = extract_downloads(tmp_profile)
        assert len(entries) == 2

    def test_start_timestamp_converted_to_utc(self, tmp_profile):
        _make_chrome_history_with_downloads(tmp_profile, [
            {"url": "https://example.com/f.zip", "start_time": _TS_2024},
        ])
        entry = extract_downloads(tmp_profile)[0]
        assert entry.timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)

    def test_target_path_and_filename(self, tmp_profile):
        _make_chrome_history_with_downloads(tmp_profile, [
            {"url": "https://x.com/tool.exe",
             "target_path": r"C:\Users\user\Downloads\tool.exe",
             "start_time": _TS_2024},
        ])
        entry = extract_downloads(tmp_profile)[0]
        assert entry.target_path == r"C:\Users\user\Downloads\tool.exe"
        assert entry.filename == "tool.exe"

    def test_file_size_stored(self, tmp_profile):
        _make_chrome_history_with_downloads(tmp_profile, [
            {"url": "https://x.com/big.zip", "start_time": _TS_2024, "total_bytes": 1_048_576},
        ])
        entry = extract_downloads(tmp_profile)[0]
        assert entry.file_size == 1_048_576

    def test_unknown_size_is_minus_one(self, tmp_profile):
        _make_chrome_history_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.bin", "start_time": _TS_2024, "total_bytes": -1},
        ])
        entry = extract_downloads(tmp_profile)[0]
        assert entry.file_size == -1

    def test_state_complete(self, tmp_profile):
        _make_chrome_history_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "start_time": _TS_2024, "state": 1},
        ])
        assert extract_downloads(tmp_profile)[0].state == "COMPLETE"

    def test_state_cancelled(self, tmp_profile):
        _make_chrome_history_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "start_time": _TS_2024, "state": 2},
        ])
        assert extract_downloads(tmp_profile)[0].state == "CANCELLED"

    def test_redirect_chain_uses_final_url(self, tmp_profile):
        """downloads_url_chains with 3 hops — extractor should return last URL."""
        _make_chrome_history_with_downloads(tmp_profile, [
            {
                "target_path": r"C:\Downloads\payload.exe",
                "start_time": _TS_2024,
                "chain": [
                    "https://redirect1.com/go",
                    "https://redirect2.com/dl",
                    "https://final-host.com/payload.exe",
                ],
            }
        ])
        entry = extract_downloads(tmp_profile)[0]
        assert entry.url == "https://final-host.com/payload.exe"

    def test_sorted_ascending_by_timestamp(self, tmp_profile):
        _make_chrome_history_with_downloads(tmp_profile, [
            {"url": "https://later.com/b.zip",   "start_time": _TS_JUNE},
            {"url": "https://earlier.com/a.zip", "start_time": _TS_2024},
        ])
        entries = extract_downloads(tmp_profile)
        assert entries[0].url == "https://earlier.com/a.zip"
        assert entries[1].url == "https://later.com/b.zip"

    def test_danger_type_preserved(self, tmp_profile):
        _make_chrome_history_with_downloads(tmp_profile, [
            {"url": "https://x.com/bad.exe", "start_time": _TS_2024, "danger_type": 3},
        ])
        assert extract_downloads(tmp_profile)[0].danger_type == 3

    def test_sha256_is_valid_hex(self, tmp_profile):
        _make_chrome_history_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "start_time": _TS_2024},
        ])
        sha = extract_downloads(tmp_profile)[0].sha256
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_raises_when_history_file_missing(self, tmp_profile):
        with pytest.raises(FileNotFoundError):
            extract_downloads(tmp_profile)

    def test_empty_database_returns_empty_list(self, tmp_profile):
        _make_chrome_history_with_downloads(tmp_profile, [])
        assert extract_downloads(tmp_profile) == []