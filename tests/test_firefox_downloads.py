import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from extractors.firefox import _fileuri_to_path, extract_downloads

# timestamps in microseconds — Firefox PRTime (used in moz_annos.dateAdded)
_TS_2024_US = 1_704_067_200_000_000   # 2024-01-01 00:00:00 UTC
_TS_JAN2_US = 1_704_153_600_000_000   # 2024-01-02 00:00:00 UTC

# timestamps in milliseconds — JS Date.now() (used in metaData startTime/endTime)
_TS_2024_MS = 1_704_067_200_000
_TS_JAN2_MS = 1_704_153_600_000


def _make_firefox_places_with_downloads(directory: Path, downloads: list[dict]) -> Path:
    """
    Create Firefox 'places.sqlite' with download annotation tables.

    Each dict may contain:
        url         : download source URL
        target_path : POSIX path string (stored as file:///path)
        state       : int — Firefox nsIDownloadManager state (1=FINISHED, 3=CANCELLED...)
        file_size   : int bytes (-1 / omit for unknown)
        start_ms    : start time in ms → stored as metaData.startTime
        end_ms      : end time in ms   → stored as metaData.endTime
        date_added  : fallback timestamp in µs → moz_annos.dateAdded
    """
    db_path = directory / "places.sqlite"
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE moz_places (
            id  INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL
        );
        CREATE TABLE moz_anno_attributes (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE moz_annos (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            place_id          INTEGER NOT NULL,
            anno_attribute_id INTEGER NOT NULL,
            content           TEXT,
            dateAdded         INTEGER DEFAULT 0
        );
    """)
    conn.execute("INSERT INTO moz_anno_attributes (name) VALUES ('downloads/destinationFileURI')")
    dest_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO moz_anno_attributes (name) VALUES ('downloads/metaData')")
    meta_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    for d in downloads:
        conn.execute("INSERT INTO moz_places (url) VALUES (?)", (d.get("url", ""),))
        place_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        date_added = d.get("date_added", 0)

        target = d.get("target_path", "")
        file_uri = f"file://{target}" if target else ""
        conn.execute(
            "INSERT INTO moz_annos (place_id, anno_attribute_id, content, dateAdded) VALUES (?, ?, ?, ?)",
            (place_id, dest_id, file_uri, date_added),
        )

        meta: dict = {}
        if "state" in d:
            meta["state"] = d["state"]
        if "file_size" in d:
            meta["fileSize"] = d["file_size"]
        if "start_ms" in d:
            meta["startTime"] = d["start_ms"]
        if "end_ms" in d:
            meta["endTime"] = d["end_ms"]

        conn.execute(
            "INSERT INTO moz_annos (place_id, anno_attribute_id, content, dateAdded) VALUES (?, ?, ?, ?)",
            (place_id, meta_id, json.dumps(meta), date_added),
        )

    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def tmp_profile(tmp_path):
    return tmp_path


class TestFirefoxExtractDownloads:

    def test_returns_correct_number_of_entries(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://example.com/a.zip", "start_ms": _TS_2024_MS},
            {"url": "https://example.com/b.exe", "start_ms": _TS_JAN2_MS},
        ])
        assert len(extract_downloads(tmp_profile)) == 2

    def test_timestamp_from_starttime_in_metadata(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)

    def test_timestamp_fallback_to_date_added(self, tmp_profile):
        """When metaData has no startTime, dateAdded from moz_annos is used."""
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "date_added": _TS_2024_US},
        ])
        assert extract_downloads(tmp_profile)[0].timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)

    def test_target_path_from_file_uri(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip",
             "target_path": "/home/user/Downloads/f.zip",
             "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].target_path == "/home/user/Downloads/f.zip"

    def test_filename_extracted_from_path(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/tool.exe",
             "target_path": "/home/user/Downloads/tool.exe",
             "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].filename == "tool.exe"

    def test_file_size_stored(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/big.zip", "file_size": 1_048_576, "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].file_size == 1_048_576

    def test_unknown_file_size_is_minus_one(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].file_size == -1

    def test_state_finished(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "state": 1, "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].state == "FINISHED"

    def test_state_cancelled(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "state": 3, "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].state == "CANCELLED"

    def test_sorted_ascending_by_timestamp(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://later.com/b.zip",   "start_ms": _TS_JAN2_MS},
            {"url": "https://earlier.com/a.zip", "start_ms": _TS_2024_MS},
        ])
        entries = extract_downloads(tmp_profile)
        assert entries[0].url == "https://earlier.com/a.zip"
        assert entries[1].url == "https://later.com/b.zip"

    def test_sha256_is_valid_hex(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "start_ms": _TS_2024_MS},
        ])
        sha = extract_downloads(tmp_profile)[0].sha256
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_raises_when_places_sqlite_missing(self, tmp_profile):
        with pytest.raises(FileNotFoundError):
            extract_downloads(tmp_profile)

    def test_empty_database_returns_empty_list(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [])
        assert extract_downloads(tmp_profile) == []

    def test_state_downloading(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "state": 0, "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].state == "DOWNLOADING"

    def test_state_failed(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "state": 2, "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].state == "FAILED"

    def test_state_paused(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "state": 4, "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].state == "PAUSED"

    def test_state_queued(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "state": 5, "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].state == "QUEUED"

    def test_state_blocked_parental(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "state": 6, "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].state == "BLOCKED_PARENTAL"

    def test_state_scanning(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "state": 7, "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].state == "SCANNING"

    def test_state_dirty(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "state": 8, "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].state == "DIRTY"

    def test_state_blocked_policy(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "state": 9, "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].state == "BLOCKED_POLICY"

    def test_unknown_state_becomes_unknown(self, tmp_profile):
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "state": 99, "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].state == "UNKNOWN"

    def test_missing_state_key_becomes_unknown(self, tmp_profile):
        # metaData without "state" key → DOWNLOAD_STATE.get(None) → "UNKNOWN"
        _make_firefox_places_with_downloads(tmp_profile, [
            {"url": "https://x.com/f.zip", "start_ms": _TS_2024_MS},
        ])
        assert extract_downloads(tmp_profile)[0].state == "UNKNOWN"

    def test_corrupted_metadata_json_does_not_crash(self, tmp_profile):
        """Uszkodzony JSON w metaData nie wywala extractora — entry z wartościami domyślnymi."""
        db_path = tmp_profile / "places.sqlite"
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE moz_places (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL);
            CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE);
            CREATE TABLE moz_annos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                place_id INTEGER NOT NULL,
                anno_attribute_id INTEGER NOT NULL,
                content TEXT,
                dateAdded INTEGER DEFAULT 0
            );
        """)
        conn.execute("INSERT INTO moz_anno_attributes (name) VALUES ('downloads/destinationFileURI')")
        dest_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute("INSERT INTO moz_anno_attributes (name) VALUES ('downloads/metaData')")
        meta_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute("INSERT INTO moz_places (url) VALUES (?)", ("https://x.com/f.zip",))
        place_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO moz_annos (place_id, anno_attribute_id, content) VALUES (?, ?, ?)",
            (place_id, dest_id, "file:///home/user/f.zip"),
        )
        conn.execute(
            "INSERT INTO moz_annos (place_id, anno_attribute_id, content) VALUES (?, ?, ?)",
            (place_id, meta_id, "{ to nie jest poprawny json !!!"),
        )
        conn.commit()
        conn.close()

        entries = extract_downloads(tmp_profile)
        assert len(entries) == 1
        assert entries[0].file_size == -1


# _fileuri_to_path — direct unit tests
class TestFileUriToPath:

    def test_empty_string_returns_empty(self):
        assert _fileuri_to_path("") == ""

    def test_posix_path(self):
        assert _fileuri_to_path("file:///home/user/Downloads/f.zip") == "/home/user/Downloads/f.zip"

    def test_windows_drive_letter_slash_stripped(self):
        # Firefox on Windows stores file:///C:/path; urlparse gives path=/C:/...
        # The function must strip the leading '/' before the drive letter.
        assert _fileuri_to_path("file:///C:/Users/user/Downloads/tool.exe") == "C:/Users/user/Downloads/tool.exe"

    def test_windows_path_with_subdirectories(self):
        result = _fileuri_to_path("file:///D:/MyDocs/report.pdf")
        assert result == "D:/MyDocs/report.pdf"

    def test_percent_encoded_spaces_decoded(self):
        result = _fileuri_to_path("file:///home/user/My%20Files/doc.pdf")
        assert result == "/home/user/My Files/doc.pdf"

    def test_percent_encoded_utf8_decoded(self):
        result = _fileuri_to_path("file:///home/user/z%C5%82o%C5%9Bliwy.exe")
        assert "złośliwy" in result

    def test_posix_path_no_slash_stripped(self):
        # "/home/..." — path[2] is 'o', not ':', so no stripping
        result = _fileuri_to_path("file:///tmp/a.bin")
        assert result.startswith("/")
        assert result == "/tmp/a.bin"