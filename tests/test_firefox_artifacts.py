"""
Tests for the v2 Firefox artifact extractors:
cookies, bookmarks, autofill (form history), extensions.
"""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from extractors.base import MalformedArtifactError
from extractors.firefox import (
    extract_autofill,
    extract_bookmarks,
    extract_cookies,
    extract_extensions,
)

# helpers

# 2024-01-01 00:00:00 UTC
_US_2024 = 1_704_067_200_000_000       # µs (creationTime, firstUsed, dateAdded)
_SEC_2024 = 1_704_067_200              # sekundy (cookie expiry)
_MS_2024 = 1_704_067_200_000           # ms (extensions installDate)
# 2024-06-15 12:30:00 UTC
_US_JUNE = 1_718_454_600_000_000


def _make_cookies_db(profile: Path, cookies: list[dict]) -> Path:
    db_path = profile / "cookies.sqlite"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE moz_cookies (
            id            INTEGER PRIMARY KEY,
            host          TEXT,
            name          TEXT,
            path          TEXT,
            expiry        INTEGER,
            lastAccessed  INTEGER,
            creationTime  INTEGER,
            isSecure      INTEGER,
            isHttpOnly    INTEGER
        );
        """
    )
    for c in cookies:
        conn.execute(
            "INSERT INTO moz_cookies (host, name, path, expiry, lastAccessed,"
            " creationTime, isSecure, isHttpOnly) VALUES (?,?,?,?,?,?,?,?)",
            (c["host"], c["name"], c.get("path", "/"), c.get("expiry", 0),
             c.get("lastAccessed", 0), c["creationTime"],
             c.get("isSecure", 0), c.get("isHttpOnly", 0)),
        )
    conn.commit()
    conn.close()
    return db_path


def _make_places_with_bookmarks(profile: Path, bookmarks: list[dict]) -> Path:
    """places.sqlite with moz_bookmarks; folders get type=2 rows."""
    db_path = profile / "places.sqlite"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE moz_places (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT NOT NULL,
            title       TEXT,
            visit_count INTEGER DEFAULT 0
        );
        CREATE TABLE moz_bookmarks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            type        INTEGER NOT NULL,
            fk          INTEGER,
            parent      INTEGER,
            title       TEXT,
            dateAdded   INTEGER
        );
        """
    )
    # folder "Toolbar" o id 1
    conn.execute(
        "INSERT INTO moz_bookmarks (type, fk, parent, title, dateAdded)"
        " VALUES (2, NULL, 0, 'Toolbar', 0)"
    )
    for b in bookmarks:
        conn.execute("INSERT INTO moz_places (url, title) VALUES (?,?)",
                     (b["url"], b.get("title", "")))
        place_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO moz_bookmarks (type, fk, parent, title, dateAdded)"
            " VALUES (1, ?, ?, ?, ?)",
            (place_id, b.get("parent", 1), b.get("title", ""),
             b.get("dateAdded", _US_2024)),
        )
    conn.commit()
    conn.close()
    return db_path


def _make_formhistory_db(profile: Path, rows: list[dict]) -> Path:
    db_path = profile / "formhistory.sqlite"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE moz_formhistory (
            id          INTEGER PRIMARY KEY,
            fieldname   TEXT NOT NULL,
            value       TEXT NOT NULL,
            timesUsed   INTEGER,
            firstUsed   INTEGER,
            lastUsed    INTEGER
        );
        """
    )
    for r in rows:
        conn.execute(
            "INSERT INTO moz_formhistory (fieldname, value, timesUsed,"
            " firstUsed, lastUsed) VALUES (?,?,?,?,?)",
            (r["fieldname"], r["value"], r.get("timesUsed", 1),
             r.get("firstUsed", _US_2024), r.get("lastUsed", _US_2024)),
        )
    conn.commit()
    conn.close()
    return db_path


def _make_extensions_file(profile: Path, addons: list[dict]) -> Path:
    path = profile / "extensions.json"
    path.write_text(json.dumps({"schemaVersion": 36, "addons": addons}),
                    encoding="utf-8")
    return path


# Cookies

class TestExtractCookies:
    def test_reads_cookies(self, tmp_path):
        _make_cookies_db(tmp_path, [
            {"host": ".mozilla.org", "name": "sid", "creationTime": _US_2024},
        ])
        entries = extract_cookies(tmp_path)
        assert len(entries) == 1
        assert entries[0].host == ".mozilla.org"

    def test_mixed_timestamp_units(self, tmp_path):
        # creationTime/lastAccessed w µs, expiry w SEKUNDACH
        _make_cookies_db(tmp_path, [
            {"host": ".x.com", "name": "c", "creationTime": _US_2024,
             "lastAccessed": _US_2024, "expiry": _SEC_2024},
        ])
        e = extract_cookies(tmp_path)[0]
        expected = datetime(2024, 1, 1, tzinfo=timezone.utc)
        assert e.timestamp == expected
        assert e.last_access == expected
        assert e.expires == expected

    def test_flags_mapped_to_bool(self, tmp_path):
        _make_cookies_db(tmp_path, [
            {"host": ".x.com", "name": "f", "creationTime": _US_2024,
             "isSecure": 1, "isHttpOnly": 1},
        ])
        e = extract_cookies(tmp_path)[0]
        assert e.is_secure is True
        assert e.is_httponly is True

    def test_sorted_by_creation_time(self, tmp_path):
        _make_cookies_db(tmp_path, [
            {"host": ".late.com", "name": "l", "creationTime": _US_JUNE},
            {"host": ".early.com", "name": "e", "creationTime": _US_2024},
        ])
        entries = extract_cookies(tmp_path)
        assert [e.host for e in entries] == [".early.com", ".late.com"]

    def test_missing_db_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            extract_cookies(tmp_path)


# Bookmarks

class TestExtractBookmarks:
    def test_reads_bookmarks_with_folder(self, tmp_path):
        _make_places_with_bookmarks(tmp_path, [
            {"url": "https://example.com", "title": "Example"},
        ])
        entries = extract_bookmarks(tmp_path)
        assert len(entries) == 1
        assert entries[0].url == "https://example.com"
        assert entries[0].title == "Example"
        assert entries[0].folder == "Toolbar"

    def test_date_added_converted(self, tmp_path):
        _make_places_with_bookmarks(tmp_path, [
            {"url": "https://x.com", "dateAdded": _US_2024},
        ])
        assert extract_bookmarks(tmp_path)[0].timestamp == \
            datetime(2024, 1, 1, tzinfo=timezone.utc)

    def test_folders_not_returned_as_bookmarks(self, tmp_path):
        # sam folder Toolbar (type=2) nie może być zwrócony
        _make_places_with_bookmarks(tmp_path, [])
        assert extract_bookmarks(tmp_path) == []

    def test_sorted_by_date_added(self, tmp_path):
        _make_places_with_bookmarks(tmp_path, [
            {"url": "https://late.com", "dateAdded": _US_JUNE},
            {"url": "https://early.com", "dateAdded": _US_2024},
        ])
        urls = [e.url for e in extract_bookmarks(tmp_path)]
        assert urls == ["https://early.com", "https://late.com"]

    def test_missing_db_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            extract_bookmarks(tmp_path)


# Autofill / form history

class TestExtractAutofill:
    def test_reads_fields(self, tmp_path):
        _make_formhistory_db(tmp_path, [
            {"fieldname": "email", "value": "user@example.com", "timesUsed": 3},
        ])
        entries = extract_autofill(tmp_path)
        assert len(entries) == 1
        assert entries[0].field_name == "email"
        assert entries[0].value == "user@example.com"
        assert entries[0].times_used == 3

    def test_microseconds_converted(self, tmp_path):
        _make_formhistory_db(tmp_path, [
            {"fieldname": "q", "value": "x",
             "firstUsed": _US_2024, "lastUsed": _US_JUNE},
        ])
        e = extract_autofill(tmp_path)[0]
        assert e.timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)
        assert e.last_used == datetime(2024, 6, 15, 12, 30, tzinfo=timezone.utc)

    def test_sorted_by_first_used(self, tmp_path):
        _make_formhistory_db(tmp_path, [
            {"fieldname": "late", "value": "x", "firstUsed": _US_JUNE},
            {"fieldname": "early", "value": "y", "firstUsed": _US_2024},
        ])
        entries = extract_autofill(tmp_path)
        assert [e.field_name for e in entries] == ["early", "late"]

    def test_missing_db_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            extract_autofill(tmp_path)


# Extensions

class TestExtractExtensions:
    def test_reads_extension_metadata(self, tmp_path):
        _make_extensions_file(tmp_path, [
            {"id": "uBlock0@raymondhill.net", "type": "extension",
             "version": "1.55.0", "active": True,
             "installDate": _MS_2024,
             "defaultLocale": {"name": "uBlock Origin"}},
        ])
        entries = extract_extensions(tmp_path)
        assert len(entries) == 1
        e = entries[0]
        assert e.ext_id == "uBlock0@raymondhill.net"
        assert e.name == "uBlock Origin"
        assert e.version == "1.55.0"
        assert e.enabled is True
        assert e.timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)

    def test_non_extension_addons_skipped(self, tmp_path):
        _make_extensions_file(tmp_path, [
            {"id": "theme@mozilla.org", "type": "theme", "active": True},
            {"id": "pl@dictionaries", "type": "dictionary", "active": True},
            {"id": "real@ext", "type": "extension", "version": "1",
             "active": True, "installDate": _MS_2024,
             "defaultLocale": {"name": "Real"}},
        ])
        entries = extract_extensions(tmp_path)
        assert [e.ext_id for e in entries] == ["real@ext"]

    def test_inactive_extension(self, tmp_path):
        _make_extensions_file(tmp_path, [
            {"id": "off@ext", "type": "extension", "version": "1",
             "active": False, "installDate": _MS_2024,
             "defaultLocale": {"name": "Off"}},
        ])
        assert extract_extensions(tmp_path)[0].enabled is False

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            extract_extensions(tmp_path)

    def test_invalid_json_raises_malformed(self, tmp_path):
        (tmp_path / "extensions.json").write_text("[broken", encoding="utf-8")
        with pytest.raises(MalformedArtifactError):
            extract_extensions(tmp_path)
