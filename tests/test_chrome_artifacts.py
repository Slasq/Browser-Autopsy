"""
Tests for the v2 Chrome artifact extractors:
cookies, bookmarks, autofill, extensions.
"""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from extractors.base import ArtifactNotFoundError, MalformedArtifactError
from extractors.chrome import (
    extract_autofill,
    extract_bookmarks,
    extract_cookies,
    extract_extensions,
)

# helpers

# 2024-01-01 00:00:00 UTC jako Chrome timestamp
_TS_2024 = 13_348_540_800_000_000
# 2024-06-15 12:30:00 UTC jako Chrome timestamp
_TS_JUNE = 13_362_928_200_000_000
# 2024-01-01 00:00:00 UTC jako Unix sekundy (autofill)
_UNIX_2024 = 1_704_067_200


def _make_cookies_db(db_path: Path, cookies: list[dict]) -> Path:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE cookies (
            creation_utc    INTEGER NOT NULL,
            host_key        TEXT NOT NULL,
            name            TEXT NOT NULL,
            path            TEXT NOT NULL,
            expires_utc     INTEGER NOT NULL DEFAULT 0,
            is_secure       INTEGER NOT NULL DEFAULT 0,
            is_httponly     INTEGER NOT NULL DEFAULT 0,
            last_access_utc INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    for c in cookies:
        conn.execute(
            "INSERT INTO cookies (creation_utc, host_key, name, path,"
            " expires_utc, is_secure, is_httponly, last_access_utc)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (c["creation_utc"], c["host_key"], c["name"], c.get("path", "/"),
             c.get("expires_utc", 0), c.get("is_secure", 0),
             c.get("is_httponly", 0), c.get("last_access_utc", 0)),
        )
    conn.commit()
    conn.close()
    return db_path


def _make_bookmarks_file(profile: Path, roots: dict) -> Path:
    path = profile / "Bookmarks"
    path.write_text(json.dumps({"roots": roots, "version": 1}), encoding="utf-8")
    return path


def _make_webdata_db(profile: Path, rows: list[dict]) -> Path:
    db_path = profile / "Web Data"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE autofill (
            name            TEXT NOT NULL,
            value           TEXT NOT NULL,
            count           INTEGER DEFAULT 1,
            date_created    INTEGER,
            date_last_used  INTEGER
        );
        """
    )
    for r in rows:
        conn.execute(
            "INSERT INTO autofill (name, value, count, date_created, date_last_used)"
            " VALUES (?,?,?,?,?)",
            (r["name"], r["value"], r.get("count", 1),
             r.get("date_created", _UNIX_2024), r.get("date_last_used", _UNIX_2024)),
        )
    conn.commit()
    conn.close()
    return db_path


def _make_preferences_file(profile: Path, settings: dict,
                           filename: str = "Preferences") -> Path:
    path = profile / filename
    path.write_text(
        json.dumps({"extensions": {"settings": settings}}), encoding="utf-8",
    )
    return path


# Cookies

class TestExtractCookies:
    def test_reads_cookies_from_legacy_location(self, tmp_path):
        _make_cookies_db(tmp_path / "Cookies", [
            {"creation_utc": _TS_2024, "host_key": ".example.com", "name": "sid"},
        ])
        entries = extract_cookies(tmp_path)
        assert len(entries) == 1
        assert entries[0].host == ".example.com"
        assert entries[0].name == "sid"

    def test_prefers_network_subdir_location(self, tmp_path):
        _make_cookies_db(tmp_path / "Network" / "Cookies", [
            {"creation_utc": _TS_2024, "host_key": ".new.com", "name": "a"},
        ])
        _make_cookies_db(tmp_path / "Cookies", [
            {"creation_utc": _TS_2024, "host_key": ".old.com", "name": "b"},
        ])
        entries = extract_cookies(tmp_path)
        assert len(entries) == 1
        assert entries[0].host == ".new.com"

    def test_timestamps_converted_to_utc(self, tmp_path):
        _make_cookies_db(tmp_path / "Cookies", [
            {"creation_utc": _TS_2024, "host_key": ".x.com", "name": "c",
             "last_access_utc": _TS_JUNE, "expires_utc": _TS_JUNE},
        ])
        e = extract_cookies(tmp_path)[0]
        assert e.timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)
        assert e.last_access == datetime(2024, 6, 15, 12, 30, tzinfo=timezone.utc)
        assert e.expires == datetime(2024, 6, 15, 12, 30, tzinfo=timezone.utc)

    def test_session_cookie_has_no_expiry(self, tmp_path):
        _make_cookies_db(tmp_path / "Cookies", [
            {"creation_utc": _TS_2024, "host_key": ".x.com", "name": "s",
             "expires_utc": 0},
        ])
        assert extract_cookies(tmp_path)[0].expires is None

    def test_flags_mapped_to_bool(self, tmp_path):
        _make_cookies_db(tmp_path / "Cookies", [
            {"creation_utc": _TS_2024, "host_key": ".x.com", "name": "f",
             "is_secure": 1, "is_httponly": 1},
        ])
        e = extract_cookies(tmp_path)[0]
        assert e.is_secure is True
        assert e.is_httponly is True

    def test_sorted_by_creation_time(self, tmp_path):
        _make_cookies_db(tmp_path / "Cookies", [
            {"creation_utc": _TS_JUNE, "host_key": ".late.com", "name": "l"},
            {"creation_utc": _TS_2024, "host_key": ".early.com", "name": "e"},
        ])
        entries = extract_cookies(tmp_path)
        assert [e.host for e in entries] == [".early.com", ".late.com"]

    def test_missing_db_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            extract_cookies(tmp_path)


# Bookmarks

class TestExtractBookmarks:
    def test_reads_flat_bookmark_bar(self, tmp_path):
        _make_bookmarks_file(tmp_path, {
            "bookmark_bar": {
                "type": "folder", "name": "Bookmarks bar",
                "children": [
                    {"type": "url", "name": "Example",
                     "url": "https://example.com", "date_added": str(_TS_2024)},
                ],
            },
        })
        entries = extract_bookmarks(tmp_path)
        assert len(entries) == 1
        assert entries[0].url == "https://example.com"
        assert entries[0].title == "Example"
        assert entries[0].folder == "Bookmarks bar"

    def test_walks_nested_folders(self, tmp_path):
        _make_bookmarks_file(tmp_path, {
            "other": {
                "type": "folder", "name": "Other",
                "children": [
                    {"type": "folder", "name": "Tools", "children": [
                        {"type": "url", "name": "GH", "url": "https://github.com",
                         "date_added": str(_TS_JUNE)},
                    ]},
                ],
            },
        })
        entries = extract_bookmarks(tmp_path)
        assert len(entries) == 1
        assert entries[0].folder == "Tools"

    def test_date_added_string_converted(self, tmp_path):
        _make_bookmarks_file(tmp_path, {
            "bookmark_bar": {"type": "folder", "name": "Bar", "children": [
                {"type": "url", "name": "X", "url": "https://x.com",
                 "date_added": str(_TS_2024)},
            ]},
        })
        assert extract_bookmarks(tmp_path)[0].timestamp == \
            datetime(2024, 1, 1, tzinfo=timezone.utc)

    def test_multiple_roots_combined(self, tmp_path):
        _make_bookmarks_file(tmp_path, {
            "bookmark_bar": {"type": "folder", "name": "Bar", "children": [
                {"type": "url", "name": "A", "url": "https://a.com",
                 "date_added": str(_TS_2024)},
            ]},
            "other": {"type": "folder", "name": "Other", "children": [
                {"type": "url", "name": "B", "url": "https://b.com",
                 "date_added": str(_TS_JUNE)},
            ]},
        })
        assert len(extract_bookmarks(tmp_path)) == 2

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            extract_bookmarks(tmp_path)

    def test_invalid_json_raises_malformed(self, tmp_path):
        (tmp_path / "Bookmarks").write_text("not json {", encoding="utf-8")
        with pytest.raises(MalformedArtifactError):
            extract_bookmarks(tmp_path)


# Autofill

class TestExtractAutofill:
    def test_reads_fields(self, tmp_path):
        _make_webdata_db(tmp_path, [
            {"name": "email", "value": "j.kowalski@firma.pl", "count": 7},
        ])
        entries = extract_autofill(tmp_path)
        assert len(entries) == 1
        assert entries[0].field_name == "email"
        assert entries[0].value == "j.kowalski@firma.pl"
        assert entries[0].times_used == 7

    def test_unix_seconds_converted(self, tmp_path):
        _make_webdata_db(tmp_path, [
            {"name": "q", "value": "x", "date_created": _UNIX_2024,
             "date_last_used": _UNIX_2024 + 3600},
        ])
        e = extract_autofill(tmp_path)[0]
        assert e.timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)
        assert e.last_used == datetime(2024, 1, 1, 1, tzinfo=timezone.utc)

    def test_sorted_by_first_used(self, tmp_path):
        _make_webdata_db(tmp_path, [
            {"name": "late", "value": "x", "date_created": _UNIX_2024 + 100},
            {"name": "early", "value": "y", "date_created": _UNIX_2024},
        ])
        entries = extract_autofill(tmp_path)
        assert [e.field_name for e in entries] == ["early", "late"]

    def test_missing_db_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            extract_autofill(tmp_path)


# Extensions

class TestExtractExtensions:
    def test_reads_extension_metadata(self, tmp_path):
        _make_preferences_file(tmp_path, {
            "abcdefghijklmnop": {
                "state": 1,
                "install_time": str(_TS_2024),
                "manifest": {"name": "uBlock Origin", "version": "1.55.0"},
            },
        })
        entries = extract_extensions(tmp_path)
        assert len(entries) == 1
        e = entries[0]
        assert e.ext_id == "abcdefghijklmnop"
        assert e.name == "uBlock Origin"
        assert e.version == "1.55.0"
        assert e.enabled is True
        assert e.timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)

    def test_first_install_time_preferred(self, tmp_path):
        _make_preferences_file(tmp_path, {
            "ext1": {
                "first_install_time": str(_TS_JUNE),
                "install_time": str(_TS_2024),
                "manifest": {"name": "New", "version": "1.0"},
            },
        })
        e = extract_extensions(tmp_path)[0]
        assert e.timestamp == datetime(2024, 6, 15, 12, 30, tzinfo=timezone.utc)

    def test_disabled_extension(self, tmp_path):
        _make_preferences_file(tmp_path, {
            "ext1": {"state": 0, "manifest": {"name": "Off", "version": "1"}},
        })
        assert extract_extensions(tmp_path)[0].enabled is False

    def test_entries_without_manifest_skipped(self, tmp_path):
        _make_preferences_file(tmp_path, {
            "component1": {"state": 1},
            "real": {"state": 1, "manifest": {"name": "Real", "version": "2"}},
        })
        entries = extract_extensions(tmp_path)
        assert [e.ext_id for e in entries] == ["real"]

    def test_reads_secure_preferences_too(self, tmp_path):
        _make_preferences_file(tmp_path, {
            "a": {"state": 1, "manifest": {"name": "A", "version": "1"}},
        })
        _make_preferences_file(tmp_path, {
            "b": {"state": 1, "manifest": {"name": "B", "version": "1"}},
        }, filename="Secure Preferences")
        ids = {e.ext_id for e in extract_extensions(tmp_path)}
        assert ids == {"a", "b"}

    def test_missing_both_files_raises(self, tmp_path):
        with pytest.raises(ArtifactNotFoundError):
            extract_extensions(tmp_path)

    def test_invalid_json_raises_malformed(self, tmp_path):
        (tmp_path / "Preferences").write_text("{{{", encoding="utf-8")
        with pytest.raises(MalformedArtifactError):
            extract_extensions(tmp_path)
