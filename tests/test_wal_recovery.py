"""
Tests for analyzers/wal.py — recovery of history records from WAL state.

Fixture strategy: build a fully checkpointed Chrome/Firefox history DB, then
reopen it in WAL mode and delete/insert rows WITHOUT checkpointing. The main
image and the -wal file are copied out while the connection is still open
(closing it would trigger the final checkpoint and merge the WAL).
"""
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from analyzers import timeline
from analyzers.timeline import build_timeline, _recovered_to_event
from analyzers.wal import RecoveredEntry, recover_history

# 2024-01-01 / 2024-01-02 00:00:00 UTC jako Chrome timestamp
_TS_A = 13_348_540_800_000_000
_TS_B = 13_348_627_200_000_000
# to samo jako Firefox µs
_US_A = 1_704_067_200_000_000
_US_B = 1_704_153_600_000_000

_CHROME_SCHEMA = """
    CREATE TABLE urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL, title TEXT DEFAULT '',
        visit_count INTEGER DEFAULT 0,
        last_visit_time INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
        transition INTEGER DEFAULT 0
    );
    CREATE TABLE downloads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        start_time INTEGER NOT NULL, end_time INTEGER,
        target_path TEXT, total_bytes INTEGER,
        state INTEGER DEFAULT 0, danger_type INTEGER DEFAULT 0
    );
    CREATE TABLE downloads_url_chains (
        id INTEGER NOT NULL, chain_index INTEGER NOT NULL, url TEXT NOT NULL,
        PRIMARY KEY (id, chain_index)
    );
"""

_FIREFOX_SCHEMA = """
    CREATE TABLE moz_places (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0
    );
    CREATE TABLE moz_historyvisits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        place_id INTEGER NOT NULL, visit_date INTEGER NOT NULL,
        visit_type INTEGER DEFAULT 1
    );
"""


def _insert_chrome_visit(conn, url, title, ts):
    conn.execute("INSERT INTO urls (url, title, last_visit_time) VALUES (?,?,?)",
                 (url, title, ts))
    url_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO visits (url, visit_time) VALUES (?,?)", (url_id, ts))


def _insert_firefox_visit(conn, url, title, ts):
    conn.execute("INSERT INTO moz_places (url, title) VALUES (?,?)", (url, title))
    place_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO moz_historyvisits (place_id, visit_date) VALUES (?,?)",
                 (place_id, ts))


def _build_profile_with_wal(profile: Path, engine: str,
                            wal_action) -> Path:
    """Create a history DB with rows A+B checkpointed, then apply `wal_action`
    in WAL mode and freeze the (main, wal) pair in `profile`."""
    schema = _CHROME_SCHEMA if engine == "chromium" else _FIREFOX_SCHEMA
    db_name = "History" if engine == "chromium" else "places.sqlite"
    insert = _insert_chrome_visit if engine == "chromium" else _insert_firefox_visit
    ts_a, ts_b = (_TS_A, _TS_B) if engine == "chromium" else (_US_A, _US_B)

    work = profile / "work"
    work.mkdir(parents=True)
    src = work / db_name

    conn = sqlite3.connect(src)
    conn.executescript(schema)
    insert(conn, "https://kept.example.com", "Kept", ts_a)
    insert(conn, "https://deleted.example.com", "Deleted", ts_b)
    conn.commit()
    conn.close()  # pełny checkpoint — main image zawiera oba wpisy

    conn = sqlite3.connect(src)
    conn.execute("PRAGMA journal_mode=WAL")
    wal_action(conn, insert, ts_a, ts_b)
    conn.commit()
    # kopiujemy PRZED close() — close robi finalny checkpoint i scala WAL
    shutil.copy2(src, profile / db_name)
    shutil.copy2(Path(str(src) + "-wal"), profile / (db_name + "-wal"))
    conn.close()
    return profile


def _delete_in_wal(conn, insert, ts_a, ts_b):
    if "urls" in {r[0] for r in
                  conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}:
        conn.execute("DELETE FROM visits WHERE visit_time = ?", (ts_b,))
        conn.execute("DELETE FROM urls WHERE url = 'https://deleted.example.com'")
    else:
        conn.execute("DELETE FROM moz_historyvisits WHERE visit_date = ?", (ts_b,))
        conn.execute("DELETE FROM moz_places WHERE url = 'https://deleted.example.com'")


def _insert_in_wal(conn, insert, ts_a, ts_b):
    insert(conn, "https://fresh.example.com", "Fresh", ts_b)


class TestRecoverHistoryChromium:
    def test_deleted_record_recovered(self, tmp_path):
        profile = _build_profile_with_wal(tmp_path, "chromium", _delete_in_wal)
        entries = recover_history(profile, "chromium")
        assert len(entries) == 1
        e = entries[0]
        assert e.url == "https://deleted.example.com"
        assert e.title == "Deleted"
        assert e.recovery == "DELETED_PENDING"
        assert e.timestamp == datetime(2024, 1, 2, tzinfo=timezone.utc)

    def test_uncheckpointed_record_flagged(self, tmp_path):
        profile = _build_profile_with_wal(tmp_path, "chromium", _insert_in_wal)
        entries = recover_history(profile, "chromium")
        assert len(entries) == 1
        assert entries[0].url == "https://fresh.example.com"
        assert entries[0].recovery == "WAL_ONLY"

    def test_no_wal_file_returns_empty(self, tmp_path):
        profile = _build_profile_with_wal(tmp_path, "chromium", _delete_in_wal)
        (profile / "History-wal").unlink()
        assert recover_history(profile, "chromium") == []

    def test_no_history_db_returns_empty(self, tmp_path):
        assert recover_history(tmp_path, "chromium") == []

    def test_unknown_engine_raises(self, tmp_path):
        with pytest.raises(ValueError):
            recover_history(tmp_path, "webkit")


class TestRecoverHistoryGecko:
    def test_deleted_record_recovered(self, tmp_path):
        profile = _build_profile_with_wal(tmp_path, "gecko", _delete_in_wal)
        entries = recover_history(profile, "gecko")
        assert len(entries) == 1
        assert entries[0].url == "https://deleted.example.com"
        assert entries[0].recovery == "DELETED_PENDING"
        assert entries[0].timestamp == datetime(2024, 1, 2, tzinfo=timezone.utc)

    def test_kept_rows_not_reported(self, tmp_path):
        profile = _build_profile_with_wal(tmp_path, "gecko", _delete_in_wal)
        urls = {e.url for e in recover_history(profile, "gecko")}
        assert "https://kept.example.com" not in urls


class TestRecoveredEventAdapter:
    def _entry(self, recovery="DELETED_PENDING"):
        return RecoveredEntry(
            timestamp=datetime(2024, 1, 2, tzinfo=timezone.utc),
            url="https://deleted.example.com", title="Deleted",
            recovery=recovery, source_file="History", sha256="a" * 64,
        )

    def test_event_type_and_details(self):
        ev = _recovered_to_event(self._entry(), "chrome")
        assert ev.event_type == "chrome_visit_recovered"
        assert ev.details["recovery"] == "DELETED_PENDING"
        assert ev.details["url"] == "https://deleted.example.com"

    def test_summary_carries_recovery_tag(self):
        ev = _recovered_to_event(self._entry("WAL_ONLY"), "firefox")
        assert "WAL_ONLY" in ev.summary

    def test_url_visible_to_domain_detector(self):
        # detektor domen czyta details["url"] — odzyskana wizyta na
        # podejrzaną domenę musi być flagowalna jak zwykła wizyta
        ev = _recovered_to_event(self._entry(), "chrome")
        assert "search" not in ev.event_type
        assert ev.details.get("url")


class TestBuildTimelineWalRecover:
    def test_recovered_events_in_timeline(self, tmp_path, monkeypatch):
        profile = _build_profile_with_wal(tmp_path, "chromium", _delete_in_wal)
        # wyłącz opcjonalne artefakty, żeby nie szumiały
        for name in ("extract_cookies", "extract_bookmarks",
                     "extract_autofill", "extract_extensions"):
            monkeypatch.setattr(
                timeline.chrome, name,
                lambda p: [],
            )

        events = build_timeline(chrome_profile=profile, wal_recover=True)
        recovered = [e for e in events if e.event_type.endswith("_recovered")]
        assert len(recovered) == 1
        assert recovered[0].details["url"] == "https://deleted.example.com"

    def test_wal_recover_off_by_default(self, tmp_path, monkeypatch):
        profile = _build_profile_with_wal(tmp_path, "chromium", _delete_in_wal)
        for name in ("extract_cookies", "extract_bookmarks",
                     "extract_autofill", "extract_extensions"):
            monkeypatch.setattr(timeline.chrome, name, lambda p: [])

        events = build_timeline(chrome_profile=profile)
        assert not any(e.event_type.endswith("_recovered") for e in events)
