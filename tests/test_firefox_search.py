import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from extractors.firefox import extract_searches

_TS_2024 = 1_704_067_200_000_000   # 2024-01-01 00:00:00 UTC
_TS_JAN2 = 1_704_153_600_000_000   # 2024-01-02 00:00:00 UTC


def _make_firefox_places(directory: Path, visits: list[dict]) -> Path:
    """
    Create a minimal Firefox 'places.sqlite' with history tables.
    visits: list of dicts with keys: url, visit_date, and optionally title, visit_count, visit_type
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


class TestFirefoxExtractSearches:

    # --- detekcja vs ignorowanie ---

    def test_returns_only_search_urls(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://www.google.com/search?q=python", "visit_date": _TS_2024},
            {"url": "https://example.com/article",            "visit_date": _TS_2024},
            {"url": "https://www.bing.com/search?q=dfir",     "visit_date": _TS_JAN2},
        ])
        assert len(extract_searches(tmp_profile)) == 2

    def test_non_search_url_ignored(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://example.com",          "visit_date": _TS_2024},
            {"url": "https://news.ycombinator.com", "visit_date": _TS_2024},
        ])
        assert extract_searches(tmp_profile) == []

    def test_empty_query_param_skipped(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://www.google.com/search?q=",       "visit_date": _TS_2024},
            {"url": "https://www.google.com/search?q=%20%20", "visit_date": _TS_2024},
        ])
        assert extract_searches(tmp_profile) == []

    # --- poszczególne silniki ---

    def test_google_detected(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://www.google.com/search?q=malware+analysis", "visit_date": _TS_2024},
        ])
        e = extract_searches(tmp_profile)[0]
        assert e.engine == "google"
        assert e.query == "malware analysis"

    def test_bing_detected(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://www.bing.com/search?q=incident+response", "visit_date": _TS_2024},
        ])
        e = extract_searches(tmp_profile)[0]
        assert e.engine == "bing.com"
        assert e.query == "incident response"

    def test_duckduckgo_detected(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://duckduckgo.com/?q=threat+intel", "visit_date": _TS_2024},
        ])
        e = extract_searches(tmp_profile)[0]
        assert e.engine == "duckduckgo.com"
        assert e.query == "threat intel"

    def test_yahoo_uses_p_param(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://search.yahoo.com/search?p=forensics", "visit_date": _TS_2024},
        ])
        e = extract_searches(tmp_profile)[0]
        assert e.engine == "search.yahoo.com"
        assert e.query == "forensics"

    def test_youtube_detected(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://www.youtube.com/results?search_query=13cubed", "visit_date": _TS_2024},
        ])
        e = extract_searches(tmp_profile)[0]
        assert e.engine == "youtube.com"
        assert e.query == "13cubed"

    def test_yandex_uses_text_param(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://yandex.com/search/?text=sqlite+wal", "visit_date": _TS_2024},
        ])
        e = extract_searches(tmp_profile)[0]
        assert e.engine == "yandex"
        assert e.query == "sqlite wal"

    # --- dekodowanie query ---

    def test_query_plus_decoded_to_spaces(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://www.google.com/search?q=jak+wykryc+anomalie", "visit_date": _TS_2024},
        ])
        assert extract_searches(tmp_profile)[0].query == "jak wykryc anomalie"

    def test_query_percent_encoding_decoded(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://www.google.com/search?q=ruch%20sieciowy",  "visit_date": _TS_2024},
            {"url": "https://www.google.com/search?q=z%C5%82o%C5%9Bliwy", "visit_date": _TS_JAN2},
        ])
        queries = {e.query for e in extract_searches(tmp_profile)}
        assert "ruch sieciowy" in queries
        assert "złośliwy" in queries

    def test_original_url_preserved(self, tmp_profile):
        url = "https://www.google.com/search?q=test+query"
        _make_firefox_places(tmp_profile, [{"url": url, "visit_date": _TS_2024}])
        assert extract_searches(tmp_profile)[0].url == url

    # --- timestampy / sortowanie ---

    def test_timestamp_converted_to_utc(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://www.google.com/search?q=x", "visit_date": _TS_2024},
        ])
        assert extract_searches(tmp_profile)[0].timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)

    def test_sorted_ascending_by_timestamp(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://www.google.com/search?q=later",   "visit_date": _TS_JAN2},
            {"url": "https://www.google.com/search?q=earlier", "visit_date": _TS_2024},
        ])
        entries = extract_searches(tmp_profile)
        assert entries[0].query == "earlier"
        assert entries[1].query == "later"

    def test_zero_visit_date_sorted_last(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://www.google.com/search?q=notime",  "visit_date": 0},
            {"url": "https://www.google.com/search?q=hastime", "visit_date": _TS_2024},
        ])
        entries = extract_searches(tmp_profile)
        assert entries[0].query == "hastime"
        assert entries[1].query == "notime"
        assert entries[1].timestamp is None

    # --- wielokrotne wyszukiwania ---

    def test_repeated_search_produces_separate_entries(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://www.google.com/search?q=powtorka", "visit_date": _TS_2024},
            {"url": "https://www.google.com/search?q=powtorka", "visit_date": _TS_JAN2},
        ])
        entries = extract_searches(tmp_profile)
        assert len(entries) == 2
        assert all(e.query == "powtorka" for e in entries)

    # --- chain of custody ---

    def test_sha256_is_valid_hex(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://www.google.com/search?q=x", "visit_date": _TS_2024},
        ])
        sha = extract_searches(tmp_profile)[0].sha256
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_sha256_consistent_across_entries(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "https://www.google.com/search?q=a", "visit_date": _TS_2024},
            {"url": "https://www.bing.com/search?q=b",   "visit_date": _TS_JAN2},
        ])
        entries = extract_searches(tmp_profile)
        first = entries[0].sha256
        assert all(e.sha256 == first for e in entries)

    # --- edge cases ---

    def test_raises_when_places_sqlite_missing(self, tmp_profile):
        with pytest.raises(FileNotFoundError):
            extract_searches(tmp_profile)

    def test_empty_database_returns_empty_list(self, tmp_profile):
        _make_firefox_places(tmp_profile, [])
        assert extract_searches(tmp_profile) == []

    def test_malformed_url_does_not_crash(self, tmp_profile):
        _make_firefox_places(tmp_profile, [
            {"url": "ht!tp://[niepoprawny",                      "visit_date": _TS_2024},
            {"url": "https://www.google.com/search?q=ok",       "visit_date": _TS_JAN2},
        ])
        entries = extract_searches(tmp_profile)
        assert len(entries) == 1
        assert entries[0].query == "ok"