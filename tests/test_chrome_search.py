import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from extractors.chrome import SearchEntry, extract_searches

# helpers

# 2024-01-01 00:00:00 UTC jako Chrome timestamp
_TS_2024 = 13_348_540_800_000_000
# 2024-06-15 12:30:00 UTC jako Chrome timestamp
_TS_JUNE = 13_364_655_000_000_000


def _make_chrome_history(directory: Path, visits: list[dict]) -> Path:
    """
    Create a minimal Chrome 'History' SQLite file with real schema.
    visits: list of dicts with keys: url, title, visit_count, visit_time, transition

    extract_searches czyta tylko visits JOIN urls, więc downloads-tabele
    nie są tu potrzebne.
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

class TestExtractSearches:

    # --- detekcja vs ignorowanie ---

    def test_returns_only_search_urls(self, tmp_profile):
        """Miks search + zwykłe URLe — tylko wyszukiwania trafiają do wyniku."""
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.google.com/search?q=python", "visit_time": _TS_2024},
            {"url": "https://example.com/article",            "visit_time": _TS_2024},
            {"url": "https://github.com/user/repo",           "visit_time": _TS_2024},
            {"url": "https://www.bing.com/search?q=dfir",      "visit_time": _TS_JUNE},
        ])
        entries = extract_searches(tmp_profile)
        assert len(entries) == 2

    def test_non_search_url_ignored(self, tmp_profile):
        """Sama zwykła nawigacja — pusty wynik."""
        _make_chrome_history(tmp_profile, [
            {"url": "https://example.com",            "visit_time": _TS_2024},
            {"url": "https://news.ycombinator.com",   "visit_time": _TS_2024},
        ])
        assert extract_searches(tmp_profile) == []

    def test_search_engine_url_without_query_param_ignored(self, tmp_profile):
        """Wejście na google.com bez parametru q to nie wyszukiwanie."""
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.google.com/", "visit_time": _TS_2024},
        ])
        assert extract_searches(tmp_profile) == []

    def test_empty_query_param_skipped(self, tmp_profile):
        """?q= z pustą wartością — pomijane (sprawdza .strip() w _extract_query)."""
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.google.com/search?q=", "visit_time": _TS_2024},
            {"url": "https://www.google.com/search?q=%20%20", "visit_time": _TS_2024},
        ])
        assert extract_searches(tmp_profile) == []

    # --- poszczególne silniki + ich parametry ---

    def test_google_detected(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.google.com/search?q=malware+analysis", "visit_time": _TS_2024},
        ])
        entry = extract_searches(tmp_profile)[0]
        assert entry.engine == "google"
        assert entry.query == "malware analysis"

    def test_bing_detected(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.bing.com/search?q=incident+response", "visit_time": _TS_2024},
        ])
        entry = extract_searches(tmp_profile)[0]
        assert entry.engine == "bing.com"
        assert entry.query == "incident response"

    def test_duckduckgo_detected(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://duckduckgo.com/?q=threat+intel", "visit_time": _TS_2024},
        ])
        entry = extract_searches(tmp_profile)[0]
        assert entry.engine == "duckduckgo.com"
        assert entry.query == "threat intel"

    def test_yahoo_uses_p_param(self, tmp_profile):
        """Yahoo używa parametru 'p', nie 'q' — łatwy do przeoczenia."""
        _make_chrome_history(tmp_profile, [
            {"url": "https://search.yahoo.com/search?p=forensics", "visit_time": _TS_2024},
        ])
        entry = extract_searches(tmp_profile)[0]
        assert entry.engine == "search.yahoo.com"
        assert entry.query == "forensics"

    def test_youtube_uses_search_query_param(self, tmp_profile):
        """YouTube używa parametru 'search_query'."""
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.youtube.com/results?search_query=13cubed", "visit_time": _TS_2024},
        ])
        entry = extract_searches(tmp_profile)[0]
        assert entry.engine == "youtube.com"
        assert entry.query == "13cubed"

    def test_yandex_uses_text_param(self, tmp_profile):
        """Yandex używa parametru 'text'."""
        _make_chrome_history(tmp_profile, [
            {"url": "https://yandex.com/search/?text=sqlite+wal", "visit_time": _TS_2024},
        ])
        entry = extract_searches(tmp_profile)[0]
        assert entry.engine == "yandex"
        assert entry.query == "sqlite wal"

    def test_ecosia_brave_startpage_detected(self, tmp_profile):
        """Pozostałe silniki na 'q' — sprawdzane zbiorczo."""
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.ecosia.org/search?q=one",       "visit_time": _TS_2024},
            {"url": "https://search.brave.com/search?q=two",     "visit_time": _TS_2024},
            {"url": "https://www.startpage.com/sp/search?q=three", "visit_time": _TS_2024},
        ])
        entries = extract_searches(tmp_profile)
        engines = {e.engine for e in entries}
        assert len(entries) == 3
        assert engines == {"ecosia.org", "search.brave.com", "startpage.com"}

    # --- dekodowanie query ---

    def test_query_plus_decoded_to_spaces(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.google.com/search?q=jak+wykryc+anomalie", "visit_time": _TS_2024},
        ])
        assert extract_searches(tmp_profile)[0].query == "jak wykryc anomalie"

    def test_query_percent_encoding_decoded(self, tmp_profile):
        """%20 oraz znaki narodowe (UTF-8 percent-encoded)."""
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.google.com/search?q=ruch%20sieciowy", "visit_time": _TS_2024},
            {"url": "https://www.google.com/search?q=z%C5%82o%C5%9Bliwy", "visit_time": _TS_JUNE},
        ])
        entries = extract_searches(tmp_profile)
        queries = {e.query for e in entries}
        assert "ruch sieciowy" in queries
        assert "złośliwy" in queries

    def test_original_url_preserved(self, tmp_profile):
        url = "https://www.google.com/search?q=test+query"
        _make_chrome_history(tmp_profile, [
            {"url": url, "visit_time": _TS_2024},
        ])
        assert extract_searches(tmp_profile)[0].url == url

    # --- timestampy / sortowanie ---

    def test_timestamp_converted_to_utc(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.google.com/search?q=x", "visit_time": _TS_2024},
        ])
        entry = extract_searches(tmp_profile)[0]
        assert entry.timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)

    def test_sorted_ascending_by_timestamp(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.google.com/search?q=later",   "visit_time": _TS_JUNE},
            {"url": "https://www.google.com/search?q=earlier", "visit_time": _TS_2024},
        ])
        entries = extract_searches(tmp_profile)
        assert entries[0].query == "earlier"
        assert entries[1].query == "later"

    def test_zero_visit_time_sorted_last(self, tmp_profile):
        """visit_time=0 → timestamp None → na koniec listy."""
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.google.com/search?q=notime",  "visit_time": 0},
            {"url": "https://www.google.com/search?q=hastime", "visit_time": _TS_2024},
        ])
        entries = extract_searches(tmp_profile)
        assert entries[0].query == "hastime"
        assert entries[1].query == "notime"
        assert entries[1].timestamp is None

    # --- wielokrotne wyszukiwania ---

    def test_repeated_search_produces_separate_entries(self, tmp_profile):
        """To samo zapytanie odwiedzone 2x = dwa osobne SearchEntry."""
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.google.com/search?q=powtorka", "visit_time": _TS_2024},
            {"url": "https://www.google.com/search?q=powtorka", "visit_time": _TS_JUNE},
        ])
        entries = extract_searches(tmp_profile)
        assert len(entries) == 2
        assert all(e.query == "powtorka" for e in entries)

    # --- chain of custody ---

    def test_sha256_is_valid_hex(self, tmp_profile):
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.google.com/search?q=x", "visit_time": _TS_2024},
        ])
        sha = extract_searches(tmp_profile)[0].sha256
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_sha256_consistent_across_entries(self, tmp_profile):
        """Wszystkie wpisy z tego samego pliku mają ten sam hash."""
        _make_chrome_history(tmp_profile, [
            {"url": "https://www.google.com/search?q=a", "visit_time": _TS_2024},
            {"url": "https://www.bing.com/search?q=b",   "visit_time": _TS_JUNE},
        ])
        entries = extract_searches(tmp_profile)
        first = entries[0].sha256
        assert all(e.sha256 == first for e in entries)

    # --- edge cases ---

    def test_raises_when_history_file_missing(self, tmp_profile):
        with pytest.raises(FileNotFoundError):
            extract_searches(tmp_profile)

    def test_empty_database_returns_empty_list(self, tmp_profile):
        _make_chrome_history(tmp_profile, [])
        assert extract_searches(tmp_profile) == []

    def test_malformed_url_does_not_crash(self, tmp_profile):
        """Uszkodzony URL nie wywala extractora — _extract_query łapie wyjątek."""
        _make_chrome_history(tmp_profile, [
            {"url": "ht!tp://[niepoprawny", "visit_time": _TS_2024},
            {"url": "https://www.google.com/search?q=ok", "visit_time": _TS_JUNE},
        ])
        entries = extract_searches(tmp_profile)
        assert len(entries) == 1
        assert entries[0].query == "ok"