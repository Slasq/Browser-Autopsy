from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from analyzers import timeline
from analyzers.timeline import (
    TimelineEvent,
    build_timeline,
    filter_by_time,
    _visit_to_event,
    _download_to_event,
    _search_to_event,
)

# Helpers
TS_JAN1 = datetime(2024, 1, 1, tzinfo=timezone.utc)
TS_JAN2 = datetime(2024, 1, 2, tzinfo=timezone.utc)
TS_JAN3 = datetime(2024, 1, 3, tzinfo=timezone.utc)
TS_JAN4 = datetime(2024, 1, 4, tzinfo=timezone.utc)

SHA_FAKE = "a" * 64


def _make_visit(visit_time, url="https://example.com", title=None,
                sha256=SHA_FAKE, source_file="History"):
    return SimpleNamespace(
        visit_time=visit_time,
        url=url,
        title=title,
        sha256=sha256,
        source_file=source_file,
    )


def _make_download(start_time, url="https://example.com/file.zip",
                   target_path="/home/user/Downloads/file.zip",
                   sha256=SHA_FAKE, source_file="History"):
    return SimpleNamespace(
        start_time=start_time,
        url=url,
        target_path=target_path,
        sha256=sha256,
        source_file=source_file,
    )


def _make_search(timestamp_utc, query="cats", engine=None,
                 sha256=SHA_FAKE, source_file="History"):
    return SimpleNamespace(
        timestamp_utc=timestamp_utc,
        query=query,
        engine=engine,
        sha256=sha256,
        source_file=source_file,
    )


@pytest.fixture
def empty_extractors(monkeypatch):
    """Stub all extractor calls to return empty lists."""
    for module in (timeline.chrome, timeline.firefox):
        monkeypatch.setattr(module, "extract_history", lambda p: [])
        monkeypatch.setattr(module, "extract_downloads", lambda p: [])
        monkeypatch.setattr(module, "extract_searches", lambda p: [])
    return monkeypatch


# Adapter tests
class TestVisitAdapter:
    def test_basic_fields_mapped(self):
        v = _make_visit(TS_JAN1, url="https://x.com", title="X")
        ev = _visit_to_event(v, "chrome")
        assert ev.timestamp_utc == TS_JAN1
        assert ev.event_type == "chrome_visit"
        assert ev.browser == "chrome"
        assert ev.source_file == "History"
        assert ev.source_sha256 == SHA_FAKE
        assert ev.details == {"url": "https://x.com", "title": "X"}

    def test_summary_includes_title(self):
        v = _make_visit(TS_JAN1, url="https://x.com", title="Hello")
        assert "Hello" in _visit_to_event(v, "chrome").summary

    def test_summary_without_title(self):
        v = _make_visit(TS_JAN1, url="https://x.com", title=None)
        ev = _visit_to_event(v, "chrome")
        assert ev.summary == "Visit: https://x.com"
        assert "—" not in ev.summary

    def test_firefox_browser_label(self):
        ev = _visit_to_event(_make_visit(TS_JAN1), "firefox")
        assert ev.event_type == "firefox_visit"
        assert ev.browser == "firefox"


class TestDownloadAdapter:
    def test_basic_fields_mapped(self):
        d = _make_download(TS_JAN1)
        ev = _download_to_event(d, "chrome")
        assert ev.timestamp_utc == TS_JAN1
        assert ev.event_type == "chrome_download"
        assert ev.details["url"] == "https://example.com/file.zip"
        assert ev.details["target_path"] == "/home/user/Downloads/file.zip"

    def test_summary_with_target(self):
        d = _make_download(TS_JAN1, target_path="/tmp/x.zip")
        assert "-> /tmp/x.zip" in _download_to_event(d, "chrome").summary

    def test_summary_without_target(self):
        d = _make_download(TS_JAN1, target_path=None)
        ev = _download_to_event(d, "chrome")
        assert ev.summary == "Download: https://example.com/file.zip"
        assert ev.details["target_path"] is None


class TestSearchAdapter:
    def test_basic_fields_mapped(self):
        s = _make_search(TS_JAN1, query="python tutorial")
        ev = _search_to_event(s, "firefox")
        assert ev.timestamp_utc == TS_JAN1
        assert ev.event_type == "firefox_search"
        assert ev.browser == "firefox"
        assert ev.details["query"] == "python tutorial"

    def test_summary_quotes_query(self):
        s = _make_search(TS_JAN1, query="cats")
        assert '"cats"' in _search_to_event(s, "chrome").summary

    def test_summary_includes_engine(self):
        s = _make_search(TS_JAN1, engine="google")
        assert "[google]" in _search_to_event(s, "chrome").summary

    def test_summary_without_engine(self):
        s = _make_search(TS_JAN1, engine=None)
        assert "[" not in _search_to_event(s, "chrome").summary


# build_timeline: errors & profile selection
class TestBuildTimelineErrors:
    def test_raises_when_no_profile_given(self):
        with pytest.raises(ValueError):
            build_timeline()

    def test_raises_when_both_none(self):
        with pytest.raises(ValueError):
            build_timeline(chrome_profile=None, firefox_profile=None)


class TestBuildTimelineChromeOnly:
    def test_returns_chrome_events_only(self, monkeypatch):
        monkeypatch.setattr(timeline.chrome, "extract_history",
                            lambda p: [_make_visit(TS_JAN1)])
        monkeypatch.setattr(timeline.chrome, "extract_downloads",
                            lambda p: [_make_download(TS_JAN2)])
        monkeypatch.setattr(timeline.chrome, "extract_searches",
                            lambda p: [_make_search(TS_JAN3)])
        # firefox nie powinien być wołany, gdy profile=None
        monkeypatch.setattr(timeline.firefox, "extract_history",
                            lambda p: pytest.fail("firefox should not be called"))

        events = build_timeline(chrome_profile=Path("/fake/chrome"))
        assert len(events) == 3
        assert all(e.browser == "chrome" for e in events)
        types = {e.event_type for e in events}
        assert types == {"chrome_visit", "chrome_download", "chrome_search"}

    def test_empty_chrome_returns_empty_list(self, empty_extractors):
        assert build_timeline(chrome_profile=Path("/fake")) == []


class TestBuildTimelineFirefoxOnly:
    def test_returns_firefox_events_only(self, monkeypatch):
        monkeypatch.setattr(timeline.firefox, "extract_history",
                            lambda p: [_make_visit(TS_JAN1)])
        monkeypatch.setattr(timeline.firefox, "extract_downloads", lambda p: [])
        monkeypatch.setattr(timeline.firefox, "extract_searches", lambda p: [])
        monkeypatch.setattr(timeline.chrome, "extract_history",
                            lambda p: pytest.fail("chrome should not be called"))

        events = build_timeline(firefox_profile=Path("/fake/firefox"))
        assert len(events) == 1
        assert events[0].browser == "firefox"


# build_timeline: orchestration semantics
class TestBuildTimelineCombined:
    def test_chronological_order_across_browsers(self, monkeypatch):
        monkeypatch.setattr(timeline.chrome, "extract_history",
                            lambda p: [_make_visit(TS_JAN3, url="chrome-late")])
        monkeypatch.setattr(timeline.chrome, "extract_downloads", lambda p: [])
        monkeypatch.setattr(timeline.chrome, "extract_searches", lambda p: [])
        monkeypatch.setattr(timeline.firefox, "extract_history",
                            lambda p: [_make_visit(TS_JAN1, url="firefox-early")])
        monkeypatch.setattr(timeline.firefox, "extract_downloads",
                            lambda p: [_make_download(TS_JAN2, url="firefox-mid")])
        monkeypatch.setattr(timeline.firefox, "extract_searches", lambda p: [])

        events = build_timeline(
            chrome_profile=Path("/fake/chrome"),
            firefox_profile=Path("/fake/firefox"),
        )
        urls = [e.details["url"] for e in events]
        assert urls == ["firefox-early", "firefox-mid", "chrome-late"]

    def test_no_deduplication_same_url_same_time(self, monkeypatch):
        # te same URL + ten sam timestamp na obu przeglądarkach — oba mają przeżyć
        monkeypatch.setattr(timeline.chrome, "extract_history",
                            lambda p: [_make_visit(TS_JAN1, url="https://dup.example")])
        monkeypatch.setattr(timeline.chrome, "extract_downloads", lambda p: [])
        monkeypatch.setattr(timeline.chrome, "extract_searches", lambda p: [])
        monkeypatch.setattr(timeline.firefox, "extract_history",
                            lambda p: [_make_visit(TS_JAN1, url="https://dup.example")])
        monkeypatch.setattr(timeline.firefox, "extract_downloads", lambda p: [])
        monkeypatch.setattr(timeline.firefox, "extract_searches", lambda p: [])

        events = build_timeline(
            chrome_profile=Path("/fake"),
            firefox_profile=Path("/fake"),
        )
        assert len(events) == 2
        assert {e.browser for e in events} == {"chrome", "firefox"}

    def test_sha256_propagated_to_event(self, monkeypatch):
        custom_sha = "deadbeef" * 8
        monkeypatch.setattr(timeline.chrome, "extract_history",
                            lambda p: [_make_visit(TS_JAN1, sha256=custom_sha)])
        monkeypatch.setattr(timeline.chrome, "extract_downloads", lambda p: [])
        monkeypatch.setattr(timeline.chrome, "extract_searches", lambda p: [])

        events = build_timeline(chrome_profile=Path("/fake"))
        assert events[0].source_sha256 == custom_sha


# filter_by_time
@pytest.fixture
def sample_events():
    return [
        TimelineEvent(TS_JAN1, "chrome_visit", "chrome", "f", "s", "v1"),
        TimelineEvent(TS_JAN2, "chrome_visit", "chrome", "f", "s", "v2"),
        TimelineEvent(TS_JAN3, "chrome_visit", "chrome", "f", "s", "v3"),
        TimelineEvent(TS_JAN4, "chrome_visit", "chrome", "f", "s", "v4"),
    ]


class TestFilterByTime:
    def test_no_bounds_returns_all(self, sample_events):
        assert filter_by_time(sample_events) == sample_events

    def test_start_only(self, sample_events):
        result = filter_by_time(sample_events, start=TS_JAN2)
        assert [e.summary for e in result] == ["v2", "v3", "v4"]

    def test_end_only(self, sample_events):
        result = filter_by_time(sample_events, end=TS_JAN2)
        assert [e.summary for e in result] == ["v1", "v2"]

    def test_both_bounds(self, sample_events):
        result = filter_by_time(sample_events, start=TS_JAN2, end=TS_JAN3)
        assert [e.summary for e in result] == ["v2", "v3"]

    def test_boundaries_inclusive(self, sample_events):
        result = filter_by_time(sample_events, start=TS_JAN1, end=TS_JAN4)
        assert result == sample_events

    def test_empty_input(self):
        assert filter_by_time([], start=TS_JAN1, end=TS_JAN2) == []

    def test_all_filtered_out(self, sample_events):
        ts_future = datetime(2099, 1, 1, tzinfo=timezone.utc)
        assert filter_by_time(sample_events, start=ts_future) == []

    def test_start_greater_than_end_raises(self, sample_events):
        with pytest.raises(ValueError):
            filter_by_time(sample_events, start=TS_JAN3, end=TS_JAN1)