"""
Tests for v2 timeline integration: cookies, bookmarks, autofill, extensions
adapters + best-effort behaviour when optional artifacts are missing.
"""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from analyzers import timeline
from analyzers.timeline import (
    build_timeline,
    filter_by_time,
    _autofill_to_event,
    _bookmark_to_event,
    _cookie_to_event,
    _extension_to_event,
)
from extractors.base import ArtifactNotFoundError, CorruptedDatabaseError

TS_JAN1 = datetime(2024, 1, 1, tzinfo=timezone.utc)
TS_JAN2 = datetime(2024, 1, 2, tzinfo=timezone.utc)
SHA_FAKE = "a" * 64


def _make_cookie(ts=TS_JAN1, host=".example.com", name="sid"):
    return SimpleNamespace(
        timestamp=ts, last_access=ts, expires=None, host=host, name=name,
        path="/", is_secure=True, is_httponly=False,
        source_file="Cookies", sha256=SHA_FAKE,
    )


def _make_bookmark(ts=TS_JAN1, url="https://example.com", title="Ex",
                   folder="Bar"):
    return SimpleNamespace(
        timestamp=ts, url=url, title=title, folder=folder,
        source_file="Bookmarks", sha256=SHA_FAKE,
    )


def _make_autofill(ts=TS_JAN1, field_name="email", value="a@b.pl"):
    return SimpleNamespace(
        timestamp=ts, last_used=ts, field_name=field_name, value=value,
        times_used=2, source_file="Web Data", sha256=SHA_FAKE,
    )


def _make_extension(ts=TS_JAN1, name="uBlock", enabled=True):
    return SimpleNamespace(
        timestamp=ts, ext_id="abc", name=name, version="1.0", enabled=enabled,
        source_file="Preferences", sha256=SHA_FAKE,
    )


@pytest.fixture
def core_extractors_stubbed(monkeypatch):
    """Core (required) extractors return empty; optional left untouched."""
    for module in (timeline.chrome, timeline.firefox):
        monkeypatch.setattr(module, "extract_history", lambda p: [])
        monkeypatch.setattr(module, "extract_downloads", lambda p: [])
        monkeypatch.setattr(module, "extract_searches", lambda p: [])
    return monkeypatch


# Adapters

class TestCookieAdapter:
    def test_fields_mapped(self):
        ev = _cookie_to_event(_make_cookie(), "chrome")
        assert ev.event_type == "chrome_cookie"
        assert ev.browser == "chrome"
        assert ev.timestamp_utc == TS_JAN1
        assert ev.details["host"] == ".example.com"
        assert ev.details["is_secure"] is True

    def test_summary_contains_host_and_name(self):
        ev = _cookie_to_event(_make_cookie(host=".x.com", name="token"), "edge")
        assert ".x.com" in ev.summary
        assert "token" in ev.summary


class TestBookmarkAdapter:
    def test_fields_mapped(self):
        ev = _bookmark_to_event(_make_bookmark(), "firefox")
        assert ev.event_type == "firefox_bookmark"
        assert ev.details == {"url": "https://example.com", "title": "Ex",
                              "folder": "Bar"}

    def test_summary_contains_url_title_folder(self):
        ev = _bookmark_to_event(_make_bookmark(), "firefox")
        assert "https://example.com" in ev.summary
        assert "Ex" in ev.summary
        assert "Bar" in ev.summary

    def test_bookmark_url_visible_to_domain_detector(self):
        # anomaly.detect_suspicious_domains czyta details["url"] z eventów
        # nie-search — zakładka na podejrzaną domenę MUSI mieć details["url"]
        ev = _bookmark_to_event(
            _make_bookmark(url="https://pastebin.com/x"), "chrome",
        )
        assert ev.details["url"] == "https://pastebin.com/x"
        assert "search" not in ev.event_type


class TestAutofillAdapter:
    def test_fields_mapped(self):
        ev = _autofill_to_event(_make_autofill(), "chrome")
        assert ev.event_type == "chrome_form"
        assert ev.details["field_name"] == "email"
        assert ev.details["times_used"] == 2

    def test_summary_contains_field_and_value(self):
        ev = _autofill_to_event(_make_autofill(), "chrome")
        assert "email" in ev.summary
        assert "a@b.pl" in ev.summary


class TestExtensionAdapter:
    def test_fields_mapped(self):
        ev = _extension_to_event(_make_extension(), "brave")
        assert ev.event_type == "brave_extension"
        assert ev.details["name"] == "uBlock"
        assert ev.details["enabled"] is True

    def test_disabled_marked_in_summary(self):
        ev = _extension_to_event(_make_extension(enabled=False), "chrome")
        assert "disabled" in ev.summary


# build_timeline: optional artifacts

class TestOptionalArtifacts:
    def test_missing_optional_artifacts_do_not_abort(self, core_extractors_stubbed):
        # Path nie istnieje — extract_cookies/bookmarks/... rzucą
        # ArtifactNotFoundError, a build_timeline ma to przełknąć.
        events = build_timeline(chrome_profile=Path("/fake/nonexistent"))
        assert events == []

    def test_corrupted_optional_artifact_skipped(self, core_extractors_stubbed,
                                                 monkeypatch, capsys):
        def boom(p):
            raise CorruptedDatabaseError("Corrupted SQLite database: Cookies")
        monkeypatch.setattr(timeline.chrome, "extract_cookies", boom)

        events = build_timeline(chrome_profile=Path("/fake"))
        assert events == []
        assert "Pominięto" in capsys.readouterr().out

    def test_cookie_events_included(self, core_extractors_stubbed, monkeypatch):
        monkeypatch.setattr(timeline.chrome, "extract_cookies",
                            lambda p: [_make_cookie()])
        monkeypatch.setattr(timeline.chrome, "extract_bookmarks",
                            lambda p: (_ for _ in ()).throw(ArtifactNotFoundError("x")))
        monkeypatch.setattr(timeline.chrome, "extract_autofill",
                            lambda p: (_ for _ in ()).throw(ArtifactNotFoundError("x")))
        monkeypatch.setattr(timeline.chrome, "extract_extensions",
                            lambda p: (_ for _ in ()).throw(ArtifactNotFoundError("x")))

        events = build_timeline(chrome_profile=Path("/fake"))
        assert len(events) == 1
        assert events[0].event_type == "chrome_cookie"

    def test_all_artifact_types_on_one_timeline(self, core_extractors_stubbed,
                                                monkeypatch):
        monkeypatch.setattr(timeline.firefox, "extract_cookies",
                            lambda p: [_make_cookie(ts=TS_JAN1)])
        monkeypatch.setattr(timeline.firefox, "extract_bookmarks",
                            lambda p: [_make_bookmark(ts=TS_JAN2)])
        monkeypatch.setattr(timeline.firefox, "extract_autofill",
                            lambda p: [_make_autofill(ts=TS_JAN1)])
        monkeypatch.setattr(timeline.firefox, "extract_extensions",
                            lambda p: [_make_extension(ts=TS_JAN2)])

        events = build_timeline(firefox_profile=Path("/fake"))
        types = {e.event_type for e in events}
        assert types == {"firefox_cookie", "firefox_bookmark",
                         "firefox_form", "firefox_extension"}

    def test_browser_label_applies_to_optional_events(self, core_extractors_stubbed,
                                                      monkeypatch):
        monkeypatch.setattr(timeline.chrome, "extract_cookies",
                            lambda p: [_make_cookie()])
        for name in ("extract_bookmarks", "extract_autofill", "extract_extensions"):
            monkeypatch.setattr(timeline.chrome, name,
                                lambda p: (_ for _ in ()).throw(ArtifactNotFoundError("x")))

        events = build_timeline(chrome_profile=Path("/fake"),
                                chrome_browser_name="vivaldi")
        assert events[0].event_type == "vivaldi_cookie"
        assert events[0].browser == "vivaldi"


# filter_by_time with None timestamps

class TestFilterByTimeNoneTimestamps:
    def test_none_timestamp_excluded_when_window_given(self):
        ev = _extension_to_event(_make_extension(ts=None), "chrome")
        assert filter_by_time([ev], start=TS_JAN1) == []
        assert filter_by_time([ev], end=TS_JAN2) == []

    def test_none_timestamp_kept_when_unbounded(self):
        ev = _extension_to_event(_make_extension(ts=None), "chrome")
        assert filter_by_time([ev]) == [ev]
