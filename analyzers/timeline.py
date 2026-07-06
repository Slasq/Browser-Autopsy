"""
NOTE: Duplicates are NOT removed because same URL/time may be from diffrent sources.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from analyzers import wal
from extractors import chrome, firefox
from extractors.base import ArtifactError

@dataclass
class TimelineEvent:
    """Unified event on the timeline."""
    timestamp_utc: datetime
    event_type: str           # chrome_visit | chrome_download | chrome_search / firefox_visit | firefox_download | firefox_search
    browser: str              # chrome | firefox
    source_file: str          # ścieżka do oryginalnego artefaktu
    source_sha256: str        # SHA256 pliku źródłowego (chain of custody)
    summary: str              # krótki opis dla output/timeline
    details: dict[str, Any] = field(default_factory=dict)


# extractor entry -> TimelineEvent
# !! Jeśli VisitEntry/DownloadEntry/SearchEntry są inne to tutaj zmienić !!
def _visit_to_event(entry, browser: str) -> TimelineEvent:
    title = getattr(entry, "title", None)
    return TimelineEvent(
        timestamp_utc=entry.timestamp,
        event_type=f"{browser}_visit",
        browser=browser,
        source_file=entry.source_file,
        source_sha256=entry.sha256,
        summary=f"Visit: {entry.url}" + (f" — {title}" if title else ""),
        details={"url": entry.url, "title": title},
    )


def _download_to_event(entry, browser: str) -> TimelineEvent:
    target = getattr(entry, "target_path", None)
    return TimelineEvent(
        timestamp_utc=entry.timestamp,
        event_type=f"{browser}_download",
        browser=browser,
        source_file=entry.source_file,
        source_sha256=entry.sha256,
        summary=f"Download: {entry.url}" + (f" -> {target}" if target else ""),
        details={"url": entry.url, "target_path": str(target) if target else None},
    )


def _search_to_event(entry, browser: str) -> TimelineEvent:
    engine = getattr(entry, "engine", None)
    return TimelineEvent(
        timestamp_utc=entry.timestamp,
        event_type=f"{browser}_search",
        browser=browser,
        source_file=entry.source_file,
        source_sha256=entry.sha256,
        summary=f'Search: "{entry.query}"' + (f" [{engine}]" if engine else ""),
        details={"query": entry.query, "engine": engine},
    )


def _cookie_to_event(entry, browser: str) -> TimelineEvent:
    return TimelineEvent(
        timestamp_utc=entry.timestamp,
        event_type=f"{browser}_cookie",
        browser=browser,
        source_file=entry.source_file,
        source_sha256=entry.sha256,
        summary=f"Cookie: {entry.host} [{entry.name}]",
        details={
            "host": entry.host,
            "name": entry.name,
            "path": entry.path,
            "is_secure": entry.is_secure,
            "is_httponly": entry.is_httponly,
        },
    )


def _bookmark_to_event(entry, browser: str) -> TimelineEvent:
    folder = getattr(entry, "folder", "")
    return TimelineEvent(
        timestamp_utc=entry.timestamp,
        event_type=f"{browser}_bookmark",
        browser=browser,
        source_file=entry.source_file,
        source_sha256=entry.sha256,
        summary=f"Bookmark: {entry.url}"
                + (f" — {entry.title}" if entry.title else "")
                + (f" ({folder})" if folder else ""),
        details={"url": entry.url, "title": entry.title, "folder": folder},
    )


def _autofill_to_event(entry, browser: str) -> TimelineEvent:
    return TimelineEvent(
        timestamp_utc=entry.timestamp,
        event_type=f"{browser}_form",
        browser=browser,
        source_file=entry.source_file,
        source_sha256=entry.sha256,
        summary=f'Form entry: {entry.field_name} = "{entry.value}"',
        details={
            "field_name": entry.field_name,
            "value": entry.value,
            "times_used": entry.times_used,
        },
    )


def _recovered_to_event(entry, browser: str) -> TimelineEvent:
    title = getattr(entry, "title", None)
    return TimelineEvent(
        timestamp_utc=entry.timestamp,
        event_type=f"{browser}_visit_recovered",
        browser=browser,
        source_file=entry.source_file,
        source_sha256=entry.sha256,
        summary=f"[{entry.recovery}] Visit: {entry.url}"
                + (f" — {title}" if title else ""),
        details={"url": entry.url, "title": title, "recovery": entry.recovery},
    )


def _extension_to_event(entry, browser: str) -> TimelineEvent:
    return TimelineEvent(
        timestamp_utc=entry.timestamp,
        event_type=f"{browser}_extension",
        browser=browser,
        source_file=entry.source_file,
        source_sha256=entry.sha256,
        summary=f"Extension: {entry.name} v{entry.version}"
                + ("" if entry.enabled else " (disabled)"),
        details={
            "ext_id": entry.ext_id,
            "name": entry.name,
            "version": entry.version,
            "enabled": entry.enabled,
        },
    )


# Optional artifacts (cookies, bookmarks, autofill, extensions) are extracted
# best-effort: a copied profile often contains only History/places.sqlite, and
# their absence must not abort the whole analysis like the core files do.
_OPTIONAL_EXTRACTORS: dict[str, list[tuple[str, Any]]] = {
    "chromium": [
        ("extract_cookies", _cookie_to_event),
        ("extract_bookmarks", _bookmark_to_event),
        ("extract_autofill", _autofill_to_event),
        ("extract_extensions", _extension_to_event),
    ],
    "gecko": [
        ("extract_cookies", _cookie_to_event),
        ("extract_bookmarks", _bookmark_to_event),
        ("extract_autofill", _autofill_to_event),
        ("extract_extensions", _extension_to_event),
    ],
}


def _extend_optional(events: list[TimelineEvent], module, engine: str,
                     profile: Path, browser: str) -> None:
    for func_name, adapter in _OPTIONAL_EXTRACTORS[engine]:
        extractor = getattr(module, func_name, None)
        if extractor is None:
            continue
        try:
            entries = extractor(profile)
        except ArtifactError as e:
            print(f"[!] Pominięto {func_name} ({browser}): {e}")
            continue
        events.extend(adapter(entry, browser) for entry in entries)


# Api
def build_timeline(
    chrome_profile: Path | None = None,
    firefox_profile: Path | None = None,
    chrome_browser_name: str = "chrome",
    firefox_browser_name: str = "firefox",
    wal_recover: bool = False,
) -> list[TimelineEvent]:
    """
    Build a full timeline from the provided profiles.

    At least one profile must be supplied. A missing artifact file in a given
    profile (e.g. no `places.sqlite`) is propagated as `FileNotFoundError`
    from the extractor — timeline does NOT swallow it silently.

    Args:
        chrome_profile: Path to a Chromium-family profile directory.
        firefox_profile: Path to a Gecko-family profile directory.
        chrome_browser_name: Browser label used in event_type / browser fields
            (e.g. "edge", "brave"). Defaults to "chrome".
        firefox_browser_name: Browser label for the Gecko profile
            (e.g. "tor", "librewolf"). Defaults to "firefox".
        wal_recover: When True, also diff each history DB against its WAL to
            surface deleted-but-recoverable records (events tagged
            *_visit_recovered). No-op for profiles without a -wal file.
    """
    if chrome_profile is None and firefox_profile is None:
        raise ValueError("at least one of chrome_profile / firefox_profile required")

    events: list[TimelineEvent] = []

    if chrome_profile is not None:
        events.extend(_visit_to_event(e, chrome_browser_name)
                      for e in chrome.extract_history(chrome_profile))
        events.extend(_download_to_event(e, chrome_browser_name)
                      for e in chrome.extract_downloads(chrome_profile))
        events.extend(_search_to_event(e, chrome_browser_name)
                      for e in chrome.extract_searches(chrome_profile))
        _extend_optional(events, chrome, "chromium",
                         chrome_profile, chrome_browser_name)
        if wal_recover:
            events.extend(_recovered_to_event(e, chrome_browser_name)
                          for e in wal.recover_history(chrome_profile, "chromium"))

    if firefox_profile is not None:
        events.extend(_visit_to_event(e, firefox_browser_name)
                      for e in firefox.extract_history(firefox_profile))
        events.extend(_download_to_event(e, firefox_browser_name)
                      for e in firefox.extract_downloads(firefox_profile))
        events.extend(_search_to_event(e, firefox_browser_name)
                      for e in firefox.extract_searches(firefox_profile))
        _extend_optional(events, firefox, "gecko",
                         firefox_profile, firefox_browser_name)
        if wal_recover:
            events.extend(_recovered_to_event(e, firefox_browser_name)
                          for e in wal.recover_history(firefox_profile, "gecko"))

    events.sort(key=lambda ev: (ev.timestamp_utc is None, ev.timestamp_utc))
    return events


def filter_by_time(
    events: list[TimelineEvent],
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[TimelineEvent]:
    """Return events within the [start, end] window, inclusive. None = unbounded.

    Events without a timestamp (e.g. extensions with no recorded install date)
    are excluded whenever any bound is given — they can't be proven to fall
    inside the window.
    """
    if start is not None and end is not None and start > end:
        raise ValueError("start must be <= end")

    result = events
    if start is not None:
        result = [e for e in result
                  if e.timestamp_utc is not None and e.timestamp_utc >= start]
    if end is not None:
        result = [e for e in result
                  if e.timestamp_utc is not None and e.timestamp_utc <= end]
    return result