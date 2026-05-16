"""
NOTE: Duplicates are NOT removed because same URL/time may be from diffrent sources.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from extractors import chrome, firefox

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
        timestamp_utc=entry.visit_time,
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
        timestamp_utc=entry.start_time,
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
        timestamp_utc=entry.timestamp_utc,
        event_type=f"{browser}_search",
        browser=browser,
        source_file=entry.source_file,
        source_sha256=entry.sha256,
        summary=f'Search: "{entry.query}"' + (f" [{engine}]" if engine else ""),
        details={"query": entry.query, "engine": engine},
    )


# Api
def build_timeline(
    chrome_profile: Path | None = None,
    firefox_profile: Path | None = None,
) -> list[TimelineEvent]:
    """
    Build a full timeline from the provided profiles.

    At least one profile must be supplied. A missing artifact file in a given
    profile (e.g. no `places.sqlite`) is propagated as `FileNotFoundError`
    from the extractor — timeline does NOT swallow it silently.
    """
    if chrome_profile is None and firefox_profile is None:
        raise ValueError("at least one of chrome_profile / firefox_profile required")

    events: list[TimelineEvent] = []

    if chrome_profile is not None:
        events.extend(_visit_to_event(e, "chrome")
                      for e in chrome.extract_history(chrome_profile))
        events.extend(_download_to_event(e, "chrome")
                      for e in chrome.extract_downloads(chrome_profile))
        events.extend(_search_to_event(e, "chrome")
                      for e in chrome.extract_searches(chrome_profile))

    if firefox_profile is not None:
        events.extend(_visit_to_event(e, "firefox")
                      for e in firefox.extract_history(firefox_profile))
        events.extend(_download_to_event(e, "firefox")
                      for e in firefox.extract_downloads(firefox_profile))
        events.extend(_search_to_event(e, "firefox")
                      for e in firefox.extract_searches(firefox_profile))

    events.sort(key=lambda ev: ev.timestamp_utc)
    return events


def filter_by_time(
    events: list[TimelineEvent],
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[TimelineEvent]:
    """Return events within the [start, end] window, inclusive. None = unbounded."""
    if start is not None and end is not None and start > end:
        raise ValueError("start must be <= end")

    result = events
    if start is not None:
        result = [e for e in result if e.timestamp_utc >= start]
    if end is not None:
        result = [e for e in result if e.timestamp_utc <= end]
    return result