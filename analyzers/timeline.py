"""
NOTE: Duplicates are NOT removed because same URL/time may be from diffrent sources.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from analyzers import wal
from extractors import chrome, firefox
from extractors.base import searches_from_visits, sha256_file

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


def _iso(dt: datetime | None) -> str | None:
    """ISO-8601 text for `details`, so JSON and CSV carry one timestamp format."""
    return dt.isoformat() if dt is not None else None


# Stany, przy których plik dotarł w całości albo stan jest nieznany. Każdy inny
# (CANCELLED, INTERRUPTED, FAILED...) trafia do summary, bo zmienia sens zdarzenia.
_QUIET_DOWNLOAD_STATES = frozenset({None, "COMPLETE", "FINISHED", "UNKNOWN"})


def _download_to_event(entry, browser: str) -> TimelineEvent:
    target = getattr(entry, "target_path", None)
    state = getattr(entry, "state", None)
    return TimelineEvent(
        timestamp_utc=entry.timestamp,
        event_type=f"{browser}_download",
        browser=browser,
        source_file=entry.source_file,
        source_sha256=entry.sha256,
        summary=f"Download: {entry.url}" + (f" -> {target}" if target else "")
                + ("" if state in _QUIET_DOWNLOAD_STATES else f" [{state}]"),
        details={
            "url": entry.url,
            "target_path": str(target) if target else None,
            "filename": getattr(entry, "filename", "") or "",
            "state": state,
            "file_size": getattr(entry, "file_size", None),
            "end_time": _iso(getattr(entry, "end_timestamp", None)),
            "danger_type": getattr(entry, "danger_type", None),
        },
    )


def _search_to_event(entry, browser: str,
                     recovery: str | None = None) -> TimelineEvent:
    engine = getattr(entry, "engine", None)
    details = {"query": entry.query, "engine": engine}
    if recovery:
        details["recovery"] = recovery
    return TimelineEvent(
        timestamp_utc=entry.timestamp,
        event_type=f"{browser}_search" + ("_recovered" if recovery else ""),
        browser=browser,
        source_file=entry.source_file,
        source_sha256=entry.sha256,
        summary=(f"[{recovery}] " if recovery else "")
                + f'Search: "{entry.query}"' + (f" [{engine}]" if engine else ""),
        details=details,
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
            "last_access": _iso(entry.last_access),
            "expires": _iso(entry.expires),
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
            "last_used": _iso(entry.last_used),
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
        # Dowód pochodzi od podejrzanego. Zła wartość w jednym artefakcie
        # nie może zatrzymać pozostałych, stąd szerokie Exception.
        except Exception as e:
            print(f"[!] Skipped {func_name} ({browser}): {e}", file=sys.stderr)
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
            *_visit_recovered). A deleted visit to a search URL also gives
            a *_search_recovered event. No-op for profiles without a -wal file.
    """
    if chrome_profile is None and firefox_profile is None:
        raise ValueError("at least one of chrome_profile / firefox_profile required")

    events: list[TimelineEvent] = []

    for module, engine, profile, browser in (
        (chrome, "chromium", chrome_profile, chrome_browser_name),
        (firefox, "gecko", firefox_profile, firefox_browser_name),
    ):
        if profile is None:
            continue
        visits = module.extract_history(profile)
        events.extend(_visit_to_event(e, browser) for e in visits)
        events.extend(_download_to_event(e, browser)
                      for e in module.extract_downloads(profile))
        events.extend(_search_to_event(e, browser)
                      for e in searches_from_visits(visits))
        _extend_optional(events, module, engine, profile, browser)
        if wal_recover:
            recovered = wal.recover_history(profile, engine)
            events.extend(_recovered_to_event(e, browser) for e in recovered)
            events.extend(_search_to_event(e, browser, recovery="DELETED_PENDING")
                          for e in searches_from_visits(recovered))

    events.sort(key=lambda ev: (ev.timestamp_utc is None, ev.timestamp_utc))
    return events


def collect_source_files(events: list[TimelineEvent]) -> dict[str, str]:
    """Unique source files of `events` as {path: sha256}, for chain of custody.

    Insertion order is preserved, so the output is deterministic.

    A SQLite '-wal' file next to a source database is listed too: open_db
    replays it, so its content shapes the extracted records. Its hash is
    calculated here, after parsing, not before.
    """
    files: dict[str, str] = {}
    for e in events:
        if e.source_file in files:
            continue
        files[e.source_file] = e.source_sha256
        wal_file = Path(e.source_file + "-wal")
        if wal_file.is_file():
            files[str(wal_file)] = sha256_file(wal_file)
    return files


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