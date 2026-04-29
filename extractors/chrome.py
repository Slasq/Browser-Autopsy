import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from extractors.base import chrome_timestamp_to_utc, open_db, sha256_file

# (hostname_fragment, query_param) UWAGA: kolejność ma znaczenie
_SEARCH_ENGINES: list[tuple[str, str]] = [
    ("google.",        "q"),
    ("bing.com",       "q"),
    ("duckduckgo.com", "q"),
    ("search.yahoo.com", "p"),
    ("ecosia.org",     "q"),
    ("search.brave.com", "q"),
    ("startpage.com",  "q"),
    ("youtube.com",    "search_query"),
    ("yandex.",        "text"),
]


def _extract_query(url: str) -> tuple[str, str] | None:
    """
    Detect if a URL is a search and return (engine_name, query_string).
    Returns None if the URL is not a recognised search URL or query is empty.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        params = parse_qs(parsed.query)
        for fragment, param in _SEARCH_ENGINES:
            if fragment in host:
                values = params.get(param)
                if values and values[0].strip():
                    return (fragment.strip(".").strip("/"), values[0].strip())
    except Exception:
        pass
    return None

# Chrome download states
DOWNLOAD_STATE = {
    0: "IN_PROGRESS",
    1: "COMPLETE",
    2: "CANCELLED",
    3: "INTERRUPTED",
    4: "INTERRUPTED",  # alias
}


@dataclass
class VisitEntry:
    """Single browser visit event. Used by timeline.py (type: VISIT)."""
    timestamp: datetime | None
    url: str
    title: str
    visit_count: int
    transition: int          #np. LINK, TYPED, RELOAD
    source_file: str
    sha256: str


def extract_history(profile_path: Path) -> list[VisitEntry]:
    """
    Parse Chrome browsing history from the 'History' SQLite database.

    Joins visits → urls to get per-visit timestamps (not just last_visit_time).
    One URL can appear multiple times — each visit is a separate VisitEntry.

    Args:
        profile_path: Path to Chrome profile directory (contains 'History' file).

    Returns:
        List of VisitEntry, sorted by timestamp ascending (None-timestamp visits last).

    Raises:
        FileNotFoundError: If 'History' file does not exist in profile_path.
    """
    db_path = profile_path / "History"
    checksum = sha256_file(db_path)
    print(f"[*] Plik: History\t SHA256: {checksum}")

    conn, tmp_dir = open_db(db_path)
    entries: list[VisitEntry] = []

    try:
        cursor = conn.execute(
            """
            SELECT
                u.url,
                u.title,
                u.visit_count,
                v.visit_time,
                v.transition
            FROM visits v
            JOIN urls u ON v.url = u.id
            """
        )
        for row in cursor:
            entries.append(
                VisitEntry(
                    timestamp=chrome_timestamp_to_utc(row["visit_time"]),
                    url=row["url"],
                    title=row["title"] or "",
                    visit_count=row["visit_count"],
                    transition=row["transition"],
                    source_file=str(db_path),
                    sha256=checksum,
                )
            )
    finally:
        conn.close()
        shutil.rmtree(tmp_dir)

    # Sort: valid timestamps first (ascending)
    entries.sort(key=lambda e: (e.timestamp is None, e.timestamp))

    print(f"[*] Znaleziono {len(entries)} wpisów historii")
    return entries


# Downloads

@dataclass
class DownloadEntry:
    """Single download event. Used by timeline.py (type: DOWNLOAD)."""
    timestamp: datetime | None          # start time
    end_timestamp: datetime | None      # end time (None if incomplete)
    url: str                            # final URL (from downloads_url_chains)
    target_path: str                    # local save path
    filename: str                       # basename only, for quick anomaly checks
    file_size: int                      # bytes (-1 if unknown)
    state: str                          # COMPLETE / CANCELLED / INTERRUPTED / IN_PROGRESS
    danger_type: int                    # raw Chrome danger_type flag
    source_file: str
    sha256: str


def extract_downloads(profile_path: Path) -> list[DownloadEntry]:
    """
    Parse Chrome downloads from the 'History' SQLite database.

    Uses downloads + downloads_url_chains tables.
    downloads_url_chains can have multiple redirect hops — we take the final URL
    (highest chain_index) as the effective download source.

    Args:
        profile_path: Path to Chrome profile directory (contains 'History' file).

    Returns:
        List of DownloadEntry, sorted by timestamp ascending (None-timestamp last).

    Raises:
        FileNotFoundError: If 'History' file does not exist in profile_path.
    """
    db_path = profile_path / "History"
    checksum = sha256_file(db_path)
    # SHA256 already printed by extract_history if called together; print anyway
    # for standalone use
    print(f"[*] Plik: History\t SHA256: {checksum}")

    conn, tmp_dir = open_db(db_path)
    entries: list[DownloadEntry] = []

    try:
        cursor = conn.execute(
            """
            SELECT
                d.id,
                d.start_time,
                d.end_time,
                d.target_path,
                d.total_bytes,
                d.state,
                d.danger_type,
                duc.url AS final_url
            FROM downloads d
            LEFT JOIN downloads_url_chains duc
                ON duc.id = d.id
                AND duc.chain_index = (
                    SELECT MAX(chain_index)
                    FROM downloads_url_chains
                    WHERE id = d.id
                )
            """
        )
        for row in cursor:
            target = row["target_path"] or ""
            entries.append(
                DownloadEntry(
                    timestamp=chrome_timestamp_to_utc(row["start_time"]),
                    end_timestamp=chrome_timestamp_to_utc(row["end_time"] or 0),
                    url=row["final_url"] or "",
                    target_path=target,
                    filename=Path(target).name if target else "",
                    file_size=row["total_bytes"] if row["total_bytes"] is not None else -1,
                    state=DOWNLOAD_STATE.get(row["state"], "UNKNOWN"),
                    danger_type=row["danger_type"] or 0,
                    source_file=str(db_path),
                    sha256=checksum,
                )
            )
    finally:
        conn.close()
        shutil.rmtree(tmp_dir)

    entries.sort(key=lambda e: (e.timestamp is None, e.timestamp))

    print(f"[*] Znaleziono {len(entries)} pobranych plików")
    return entries


# Searches

@dataclass
class SearchEntry:
    """Single search event extracted from a URL. Used by timeline.py (type: SEARCH)."""
    timestamp: datetime | None
    engine: str       # e.g. "google", "bing", "duckduckgo"
    query: str        # decoded search phrase
    url: str          # original full URL
    source_file: str
    sha256: str


def extract_searches(profile_path: Path) -> list[SearchEntry]:
    """
    Extract search queries from Chrome browsing history by parsing URLs.

    Scans all visited URLs from the visits+urls tables and tries to detect
    known search engine patterns (Google, Bing, DuckDuckGo, Yahoo, YouTube,
    Ecosia, Brave, Startpage, Yandex). Each visit that matches produces a
    separate SearchEntry — repeated searches appear multiple times.

    Args:
        profile_path: Path to Chrome profile directory (contains 'History' file).

    Returns:
        List of SearchEntry, sorted by timestamp ascending (None-timestamp last).

    Raises:
        FileNotFoundError: If 'History' file does not exist in profile_path.
    """
    db_path = profile_path / "History"
    checksum = sha256_file(db_path)
    print(f"[*] Plik: History\t SHA256: {checksum}")

    conn, tmp_dir = open_db(db_path)
    entries: list[SearchEntry] = []

    try:
        cursor = conn.execute(
            """
            SELECT u.url, v.visit_time
            FROM visits v
            JOIN urls u ON v.url = u.id
            """
        )
        for row in cursor:
            result = _extract_query(row["url"])
            if result is None:
                continue
            engine, query = result
            entries.append(
                SearchEntry(
                    timestamp=chrome_timestamp_to_utc(row["visit_time"]),
                    engine=engine,
                    query=query,
                    url=row["url"],
                    source_file=str(db_path),
                    sha256=checksum,
                )
            )
    finally:
        conn.close()
        shutil.rmtree(tmp_dir)

    entries.sort(key=lambda e: (e.timestamp is None, e.timestamp))

    print(f"[*] Znaleziono {len(entries)} wyszukiwań")
    return entries