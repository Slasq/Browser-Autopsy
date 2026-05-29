import hashlib
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse


# Errors
class ArtifactError(Exception):
    """Base class for failures while accessing a browser artifact."""


class ArtifactNotFoundError(ArtifactError, FileNotFoundError):
    """The artifact file does not exist on disk.

    Subclasses FileNotFoundError so existing `except FileNotFoundError`
    callers keep working, while new code can catch the more specific type.
    """


class CorruptedDatabaseError(ArtifactError):
    """The artifact exists but is not a readable SQLite database.

    Covers both "this is not a database at all" (random bytes) and
    "database disk image is malformed" (truncated / partially overwritten
    file). NOT a FileNotFoundError — the file is present, just unusable.
    """


# Chrome: mikrosek od 1601-01-01 → różnica do Unix epoch w mikrosekundach
_CHROME_EPOCH_DELTA = 11_644_473_600_000_000

# Chrome modules
def chrome_timestamp_to_utc(microseconds: int) -> datetime:
    """Convert Chrome WebKit timestamp (µs since 1601-01-01) to UTC datetime."""
    if microseconds == 0:
        return None
    unix_us = microseconds - _CHROME_EPOCH_DELTA
    return datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc)


def firefox_timestamp_to_utc(microseconds: int) -> datetime:
    """Convert Firefox timestamp (µs since Unix epoch) to UTC datetime."""
    if microseconds == 0:
        return None
    return datetime.fromtimestamp(microseconds / 1_000_000, tz=timezone.utc)


def sha256_file(path: Path) -> str:
    """Calculate SHA256 of a file. Used for chain of custody.

    Raises ArtifactNotFoundError if `path` does not exist. (Extractors call
    sha256_file BEFORE open_db, so a missing artifact is first noticed here.)
    """
    if not path.exists():
        raise ArtifactNotFoundError(f"Artifact not found: {path}")

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65_536), b""):
            h.update(chunk)
    return h.hexdigest()


def open_db(path: Path) -> tuple[sqlite3.Connection, Path]:
    """
    Open a SQLite database read-only by copying it to a temp file first.
    Returns (connection, temp_path); caller is responsible for cleanup.

    The copy is validated with `PRAGMA quick_check` before being returned, so
    a corrupted artifact fails loudly here instead of blowing up mid-iteration
    inside an extractor's row loop.

    Raises:
        ArtifactNotFoundError: if `path` does not exist.
        CorruptedDatabaseError: if the file is not a valid SQLite database or
            its disk image is malformed.
    """
    if not path.exists():
        raise ArtifactNotFoundError(f"Artifact not found: {path}")

    tmp_dir = Path(tempfile.mkdtemp(prefix="bft_"))
    tmp_db = tmp_dir / path.name
    shutil.copy2(path, tmp_db)

    for ext in (".wal", "-wal", ".shm", "-shm"):
        wal = path.with_suffix(ext) if ext.startswith(".") else Path(str(path) + ext)
        if wal.exists():
            shutil.copy2(wal, tmp_dir / wal.name)

    conn = sqlite3.connect(f"file:{tmp_db}?mode=ro", uri=True)

    # Integrity gate quick_check wykrywa zarówno file is not a database jak i database disk image is malformed czego samo PRAGMA schema_version by nie złapało.
    try:
        check = [row[0] for row in conn.execute("PRAGMA quick_check").fetchall()]
    except sqlite3.DatabaseError as exc:
        conn.close()
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise CorruptedDatabaseError(
            f"Not a valid SQLite database: {path} ({exc})"
        ) from exc

    if check != ["ok"]:
        conn.close()
        shutil.rmtree(tmp_dir, ignore_errors=True)
        detail = "; ".join(check) if check else "unknown error"
        raise CorruptedDatabaseError(
            f"Corrupted SQLite database: {path} (quick_check: {detail})"
        )

    conn.row_factory = sqlite3.Row
    return conn, tmp_dir

# History
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