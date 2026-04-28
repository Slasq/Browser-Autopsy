import hashlib
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path


# Chrome: mikrosek od 1601-01-01 → różnica do Unix epoch w mikrosekundach
_CHROME_EPOCH_DELTA = 11_644_473_600_000_000


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
    """Calculate SHA256 of a file. Used for chain of custody."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65_536), b""):
            h.update(chunk)
    return h.hexdigest()


def open_db(path: Path) -> tuple[sqlite3.Connection, Path]:
    """
    Open a SQLite database read-only by copying it to a temp file first.
    Returns (connection, temp_path) caller is responsible for cleanup.

    """
    if not path.exists():
        raise FileNotFoundError(f"Artifact not found: {path}")

    tmp_dir = Path(tempfile.mkdtemp(prefix="bft_"))
    tmp_db = tmp_dir / path.name
    shutil.copy2(path, tmp_db)

    for ext in (".wal", "-wal", ".shm", "-shm"):
        wal = path.with_suffix(ext) if ext.startswith(".") else Path(str(path) + ext)
        if wal.exists():
            shutil.copy2(wal, tmp_dir / wal.name)

    conn = sqlite3.connect(f"file:{tmp_db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn, tmp_dir