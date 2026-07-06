"""
wal.py — recover history records hidden by SQLite Write-Ahead Log state.

A browser DB in WAL mode is really two files: the main image (state as of the
last checkpoint) and the -wal file (committed changes not yet merged back).
Copied artifacts freeze that split, which lets us surface two things a plain
`SELECT` on the replayed database would hide:

  DELETED_PENDING  — row exists in the main image but the WAL deletes it.
                     The user deleted history AFTER the last checkpoint; the
                     record is still recoverable from the main image.
  WAL_ONLY         — row exists only in the WAL (not yet checkpointed).
                     Not hidden data per se, but proves the main image alone
                     is incomplete — worth flagging in a report.

This is a state diff of two valid database views — not a byte-level carver.
Records whose pages were already checkpointed AND vacuumed are gone and stay
gone; recovering those would need freelist/page carving (poza zakresem).
"""
from __future__ import annotations

import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from extractors.base import (
    CorruptedDatabaseError,
    chrome_timestamp_to_utc,
    firefox_timestamp_to_utc,
    sha256_file,
)

# (history db filename, row query, timestamp converter) per engine
_ENGINES = {
    "chromium": {
        "db_name": "History",
        "query": """
            SELECT u.url AS url, u.title AS title, v.visit_time AS ts
            FROM visits v JOIN urls u ON v.url = u.id
        """,
        "to_utc": chrome_timestamp_to_utc,
    },
    "gecko": {
        "db_name": "places.sqlite",
        "query": """
            SELECT p.url AS url, p.title AS title, v.visit_date AS ts
            FROM moz_historyvisits v JOIN moz_places p ON v.place_id = p.id
        """,
        "to_utc": firefox_timestamp_to_utc,
    },
}


@dataclass
class RecoveredEntry:
    """A history record recovered from WAL/main-image divergence."""
    timestamp: datetime | None
    url: str
    title: str
    recovery: str          # DELETED_PENDING | WAL_ONLY
    source_file: str
    sha256: str


def _read_rows(db_copy: Path, query: str) -> set[tuple]:
    """Read (url, ts, title) rows from a temp copy of a history database.

    Plain read-write connect — the copy is disposable, and a read-only URI
    connection can fail on WAL recovery (SQLITE_READONLY_RECOVERY).
    """
    conn = sqlite3.connect(db_copy)
    conn.row_factory = sqlite3.Row
    try:
        return {
            (row["url"], row["ts"], row["title"] or "")
            for row in conn.execute(query)
        }
    except sqlite3.DatabaseError as exc:
        raise CorruptedDatabaseError(
            f"Not a valid SQLite database: {db_copy} ({exc})"
        ) from exc
    finally:
        conn.close()


def recover_history(profile_path: Path, engine: str) -> list[RecoveredEntry]:
    """Diff the main database image against its WAL-replayed state.

    Args:
        profile_path: Browser profile directory.
        engine: "chromium" or "gecko".

    Returns:
        List of RecoveredEntry sorted by timestamp (None last). Empty when
        the profile has no -wal file (nothing to diff) or no history db.

    Raises:
        ValueError: On an unknown engine name.
        CorruptedDatabaseError: If the history database cannot be read.
    """
    spec = _ENGINES.get(engine)
    if spec is None:
        raise ValueError(f"unknown engine: {engine!r} (chromium/gecko)")

    db_path = profile_path / spec["db_name"]
    wal_path = Path(str(db_path) + "-wal")
    if not db_path.exists() or not wal_path.exists():
        return []

    checksum = sha256_file(db_path)
    print(f"[*] WAL recovery: {db_path.name} (+{wal_path.name})")

    tmp_dir = Path(tempfile.mkdtemp(prefix="bft_wal_"))
    try:
        # Replayed view: main image + WAL (sqlite merges on open).
        replayed_db = tmp_dir / "replayed.db"
        shutil.copy2(db_path, replayed_db)
        shutil.copy2(wal_path, Path(str(replayed_db) + "-wal"))
        shm_path = Path(str(db_path) + "-shm")
        if shm_path.exists():
            shutil.copy2(shm_path, Path(str(replayed_db) + "-shm"))

        # Main-image view: db file alone — state as of the last checkpoint.
        main_db = tmp_dir / "main_only.db"
        shutil.copy2(db_path, main_db)

        replayed_rows = _read_rows(replayed_db, spec["query"])
        main_rows = _read_rows(main_db, spec["query"])
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    to_utc = spec["to_utc"]
    entries = [
        RecoveredEntry(
            timestamp=to_utc(ts or 0),
            url=url,
            title=title,
            recovery="DELETED_PENDING",
            source_file=str(db_path),
            sha256=checksum,
        )
        for (url, ts, title) in main_rows - replayed_rows
    ]
    entries += [
        RecoveredEntry(
            timestamp=to_utc(ts or 0),
            url=url,
            title=title,
            recovery="WAL_ONLY",
            source_file=str(db_path),
            sha256=checksum,
        )
        for (url, ts, title) in replayed_rows - main_rows
    ]

    entries.sort(key=lambda e: (e.timestamp is None, e.timestamp))

    deleted = sum(1 for e in entries if e.recovery == "DELETED_PENDING")
    print(f"[*] Odzyskano {deleted} usuniętych i {len(entries) - deleted} "
          f"niezcheckpointowanych rekordów z WAL")
    return entries
