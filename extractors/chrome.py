import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from extractors.base import chrome_timestamp_to_utc, open_db, sha256_file


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

    # Sort: valid timestamps first (ascending), None-timestamp entries at the end
    entries.sort(key=lambda e: (e.timestamp is None, e.timestamp))

    print(f"[*] Znaleziono {len(entries)} wpisów historii")
    return entries