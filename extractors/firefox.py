import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from extractors.base import firefox_timestamp_to_utc, open_db, sha256_file


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

# Extractor for firefox history
def extract_history(profile_path: Path) -> list[VisitEntry]:
    """
    Parse Firefox browsing history from the 'places.sqlite' SQLite database.

    Joins visits → urls to get per-visit timestamps (not just last_visit_time).
    One URL can appear multiple times — each visit is a separate VisitEntry.

    Args:
        profile_path: Path to Firefox profile directory (contains 'places.sqlite' file).

    Returns:
        List of VisitEntry, sorted by timestamp ascending (None-timestamp visits last).

    Raises:
        FileNotFoundError: If 'places.sqlite' file does not exist in profile_path.
    """
    db_path = profile_path / "places.sqlite"
    checksum = sha256_file(db_path)
    print(f"[*] Plik: places.sqlite\t SHA256: {checksum}")

    conn, tmp_dir = open_db(db_path)
    entries: list[VisitEntry] = []

    try:
        cursor = conn.execute(
            """
            SELECT
                u.url,
                u.title,
                u.visit_count,
                v.visit_date,
                v.visit_type
            FROM moz_historyvisits v
            JOIN moz_places u ON v.place_id = u.id
            """
        )
        for row in cursor:
            entries.append(
                VisitEntry(
                    timestamp=firefox_timestamp_to_utc(row["visit_date"]),
                    url=row["url"],
                    title=row["title"] or "",
                    visit_count=row["visit_count"],
                    transition=row["visit_type"],
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