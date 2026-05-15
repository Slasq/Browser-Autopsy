import json
import shutil
from pathlib import Path
from urllib.parse import unquote, urlparse

from extractors.base import (
    firefox_timestamp_to_utc,
    open_db,
    sha256_file,
    VisitEntry,
    DownloadEntry,
)


# Firefox History

def extract_history(profile_path: Path) -> list[VisitEntry]:
    """
    Parse Firefox browsing history from the 'places.sqlite' database.

    Joins moz_historyvisits -> moz_places to get per-visit timestamps.
    One URL can appear multiple times - each visit is a separate VisitEntry.

    Args:
        profile_path: Path to Firefox profile directory (contains 'places.sqlite').

    Returns:
        List of VisitEntry, sorted by timestamp ascending (None-timestamp last).

    Raises:
        FileNotFoundError: If 'places.sqlite' does not exist in profile_path.
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
                p.url,
                p.title,
                p.visit_count,
                v.visit_date,
                v.visit_type
            FROM moz_historyvisits v
            JOIN moz_places p ON v.place_id = p.id
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


# firefox Downloads

# Firefox download states - nsIDownloadManager constants.
# UWAGA DANE MOGĄ SIĘ RÓŻNNIĆ NA RÓŻNYCH WERSJACH FIRFOXA
DOWNLOAD_STATE = {
    0: "DOWNLOADING",
    1: "FINISHED",
    2: "FAILED",
    3: "CANCELLED",
    4: "PAUSED",
    5: "QUEUED",
    6: "BLOCKED_PARENTAL",
    7: "SCANNING",
    8: "DIRTY",
    9: "BLOCKED_POLICY",
}


def _fileuri_to_path(uri: str) -> str:
    """Convert a file:// URI to a local filesystem path."""
    if not uri:
        return ""
    parsed = urlparse(uri)
    path = unquote(parsed.path)
    # Windows: urlparse zostawia wiodący '/' przed literą dysku (/C:/...)
    if len(path) > 2 and path[0] == "/" and path[2] == ":":
        path = path[1:]
    return path


def extract_downloads(profile_path: Path) -> list[DownloadEntry]:
    """
    Parse Firefox downloads from the 'places.sqlite' database.

    Firefox (26+) stores downloads as annotations, not in a dedicated table.
    Each download is a moz_places row carrying two annotations:
      - downloads/destinationFileURI : local save path (as file:// URI)
      - downloads/metaData           : JSON blob (state, endTime, fileSize...)
    Annotations are grouped per place_id.

    Args:
        profile_path: Path to Firefox profile directory (contains 'places.sqlite').

    Returns:
        List of DownloadEntry, sorted by timestamp ascending (None-timestamp last).

    Raises:
        FileNotFoundError: If 'places.sqlite' does not exist in profile_path.
    """
    db_path = profile_path / "places.sqlite"
    checksum = sha256_file(db_path)
    print(f"[*] Plik: places.sqlite\t SHA256: {checksum}")

    conn, tmp_dir = open_db(db_path)
    grouped: dict[int, dict] = {}

    try:
        cursor = conn.execute(
            """
            SELECT
                p.id   AS place_id,
                p.url  AS url,
                a.name AS anno_name,
                n.content   AS anno_content,
                n.dateAdded AS date_added
            FROM moz_annos n
            JOIN moz_anno_attributes a ON n.anno_attribute_id = a.id
            JOIN moz_places p ON n.place_id = p.id
            WHERE a.name IN ('downloads/destinationFileURI', 'downloads/metaData')
            """
        )
        # Jeden place_id niesie dwie osobne annotacje (URI + metaData)
        # sklejamy je w jeden rekend.
        for row in cursor:
            g = grouped.setdefault(
                row["place_id"],
                {"url": row["url"], "fileuri": None, "metadata": None, "date_added": None},
            )
            if row["anno_name"] == "downloads/destinationFileURI":
                g["fileuri"] = row["anno_content"]
            elif row["anno_name"] == "downloads/metaData":
                g["metadata"] = row["anno_content"]
                g["date_added"] = row["date_added"]
    finally:
        conn.close()
        shutil.rmtree(tmp_dir)

    entries: list[DownloadEntry] = []

    for place_id, g in grouped.items():
        # metaData to JSON może być pusty albo uszkodzony.
        meta: dict = {}
        if g["metadata"]:
            try:
                meta = json.loads(g["metadata"])
            except (ValueError, TypeError):
                meta = {}

        # endTime w metaData jest w MILISEKUNDACH (JS timestamp),
        # a firefox_timestamp_to_utc oczekuje mikrosekund dlatego *1000.
        end_ms = meta.get("endTime")
        end_timestamp = firefox_timestamp_to_utc(end_ms * 1000) if end_ms else None

        # startTime nie zawsze jest w metaData fallback na dateAdded
        # moz_annos.dateAdded jest w mikrosekundach PRTime.
        start_ms = meta.get("startTime")
        if start_ms:
            timestamp = firefox_timestamp_to_utc(start_ms * 1000)
        elif g["date_added"]:
            timestamp = firefox_timestamp_to_utc(g["date_added"])
        else:
            timestamp = None

        target_path = _fileuri_to_path(g["fileuri"])

        fs = meta.get("fileSize")
        file_size = fs if fs is not None else -1

        entries.append(
            DownloadEntry(
                timestamp=timestamp,
                end_timestamp=end_timestamp,
                url=g["url"] or "",
                target_path=target_path,
                filename=Path(target_path).name if target_path else "",
                file_size=file_size,
                state=DOWNLOAD_STATE.get(meta.get("state"), "UNKNOWN"),
                danger_type=0,  # pole Chrome-specific bo firefox nie ma odpowiednika
                source_file=str(db_path),
                sha256=checksum,
            )
        )

    entries.sort(key=lambda e: (e.timestamp is None, e.timestamp))

    print(f"[*] Znaleziono {len(entries)} pobranych plików")
    return entries

# Firefox URLs
def extract_searches(profile_path: Path) -> list[SearchEntry]:
    """
    Extract search queries from Firefox browsing history by parsing URLs.

    Scans all visited URLs from moz_historyvisits + moz_places and tries to
    detect known search engine patterns. Each visit that matches produces a
    separate SearchEntry — repeated searches appear multiple times.

    Args:
        profile_path: Path to Firefox profile directory (contains 'places.sqlite').

    Returns:
        List of SearchEntry, sorted by timestamp ascending (None-timestamp last).

    Raises:
        FileNotFoundError: If 'places.sqlite' does not exist in profile_path.
    """
    db_path = profile_path / "places.sqlite"
    checksum = sha256_file(db_path)
    print(f"[*] Plik: places.sqlite\t SHA256: {checksum}")

    conn, tmp_dir = open_db(db_path)
    entries: list[SearchEntry] = []

    try:
        cursor = conn.execute(
            """
            SELECT p.url, v.visit_date
            FROM moz_historyvisits v
            JOIN moz_places p ON v.place_id = p.id
            """
        )
        for row in cursor:
            result = _extract_query(row["url"])
            if result is None:
                continue
            engine, query = result
            entries.append(
                SearchEntry(
                    timestamp=firefox_timestamp_to_utc(row["visit_date"]),
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