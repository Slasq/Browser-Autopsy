import json
import os
import platform
import shutil
from pathlib import Path
from urllib.parse import unquote, urlparse

from extractors.base import (
    basename,
    firefox_timestamp_to_utc,
    open_db,
    sha256_file,
    unix_seconds_to_utc,
    MalformedArtifactError,
    VisitEntry,
    DownloadEntry,
    SearchEntry,
    CookieEntry,
    BookmarkEntry,
    AutofillEntry,
    ExtensionEntry,
    _extract_query,
)

# Gecko family — profile path detection
#
# Unlike Chromium, Gecko does not keep a fixed "Default" profile directory:
# profiles live under a per-browser root as randomly named folders
# ("Profiles/ab12cd34.default-release"). Detection therefore means: find the
# root, then scan it for directories that actually contain places.sqlite.

GECKO_BROWSERS: tuple[str, ...] = (
    "firefox", "tor", "librewolf", "waterfox",
)


def _env_dir(var: str, default: Path) -> Path:
    # Path("") is truthy (== Path(".")), so a plain `or` fallback never fires —
    # check the env var itself before building a Path from it.
    value = os.environ.get(var)
    return Path(value).expanduser() if value else default


def _gecko_roots_windows() -> dict[str, list[Path]]:
    roaming = _env_dir("APPDATA", Path.home() / "AppData" / "Roaming")
    home = Path.home()
    return {
        "firefox":   [roaming / "Mozilla" / "Firefox" / "Profiles"],
        "librewolf": [roaming / "librewolf" / "Profiles"],
        "waterfox":  [roaming / "Waterfox" / "Profiles"],
        # Tor Browser is portable — the installer defaults to the Desktop.
        "tor": [
            home / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser"
                 / "Data" / "Browser",
            home / "Tor Browser" / "Browser" / "TorBrowser" / "Data" / "Browser",
        ],
    }


def _gecko_roots_darwin() -> dict[str, list[Path]]:
    app_support = Path.home() / "Library" / "Application Support"
    return {
        "firefox":   [app_support / "Firefox" / "Profiles"],
        "librewolf": [app_support / "LibreWolf" / "Profiles"],
        "waterfox":  [app_support / "Waterfox" / "Profiles"],
        "tor":       [app_support / "TorBrowser-Data" / "Browser"],
    }


def _gecko_roots_linux() -> dict[str, list[Path]]:
    home = Path.home()
    return {
        "firefox":   [home / ".mozilla" / "firefox",
                      home / "snap" / "firefox" / "common" / ".mozilla" / "firefox"],
        "librewolf": [home / ".librewolf"],
        "waterfox":  [home / ".waterfox"],
        # Extracted tarball and torbrowser-launcher layouts.
        "tor": [
            home / "tor-browser" / "Browser" / "TorBrowser" / "Data" / "Browser",
            home / ".local" / "share" / "torbrowser" / "tbb" / "x86_64"
                 / "tor-browser" / "Browser" / "TorBrowser" / "Data" / "Browser",
        ],
    }


_GECKO_PLATFORM_RESOLVERS = {
    "Windows": _gecko_roots_windows,
    "Darwin":  _gecko_roots_darwin,
    "Linux":   _gecko_roots_linux,
}


def get_profile_roots(browser: str, system: str | None = None) -> list[Path]:
    """Return candidate profile-root directories for a Gecko-family browser.

    A "root" is where profile folders live (e.g. ~/.mozilla/firefox) — NOT the
    profile itself. Use detect_gecko_profiles() to find actual profiles.

    Args:
        browser: One of GECKO_BROWSERS (case-insensitive).
        system: Override platform.system() — useful in tests.

    Returns:
        List of candidate root Paths ([] if browser or OS is unknown).
    """
    resolver = _GECKO_PLATFORM_RESOLVERS.get(system or platform.system())
    if resolver is None:
        return []
    return resolver().get(browser.lower(), [])


def _profiles_under(root: Path) -> list[Path]:
    """Directories in/under `root` that contain places.sqlite.

    Checks the root itself (Tor's profile.default layout) and one level of
    subdirectories (Profiles/xxxx.default-release layout).
    """
    if not root.is_dir():
        return []
    found = []
    if (root / "places.sqlite").exists():
        found.append(root)
    for child in root.iterdir():
        if child.is_dir() and (child / "places.sqlite").exists():
            found.append(child)
    return found


def detect_gecko_profiles(system: str | None = None) -> dict[str, Path]:
    """Find Gecko-family browser profiles present on this machine.

    Scans each browser's candidate roots for directories containing
    places.sqlite. When a browser has several profiles, the one with the most
    recently modified places.sqlite wins (= the actively used profile).

    Args:
        system: Override platform.system() — useful in tests.

    Returns:
        {browser_name: profile_path} for every browser found.
    """
    resolver = _GECKO_PLATFORM_RESOLVERS.get(system or platform.system())
    if resolver is None:
        return {}

    detected: dict[str, Path] = {}
    for name, roots in resolver().items():
        profiles = [p for root in roots for p in _profiles_under(root)]
        if profiles:
            detected[name] = max(
                profiles, key=lambda p: (p / "places.sqlite").stat().st_mtime
            )
    return detected


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
                filename=basename(target_path),
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


# Cookies
def extract_cookies(profile_path: Path) -> list[CookieEntry]:
    """
    Parse cookies from the 'cookies.sqlite' database.

    Timestamp units in moz_cookies are mixed (typowe dla Mozilli):
    creationTime / lastAccessed are µs since Unix epoch, expiry is SECONDS.

    Args:
        profile_path: Path to Firefox profile directory (contains 'cookies.sqlite').

    Returns:
        List of CookieEntry, sorted by creation time ascending (None last).

    Raises:
        FileNotFoundError: If 'cookies.sqlite' does not exist in profile_path.
    """
    db_path = profile_path / "cookies.sqlite"
    checksum = sha256_file(db_path)
    print(f"[*] Plik: cookies.sqlite\t SHA256: {checksum}")

    conn, tmp_dir = open_db(db_path)
    entries: list[CookieEntry] = []

    try:
        cursor = conn.execute(
            """
            SELECT
                creationTime,
                lastAccessed,
                expiry,
                host,
                name,
                path,
                isSecure,
                isHttpOnly
            FROM moz_cookies
            """
        )
        for row in cursor:
            entries.append(
                CookieEntry(
                    timestamp=firefox_timestamp_to_utc(row["creationTime"] or 0),
                    last_access=firefox_timestamp_to_utc(row["lastAccessed"] or 0),
                    expires=unix_seconds_to_utc(row["expiry"] or 0),
                    host=row["host"],
                    name=row["name"],
                    path=row["path"],
                    is_secure=bool(row["isSecure"]),
                    is_httponly=bool(row["isHttpOnly"]),
                    source_file=str(db_path),
                    sha256=checksum,
                )
            )
    finally:
        conn.close()
        shutil.rmtree(tmp_dir)

    entries.sort(key=lambda e: (e.timestamp is None, e.timestamp))

    print(f"[*] Znaleziono {len(entries)} cookies")
    return entries


# Bookmarks
def extract_bookmarks(profile_path: Path) -> list[BookmarkEntry]:
    """
    Parse bookmarks from the 'places.sqlite' database (moz_bookmarks).

    Only real bookmarks (type = 1) pointing at a moz_places URL are returned;
    folders and separators are skipped. The parent folder title comes from a
    self-join on moz_bookmarks.

    Args:
        profile_path: Path to Firefox profile directory (contains 'places.sqlite').

    Returns:
        List of BookmarkEntry, sorted by date-added ascending (None last).

    Raises:
        FileNotFoundError: If 'places.sqlite' does not exist in profile_path.
    """
    db_path = profile_path / "places.sqlite"
    checksum = sha256_file(db_path)
    print(f"[*] Plik: places.sqlite\t SHA256: {checksum}")

    conn, tmp_dir = open_db(db_path)
    entries: list[BookmarkEntry] = []

    try:
        cursor = conn.execute(
            """
            SELECT
                b.title       AS title,
                b.dateAdded   AS date_added,
                p.url         AS url,
                parent.title  AS folder
            FROM moz_bookmarks b
            JOIN moz_places p ON b.fk = p.id
            LEFT JOIN moz_bookmarks parent ON b.parent = parent.id
            WHERE b.type = 1
            """
        )
        for row in cursor:
            entries.append(
                BookmarkEntry(
                    timestamp=firefox_timestamp_to_utc(row["date_added"] or 0),
                    url=row["url"],
                    title=row["title"] or "",
                    folder=row["folder"] or "",
                    source_file=str(db_path),
                    sha256=checksum,
                )
            )
    finally:
        conn.close()
        shutil.rmtree(tmp_dir)

    entries.sort(key=lambda e: (e.timestamp is None, e.timestamp))

    print(f"[*] Znaleziono {len(entries)} zakładek")
    return entries


# Autofill / form history
def extract_autofill(profile_path: Path) -> list[AutofillEntry]:
    """
    Parse saved form-field history from the 'formhistory.sqlite' database.

    Args:
        profile_path: Path to Firefox profile directory
            (contains 'formhistory.sqlite').

    Returns:
        List of AutofillEntry, sorted by first-used ascending (None last).

    Raises:
        FileNotFoundError: If 'formhistory.sqlite' does not exist in profile_path.
    """
    db_path = profile_path / "formhistory.sqlite"
    checksum = sha256_file(db_path)
    print(f"[*] Plik: formhistory.sqlite\t SHA256: {checksum}")

    conn, tmp_dir = open_db(db_path)
    entries: list[AutofillEntry] = []

    try:
        cursor = conn.execute(
            """
            SELECT fieldname, value, timesUsed, firstUsed, lastUsed
            FROM moz_formhistory
            """
        )
        for row in cursor:
            entries.append(
                AutofillEntry(
                    timestamp=firefox_timestamp_to_utc(row["firstUsed"] or 0),
                    last_used=firefox_timestamp_to_utc(row["lastUsed"] or 0),
                    field_name=row["fieldname"],
                    value=row["value"],
                    times_used=row["timesUsed"] or 0,
                    source_file=str(db_path),
                    sha256=checksum,
                )
            )
    finally:
        conn.close()
        shutil.rmtree(tmp_dir)

    entries.sort(key=lambda e: (e.timestamp is None, e.timestamp))

    print(f"[*] Znaleziono {len(entries)} wpisów autofill")
    return entries


# Extensions
def extract_extensions(profile_path: Path) -> list[ExtensionEntry]:
    """
    Parse installed-addon metadata from the 'extensions.json' file.

    Only type == "extension" addons are returned (themes, dictionaries and
    langpacks are skipped). installDate is in MILLISECONDS (JS timestamp).

    Args:
        profile_path: Path to Firefox profile directory (contains 'extensions.json').

    Returns:
        List of ExtensionEntry, sorted by install time ascending (None last).

    Raises:
        FileNotFoundError: If 'extensions.json' does not exist in profile_path.
        MalformedArtifactError: If the file exists but is not valid JSON.
    """
    db_path = profile_path / "extensions.json"
    checksum = sha256_file(db_path)
    print(f"[*] Plik: extensions.json\t SHA256: {checksum}")

    try:
        data = json.loads(db_path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise MalformedArtifactError(
            f"Not a valid extensions.json file: {db_path} ({exc})"
        ) from exc

    entries: list[ExtensionEntry] = []
    addons = data.get("addons", []) if isinstance(data, dict) else []
    for addon in addons:
        if not isinstance(addon, dict) or addon.get("type") != "extension":
            continue
        install_ms = addon.get("installDate") or 0
        locale = addon.get("defaultLocale") or {}
        entries.append(
            ExtensionEntry(
                timestamp=firefox_timestamp_to_utc(int(install_ms) * 1000),
                ext_id=addon.get("id", ""),
                name=locale.get("name", "") if isinstance(locale, dict) else "",
                version=addon.get("version", ""),
                enabled=bool(addon.get("active", False)),
                source_file=str(db_path),
                sha256=checksum,
            )
        )

    entries.sort(key=lambda e: (e.timestamp is None, e.timestamp))

    print(f"[*] Znaleziono {len(entries)} rozszerzeń")
    return entries