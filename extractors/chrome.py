import json
import os
import platform
import shutil
from pathlib import Path

from extractors.base import (
    basename,
    chrome_timestamp_to_utc,
    open_db,
    sha256_file,
    unix_seconds_to_utc,
    ArtifactNotFoundError,
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

# Chromium family — profile path detection

CHROMIUM_BROWSERS: tuple[str, ...] = (
    "chrome", "edge", "brave", "opera", "vivaldi", "chromium", "yandex",
)


def _env_dir(var: str, default: Path) -> Path:
    # Path("") is truthy (== Path(".")), so a plain `or` fallback never fires —
    # check the env var itself before building a Path from it.
    value = os.environ.get(var)
    return Path(value).expanduser() if value else default


def _chromium_paths_windows() -> dict[str, Path]:
    local = _env_dir("LOCALAPPDATA", Path.home() / "AppData" / "Local")
    roaming = _env_dir("APPDATA", Path.home() / "AppData" / "Roaming")
    return {
        "chrome":   local / "Google" / "Chrome" / "User Data" / "Default",
        "edge":     local / "Microsoft" / "Edge" / "User Data" / "Default",
        "brave":    local / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default",
        "opera":    roaming / "Opera Software" / "Opera Stable",
        "vivaldi":  local / "Vivaldi" / "User Data" / "Default",
        "chromium": local / "Chromium" / "User Data" / "Default",
        "yandex":   local / "Yandex" / "YandexBrowser" / "User Data" / "Default",
    }


def _chromium_paths_darwin() -> dict[str, Path]:
    app_support = Path.home() / "Library" / "Application Support"
    return {
        "chrome":   app_support / "Google" / "Chrome" / "Default",
        "edge":     app_support / "Microsoft Edge" / "Default",
        "brave":    app_support / "BraveSoftware" / "Brave-Browser" / "Default",
        "opera":    app_support / "com.operasoftware.Opera",
        "vivaldi":  app_support / "Vivaldi" / "Default",
        "chromium": app_support / "Chromium" / "Default",
        "yandex":   app_support / "Yandex" / "YandexBrowser" / "Default",
    }


def _chromium_paths_linux() -> dict[str, Path]:
    config = Path.home() / ".config"
    return {
        "chrome":   config / "google-chrome" / "Default",
        "edge":     config / "microsoft-edge" / "Default",
        "brave":    config / "BraveSoftware" / "Brave-Browser" / "Default",
        "opera":    config / "opera",
        "vivaldi":  config / "vivaldi" / "Default",
        "chromium": config / "chromium" / "Default",
        "yandex":   config / "yandex-browser" / "Default",
    }


_PLATFORM_RESOLVERS = {
    "Windows": _chromium_paths_windows,
    "Darwin":  _chromium_paths_darwin,
    "Linux":   _chromium_paths_linux,
}


def get_default_profile_path(browser: str, system: str | None = None) -> Path | None:
    """Return the default profile directory for a Chromium-family browser on the current OS.

    Args:
        browser: One of CHROMIUM_BROWSERS (case-insensitive).
        system: Override platform.system() — useful in tests.

    Returns:
        Resolved Path, or None if browser or OS is unknown.
    """
    resolver = _PLATFORM_RESOLVERS.get(system or platform.system())
    if resolver is None:
        return None
    return resolver().get(browser.lower())


def detect_chromium_profiles(system: str | None = None) -> dict[str, Path]:
    """Find Chromium-family browsers installed on this machine.

    Checks each browser's default profile directory. Returns only those whose
    profile directory actually exists on disk.

    Args:
        system: Override platform.system() — useful in tests.

    Returns:
        {browser_name: profile_path} for every browser found.
    """
    resolver = _PLATFORM_RESOLVERS.get(system or platform.system())
    if resolver is None:
        return {}
    return {name: path for name, path in resolver().items() if path.exists()}


# Chrome download states
DOWNLOAD_STATE = {
    0: "IN_PROGRESS",
    1: "COMPLETE",
    2: "CANCELLED",
    3: "INTERRUPTED",
    4: "INTERRUPTED",  # alias
}


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
                    filename=basename(target),
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


# Cookies
def _cookies_db_path(profile_path: Path) -> Path:
    """Newer Chromium keeps cookies in Network/Cookies; older at profile root.

    Returns whichever exists, preferring the newer location. When neither
    exists, returns the newer path so the caller's error names the location
    current Chromium actually uses.
    """
    network = profile_path / "Network" / "Cookies"
    legacy = profile_path / "Cookies"
    if network.exists():
        return network
    if legacy.exists():
        return legacy
    return network


def extract_cookies(profile_path: Path) -> list[CookieEntry]:
    """
    Parse cookies from the 'Cookies' SQLite database (metadata only).

    Values are NOT extracted — Chromium encrypts them with the OS keystore
    (DPAPI / Keychain), which is unavailable when analysing copied artifacts.

    Args:
        profile_path: Path to Chromium profile directory
            (contains 'Network/Cookies' or legacy 'Cookies').

    Returns:
        List of CookieEntry, sorted by creation time ascending (None last).

    Raises:
        FileNotFoundError: If no cookies database exists in profile_path.
    """
    db_path = _cookies_db_path(profile_path)
    checksum = sha256_file(db_path)
    print(f"[*] Plik: {db_path.name}\t SHA256: {checksum}")

    conn, tmp_dir = open_db(db_path)
    entries: list[CookieEntry] = []

    try:
        cursor = conn.execute(
            """
            SELECT
                creation_utc,
                last_access_utc,
                expires_utc,
                host_key,
                name,
                path,
                is_secure,
                is_httponly
            FROM cookies
            """
        )
        for row in cursor:
            entries.append(
                CookieEntry(
                    timestamp=chrome_timestamp_to_utc(row["creation_utc"]),
                    last_access=chrome_timestamp_to_utc(row["last_access_utc"]),
                    expires=chrome_timestamp_to_utc(row["expires_utc"]),
                    host=row["host_key"],
                    name=row["name"],
                    path=row["path"],
                    is_secure=bool(row["is_secure"]),
                    is_httponly=bool(row["is_httponly"]),
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
def _walk_bookmark_nodes(node: dict, folder: str, out: list, db_path: Path,
                         checksum: str) -> None:
    """Depth-first walk over the Bookmarks JSON tree collecting url nodes."""
    node_type = node.get("type")
    if node_type == "url":
        # date_added is a WebKit-epoch µs value stored as a STRING
        try:
            date_added = int(node.get("date_added", 0))
        except (TypeError, ValueError):
            date_added = 0
        out.append(
            BookmarkEntry(
                timestamp=chrome_timestamp_to_utc(date_added),
                url=node.get("url", ""),
                title=node.get("name", ""),
                folder=folder,
                source_file=str(db_path),
                sha256=checksum,
            )
        )
    elif node_type == "folder":
        child_folder = node.get("name", "") or folder
        for child in node.get("children", []):
            _walk_bookmark_nodes(child, child_folder, out, db_path, checksum)


def extract_bookmarks(profile_path: Path) -> list[BookmarkEntry]:
    """
    Parse bookmarks from the 'Bookmarks' JSON file.

    Walks all roots (bookmark_bar, other, synced) recursively; each url node
    becomes one BookmarkEntry with its direct parent folder name.

    Args:
        profile_path: Path to Chromium profile directory (contains 'Bookmarks').

    Returns:
        List of BookmarkEntry, sorted by date-added ascending (None last).

    Raises:
        FileNotFoundError: If 'Bookmarks' does not exist in profile_path.
        MalformedArtifactError: If the file exists but is not valid JSON.
    """
    db_path = profile_path / "Bookmarks"
    checksum = sha256_file(db_path)
    print(f"[*] Plik: Bookmarks\t SHA256: {checksum}")

    try:
        data = json.loads(db_path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise MalformedArtifactError(
            f"Not a valid Bookmarks JSON file: {db_path} ({exc})"
        ) from exc

    entries: list[BookmarkEntry] = []
    roots = data.get("roots", {}) if isinstance(data, dict) else {}
    for root in roots.values():
        if isinstance(root, dict):
            _walk_bookmark_nodes(root, root.get("name", ""), entries,
                                 db_path, checksum)

    entries.sort(key=lambda e: (e.timestamp is None, e.timestamp))

    print(f"[*] Znaleziono {len(entries)} zakładek")
    return entries


# Autofill
def extract_autofill(profile_path: Path) -> list[AutofillEntry]:
    """
    Parse saved form-field history from the 'Web Data' SQLite database.

    UWAGA: the autofill table stores Unix SECONDS (date_created,
    date_last_used) — not the WebKit µs used everywhere else in Chromium.

    Args:
        profile_path: Path to Chromium profile directory (contains 'Web Data').

    Returns:
        List of AutofillEntry, sorted by first-used ascending (None last).

    Raises:
        FileNotFoundError: If 'Web Data' does not exist in profile_path.
    """
    db_path = profile_path / "Web Data"
    checksum = sha256_file(db_path)
    print(f"[*] Plik: Web Data\t SHA256: {checksum}")

    conn, tmp_dir = open_db(db_path)
    entries: list[AutofillEntry] = []

    try:
        cursor = conn.execute(
            """
            SELECT name, value, count, date_created, date_last_used
            FROM autofill
            """
        )
        for row in cursor:
            entries.append(
                AutofillEntry(
                    timestamp=unix_seconds_to_utc(row["date_created"] or 0),
                    last_used=unix_seconds_to_utc(row["date_last_used"] or 0),
                    field_name=row["name"],
                    value=row["value"],
                    times_used=row["count"] or 0,
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
def _extension_install_time(settings: dict):
    """Best-effort install timestamp — the key changed across Chromium versions.

    Both install_time (old) and first_install_time (new) are WebKit-epoch µs
    stored as strings.
    """
    for key in ("first_install_time", "install_time"):
        raw = settings.get(key)
        if raw:
            try:
                return chrome_timestamp_to_utc(int(raw))
            except (TypeError, ValueError):
                continue
    return None


def extract_extensions(profile_path: Path) -> list[ExtensionEntry]:
    """
    Parse installed-extension metadata from the 'Preferences' JSON file.

    Reads extensions.settings from 'Preferences'; on Windows Chromium moves
    that section to 'Secure Preferences', so both files are consulted
    (whichever exist). Component/built-in entries without a manifest are
    skipped — they are not user-installed extensions.

    Args:
        profile_path: Path to Chromium profile directory.

    Returns:
        List of ExtensionEntry, sorted by install time ascending (None last).

    Raises:
        FileNotFoundError: If neither 'Preferences' nor 'Secure Preferences'
            exists in profile_path.
        MalformedArtifactError: If a preferences file is not valid JSON.
    """
    candidates = [profile_path / "Preferences",
                  profile_path / "Secure Preferences"]
    present = [p for p in candidates if p.exists()]
    if not present:
        raise ArtifactNotFoundError(
            f"Artifact not found: {candidates[0]} (ani 'Secure Preferences')"
        )

    entries: list[ExtensionEntry] = []

    for db_path in present:
        checksum = sha256_file(db_path)
        print(f"[*] Plik: {db_path.name}\t SHA256: {checksum}")

        try:
            data = json.loads(db_path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise MalformedArtifactError(
                f"Not a valid Preferences JSON file: {db_path} ({exc})"
            ) from exc

        settings = (
            data.get("extensions", {}).get("settings", {})
            if isinstance(data, dict) else {}
        )
        for ext_id, ext in settings.items():
            if not isinstance(ext, dict):
                continue
            manifest = ext.get("manifest")
            if not isinstance(manifest, dict):
                continue  # component / corrupted entry
            entries.append(
                ExtensionEntry(
                    timestamp=_extension_install_time(ext),
                    ext_id=ext_id,
                    name=manifest.get("name", ""),
                    version=manifest.get("version", ""),
                    # state: 1 = enabled, 0 = disabled (older Chromium);
                    # newer builds drop 'state' — treat missing as enabled
                    enabled=bool(ext.get("state", 1)),
                    source_file=str(db_path),
                    sha256=checksum,
                )
            )

    entries.sort(key=lambda e: (e.timestamp is None, e.timestamp))

    print(f"[*] Znaleziono {len(entries)} rozszerzeń")
    return entries