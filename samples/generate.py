"""
Generate anonymized sample browser artifacts for Browser-Autopsy demos.

Scenario: INC-2026-03-14 — suspicious insider activity.
An employee starts the day normally, then begins researching offensive tools,
visits suspicious domains, downloads malicious-looking files — and at the end
of the day deletes the most incriminating history entry (recoverable from the
frozen WAL with --wal-recover).

Run from repo root:
    python samples/generate.py

Outputs:
    samples/chrome/History (+History-wal), Cookies, Bookmarks, Web Data,
                   Preferences
    samples/firefox/places.sqlite, cookies.sqlite, formhistory.sqlite,
                    extensions.json
"""
import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

# Timestamp helpers
_CHROME_EPOCH_OFFSET = 11_644_473_600  # seconds between 1601-01-01 and 1970-01-01


def _chrome_ts(unix: int) -> int:
    """Unix timestamp (seconds) → Chrome microseconds since 1601-01-01."""
    return (unix + _CHROME_EPOCH_OFFSET) * 1_000_000


def _firefox_ts(unix: int) -> int:
    """Unix timestamp (seconds) → Firefox microseconds since 1970-01-01."""
    return unix * 1_000_000


# Incident timeline  (2024-03-15 UTC)
# t_hhmm = Unix timestamp for 2024-03-15 HH:MM UTC

def _t(h: int, m: int = 0) -> int:
    """Return Unix timestamp for 2026-03-14 HH:MM UTC."""
    return 1_773_446_400 + h * 3600 + m * 60   # 1773446400 = 2026-03-14 00:00 UTC


# Chrome  (samples/chrome/History)
CHROME_HISTORY_URLS = [
    # Normal morning browsing
    {"url": "https://www.google.com/search?q=python+tutorial",
     "title": "python tutorial - Google Search", "visit_count": 3, "ts": _t(8, 5)},
    {"url": "https://docs.python.org/3/",
     "title": "Python 3 Documentation", "visit_count": 2, "ts": _t(8, 12)},
    {"url": "https://github.com/",
     "title": "GitHub", "visit_count": 5, "ts": _t(8, 30)},

    # Suspicious searches start
    {"url": "https://www.google.com/search?q=how+to+bypass+windows+defender",
     "title": "how to bypass windows defender - Google Search", "visit_count": 1, "ts": _t(9, 3)},
    {"url": "https://www.google.com/search?q=disable+uac+windows+10+registry",
     "title": "disable uac windows 10 registry - Google Search", "visit_count": 1, "ts": _t(9, 18)},

    # Suspicious site visits
    {"url": "https://pastebin.com/xK7mN2pQ",
     "title": "Pastebin - PowerShell loader", "visit_count": 1, "ts": _t(9, 45)},
    {"url": "https://cdn.discordapp.com/attachments/fake/tool.zip",
     "title": "", "visit_count": 1, "ts": _t(10, 2)},

    # More suspicious searches
    {"url": "https://www.google.com/search?q=mimikatz+tutorial+windows",
     "title": "mimikatz tutorial windows - Google Search", "visit_count": 2, "ts": _t(10, 30)},
    {"url": "https://www.bing.com/search?q=credential+dumping+lsass",
     "title": "credential dumping lsass - Bing", "visit_count": 1, "ts": _t(11, 5)},

    # Normal-looking cover browsing in the afternoon
    {"url": "https://www.onet.pl/",
     "title": "Onet – portal", "visit_count": 4, "ts": _t(13, 0)},
    {"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
     "title": "YouTube", "visit_count": 1, "ts": _t(13, 20)},
    {"url": "https://www.google.com/search?q=weather+warsaw",
     "title": "weather warsaw - Google Search", "visit_count": 1, "ts": _t(14, 0)},
]

CHROME_DOWNLOADS = [
    {
        "start": _t(10, 5), "end": _t(10, 6),
        "target": r"C:\Users\jkowalski\Downloads\update.exe",
        "size": 2_457_600, "state": 1, "danger": 1,
        "url": "https://cdn.discordapp.com/attachments/fake/update.exe",
    },
    {
        "start": _t(11, 15), "end": _t(11, 16),
        "target": r"C:\Users\jkowalski\Downloads\invoice.pdf.exe",
        "size": 892_416, "state": 1, "danger": 1,
        "url": "https://pastebin.com/raw/fake_loader",
    },
    {
        "start": _t(8, 35), "end": _t(8, 36),
        "target": r"C:\Users\jkowalski\Downloads\notes.pdf",
        "size": 124_512, "state": 1, "danger": 0,
        "url": "https://github.com/octocat/notes/releases/download/v1/notes.pdf",
    },
]


def build_chrome(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE urls (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            url             TEXT NOT NULL,
            title           TEXT DEFAULT '',
            visit_count     INTEGER DEFAULT 0,
            last_visit_time INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE visits (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         INTEGER NOT NULL,
            visit_time  INTEGER NOT NULL,
            transition  INTEGER DEFAULT 0,
            FOREIGN KEY (url) REFERENCES urls(id)
        );
        CREATE TABLE downloads (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time  INTEGER NOT NULL,
            end_time    INTEGER,
            target_path TEXT,
            total_bytes INTEGER,
            state       INTEGER DEFAULT 0,
            danger_type INTEGER DEFAULT 0
        );
        CREATE TABLE downloads_url_chains (
            id          INTEGER NOT NULL,
            chain_index INTEGER NOT NULL,
            url         TEXT NOT NULL,
            PRIMARY KEY (id, chain_index)
        );
    """)

    for entry in CHROME_HISTORY_URLS:
        conn.execute(
            "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?,?,?,?)",
            (entry["url"], entry["title"], entry["visit_count"], _chrome_ts(entry["ts"])),
        )
        url_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO visits (url, visit_time, transition) VALUES (?,?,?)",
            (url_id, _chrome_ts(entry["ts"]), 1),
        )

    for i, dl in enumerate(CHROME_DOWNLOADS, start=1):
        conn.execute(
            "INSERT INTO downloads (start_time, end_time, target_path, total_bytes, state, danger_type)"
            " VALUES (?,?,?,?,?,?)",
            (_chrome_ts(dl["start"]), _chrome_ts(dl["end"]),
             dl["target"], dl["size"], dl["state"], dl["danger"]),
        )
        conn.execute(
            "INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (?,?,?)",
            (i, 0, dl["url"]),
        )

    conn.commit()
    conn.close()
    print(f"[+] Chrome  -> {db_path}")


# Firefox  (samples/firefox/places.sqlite)
FIREFOX_HISTORY_URLS = [
    # Normal morning
    {"url": "https://www.google.com/search?q=linux+commands+cheatsheet",
     "title": "linux commands cheatsheet - Google Search", "visit_count": 2, "ts": _t(8, 20)},
    {"url": "https://stackoverflow.com/questions/tagged/python",
     "title": "Newest Python Questions - Stack Overflow", "visit_count": 3, "ts": _t(8, 45)},

    # Suspicious searches
    {"url": "https://duckduckgo.com/?q=mimikatz+download+github",
     "title": "mimikatz download github at DuckDuckGo", "visit_count": 1, "ts": _t(11, 10)},
    {"url": "https://duckduckgo.com/?q=how+to+dump+ntlm+hashes",
     "title": "how to dump ntlm hashes at DuckDuckGo", "visit_count": 1, "ts": _t(11, 35)},

    # Tor / onion
    {"url": "http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion/",
     "title": "Dark.Fail — Onion Mirror Index", "visit_count": 1, "ts": _t(12, 0)},

    # Cover browsing
    {"url": "https://www.wp.pl/",
     "title": "Wirtualna Polska", "visit_count": 2, "ts": _t(14, 30)},
    {"url": "https://www.youtube.com/watch?v=fake",
     "title": "YouTube", "visit_count": 1, "ts": _t(15, 0)},
]

FIREFOX_DOWNLOADS = [
    {
        "url": "https://github.com/gentilkiwi/mimikatz/releases/download/fake/mimikatz.zip",
        "dest": "file:///home/jkowalski/Downloads/mimikatz.zip",
        "start": _t(11, 40), "end": _t(11, 41),
        "size": 1_048_576, "state": 1,
    },
    {
        "url": "https://transfer.sh/fake/invoice.pdf.exe",
        "dest": "file:///home/jkowalski/Downloads/invoice.pdf.exe",
        "start": _t(12, 30), "end": _t(12, 31),
        "size": 327_680, "state": 1,
    },
]


def build_firefox(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE moz_places (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT NOT NULL,
            title       TEXT,
            visit_count INTEGER DEFAULT 0
        );
        CREATE TABLE moz_historyvisits (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            place_id    INTEGER NOT NULL,
            visit_date  INTEGER NOT NULL,
            visit_type  INTEGER DEFAULT 1,
            FOREIGN KEY (place_id) REFERENCES moz_places(id)
        );
        CREATE TABLE moz_anno_attributes (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE moz_annos (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            place_id            INTEGER NOT NULL,
            anno_attribute_id   INTEGER NOT NULL,
            content             TEXT,
            dateAdded           INTEGER,
            FOREIGN KEY (place_id) REFERENCES moz_places(id),
            FOREIGN KEY (anno_attribute_id) REFERENCES moz_anno_attributes(id)
        );
    """)

    for entry in FIREFOX_HISTORY_URLS:
        conn.execute(
            "INSERT INTO moz_places (url, title, visit_count) VALUES (?,?,?)",
            (entry["url"], entry["title"], entry["visit_count"]),
        )
        place_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO moz_historyvisits (place_id, visit_date, visit_type) VALUES (?,?,?)",
            (place_id, _firefox_ts(entry["ts"]), 1),
        )

    conn.execute("INSERT INTO moz_anno_attributes (name) VALUES ('downloads/destinationFileURI')")
    dest_attr_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO moz_anno_attributes (name) VALUES ('downloads/metaData')")
    meta_attr_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    for dl in FIREFOX_DOWNLOADS:
        conn.execute(
            "INSERT INTO moz_places (url, title, visit_count) VALUES (?,?,?)",
            (dl["url"], "", 1),
        )
        place_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        conn.execute(
            "INSERT INTO moz_annos (place_id, anno_attribute_id, content, dateAdded) VALUES (?,?,?,?)",
            (place_id, dest_attr_id, dl["dest"], _firefox_ts(dl["start"])),
        )
        meta = json.dumps({
            "state": dl["state"],
            "startTime": dl["start"] * 1000,
            "endTime": dl["end"] * 1000,
            "fileSize": dl["size"],
        })
        conn.execute(
            "INSERT INTO moz_annos (place_id, anno_attribute_id, content, dateAdded) VALUES (?,?,?,?)",
            (place_id, meta_attr_id, meta, _firefox_ts(dl["start"])),
        )

    conn.commit()
    conn.close()
    print(f"[+] Firefox -> {db_path}")


# Chrome — v2 artifacts (cookies, bookmarks, autofill, extensions)
CHROME_COOKIES = [
    {"host": ".google.com", "name": "SID", "created": _t(8, 5),
     "expires": _t(8, 5) + 63_072_000, "secure": 1, "httponly": 1},
    {"host": ".github.com", "name": "user_session", "created": _t(8, 30),
     "expires": _t(8, 30) + 1_209_600, "secure": 1, "httponly": 1},
    {"host": ".pastebin.com", "name": "__cf_bm", "created": _t(9, 45),
     "expires": 0, "secure": 1, "httponly": 1},
    {"host": ".onet.pl", "name": "onet_ubi", "created": _t(13, 0),
     "expires": _t(13, 0) + 31_536_000, "secure": 0, "httponly": 0},
]

CHROME_BOOKMARKS = [
    {"folder": "Bookmarks bar", "name": "GitHub", "url": "https://github.com/",
     "added": _t(8, 30)},
    {"folder": "Bookmarks bar", "name": "Python Docs",
     "url": "https://docs.python.org/3/", "added": _t(8, 12)},
    {"folder": "Research", "name": "Pastebin loader",
     "url": "https://pastebin.com/xK7mN2pQ", "added": _t(9, 46)},
]

CHROME_AUTOFILL = [
    {"name": "email", "value": "j.kowalski@firma.pl", "count": 12,
     "created": _t(8, 5), "last_used": _t(14, 0)},
    {"name": "search", "value": "mimikatz tutorial", "count": 2,
     "created": _t(10, 30), "last_used": _t(11, 5)},
    {"name": "username", "value": "jkowalski", "count": 8,
     "created": _t(8, 30), "last_used": _t(13, 20)},
]

CHROME_EXTENSIONS = {
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": {
        "state": 1, "install_time": str(_chrome_ts(_t(8, 0))),
        "manifest": {"name": "uBlock Origin", "version": "1.55.0"},
    },
    "nkbihfbeogaeaoehlefnkodbefgpgknn": {
        "state": 1, "install_time": str(_chrome_ts(_t(9, 40))),
        "manifest": {"name": "MetaMask", "version": "11.9.1"},
    },
}


def _augment_chrome(db_path: Path, profile: Path) -> None:
    """Add cookies / bookmarks / autofill / extensions next to History."""
    # Cookies (Network/Cookies — nowsza lokalizacja)
    cookies_path = profile / "Network" / "Cookies"
    cookies_path.parent.mkdir(parents=True, exist_ok=True)
    if cookies_path.exists():
        cookies_path.unlink()
    conn = sqlite3.connect(cookies_path)
    conn.executescript("""
        CREATE TABLE cookies (
            creation_utc    INTEGER NOT NULL,
            host_key        TEXT NOT NULL,
            name            TEXT NOT NULL,
            path            TEXT NOT NULL DEFAULT '/',
            expires_utc     INTEGER NOT NULL DEFAULT 0,
            is_secure       INTEGER NOT NULL DEFAULT 0,
            is_httponly     INTEGER NOT NULL DEFAULT 0,
            last_access_utc INTEGER NOT NULL DEFAULT 0
        );
    """)
    for c in CHROME_COOKIES:
        conn.execute(
            "INSERT INTO cookies (creation_utc, host_key, name, expires_utc,"
            " is_secure, is_httponly, last_access_utc) VALUES (?,?,?,?,?,?,?)",
            (_chrome_ts(c["created"]), c["host"], c["name"],
             _chrome_ts(c["expires"]) if c["expires"] else 0,
             c["secure"], c["httponly"], _chrome_ts(c["created"])),
        )
    conn.commit()
    conn.close()

    # Bookmarks (JSON) — grupujemy po folderach
    folders: dict[str, list] = {}
    for b in CHROME_BOOKMARKS:
        folders.setdefault(b["folder"], []).append({
            "type": "url", "name": b["name"], "url": b["url"],
            "date_added": str(_chrome_ts(b["added"])),
        })
    bar_children = folders.get("Bookmarks bar", []) + [
        {"type": "folder", "name": name, "children": children}
        for name, children in folders.items() if name != "Bookmarks bar"
    ]
    (profile / "Bookmarks").write_text(json.dumps({
        "roots": {
            "bookmark_bar": {"type": "folder", "name": "Bookmarks bar",
                             "children": bar_children},
            "other": {"type": "folder", "name": "Other bookmarks", "children": []},
        },
        "version": 1,
    }, indent=2), encoding="utf-8")

    # Web Data (autofill) — date_* w SEKUNDACH
    webdata_path = profile / "Web Data"
    if webdata_path.exists():
        webdata_path.unlink()
    conn = sqlite3.connect(webdata_path)
    conn.executescript("""
        CREATE TABLE autofill (
            name TEXT NOT NULL, value TEXT NOT NULL, count INTEGER DEFAULT 1,
            date_created INTEGER, date_last_used INTEGER
        );
    """)
    for a in CHROME_AUTOFILL:
        conn.execute(
            "INSERT INTO autofill (name, value, count, date_created,"
            " date_last_used) VALUES (?,?,?,?,?)",
            (a["name"], a["value"], a["count"], a["created"], a["last_used"]),
        )
    conn.commit()
    conn.close()

    # Preferences (extensions)
    (profile / "Preferences").write_text(json.dumps({
        "extensions": {"settings": CHROME_EXTENSIONS},
    }, indent=2), encoding="utf-8")


def _add_chrome_wal_deletion(db_path: Path) -> None:
    """Freeze a History + History-wal pair where the mimikatz search visit is
    deleted only in the WAL — recoverable with --wal-recover."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        "DELETE FROM visits WHERE url IN "
        "(SELECT id FROM urls WHERE url LIKE '%mimikatz%')"
    )
    conn.execute("DELETE FROM urls WHERE url LIKE '%mimikatz%'")
    conn.commit()
    # kopiujemy main+wal PRZED close() (close scala WAL)
    shutil.copy2(db_path, db_path.parent / (db_path.name + ".main"))
    shutil.copy2(Path(str(db_path) + "-wal"),
                 db_path.parent / (db_path.name + "-wal.frozen"))
    conn.close()
    # przywracamy zamrożony split jako finalne artefakty
    shutil.move(str(db_path.parent / (db_path.name + ".main")), str(db_path))
    shutil.move(str(db_path.parent / (db_path.name + "-wal.frozen")),
                str(Path(str(db_path) + "-wal")))


# Firefox — v2 artifacts (cookies, form history, extensions)
FIREFOX_COOKIES = [
    {"host": ".mozilla.org", "name": "sessionid", "created": _t(8, 20),
     "expiry": _t(8, 20) + 31_536_000, "secure": 1, "httponly": 1},
    {"host": ".duckduckgo.com", "name": "5", "created": _t(11, 10),
     "expiry": 0, "secure": 1, "httponly": 0},
    {"host": ".transfer.sh", "name": "session", "created": _t(12, 30),
     "expiry": _t(12, 30) + 86_400, "secure": 1, "httponly": 1},
]

FIREFOX_FORMHISTORY = [
    {"field": "searchbar-history", "value": "mimikatz download github",
     "count": 1, "first": _t(11, 10), "last": _t(11, 10)},
    {"field": "email", "value": "j.kowalski@firma.pl", "count": 5,
     "first": _t(8, 20), "last": _t(14, 30)},
]

FIREFOX_EXTENSIONS = [
    {"id": "uBlock0@raymondhill.net", "type": "extension", "version": "1.55.0",
     "active": True, "installDate": _t(8, 15) * 1000,
     "defaultLocale": {"name": "uBlock Origin"}},
    {"id": "{446900e4-71c2-419f-a6a7-df9c091e268b}", "type": "extension",
     "version": "3.5.0", "active": True, "installDate": _t(9, 0) * 1000,
     "defaultLocale": {"name": "Bitwarden"}},
    {"id": "default-theme@mozilla.org", "type": "theme", "active": True,
     "installDate": _t(8, 0) * 1000, "defaultLocale": {"name": "System theme"}},
]


def _augment_firefox(profile: Path) -> None:
    """Add cookies / formhistory / extensions next to places.sqlite; also
    write a few bookmarks into places.sqlite (moz_bookmarks)."""
    # cookies.sqlite — creationTime/lastAccessed µs, expiry sekundy
    cookies_path = profile / "cookies.sqlite"
    if cookies_path.exists():
        cookies_path.unlink()
    conn = sqlite3.connect(cookies_path)
    conn.executescript("""
        CREATE TABLE moz_cookies (
            id INTEGER PRIMARY KEY, host TEXT, name TEXT, path TEXT DEFAULT '/',
            expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER,
            isSecure INTEGER, isHttpOnly INTEGER
        );
    """)
    for c in FIREFOX_COOKIES:
        conn.execute(
            "INSERT INTO moz_cookies (host, name, expiry, lastAccessed,"
            " creationTime, isSecure, isHttpOnly) VALUES (?,?,?,?,?,?,?)",
            (c["host"], c["name"], c["expiry"], _firefox_ts(c["created"]),
             _firefox_ts(c["created"]), c["secure"], c["httponly"]),
        )
    conn.commit()
    conn.close()

    # formhistory.sqlite
    form_path = profile / "formhistory.sqlite"
    if form_path.exists():
        form_path.unlink()
    conn = sqlite3.connect(form_path)
    conn.executescript("""
        CREATE TABLE moz_formhistory (
            id INTEGER PRIMARY KEY, fieldname TEXT NOT NULL, value TEXT NOT NULL,
            timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER
        );
    """)
    for f in FIREFOX_FORMHISTORY:
        conn.execute(
            "INSERT INTO moz_formhistory (fieldname, value, timesUsed,"
            " firstUsed, lastUsed) VALUES (?,?,?,?,?)",
            (f["field"], f["value"], f["count"],
             _firefox_ts(f["first"]), _firefox_ts(f["last"])),
        )
    conn.commit()
    conn.close()

    # extensions.json — installDate w MILISEKUNDACH
    (profile / "extensions.json").write_text(json.dumps({
        "schemaVersion": 36, "addons": FIREFOX_EXTENSIONS,
    }, indent=2), encoding="utf-8")


def _add_firefox_bookmarks(db_path: Path) -> None:
    """Add moz_bookmarks rows to an existing places.sqlite."""
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS moz_bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, type INTEGER NOT NULL,
            fk INTEGER, parent INTEGER, title TEXT, dateAdded INTEGER
        );
    """)
    conn.execute("INSERT INTO moz_bookmarks (type, parent, title, dateAdded)"
                 " VALUES (2, 0, 'Toolbar', 0)")
    toolbar_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    bookmarks = [
        ("https://stackoverflow.com/questions/tagged/python",
         "Python — Stack Overflow", _t(8, 45)),
        ("https://github.com/gentilkiwi/mimikatz",
         "gentilkiwi/mimikatz", _t(11, 40)),
    ]
    for url, title, added in bookmarks:
        conn.execute("INSERT INTO moz_places (url, title, visit_count)"
                     " VALUES (?,?,0)", (url, title))
        place_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO moz_bookmarks (type, fk, parent, title, dateAdded)"
            " VALUES (1, ?, ?, ?, ?)",
            (place_id, toolbar_id, title, _firefox_ts(added)),
        )
    conn.commit()
    conn.close()


# Main
if __name__ == "__main__":
    root = Path(__file__).resolve().parent

    chrome_history = root / "chrome" / "History"
    build_chrome(chrome_history)
    _augment_chrome(chrome_history, root / "chrome")
    _add_chrome_wal_deletion(chrome_history)
    print(f"[+] Chrome  v2 artifacts (cookies, bookmarks, autofill, "
          f"extensions, WAL) -> {root / 'chrome'}")

    firefox_places = root / "firefox" / "places.sqlite"
    build_firefox(firefox_places)
    _add_firefox_bookmarks(firefox_places)
    _augment_firefox(root / "firefox")
    print(f"[+] Firefox v2 artifacts (cookies, bookmarks, formhistory, "
          f"extensions) -> {root / 'firefox'}")

    print()
    print("Sample artifacts generated. Run the tool with:")
    print()
    print(f"  python main.py --chrome-profile {root / 'chrome'} "
          f"--firefox-profile {root / 'firefox'} --wal-recover "
          f"--case-id INC-2026-03-14 --report all --output-dir output/demo")
