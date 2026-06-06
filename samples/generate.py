"""
Generate anonymized sample browser artifacts for Browser-Autopsy demos.

Scenario: INC-2026-03-14 — suspicious insider activity.
An employee starts the day normally, then begins researching offensive tools,
visits suspicious domains, and downloads malicious-looking files.

Run from repo root:
    python samples/generate.py

Outputs:
    samples/chrome/History
    samples/firefox/places.sqlite
"""
import json
import sqlite3
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


# Main
if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    build_chrome(root / "chrome" / "History")
    build_firefox(root / "firefox" / "places.sqlite")
    print()
    print("Sample artifacts generated. Run the tool with:")
    print()
    print("  python main.py \\")
    print(f"      --chrome-profile  {root / 'chrome'} \\")
    print(f"      --firefox-profile {root / 'firefox'} \\")
    print("      --case-id         INC-2026-03-14 \\")
    print("      --output-dir      output/demo")
