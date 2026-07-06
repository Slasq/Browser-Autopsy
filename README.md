```
██████╗ ██████╗  ██████╗ ██╗    ██╗███████╗███████╗██████╗ 
██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔════╝██╔══██╗
██████╔╝██████╔╝██║   ██║██║ █╗ ██║███████╗█████╗  ██████╔╝
██╔══██╗██╔══██╗██║   ██║██║███╗██║╚════██║██╔══╝  ██╔══██╗
██████╔╝██║  ██║╚██████╔╝╚███╔███╔╝███████║███████╗██║  ██║
╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
   █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ███████╗██╗   ██╗
  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝╚██╗ ██╔╝
  ███████║██║   ██║   ██║   ██║   ██║██████╔╝███████╗ ╚████╔╝ 
  ██╔══██║██║   ██║   ██║   ██║   ██║██╔═══╝ ╚════██║  ╚██╔╝  
  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║     ███████║   ██║   
  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚══════╝   ╚═╝   
```

Offline forensic analyzer for Chromium- and Gecko-family browser artifacts.
Built for DFIR investigations — extracts browsing history, downloads,
searches, cookies, bookmarks, autofill, and extensions, builds a unified
timeline, recovers deleted history from the SQLite WAL, flags suspicious
activity against a configurable IOC set, and produces HTML/CSV/JSON reports.

**Everything runs 100% offline** — no network calls, no external APIs, no
live capture. All analysis is performed on copied artifact files.

---

## Features

- **Whole-family browser support**:
  - **Chromium**: Chrome, Edge, Brave, Opera, Vivaldi, Chromium, Yandex
  - **Gecko**: Firefox, Tor Browser, LibreWolf, Waterfox
- **Seven artifact types** per browser:
  - Browsing history (per-visit timestamps, not just last visit)
  - Downloads (target path, file size, state, redirect chains)
  - Search queries auto-detected from 9 engines: Google, Bing, DuckDuckGo, Yahoo, YouTube, Ecosia, Brave, Startpage, Yandex
  - Cookies (host, name, creation/expiry — metadata only, values stay encrypted)
  - Bookmarks (title, URL, folder)
  - Autofill / form history (field, value, use count)
  - Installed extensions (id, name, version, enabled state)
- **Deleted-history recovery** — diffs the main SQLite image against the
  WAL-replayed state to surface records deleted-but-not-yet-checkpointed
  (`--wal-recover`)
- **Auto-discovery** — point `--input` at an evidence directory and every
  Chromium/Gecko profile underneath is found and analyzed
- **Chain of custody** — every source file is SHA-256 hashed before parsing; the hash is propagated through every derived event
- **Read-only access** — source database is copied to temp before being opened (WAL/SHM included); the original is never modified
- **Anomaly detection** against a configurable IOC YAML:
  - Suspicious domains (exact + wildcard `*.tld`)
  - Suspicious file extensions (incl. the double-extension trick — `invoice.pdf.exe`)
  - Suspicious search keywords
- **Time-window filtering** — narrow analysis to an incident window
- **Reports**:
  - Self-contained HTML with a visual timeline strip and hourly-activity
    chart, print-friendly (`@media print` → clean A4 PDF)
  - CSV exports (timeline + anomalies) with UTF-8 BOM for Excel
  - JSON export for machine-readable pipelines / further tooling

---

## Install

Requires Python **3.10+**.

**Recommended — [uv](https://github.com/astral-sh/uv) (installs deps into an isolated `.venv` automatically):**

```bash
uv sync
```

**Or with pip:**

```bash
pip install -r requirements.txt
```

---

## Quick start

```bash
# uv
uv run python main.py --chrome-profile /path/to/chrome/Default --case-id INC-2024-001

# pip / system Python
python main.py --chrome-profile /path/to/chrome/Default --case-id INC-2024-001
```

Reports land in `./output/`. Open `output/report.html` in any browser.

> Want to see what a generated report looks like without running the tool?
> Open `report_demo.html` in the repository root.

---

## Demo — sample data

The repository ships with a script that generates synthetic browser artifacts
simulating a suspicious insider-activity scenario (case `INC-2026-03-14`).
Use it to see the tool in action without needing real browser profiles.

**1. Generate the artifacts:**

```bash
python samples/generate.py
```

This creates a full Chrome and Firefox profile (history, downloads, cookies,
bookmarks, autofill, extensions) with a mix of benign and suspicious activity
(malware searches, downloads from flagged domains, etc.) — including one
history entry deleted only in the WAL, so `--wal-recover` has something to
recover.

**2. Run the tool against them:**

```bash
python main.py \
    --chrome-profile  samples/chrome \
    --firefox-profile samples/firefox \
    --wal-recover \
    --case-id         INC-2026-03-14 \
    --report          all \
    --output-dir      output/demo
```

**3. Open the report:**

```
output/demo/report.html
```

> A pre-rendered version is included in the repo root as `report_demo.html`
> — no setup needed to preview the output format.

---

## Usage

### Full example

```bash
python main.py \
    --input           /evidence/seized_laptop \
    --output-dir      /cases/INC-2024-001/reports \
    --case-id         INC-2024-001 \
    --ioc-file        /cases/INC-2024-001/custom_iocs.yaml \
    --wal-recover \
    --start           2024-01-15T22:00:00 \
    --end             2024-01-16T06:00:00 \
    --report          all
```

### Options

| Flag                  | Default               | Description |
|-----------------------|-----------------------|-------------|
| `--input`             | —                     | Evidence directory — auto-discovers every Chromium/Gecko profile underneath |
| `--chrome-profile`    | —                     | Path to a Chromium-family profile directory |
| `--firefox-profile`   | —                     | Path to a Gecko-family profile directory |
| `--firefox-browser`   | `firefox`             | Label for the Gecko profile (`firefox`, `tor`, `librewolf`, `waterfox`) |
| `--wal-recover`       | off                   | Recover history rows deleted-but-not-checkpointed from the SQLite WAL |
| `--output-dir`        | `./output`            | Directory for generated reports |
| `--report`            | `both`                | `html` / `csv` / `json` / `both` (html+csv) / `all` |
| `--case-id`           | `UNSPECIFIED`         | Case ID displayed in HTML report header |
| `--ioc-file`          | `./config/iocs.yaml`  | Path to IOC YAML config |
| `--start`             | —                     | Earliest event (ISO-8601; naive = UTC) |
| `--end`               | —                     | Latest event (ISO-8601; naive = UTC) |

At least one of `--input` / `--chrome-profile` / `--firefox-profile` is required.

### Where browser profiles live

| OS       | Chrome                                                  | Firefox                                                        |
|----------|---------------------------------------------------------|----------------------------------------------------------------|
| Windows  | `%LOCALAPPDATA%\Google\Chrome\User Data\Default`        | `%APPDATA%\Mozilla\Firefox\Profiles\<id>.default-release`      |
| macOS    | `~/Library/Application Support/Google/Chrome/Default`   | `~/Library/Application Support/Firefox/Profiles/<id>.default`  |
| Linux    | `~/.config/google-chrome/Default`                       | `~/.mozilla/firefox/<id>.default-release`                      |

> **Windows note**: close Chrome / Firefox before running — Windows holds an exclusive lock on the profile databases.

### Exit codes

- `0` — success
- `1` — runtime failure (missing artifact, missing IOC file)
- `2` — argument error (no profile, invalid date, `--start > --end`)

---

## IOC configuration

The default `config/iocs.yaml` ships with sensible starter content — Tor
hidden services, paste sites, anonymous file-sharing, malware extensions,
offensive-security keywords. Override per investigation with `--ioc-file`:

```yaml
suspicious_domains:
  - "*.onion"            # wildcard suffix match — any .onion
  - pastebin.com         # exact match (sub.pastebin.com NOT included)
  - cdn.discordapp.com

suspicious_extensions:
  - .exe
  - .ps1
  - .hta                 # HTML Application — classic phishing vector

suspicious_keywords:
  - mimikatz
  - "bypass uac"
  - "disable defender"
```

Matching is case-insensitive throughout. Leading `.` in extensions is
optional — `exe` and `.exe` both work.

---

## Project structure

```
Browser-Autopsy/
├── main.py                  CLI entry point
├── requirements.txt
├── report_demo.html         sample rendered report
│
├── config/
│   └── iocs.yaml            default IOC config
│
├── extractors/              parse raw browser artifacts
│   ├── base.py              shared helpers + dataclasses
│   ├── chrome.py            Chromium-family parser (history, cookies, ...)
│   ├── firefox.py           Gecko-family parser + profile detection
│   └── discovery.py         --input evidence-directory profile discovery
│
├── analyzers/               process extracted data
│   ├── timeline.py          unify events into a chronological timeline
│   ├── anomaly.py           IOC-based detection
│   └── wal.py               deleted-history recovery from the SQLite WAL
│
├── reporters/               generate output
│   ├── html.py              Jinja2-rendered HTML report (+ visual timeline)
│   ├── csv.py               CSV exports
│   ├── json.py              machine-readable JSON export
│   └── templates/
│       └── report.html      report template (inline CSS, no JS)
│
└── tests/                   extensive pytest suite
```

---

## Testing

The project has an extensive pytest suite covering all layers of the pipeline:

| Module | What's tested |
|---|---|
| `test_base.py` | timestamp converters, `basename`, `_extract_query`, `sha256_file` |
| `test_open_db.py` | `open_db` — missing file, corrupted DB, WAL/SHM copy, temp-dir cleanup |
| `test_chrome_history/downloads/search.py` | Chrome extractor end-to-end against real SQLite schemas |
| `test_firefox_history/downloads/search.py` | Firefox extractor end-to-end, incl. annotation-based downloads |
| `test_timeline.py` | adapter mapping, `build_timeline`, `filter_by_time`, None-timestamp edge cases |
| `test_anomaly.py` | `load_iocs`, all three detectors, `_domain_from_url`, `_domain_matches` |
| `test_chrome/firefox_artifacts.py` | cookies, bookmarks, autofill, extensions extractors |
| `test_gecko_profiles.py` | Gecko profile detection across OSes + browser families |
| `test_discovery.py` | `--input` evidence-directory profile discovery + classification |
| `test_wal_recovery.py` | main-vs-WAL diff, deleted-record recovery, WAL-only rows |
| `test_csv_reporter.py` | CSV schema, BOM, encoding, None-timestamp rows |
| `test_html_reporter.py` | context builder, Jinja2 render, XSS escaping, visual charts |
| `test_json_reporter.py` | JSON schema, chain of custody, stats block |
| `test_main.py` | CLI parsing, exit codes, orchestrator plumbing |

```bash
# uv
uv run pytest                          # full suite
uv run pytest tests/test_timeline.py   # one module
uv run pytest -v -k chrome             # only chrome-related tests

# pip / system Python
pytest
```

---

## Output

Depending on `--report`, up to four files land in `--output-dir`:

- **`report.html`** — full forensic report with summary stats, a visual
  timeline strip, an hourly-activity chart, source files table (path +
  SHA-256), anomaly table, and the complete timeline. Anomaly-flagged rows
  are visually highlighted. Print-friendly.
- **`timeline.csv`** — every event as a row. Flat columns
  (`url`, `query`, `filename`) plus a `details_json` column for forensic
  completeness.
- **`anomalies.csv`** — flagged anomalies with full event context for
  triage. Sorted by severity (high → low).
- **`report.json`** — machine-readable document (case metadata, chain of
  custody, full timeline, anomalies) for downstream tooling.

CSVs are UTF-8 with BOM so Excel on Windows handles non-ASCII (Polish,
Cyrillic, etc.) correctly out of the box.