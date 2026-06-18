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

Offline forensic analyzer for Chrome and Firefox browser artifacts.
Built for DFIR investigations — extracts browsing history, downloads, and
search queries, builds a unified timeline, flags suspicious activity
against a configurable IOC set, and produces HTML/CSV reports.

---

## Features

- **Two-browser support** — Chrome (`History` SQLite) and Firefox (`places.sqlite`)
- **Three artifact types** per browser:
  - Browsing history (per-visit timestamps, not just last visit)
  - Downloads (target path, file size, state, redirect chains)
  - Search queries auto-detected from 9 engines: Google, Bing, DuckDuckGo, Yahoo, YouTube, Ecosia, Brave, Startpage, Yandex
- **Chain of custody** — every source file is SHA-256 hashed before parsing; the hash is propagated through every derived event
- **Read-only access** — source database is copied to temp before being opened (WAL/SHM included); the original is never modified
- **Anomaly detection** against a configurable IOC YAML:
  - Suspicious domains (exact + wildcard `*.tld`)
  - Suspicious file extensions (incl. the double-extension trick — `invoice.pdf.exe`)
  - Suspicious search keywords
- **Time-window filtering** — narrow analysis to an incident window
- **Reports**:
  - Self-contained HTML, print-friendly (`@media print` → clean A4 PDF)
  - CSV exports (timeline + anomalies) with UTF-8 BOM for Excel

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

This creates `samples/chrome/History` and `samples/firefox/places.sqlite`
with a mix of benign and suspicious activity (malware searches, downloads
from flagged domains, etc.).

**2. Run the tool against them:**

```bash
python main.py \
    --chrome-profile  samples/chrome \
    --firefox-profile samples/firefox \
    --case-id         INC-2026-03-14 \
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
    --chrome-profile  /evidence/chrome/Default \
    --firefox-profile /evidence/firefox/abc123.default-release \
    --output-dir      /cases/INC-2024-001/reports \
    --case-id         INC-2024-001 \
    --ioc-file        /cases/INC-2024-001/custom_iocs.yaml \
    --start           2024-01-15T22:00:00 \
    --end             2024-01-16T06:00:00 \
    --report          both
```

### Options

| Flag                  | Default               | Description |
|-----------------------|-----------------------|-------------|
| `--chrome-profile`    | —                     | Path to a Chrome profile directory |
| `--firefox-profile`   | —                     | Path to a Firefox profile directory |
| `--output-dir`        | `./output`            | Directory for generated reports |
| `--report`            | `both`                | `html` / `csv` / `both` |
| `--case-id`           | `UNSPECIFIED`         | Case ID displayed in HTML report header |
| `--ioc-file`          | `./config/iocs.yaml`  | Path to IOC YAML config |
| `--start`             | —                     | Earliest event (ISO-8601; naive = UTC) |
| `--end`               | —                     | Latest event (ISO-8601; naive = UTC) |

At least one of `--chrome-profile` / `--firefox-profile` is required.

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
│   ├── chrome.py            Chrome History parser
│   └── firefox.py           Firefox places.sqlite parser
│
├── analyzers/               process extracted data
│   ├── timeline.py          unify events into a chronological timeline
│   └── anomaly.py           IOC-based detection
│
├── reporters/               generate output
│   ├── html.py              Jinja2-rendered HTML report
│   ├── csv.py               CSV exports
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
| `test_csv_reporter.py` | CSV schema, BOM, encoding, None-timestamp rows |
| `test_html_reporter.py` | context builder, Jinja2 render, XSS escaping, None-timestamp |
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

Three files land in `--output-dir`:

- **`report.html`** — full forensic report with summary stats, source
  files table (path + SHA-256), anomaly table, and the complete
  timeline. Anomaly-flagged rows are visually highlighted. Print-friendly.
- **`timeline.csv`** — every event as a row. Flat columns
  (`url`, `query`, `filename`) plus a `details_json` column for forensic
  completeness.
- **`anomalies.csv`** — flagged anomalies with full event context for
  triage. Sorted by severity (high → low).

CSVs are UTF-8 with BOM so Excel on Windows handles non-ASCII (Polish,
Cyrillic, etc.) correctly out of the box.