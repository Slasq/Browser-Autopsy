"""
Browser-Autopsy — CLI entry point.

Orchestrates the full forensic pipeline:
  1. extract artifacts from browser profile(s)
  2. build a unified, chronological timeline
  3. (optional) narrow it to a time window
  4. detect anomalies against an IOC config
  5. render HTML and/or CSV reports

Exit codes follow common DFIR-tool conventions:
  0 - success
  1 - runtime failure (missing artifact / IOC file / template)
  2 - argument error
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from analyzers.anomaly import detect, load_iocs
from analyzers.timeline import build_timeline, filter_by_time
from reporters.csv import export_to_csv
from reporters.html import render_report


# Default IOC file lives at the repo root, next to this script.
_PROJECT_ROOT = Path(__file__).resolve().parent
_DEFAULT_IOC_FILE = _PROJECT_ROOT / "iocs.yaml"
_DEFAULT_OUTPUT_DIR = Path("output")


# Argument parsing
def _parse_iso_datetime(value: str) -> datetime:
    """argparse type for ISO-8601 datetimes used by --start / --end.

    Accepts (examples):
      - '2024-01-15'                 (date, midnight assumed)
      - '2024-01-15T22:00:00'         (naive datetime)
      - '2024-01-15T22:00:00+00:00'   (timezone-aware)
      - '2024-01-15T22:00:00Z'        (Z suffix)

    Naive values are treated as UTC because TimelineEvent.timestamp_utc
    is always UTC-aware — comparing naive vs aware would TypeError.
    """
    try:
        # fromisoformat obsługuje 'Z' dopiero od 3.11 — normalizujemy ręcznie
        normalised = value.replace("Z", "+00:00") if value.endswith("Z") else value
        dt = datetime.fromisoformat(normalised)
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            f"invalid ISO-8601 datetime: {value!r} "
            f"(expected e.g. 2024-01-15 or 2024-01-15T22:00:00)"
        ) from e

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="browser-autopsy",
        description=(
            "Browser-Autopsy — offline DFIR analyzer for Chrome and Firefox "
            "artifacts. Builds a unified timeline, flags suspicious activity "
            "against a configurable IOC set, and produces HTML/CSV reports."
        ),
    )

    # Profiles
    profiles = parser.add_argument_group("profiles (at least one required)")
    profiles.add_argument(
        "--chrome-profile", type=Path, default=None, metavar="PATH",
        help="Path to a Chrome profile directory (contains 'History').",
    )
    profiles.add_argument(
        "--firefox-profile", type=Path, default=None, metavar="PATH",
        help="Path to a Firefox profile directory (contains 'places.sqlite').",
    )

    # Output
    output = parser.add_argument_group("output")
    output.add_argument(
        "--output-dir", type=Path, default=_DEFAULT_OUTPUT_DIR, metavar="DIR",
        help="Directory for generated reports (default: ./output).",
    )
    output.add_argument(
        "--report", choices=["html", "csv", "both"], default="both",
        help="Report format (default: both).",
    )
    output.add_argument(
        "--case-id", default="UNSPECIFIED", metavar="ID",
        help="Case identifier displayed in the HTML report header "
             "(default: UNSPECIFIED).",
    )

    # Detection
    detection = parser.add_argument_group("detection")
    detection.add_argument(
        "--ioc-file", type=Path, default=_DEFAULT_IOC_FILE, metavar="PATH",
        help=f"Path to IOC YAML config (default: {_DEFAULT_IOC_FILE.name} "
             "at repo root).",
    )

    # Time filter
    timefilter = parser.add_argument_group("time filter (optional)")
    timefilter.add_argument(
        "--start", type=_parse_iso_datetime, default=None, metavar="ISO_DT",
        help="Earliest event to include (ISO-8601; naive values assumed UTC).",
    )
    timefilter.add_argument(
        "--end", type=_parse_iso_datetime, default=None, metavar="ISO_DT",
        help="Latest event to include (ISO-8601; naive values assumed UTC).",
    )

    return parser.parse_args(argv)


# Orchestrator
def _log(msg: str = "") -> None:
    """Single output channel — stdout, flushed for piping/tee friendliness."""
    print(msg, flush=True)


def _err(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # Validation that argparse itself can't express
    if args.chrome_profile is None and args.firefox_profile is None:
        _err("[!] At least one of --chrome-profile / --firefox-profile is required.")
        return 2

    if args.start is not None and args.end is not None and args.start > args.end:
        _err("[!] --start must be <= --end")
        return 2

    # Header / audit summary
    _log("=" * 64)
    _log(" Browser-Autopsy")
    _log("=" * 64)
    _log(f"[*] Case ID:         {args.case_id}")
    _log(f"[*] Chrome profile:  {args.chrome_profile or '(none)'}")
    _log(f"[*] Firefox profile: {args.firefox_profile or '(none)'}")
    _log(f"[*] IOC file:        {args.ioc_file}")
    _log(f"[*] Output dir:      {args.output_dir}")
    _log(f"[*] Report format:   {args.report}")
    if args.start is not None or args.end is not None:
        window_start = args.start.isoformat() if args.start else "-inf"
        window_end = args.end.isoformat() if args.end else "+inf"
        _log(f"[*] Time window:     {window_start}  ..  {window_end}")
    _log("")

    # 1 Build timeline
    _log("[*] Building timeline...")
    try:
        events = build_timeline(
            chrome_profile=args.chrome_profile,
            firefox_profile=args.firefox_profile,
        )
    except FileNotFoundError as e:
        _err(f"[!] Artifact not found: {e}")
        return 1
    _log(f"[+] Timeline: {len(events)} events")

    # 2 Optional time-window filter
    if args.start is not None or args.end is not None:
        before = len(events)
        events = filter_by_time(events, start=args.start, end=args.end)
        _log(
            f"[+] After time filter: {len(events)} events "
            f"({before - len(events)} dropped)"
        )

    # 3 Load IOCs
    _log(f"[*] Loading IOCs from {args.ioc_file}...")
    try:
        iocs = load_iocs(args.ioc_file)
    except FileNotFoundError as e:
        _err(f"[!] {e}")
        return 1
    _log(
        f"[+] IOCs: {len(iocs.suspicious_domains)} domains, "
        f"{len(iocs.suspicious_extensions)} extensions, "
        f"{len(iocs.suspicious_keywords)} keywords"
    )

    # 4 Detect anomalies
    _log("[*] Detecting anomalies...")
    anomalies = detect(events, iocs)
    _log(f"[+] Anomalies: {len(anomalies)}")

    # 5 Generate reports
    args.output_dir.mkdir(parents=True, exist_ok=True)

    if args.report in ("html", "both"):
        html_path = args.output_dir / "report.html"
        render_report(events, anomalies, html_path, case_id=args.case_id)
        _log(f"[+] HTML report:   {html_path}")

    if args.report in ("csv", "both"):
        timeline_csv, anomalies_csv = export_to_csv(
            events, anomalies, args.output_dir,
        )
        _log(f"[+] CSV timeline:  {timeline_csv}")
        _log(f"[+] CSV anomalies: {anomalies_csv}")

    _log("")
    _log("[*] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())