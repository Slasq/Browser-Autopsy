"""
NOTE: this module is named 'csv' but Python's import system resolves
`from csv import DictWriter` to the stdlib (absolute imports), not to
this file.
"""
from __future__ import annotations

import json
from csv import DictWriter
from pathlib import Path

from analyzers.anomaly import Anomaly
from analyzers.timeline import TimelineEvent


# Column schemas
_TIMELINE_FIELDS: list[str] = [
    "timestamp_utc",
    "event_type",
    "browser",
    "source_file",
    "source_sha256",
    "summary",
    # Flat key fields pulled out of `details` for easy filtering in Excel.
    "url",
    "query",
    "filename",
    # Full original details dict, JSON-encoded, for forensic completeness.
    "details_json",
]

_ANOMALY_FIELDS: list[str] = [
    "timestamp_utc",
    "rule_id",
    "severity",
    "matched_value",
    "reason",
    # Event context — useful when triaging from anomalies.csv alone.
    "event_type",
    "browser",
    "source_file",
    "source_sha256",
    "summary",
]

# UTF-8 with BOM so Excel on Windows doesn't mangle Polish characters.
_CSV_ENCODING = "utf-8-sig"


# Individual exporters
def export_timeline_to_csv(
    events: list[TimelineEvent],
    output_path: Path,
) -> Path:
    """Write all timeline events to `output_path` as CSV. Returns the path."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding=_CSV_ENCODING, newline="") as f:
        writer = DictWriter(f, fieldnames=_TIMELINE_FIELDS)
        writer.writeheader()
        for event in events:
            details = event.details or {}
            writer.writerow({
                "timestamp_utc": event.timestamp_utc.isoformat(),
                "event_type": event.event_type,
                "browser": event.browser,
                "source_file": event.source_file,
                "source_sha256": event.source_sha256,
                "summary": event.summary,
                # bezpieczne .get — różne event_type ma różne klucze
                "url": details.get("url", ""),
                "query": details.get("query", ""),
                "filename": details.get("filename", ""),
                # default=str ratuje przed dataclassami / datetime w details
                "details_json": json.dumps(
                    details, ensure_ascii=False, default=str, sort_keys=True,
                ),
            })
    return output_path


def export_anomalies_to_csv(
    anomalies: list[Anomaly],
    output_path: Path,
) -> Path:
    """Write all anomalies to `output_path` as CSV. Returns the path."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding=_CSV_ENCODING, newline="") as f:
        writer = DictWriter(f, fieldnames=_ANOMALY_FIELDS)
        writer.writeheader()
        for a in anomalies:
            writer.writerow({
                "timestamp_utc": a.event.timestamp_utc.isoformat(),
                "rule_id": a.rule_id,
                "severity": a.severity,
                "matched_value": a.matched_value,
                "reason": a.reason,
                "event_type": a.event.event_type,
                "browser": a.event.browser,
                "source_file": a.event.source_file,
                "source_sha256": a.event.source_sha256,
                "summary": a.event.summary,
            })
    return output_path


# Convenience entry point
def export_to_csv(
    events: list[TimelineEvent],
    anomalies: list[Anomaly],
    output_dir: Path,
) -> tuple[Path, Path]:
    """Export both timeline and anomalies as CSVs into `output_dir`.

    Returns (timeline_csv_path, anomalies_csv_path).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    timeline_path = export_timeline_to_csv(events, output_dir / "timeline.csv")
    anomalies_path = export_anomalies_to_csv(anomalies, output_dir / "anomalies.csv")
    return timeline_path, anomalies_path