"""
NOTE: this module is named 'json' but Python's import system resolves
`import json` below to the stdlib (absolute imports), not to this file —
same caveat as reporters/csv.py.

Machine-readable export of the full analysis: one self-describing JSON
document with metadata, chain of custody, the timeline and all anomalies.
Intended for piping into SIEM/jq/pandas — the HTML report stays the
human-facing artifact.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analyzers.anomaly import Anomaly
from analyzers.timeline import TimelineEvent


def _event_to_dict(event: TimelineEvent) -> dict[str, Any]:
    return {
        "timestamp_utc": event.timestamp_utc.isoformat()
                         if event.timestamp_utc is not None else None,
        "event_type": event.event_type,
        "browser": event.browser,
        "source_file": event.source_file,
        "source_sha256": event.source_sha256,
        "summary": event.summary,
        "details": event.details,
    }


def _anomaly_to_dict(anomaly: Anomaly) -> dict[str, Any]:
    return {
        "rule_id": anomaly.rule_id,
        "severity": anomaly.severity,
        "reason": anomaly.reason,
        "matched_value": anomaly.matched_value,
        "event": _event_to_dict(anomaly.event),
    }


def export_to_json(
    events: list[TimelineEvent],
    anomalies: list[Anomaly],
    output_path: Path,
    case_id: str = "UNSPECIFIED",
) -> Path:
    """Write the complete analysis to `output_path` as one JSON document.

    Args:
        events: list of TimelineEvent from analyzers.timeline.build_timeline()
        anomalies: list of Anomaly from analyzers.anomaly.detect()
        output_path: where to write the .json file (parent dirs auto-created)
        case_id: case identifier included in the document metadata

    Returns:
        The output_path, for convenient chaining.
    """
    # Unique source files for chain of custody (insertion order preserved).
    source_files: dict[str, str] = {}
    for e in events:
        if e.source_file not in source_files:
            source_files[e.source_file] = e.source_sha256

    document = {
        "tool": "browser-autopsy",
        "case_id": case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "stats": {
            "total_events": len(events),
            "total_anomalies": len(anomalies),
        },
        "source_files": source_files,
        "timeline": [_event_to_dict(e) for e in events],
        "anomalies": [_anomaly_to_dict(a) for a in anomalies],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    return output_path
