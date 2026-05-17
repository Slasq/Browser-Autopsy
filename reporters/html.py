"""
NOTE: Render a self-contained HTML forensic report via Jinja2.
Entry point: `render_report()`. The template at templates/report.html
includes inline CSS and @media print rules — no external assets needed.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from analyzers.anomaly import Anomaly
from analyzers.timeline import TimelineEvent


_TEMPLATE_DIR: Path = Path(__file__).parent / "templates"
_TEMPLATE_NAME: str = "report.html"

# Severity ordering — high first, unknown values sink to the bottom.
_SEVERITY_RANK: dict[str, int] = {"high": 0, "medium": 1, "low": 2}


# Context builder
def _build_context(
    events: list[TimelineEvent],
    anomalies: list[Anomaly],
    case_id: str,
) -> dict[str, Any]:
    """Compose the Jinja2 render context from raw events + anomalies."""

    # Pair each event with the anomalies that triggered on it.
    # detect() preserves the original TimelineEvent reference in Anomaly.event,
    # so id() comparison is reliable here.
    by_event_id: dict[int, list[Anomaly]] = defaultdict(list)
    for a in anomalies:
        by_event_id[id(a.event)].append(a)
    events_with_anomalies = [(e, by_event_id.get(id(e), [])) for e in events]

    # Unique source files for chain of custody display.
    # dict preserves insertion order in 3.7+, so output is deterministic.
    source_files: dict[str, str] = {}
    for e in events:
        if e.source_file not in source_files:
            source_files[e.source_file] = e.source_sha256

    # Anomalies sorted for the dedicated table (severity desc, then time asc)
    anomalies_sorted = sorted(
        anomalies,
        key=lambda a: (_SEVERITY_RANK.get(a.severity, 99), a.event.timestamp_utc),
    )

    # Stats — Counter is a dict subclass, jinja can iterate it directly
    events_by_type = Counter(e.event_type for e in events)
    events_by_browser = Counter(e.browser for e in events)
    anomalies_by_severity = Counter(a.severity for a in anomalies)
    anomalies_by_rule = Counter(a.rule_id for a in anomalies)

    return {
        "case_id": case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_files": source_files,
        "events": events,
        "events_with_anomalies": events_with_anomalies,
        "anomalies": anomalies,
        "anomalies_sorted": anomalies_sorted,
        "stats": {
            "total_events": len(events),
            "total_anomalies": len(anomalies),
            # most_common() returns sorted (value desc) tuples; dict() preserves order
            "events_by_type": dict(events_by_type.most_common()),
            "events_by_browser": dict(events_by_browser.most_common()),
            "anomalies_by_severity": dict(anomalies_by_severity),
            "anomalies_by_rule": dict(anomalies_by_rule.most_common()),
        },
    }


# Public API
def render_report(
    events: list[TimelineEvent],
    anomalies: list[Anomaly],
    output_path: Path,
    case_id: str = "UNSPECIFIED",
) -> Path:
    """Render a complete HTML report to `output_path`.

    Args:
        events: list of TimelineEvent from analyzers.timeline.build_timeline()
        anomalies: list of Anomaly from analyzers.anomaly.detect()
        output_path: where to write the .html file (parent dirs auto-created)
        case_id: case identifier shown in the report header (default UNSPECIFIED)

    Returns:
        The output_path, for convenient chaining.

    Raises:
        jinja2.TemplateNotFound: if reporters/templates/report.html is missing
    """
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(enabled_extensions=("html",)),
        # whitespace trimming makes the output a touch less noisy
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(_TEMPLATE_NAME)
    context = _build_context(events, anomalies, case_id)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(template.render(**context), encoding="utf-8")
    return output_path