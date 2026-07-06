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


def _viz_category(event_type: str) -> str:
    """Bucket an event_type into one of the visual timeline categories."""
    for cat in ("download", "search", "visit"):
        if cat in event_type:
            return cat
    return "other"


def _build_hourly_activity(events: list[TimelineEvent]) -> list[dict[str, Any]]:
    """24 bins (0-23 UTC) with counts and bar heights in % of the max bin."""
    hour_counts = Counter(
        e.timestamp_utc.hour for e in events if e.timestamp_utc is not None
    )
    max_count = max(hour_counts.values(), default=0)
    return [
        {
            "hour": h,
            "count": hour_counts.get(h, 0),
            "pct": round(hour_counts.get(h, 0) / max_count * 100, 1)
                   if max_count else 0,
        }
        for h in range(24)
    ]


def _build_viz_timeline(
    events: list[TimelineEvent],
    by_event_id: dict[int, list[Anomaly]],
) -> dict[str, Any] | None:
    """Precompute the visual timeline strip: one row per browser, each event
    as a dot at its %-position within the case time span.

    Rendered by pure CSS (absolute-positioned dots) — no JS, no SVG scaling
    issues, print-safe. Returns None when there are no timestamped events.
    """
    timed = [e for e in events if e.timestamp_utc is not None]
    if not timed:
        return None

    start = min(e.timestamp_utc for e in timed)
    end = max(e.timestamp_utc for e in timed)
    span = (end - start).total_seconds()

    rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in timed:
        x = 50.0 if span == 0 else \
            (e.timestamp_utc - start).total_seconds() / span * 100
        rows[e.browser].append({
            "x_pct": round(x, 2),
            "category": _viz_category(e.event_type),
            "is_anomaly": bool(by_event_id.get(id(e))),
            "title": f"{e.timestamp_utc:%Y-%m-%d %H:%M} UTC — {e.summary[:100]}",
        })

    return {
        "start_label": start.strftime("%Y-%m-%d %H:%M UTC"),
        "end_label": end.strftime("%Y-%m-%d %H:%M UTC"),
        "rows": [{"browser": b, "points": pts} for b, pts in rows.items()],
    }


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
        key=lambda a: (_SEVERITY_RANK.get(a.severity, 99), a.event.timestamp_utc is None, a.event.timestamp_utc),
    )

    # Stats — Counter is a dict subclass, jinja can iterate it directly
    events_by_type = Counter(e.event_type for e in events)
    events_by_browser = Counter(e.browser for e in events)
    anomalies_by_severity = Counter(a.severity for a in anomalies)
    anomalies_by_rule = Counter(a.rule_id for a in anomalies)

    return {
        "case_id": case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "activity_by_hour": _build_hourly_activity(events),
        "viz_timeline": _build_viz_timeline(events, by_event_id),
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