from __future__ import annotations

import csv as _csv  # stdlib, używany tylko do czytania w testach
import json
from datetime import datetime, timezone

import pytest

from analyzers.anomaly import Anomaly
from analyzers.timeline import TimelineEvent
from reporters.csv import (
    export_anomalies_to_csv,
    export_timeline_to_csv,
    export_to_csv,
)


# Helpers
def _ev(
    event_type: str = "chrome_visit",
    details=None,
    ts=None,
    browser: str = "chrome",
    summary: str = "test event",
) -> TimelineEvent:
    return TimelineEvent(
        timestamp_utc=ts or datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
        event_type=event_type,
        browser=browser,
        source_file="/fake/path/History",
        source_sha256="a" * 64,
        summary=summary,
        details=details or {},
    )


def _anomaly(event=None, rule_id: str = "SUSPICIOUS_DOMAIN") -> Anomaly:
    return Anomaly(
        event=event or _ev(),
        rule_id=rule_id,
        severity="high",
        reason="test reason",
        matched_value="bad.com",
    )


def _read_csv(path) -> list[dict]:
    """Read a CSV (utf-8-sig handles BOM) and return list of row dicts."""
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(_csv.DictReader(f))


# export_timeline_to_csv
class TestExportTimelineToCsv:

    def test_writes_header_and_rows(self, tmp_path):
        events = [
            _ev("chrome_visit", {"url": "https://example.com/"}),
            _ev("chrome_download", {"filename": "report.pdf"}),
        ]
        out = export_timeline_to_csv(events, tmp_path / "timeline.csv")
        assert out.exists()

        rows = _read_csv(out)
        assert len(rows) == 2
        assert rows[0]["event_type"] == "chrome_visit"
        assert rows[0]["url"] == "https://example.com/"
        assert rows[1]["event_type"] == "chrome_download"
        assert rows[1]["filename"] == "report.pdf"

    def test_empty_events_writes_only_header(self, tmp_path):
        out = export_timeline_to_csv([], tmp_path / "timeline.csv")
        rows = _read_csv(out)
        assert rows == []
        # nagłówek musi być w pliku, nawet gdy brak danych
        content = out.read_text(encoding="utf-8-sig")
        assert "timestamp_utc" in content.splitlines()[0]

    def test_details_json_roundtrip(self, tmp_path):
        details = {"url": "https://x.com/", "extra": "value", "nested": {"a": 1}}
        out = export_timeline_to_csv(
            [_ev("chrome_visit", details)], tmp_path / "t.csv",
        )
        row = _read_csv(out)[0]
        parsed = json.loads(row["details_json"])
        assert parsed == details

    def test_polish_chars_preserved(self, tmp_path):
        # BOM + UTF-8 powinno przepuścić polskie znaki w queryach
        events = [_ev("chrome_search", {"query": "jak włamać się żółć"})]
        out = export_timeline_to_csv(events, tmp_path / "t.csv")
        row = _read_csv(out)[0]
        assert row["query"] == "jak włamać się żółć"

    def test_bom_present_for_excel(self, tmp_path):
        # czytamy raw bytes — pierwsze 3 bajty muszą być UTF-8 BOM
        out = export_timeline_to_csv([_ev()], tmp_path / "t.csv")
        raw = out.read_bytes()
        assert raw[:3] == b"\xef\xbb\xbf"

    def test_creates_parent_dirs(self, tmp_path):
        # parent nie istnieje — funkcja musi go utworzyć
        out_path = tmp_path / "nested" / "subdir" / "timeline.csv"
        out = export_timeline_to_csv([_ev()], out_path)
        assert out.exists()

    def test_timestamp_iso_format(self, tmp_path):
        ts = datetime(2024, 3, 15, 14, 30, 45, tzinfo=timezone.utc)
        out = export_timeline_to_csv([_ev(ts=ts)], tmp_path / "t.csv")
        row = _read_csv(out)[0]
        # ISO 8601 z offsetem UTC
        assert "2024-03-15" in row["timestamp_utc"]
        assert "14:30:45" in row["timestamp_utc"]

    def test_missing_details_keys_become_empty_strings(self, tmp_path):
        # event bez 'url' / 'query' / 'filename' — puste kolumny, nie KeyError
        out = export_timeline_to_csv(
            [_ev("chrome_visit", {"random_field": "x"})],
            tmp_path / "t.csv",
        )
        row = _read_csv(out)[0]
        assert row["url"] == ""
        assert row["query"] == ""
        assert row["filename"] == ""


# export_anomalies_to_csv
class TestExportAnomaliesToCsv:

    def test_writes_anomalies(self, tmp_path):
        anomalies = [
            _anomaly(rule_id="SUSPICIOUS_DOMAIN"),
            _anomaly(rule_id="SUSPICIOUS_EXTENSION"),
        ]
        out = export_anomalies_to_csv(anomalies, tmp_path / "anomalies.csv")
        rows = _read_csv(out)
        assert len(rows) == 2
        assert rows[0]["rule_id"] == "SUSPICIOUS_DOMAIN"
        assert rows[1]["rule_id"] == "SUSPICIOUS_EXTENSION"

    def test_empty_anomalies_writes_only_header(self, tmp_path):
        out = export_anomalies_to_csv([], tmp_path / "anomalies.csv")
        rows = _read_csv(out)
        assert rows == []
        content = out.read_text(encoding="utf-8-sig")
        assert "rule_id" in content.splitlines()[0]

    def test_event_context_in_row(self, tmp_path):
        # anomalia musi nieść kontekst eventu (browser, source_file etc.)
        event = _ev(
            event_type="firefox_download",
            browser="firefox",
            summary="downloaded malware.exe",
        )
        out = export_anomalies_to_csv(
            [_anomaly(event=event)], tmp_path / "anomalies.csv",
        )
        row = _read_csv(out)[0]
        assert row["browser"] == "firefox"
        assert row["event_type"] == "firefox_download"
        assert row["summary"] == "downloaded malware.exe"
        assert row["source_sha256"] == "a" * 64

    def test_bom_present_for_excel(self, tmp_path):
        out = export_anomalies_to_csv([_anomaly()], tmp_path / "a.csv")
        assert out.read_bytes()[:3] == b"\xef\xbb\xbf"


# export_to_csv (orchestrator)
class TestExportToCsv:

    def test_creates_both_files(self, tmp_path):
        events = [_ev("chrome_visit", {"url": "https://example.com/"})]
        anomalies = [_anomaly()]
        timeline_path, anomalies_path = export_to_csv(
            events, anomalies, tmp_path,
        )
        assert timeline_path.exists()
        assert anomalies_path.exists()
        assert timeline_path.name == "timeline.csv"
        assert anomalies_path.name == "anomalies.csv"

    def test_creates_output_dir(self, tmp_path):
        out_dir = tmp_path / "fresh_dir"
        timeline_path, anomalies_path = export_to_csv([_ev()], [_anomaly()], out_dir)
        assert out_dir.is_dir()
        assert timeline_path.parent == out_dir
        assert anomalies_path.parent == out_dir

    def test_both_empty_inputs_still_produces_files(self, tmp_path):
        # nawet pusty case ma dawać dwa pliki z samymi nagłówkami
        timeline_path, anomalies_path = export_to_csv([], [], tmp_path)
        assert timeline_path.exists()
        assert anomalies_path.exists()
        assert _read_csv(timeline_path) == []
        assert _read_csv(anomalies_path) == []