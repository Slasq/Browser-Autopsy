"""
Tests for reporters/json.py — machine-readable JSON export.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from analyzers.anomaly import Anomaly
from analyzers.timeline import TimelineEvent
from reporters.json import export_to_json

TS = datetime(2024, 3, 15, 10, 30, tzinfo=timezone.utc)
SHA = "a" * 64


def _event(event_type="chrome_visit", browser="chrome", ts=TS,
           source_file="History", details=None):
    return TimelineEvent(
        timestamp_utc=ts,
        event_type=event_type,
        browser=browser,
        source_file=source_file,
        source_sha256=SHA,
        summary=f"{event_type} summary",
        details=details or {"url": "https://example.com"},
    )


def _anomaly(event):
    return Anomaly(
        event=event, rule_id="SUSPICIOUS_DOMAIN", severity="high",
        reason="Connection to suspicious domain", matched_value="pastebin.com",
    )


class TestExportToJson:
    def test_writes_valid_json(self, tmp_path):
        path = export_to_json([_event()], [], tmp_path / "report.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["tool"] == "browser-autopsy"
        assert data["stats"]["total_events"] == 1

    def test_returns_output_path(self, tmp_path):
        out = tmp_path / "r.json"
        assert export_to_json([], [], out) == out

    def test_creates_parent_dirs(self, tmp_path):
        out = tmp_path / "deep" / "nested" / "r.json"
        export_to_json([], [], out)
        assert out.exists()

    def test_case_id_included(self, tmp_path):
        path = export_to_json([], [], tmp_path / "r.json", case_id="INC-42")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["case_id"] == "INC-42"

    def test_event_fields_serialized(self, tmp_path):
        path = export_to_json([_event()], [], tmp_path / "r.json")
        ev = json.loads(path.read_text(encoding="utf-8"))["timeline"][0]
        assert ev["timestamp_utc"] == "2024-03-15T10:30:00+00:00"
        assert ev["event_type"] == "chrome_visit"
        assert ev["browser"] == "chrome"
        assert ev["source_sha256"] == SHA
        assert ev["details"] == {"url": "https://example.com"}

    def test_none_timestamp_serialized_as_null(self, tmp_path):
        path = export_to_json([_event(ts=None)], [], tmp_path / "r.json")
        ev = json.loads(path.read_text(encoding="utf-8"))["timeline"][0]
        assert ev["timestamp_utc"] is None

    def test_anomaly_fields_serialized(self, tmp_path):
        ev = _event()
        path = export_to_json([ev], [_anomaly(ev)], tmp_path / "r.json")
        an = json.loads(path.read_text(encoding="utf-8"))["anomalies"][0]
        assert an["rule_id"] == "SUSPICIOUS_DOMAIN"
        assert an["severity"] == "high"
        assert an["matched_value"] == "pastebin.com"
        assert an["event"]["event_type"] == "chrome_visit"

    def test_source_files_chain_of_custody(self, tmp_path):
        events = [_event(source_file="History"),
                  _event(source_file="Cookies"),
                  _event(source_file="History")]
        path = export_to_json(events, [], tmp_path / "r.json")
        files = json.loads(path.read_text(encoding="utf-8"))["source_files"]
        assert files == {"History": SHA, "Cookies": SHA}

    def test_unicode_not_escaped(self, tmp_path):
        ev = _event(details={"query": "zażółć gęślą jaźń"})
        path = export_to_json([ev], [], tmp_path / "r.json")
        assert "zażółć gęślą jaźń" in path.read_text(encoding="utf-8")
