from __future__ import annotations

from datetime import datetime, timezone

import pytest

from analyzers.anomaly import Anomaly
from analyzers.timeline import TimelineEvent
from reporters.html import _build_context, render_report



# Helpers
def _ev(
    event_type: str = "chrome_visit",
    details=None,
    ts=None,
    browser: str = "chrome",
    source_file: str = "/fake/History",
    source_sha256: str = "a" * 64,
    summary: str = "test event",
) -> TimelineEvent:
    return TimelineEvent(
        timestamp_utc=ts or datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
        event_type=event_type,
        browser=browser,
        source_file=source_file,
        source_sha256=source_sha256,
        summary=summary,
        details=details or {},
    )


def _anomaly(
    event=None,
    rule_id: str = "SUSPICIOUS_DOMAIN",
    severity: str = "high",
    reason: str = "test reason",
    matched_value: str = "bad.com",
) -> Anomaly:
    return Anomaly(
        event=event or _ev(),
        rule_id=rule_id,
        severity=severity,
        reason=reason,
        matched_value=matched_value,
    )


# _build_context
class TestBuildContext:

    def test_basic_fields(self):
        ctx = _build_context([_ev()], [_anomaly()], case_id="CASE-001")
        assert ctx["case_id"] == "CASE-001"
        assert "T" in ctx["generated_at"]  # ISO 8601 has 'T' separator
        assert ctx["stats"]["total_events"] == 1
        assert ctx["stats"]["total_anomalies"] == 1

    def test_default_case_id(self):
        # default ma być UNSPECIFIED gdy nie podano
        ctx = _build_context([], [], case_id="UNSPECIFIED")
        assert ctx["case_id"] == "UNSPECIFIED"

    def test_unique_source_files(self):
        # 3 eventy z 2 unique source files -> 2 wpisy w source_files
        events = [
            _ev(source_file="/a/History", source_sha256="aa" * 32),
            _ev(source_file="/b/History", source_sha256="bb" * 32),
            _ev(source_file="/a/History", source_sha256="aa" * 32),  # duplicate
        ]
        ctx = _build_context(events, [], case_id="X")
        assert len(ctx["source_files"]) == 2
        assert ctx["source_files"]["/a/History"] == "aa" * 32
        assert ctx["source_files"]["/b/History"] == "bb" * 32

    def test_events_with_anomalies_mapping(self):
        # eventy splatane z anomaliami via id() — używam shared reference
        ev1 = _ev(event_type="chrome_visit")
        ev2 = _ev(event_type="chrome_download")
        a = _anomaly(event=ev1)  # tylko ev1 ma anomalia
        ctx = _build_context([ev1, ev2], [a], case_id="X")

        pairs = ctx["events_with_anomalies"]
        assert len(pairs) == 2
        # ev1: dostał anomalia
        assert pairs[0][0] is ev1
        assert len(pairs[0][1]) == 1
        # ev2: brak
        assert pairs[1][0] is ev2
        assert pairs[1][1] == []

    def test_anomalies_sorted_by_severity_then_time(self):
        ev_low = _ev(ts=datetime(2024, 1, 1, tzinfo=timezone.utc))
        ev_high_late = _ev(ts=datetime(2024, 1, 3, tzinfo=timezone.utc))
        ev_high_early = _ev(ts=datetime(2024, 1, 2, tzinfo=timezone.utc))
        ev_med = _ev(ts=datetime(2024, 1, 1, tzinfo=timezone.utc))

        anomalies = [
            _anomaly(event=ev_low, severity="low"),
            _anomaly(event=ev_high_late, severity="high"),
            _anomaly(event=ev_high_early, severity="high"),
            _anomaly(event=ev_med, severity="medium"),
        ]
        ctx = _build_context([], anomalies, case_id="X")
        sorted_severities = [a.severity for a in ctx["anomalies_sorted"]]
        assert sorted_severities == ["high", "high", "medium", "low"]
        # wśród "high" — wcześniejsza timestamp pierwsza
        first_two = ctx["anomalies_sorted"][:2]
        assert first_two[0].event.timestamp_utc < first_two[1].event.timestamp_utc

    def test_stats_counts(self):
        events = [
            _ev(event_type="chrome_visit", browser="chrome"),
            _ev(event_type="chrome_visit", browser="chrome"),
            _ev(event_type="firefox_download", browser="firefox"),
        ]
        anomalies = [
            _anomaly(severity="high", rule_id="SUSPICIOUS_DOMAIN"),
            _anomaly(severity="medium", rule_id="SUSPICIOUS_EXTENSION"),
            _anomaly(severity="medium", rule_id="SUSPICIOUS_EXTENSION"),
        ]
        ctx = _build_context(events, anomalies, case_id="X")

        assert ctx["stats"]["total_events"] == 3
        assert ctx["stats"]["total_anomalies"] == 3
        assert ctx["stats"]["events_by_type"]["chrome_visit"] == 2
        assert ctx["stats"]["events_by_type"]["firefox_download"] == 1
        assert ctx["stats"]["events_by_browser"]["chrome"] == 2
        assert ctx["stats"]["events_by_browser"]["firefox"] == 1
        assert ctx["stats"]["anomalies_by_severity"]["high"] == 1
        assert ctx["stats"]["anomalies_by_severity"]["medium"] == 2
        assert ctx["stats"]["anomalies_by_rule"]["SUSPICIOUS_EXTENSION"] == 2

    def test_empty_inputs(self):
        ctx = _build_context([], [], case_id="X")
        assert ctx["stats"]["total_events"] == 0
        assert ctx["stats"]["total_anomalies"] == 0
        assert ctx["source_files"] == {}
        assert ctx["events_with_anomalies"] == []
        assert ctx["anomalies_sorted"] == []


# render_report — integration tests against the real template
class TestRenderReport:

    def test_creates_output_file(self, tmp_path):
        out_path = tmp_path / "report.html"
        result = render_report([_ev()], [_anomaly()], out_path, case_id="CASE-001")
        assert result == out_path
        assert out_path.exists()
        assert out_path.stat().st_size > 0

    def test_creates_parent_dirs(self, tmp_path):
        out_path = tmp_path / "nested" / "deep" / "report.html"
        render_report([_ev()], [_anomaly()], out_path, case_id="X")
        assert out_path.exists()

    def test_case_id_in_output(self, tmp_path):
        out = tmp_path / "report.html"
        render_report([_ev()], [], out, case_id="INCIDENT-2024-117")
        html = out.read_text(encoding="utf-8")
        assert "INCIDENT-2024-117" in html

    def test_renders_with_empty_inputs(self, tmp_path):
        # nawet pusty case ma się zrenderować — żaden crash
        out = tmp_path / "report.html"
        render_report([], [], out, case_id="EMPTY")
        html = out.read_text(encoding="utf-8")
        assert "EMPTY" in html
        # empty-note powinno się pojawić zamiast tabeli
        assert "No anomalies detected" in html
        assert "No timeline events" in html

    def test_anomaly_appears_in_html(self, tmp_path):
        ev = _ev(summary="visited bad domain")
        a = _anomaly(
            event=ev,
            rule_id="SUSPICIOUS_DOMAIN",
            matched_value="*.onion",
            reason="connection to onion service",
        )
        out = tmp_path / "report.html"
        render_report([ev], [a], out, case_id="X")
        html = out.read_text(encoding="utf-8")
        assert "SUSPICIOUS_DOMAIN" in html
        assert "*.onion" in html
        assert "connection to onion service" in html

    def test_source_file_appears_in_html(self, tmp_path):
        ev = _ev(source_file="/evidence/chrome/History", source_sha256="deadbeef" * 8)
        out = tmp_path / "report.html"
        render_report([ev], [], out, case_id="X")
        html = out.read_text(encoding="utf-8")
        assert "/evidence/chrome/History" in html
        assert "deadbeef" * 8 in html

    def test_html_escapes_user_data(self, tmp_path):
        # XSS w summary nie może wyciec do HTMLa
        ev = _ev(summary="<script>alert('xss')</script>")
        out = tmp_path / "report.html"
        render_report([ev], [], out, case_id="X")
        html = out.read_text(encoding="utf-8")
        # raw <script> nie może pojawić się jako tag
        assert "<script>alert" not in html
        # ale escapowana wersja musi być widoczna
        assert "&lt;script&gt;" in html

    def test_html_escapes_case_id(self, tmp_path):
        # case_id przychodzi z CLI, może być wstrzyknięte
        out = tmp_path / "report.html"
        render_report([], [], out, case_id="<img src=x onerror=alert(1)>")
        html = out.read_text(encoding="utf-8")
        assert "<img src=x onerror=" not in html
        assert "&lt;img" in html

    def test_polish_chars_preserved(self, tmp_path):
        ev = _ev(details={"query": "jak włamać się żółć"}, summary="search: żółć")
        out = tmp_path / "report.html"
        render_report([ev], [], out, case_id="POLSKA-001")
        html = out.read_text(encoding="utf-8")
        assert "POLSKA-001" in html
        assert "żółć" in html

    def test_anomaly_highlights_event_in_timeline(self, tmp_path):
        ev = _ev(summary="malicious event")
        a = _anomaly(event=ev)
        out = tmp_path / "report.html"
        render_report([ev], [a], out, case_id="X")
        html = out.read_text(encoding="utf-8")
        # event w timeline powinien mieć klasę has-anomaly
        assert 'class="has-anomaly"' in html

    def test_event_without_anomaly_not_highlighted(self, tmp_path):
        ev = _ev()
        out = tmp_path / "report.html"
        render_report([ev], [], out, case_id="X")
        html = out.read_text(encoding="utf-8")
        # event bez anomalii — żaden <tr> nie powinien mieć class="has-anomaly".
        # Sprawdzamy konkretny attribute, nie samego stringa — bo "has-anomaly"
        # występuje też w selektorach CSS w <style>.
        assert 'class="has-anomaly"' not in html

    def test_stats_section_shows_totals(self, tmp_path):
        events = [_ev() for _ in range(5)]
        anomalies = [_anomaly() for _ in range(3)]
        out = tmp_path / "report.html"
        render_report(events, anomalies, out, case_id="X")
        html = out.read_text(encoding="utf-8")
        # liczby muszą gdzieś być
        assert ">5<" in html  # total events
        assert ">3<" in html  # total anomalies

    def test_renders_valid_html_structure(self, tmp_path):
        out = tmp_path / "report.html"
        render_report([_ev()], [_anomaly()], out, case_id="X")
        html = out.read_text(encoding="utf-8")
        # bardzo lekka walidacja struktury
        assert html.startswith("<!DOCTYPE html>")
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html and "</head>" in html
        assert "<body>" in html and "</body>" in html