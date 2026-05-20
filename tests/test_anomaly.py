"""Tests for analyzers/anomaly.py — all three v1 detectors + config loader."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from analyzers.anomaly import (
    IOCs,
    detect,
    detect_suspicious_domains,
    detect_suspicious_extensions,
    detect_suspicious_keywords,
    load_iocs,
)
from analyzers.timeline import TimelineEvent


# Helpers
def _ev(event_type: str, details=None, ts=None) -> TimelineEvent:
    """Build a minimal TimelineEvent for testing."""
    return TimelineEvent(
        timestamp_utc=ts or datetime(2024, 1, 1, tzinfo=timezone.utc),
        event_type=event_type,
        browser="chrome",
        source_file="/fake/path",
        source_sha256="0" * 64,
        summary="test event",
        details=details or {},
    )


@pytest.fixture
def sample_iocs() -> IOCs:
    return IOCs(
        suspicious_domains=frozenset({"bad-c2.com", "*.onion", "pastebin.com"}),
        suspicious_extensions=frozenset({".exe", ".ps1", ".scr"}),
        suspicious_keywords=frozenset({"mimikatz", "bypass uac", "disable defender"}),
    )


# load_iocs
class TestLoadIOCs:

    def test_loads_valid_yaml(self, tmp_path):
        f = tmp_path / "iocs.yaml"
        f.write_text(
            "suspicious_domains:\n  - bad.com\n"
            "suspicious_extensions:\n  - .exe\n"
            "suspicious_keywords:\n  - mimikatz\n",
            encoding="utf-8",
        )
        iocs = load_iocs(f)
        assert "bad.com" in iocs.suspicious_domains
        assert ".exe" in iocs.suspicious_extensions
        assert "mimikatz" in iocs.suspicious_keywords

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_iocs(tmp_path / "does_not_exist.yaml")

    def test_extensions_get_leading_dot(self, tmp_path):
        # YAMLowy "exe" bez kropki też ma działać
        f = tmp_path / "iocs.yaml"
        f.write_text("suspicious_extensions:\n  - exe\n  - .scr\n", encoding="utf-8")
        iocs = load_iocs(f)
        assert ".exe" in iocs.suspicious_extensions
        assert ".scr" in iocs.suspicious_extensions

    def test_case_insensitive_normalisation(self, tmp_path):
        f = tmp_path / "iocs.yaml"
        f.write_text(
            "suspicious_domains:\n  - BAD.COM\n"
            "suspicious_extensions:\n  - .EXE\n"
            "suspicious_keywords:\n  - Mimikatz\n",
            encoding="utf-8",
        )
        iocs = load_iocs(f)
        assert "bad.com" in iocs.suspicious_domains
        assert ".exe" in iocs.suspicious_extensions
        assert "mimikatz" in iocs.suspicious_keywords

    def test_empty_yaml(self, tmp_path):
        f = tmp_path / "iocs.yaml"
        f.write_text("", encoding="utf-8")
        iocs = load_iocs(f)
        assert iocs.suspicious_domains == frozenset()
        assert iocs.suspicious_extensions == frozenset()
        assert iocs.suspicious_keywords == frozenset()

    def test_missing_keys_treated_as_empty(self, tmp_path):
        # tylko jedna kategoria zdefiniowana
        f = tmp_path / "iocs.yaml"
        f.write_text("suspicious_keywords:\n  - mimikatz\n", encoding="utf-8")
        iocs = load_iocs(f)
        assert iocs.suspicious_domains == frozenset()
        assert iocs.suspicious_extensions == frozenset()
        assert "mimikatz" in iocs.suspicious_keywords


# detect_suspicious_domains
class TestDetectSuspiciousDomains:

    def test_exact_match(self, sample_iocs):
        events = [_ev("chrome_visit", {"url": "https://bad-c2.com/payload"})]
        out = detect_suspicious_domains(events, sample_iocs.suspicious_domains)
        assert len(out) == 1
        assert out[0].rule_id == "SUSPICIOUS_DOMAIN"
        assert out[0].matched_value == "bad-c2.com"
        assert out[0].severity == "high"

    def test_strips_www_prefix(self, sample_iocs):
        events = [_ev("chrome_visit", {"url": "https://www.bad-c2.com/"})]
        out = detect_suspicious_domains(events, sample_iocs.suspicious_domains)
        assert len(out) == 1

    def test_wildcard_suffix(self, sample_iocs):
        events = [
            _ev("chrome_visit", {"url": "http://abc123.onion/forum"}),
            _ev("chrome_visit", {"url": "http://xyz.onion/"}),
        ]
        out = detect_suspicious_domains(events, sample_iocs.suspicious_domains)
        assert len(out) == 2
        assert all(a.matched_value == "*.onion" for a in out)

    def test_clean_domain_not_flagged(self, sample_iocs):
        events = [_ev("chrome_visit", {"url": "https://example.com/"})]
        assert detect_suspicious_domains(events, sample_iocs.suspicious_domains) == []

    def test_subdomain_of_exact_not_matched(self, sample_iocs):
        # "pastebin.com" w IOC; "sub.pastebin.com" NIE powinno trafić
        events = [_ev("chrome_visit", {"url": "https://sub.pastebin.com/"})]
        assert detect_suspicious_domains(events, sample_iocs.suspicious_domains) == []

    def test_downloads_checked(self, sample_iocs):
        events = [_ev("chrome_download", {
            "url": "https://bad-c2.com/file.zip",
            "filename": "file.zip",
        })]
        out = detect_suspicious_domains(events, sample_iocs.suspicious_domains)
        assert len(out) == 1

    def test_searches_skipped(self, sample_iocs):
        # google.com itp. nigdy nie powinny być flagowane przez ten detektor
        events = [_ev("chrome_search", {
            "url": "https://google.com/search?q=x", "query": "x",
        })]
        assert detect_suspicious_domains(events, sample_iocs.suspicious_domains) == []

    def test_missing_url_skipped(self, sample_iocs):
        events = [_ev("chrome_visit", {})]
        assert detect_suspicious_domains(events, sample_iocs.suspicious_domains) == []

    def test_url_with_port(self, sample_iocs):
        events = [_ev("chrome_visit", {"url": "http://bad-c2.com:8080/"})]
        out = detect_suspicious_domains(events, sample_iocs.suspicious_domains)
        assert len(out) == 1


# detect_suspicious_extensions
class TestDetectSuspiciousExtensions:

    def test_flags_exe(self, sample_iocs):
        events = [_ev("chrome_download", {"filename": "malware.exe"})]
        out = detect_suspicious_extensions(events, sample_iocs.suspicious_extensions)
        assert len(out) == 1
        assert out[0].rule_id == "SUSPICIOUS_EXTENSION"
        assert out[0].severity == "medium"
        assert out[0].matched_value == ".exe"

    def test_case_insensitive(self, sample_iocs):
        events = [_ev("chrome_download", {"filename": "Malware.EXE"})]
        out = detect_suspicious_extensions(events, sample_iocs.suspicious_extensions)
        assert len(out) == 1

    def test_double_extension_trick(self, sample_iocs):
        events = [_ev("chrome_download", {"filename": "invoice.pdf.exe"})]
        out = detect_suspicious_extensions(events, sample_iocs.suspicious_extensions)
        assert len(out) == 1
        assert out[0].rule_id == "DOUBLE_EXTENSION"
        assert out[0].severity == "high"
        assert ".pdf" in out[0].matched_value

    def test_double_ext_with_non_benign_first(self, sample_iocs):
        # 'tool.exe.exe' — pierwsze rozszerzenie nie wygląda na dokument,
        # klasyfikujemy jako zwykłe SUSPICIOUS_EXTENSION
        events = [_ev("chrome_download", {"filename": "tool.exe.exe"})]
        out = detect_suspicious_extensions(events, sample_iocs.suspicious_extensions)
        assert len(out) == 1
        assert out[0].rule_id == "SUSPICIOUS_EXTENSION"

    def test_clean_extension(self, sample_iocs):
        events = [_ev("chrome_download", {"filename": "report.pdf"})]
        assert detect_suspicious_extensions(events, sample_iocs.suspicious_extensions) == []

    def test_visits_skipped(self, sample_iocs):
        events = [_ev("chrome_visit", {"url": "https://example.com/foo.exe"})]
        assert detect_suspicious_extensions(events, sample_iocs.suspicious_extensions) == []

    def test_no_extension_skipped(self, sample_iocs):
        events = [_ev("chrome_download", {"filename": "Makefile"})]
        assert detect_suspicious_extensions(events, sample_iocs.suspicious_extensions) == []

    def test_fallback_to_target_path_windows(self, sample_iocs):
        # gdy `filename` puste, używamy basename(target_path) — z backslashami
        events = [_ev("chrome_download", {
            "filename": "",
            "target_path": r"C:\Users\victim\Downloads\malware.exe",
        })]
        out = detect_suspicious_extensions(events, sample_iocs.suspicious_extensions)
        assert len(out) == 1
        assert out[0].matched_value == ".exe"

    def test_fallback_to_target_path_unix(self, sample_iocs):
        events = [_ev("chrome_download", {
            "filename": "",
            "target_path": "/home/victim/Downloads/malware.ps1",
        })]
        out = detect_suspicious_extensions(events, sample_iocs.suspicious_extensions)
        assert len(out) == 1
        assert out[0].matched_value == ".ps1"


# detect_suspicious_keywords
class TestDetectSuspiciousKeywords:

    def test_exact_keyword(self, sample_iocs):
        events = [_ev("chrome_search", {"query": "mimikatz download"})]
        out = detect_suspicious_keywords(events, sample_iocs.suspicious_keywords)
        assert len(out) == 1
        assert out[0].rule_id == "SUSPICIOUS_KEYWORD"
        assert out[0].matched_value == "mimikatz"

    def test_case_insensitive(self, sample_iocs):
        events = [_ev("chrome_search", {"query": "MimiKatz tutorial"})]
        out = detect_suspicious_keywords(events, sample_iocs.suspicious_keywords)
        assert len(out) == 1

    def test_multi_word_keyword(self, sample_iocs):
        events = [_ev("chrome_search", {"query": "how to bypass uac on windows 10"})]
        out = detect_suspicious_keywords(events, sample_iocs.suspicious_keywords)
        assert len(out) == 1
        assert out[0].matched_value == "bypass uac"

    def test_clean_query(self, sample_iocs):
        events = [_ev("chrome_search", {"query": "python tutorial"})]
        assert detect_suspicious_keywords(events, sample_iocs.suspicious_keywords) == []

    def test_visits_skipped(self, sample_iocs):
        events = [_ev("chrome_visit", {"url": "https://example.com/mimikatz"})]
        assert detect_suspicious_keywords(events, sample_iocs.suspicious_keywords) == []

    def test_one_anomaly_per_event(self, sample_iocs):
        # query trafia w DWA keywordy — chcemy tylko jeden anomaly
        events = [_ev("chrome_search", {"query": "mimikatz bypass uac"})]
        out = detect_suspicious_keywords(events, sample_iocs.suspicious_keywords)
        assert len(out) == 1

    def test_empty_query_skipped(self, sample_iocs):
        events = [_ev("chrome_search", {"query": ""})]
        assert detect_suspicious_keywords(events, sample_iocs.suspicious_keywords) == []

    def test_missing_query_key_skipped(self, sample_iocs):
        events = [_ev("chrome_search", {})]
        assert detect_suspicious_keywords(events, sample_iocs.suspicious_keywords) == []


# detect() — orchestrator
class TestDetectOrchestrator:

    def test_all_three_detectors_run(self, sample_iocs):
        events = [
            _ev("chrome_visit",    {"url": "https://bad-c2.com/"},
                ts=datetime(2024, 1, 1, tzinfo=timezone.utc)),
            _ev("chrome_download", {"filename": "malware.exe"},
                ts=datetime(2024, 1, 2, tzinfo=timezone.utc)),
            _ev("chrome_search",   {"query": "mimikatz tutorial"},
                ts=datetime(2024, 1, 3, tzinfo=timezone.utc)),
        ]
        out = detect(events, sample_iocs)
        rule_ids = {a.rule_id for a in out}
        assert rule_ids == {"SUSPICIOUS_DOMAIN", "SUSPICIOUS_EXTENSION", "SUSPICIOUS_KEYWORD"}

    def test_results_sorted_chronologically(self, sample_iocs):
        events = [
            _ev("chrome_search",   {"query": "mimikatz"},
                ts=datetime(2024, 1, 3, tzinfo=timezone.utc)),
            _ev("chrome_visit",    {"url": "https://bad-c2.com/"},
                ts=datetime(2024, 1, 1, tzinfo=timezone.utc)),
            _ev("chrome_download", {"filename": "x.exe"},
                ts=datetime(2024, 1, 2, tzinfo=timezone.utc)),
        ]
        out = detect(events, sample_iocs)
        timestamps = [a.event.timestamp_utc for a in out]
        assert timestamps == sorted(timestamps)

    def test_no_events_no_anomalies(self, sample_iocs):
        assert detect([], sample_iocs) == []

    def test_clean_timeline_no_anomalies(self, sample_iocs):
        events = [
            _ev("chrome_visit",    {"url": "https://example.com/"}),
            _ev("chrome_download", {"filename": "report.pdf"}),
            _ev("chrome_search",   {"query": "python tutorial"}),
        ]
        assert detect(events, sample_iocs) == []

    def test_firefox_events_also_handled(self, sample_iocs):
        # detektory używają "search in event_type", więc firefox_* też lapie
        events = [
            _ev("firefox_visit",    {"url": "https://bad-c2.com/"}),
            _ev("firefox_download", {"filename": "x.exe"}),
            _ev("firefox_search",   {"query": "mimikatz"}),
        ]
        out = detect(events, sample_iocs)
        assert len(out) == 3