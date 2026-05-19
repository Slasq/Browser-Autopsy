"""
Tests for main.py — CLI parsing + orchestrator end-to-end.

Strategy:
  - _parse_iso_datetime / _parse_args : pure unit tests, no I/O
  - main()                            : monkeypatch the heavy operations
                                        (build_timeline, render_report, export_to_csv)
                                        and assert on exit codes + what was called

We do NOT call the real extractors / Jinja template here — those have their
own dedicated test files. main.py's job is plumbing, so that's what we test.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

import pytest

import main as cli_main
from main import _parse_args, _parse_iso_datetime, main


# Helpers
SAMPLE_IOC_YAML = """
suspicious_domains:
  - bad.com
suspicious_extensions:
  - .exe
suspicious_keywords:
  - mimikatz
"""


@pytest.fixture
def ioc_file(tmp_path: Path) -> Path:
    """Real IOC YAML on disk — load_iocs() is NOT mocked, it actually reads."""
    f = tmp_path / "iocs.yaml"
    f.write_text(SAMPLE_IOC_YAML, encoding="utf-8")
    return f


@pytest.fixture
def stub_pipeline(monkeypatch):
    """Replace heavy operations with no-op stubs.

    Returns a dict of call-trackers so tests can assert which functions
    were invoked and with which arguments.
    """
    calls: dict[str, list] = {
        "build_timeline": [],
        "filter_by_time": [],
        "render_report": [],
        "export_to_csv": [],
    }

    def fake_build_timeline(**kwargs):
        calls["build_timeline"].append(kwargs)
        return []  # pusty timeline → detect() zwróci []

    def fake_filter_by_time(events, **kwargs):
        calls["filter_by_time"].append(kwargs)
        return events

    def fake_render_report(events, anomalies, output_path, case_id="UNSPECIFIED"):
        calls["render_report"].append({
            "events": events,
            "anomalies": anomalies,
            "output_path": output_path,
            "case_id": case_id,
        })
        return output_path

    def fake_export_to_csv(events, anomalies, output_dir):
        calls["export_to_csv"].append({
            "events": events,
            "anomalies": anomalies,
            "output_dir": output_dir,
        })
        return output_dir / "timeline.csv", output_dir / "anomalies.csv"

    monkeypatch.setattr(cli_main, "build_timeline", fake_build_timeline)
    monkeypatch.setattr(cli_main, "filter_by_time", fake_filter_by_time)
    monkeypatch.setattr(cli_main, "render_report", fake_render_report)
    monkeypatch.setattr(cli_main, "export_to_csv", fake_export_to_csv)
    return calls


def _base_argv(ioc_file: Path, out_dir: Path) -> list[str]:
    """Minimum viable argv — chrome profile + ioc file + output dir."""
    return [
        "--chrome-profile", "/fake/chrome",
        "--ioc-file", str(ioc_file),
        "--output-dir", str(out_dir),
    ]


# _parse_iso_datetime
class TestParseIsoDatetime:

    def test_date_only(self):
        # naga data → północ UTC
        assert _parse_iso_datetime("2024-01-15") == \
            datetime(2024, 1, 15, tzinfo=timezone.utc)

    def test_naive_datetime_assumed_utc(self):
        # bez tzinfo musi być UTC (żeby porównywać się z timestamp_utc)
        assert _parse_iso_datetime("2024-01-15T22:00:00") == \
            datetime(2024, 1, 15, 22, 0, tzinfo=timezone.utc)

    def test_with_explicit_timezone(self):
        # +02:00 → offset zachowany
        result = _parse_iso_datetime("2024-01-15T22:00:00+02:00")
        assert result.utcoffset().total_seconds() == 7200

    def test_z_suffix(self):
        # 'Z' = Zulu = UTC, fromisoformat sam nie ogarnia na 3.10
        assert _parse_iso_datetime("2024-01-15T22:00:00Z") == \
            datetime(2024, 1, 15, 22, 0, tzinfo=timezone.utc)

    def test_garbage_raises_argument_type_error(self):
        with pytest.raises(argparse.ArgumentTypeError):
            _parse_iso_datetime("not a date")

    def test_invalid_month_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            _parse_iso_datetime("2024-13-01")


# _parse_args
class TestParseArgs:

    def test_chrome_profile_only(self):
        args = _parse_args(["--chrome-profile", "/fake/chrome"])
        assert args.chrome_profile == Path("/fake/chrome")
        assert args.firefox_profile is None

    def test_both_profiles(self):
        args = _parse_args([
            "--chrome-profile", "/fake/c",
            "--firefox-profile", "/fake/f",
        ])
        assert args.chrome_profile == Path("/fake/c")
        assert args.firefox_profile == Path("/fake/f")

    def test_defaults(self):
        args = _parse_args(["--chrome-profile", "/x"])
        assert args.report == "both"
        assert args.case_id == "UNSPECIFIED"
        assert args.start is None
        assert args.end is None

    def test_case_id(self):
        args = _parse_args(["--chrome-profile", "/x", "--case-id", "INC-001"])
        assert args.case_id == "INC-001"

    def test_output_dir(self):
        args = _parse_args(["--chrome-profile", "/x", "--output-dir", "/tmp/out"])
        assert args.output_dir == Path("/tmp/out")

    def test_report_choices(self):
        for fmt in ["html", "csv", "both"]:
            args = _parse_args(["--chrome-profile", "/x", "--report", fmt])
            assert args.report == fmt

    def test_invalid_report_format_exits(self):
        # argparse robi sys.exit(2) na nieprawidłowy choice
        with pytest.raises(SystemExit):
            _parse_args(["--chrome-profile", "/x", "--report", "pdf"])

    def test_start_and_end_parsed(self):
        args = _parse_args([
            "--chrome-profile", "/x",
            "--start", "2024-01-15",
            "--end", "2024-01-16T12:00:00",
        ])
        assert args.start == datetime(2024, 1, 15, tzinfo=timezone.utc)
        assert args.end == datetime(2024, 1, 16, 12, 0, tzinfo=timezone.utc)


# main() — happy paths
class TestMainHappyPath:

    def test_returns_zero_on_success(self, tmp_path, ioc_file, stub_pipeline):
        rc = main(_base_argv(ioc_file, tmp_path / "out"))
        assert rc == 0

    def test_builds_timeline_with_chrome_only(self, tmp_path, ioc_file, stub_pipeline):
        main(_base_argv(ioc_file, tmp_path / "out"))
        call = stub_pipeline["build_timeline"][0]
        assert call["chrome_profile"] == Path("/fake/chrome")
        assert call["firefox_profile"] is None

    def test_builds_timeline_with_both_profiles(self, tmp_path, ioc_file, stub_pipeline):
        main([
            "--chrome-profile", "/fake/c",
            "--firefox-profile", "/fake/f",
            "--ioc-file", str(ioc_file),
            "--output-dir", str(tmp_path / "out"),
        ])
        call = stub_pipeline["build_timeline"][0]
        assert call["chrome_profile"] == Path("/fake/c")
        assert call["firefox_profile"] == Path("/fake/f")

    def test_default_report_writes_both(self, tmp_path, ioc_file, stub_pipeline):
        main(_base_argv(ioc_file, tmp_path / "out"))
        assert len(stub_pipeline["render_report"]) == 1
        assert len(stub_pipeline["export_to_csv"]) == 1

    def test_report_html_only(self, tmp_path, ioc_file, stub_pipeline):
        main(_base_argv(ioc_file, tmp_path / "out") + ["--report", "html"])
        assert len(stub_pipeline["render_report"]) == 1
        assert len(stub_pipeline["export_to_csv"]) == 0

    def test_report_csv_only(self, tmp_path, ioc_file, stub_pipeline):
        main(_base_argv(ioc_file, tmp_path / "out") + ["--report", "csv"])
        assert len(stub_pipeline["render_report"]) == 0
        assert len(stub_pipeline["export_to_csv"]) == 1

    def test_case_id_passed_to_html_render(self, tmp_path, ioc_file, stub_pipeline):
        main(_base_argv(ioc_file, tmp_path / "out") + ["--case-id", "INC-2024-117"])
        assert stub_pipeline["render_report"][0]["case_id"] == "INC-2024-117"

    def test_html_path_under_output_dir(self, tmp_path, ioc_file, stub_pipeline):
        out = tmp_path / "out"
        main(_base_argv(ioc_file, out))
        html_path = stub_pipeline["render_report"][0]["output_path"]
        assert html_path == out / "report.html"

    def test_csv_called_with_output_dir(self, tmp_path, ioc_file, stub_pipeline):
        out = tmp_path / "out"
        main(_base_argv(ioc_file, out))
        assert stub_pipeline["export_to_csv"][0]["output_dir"] == out

    def test_output_dir_auto_created(self, tmp_path, ioc_file, stub_pipeline):
        out = tmp_path / "nested" / "deep" / "out"
        assert not out.exists()
        main(_base_argv(ioc_file, out))
        assert out.is_dir()

    def test_iocs_loaded_from_custom_file(self, tmp_path, ioc_file, stub_pipeline):
        # jeśli load_iocs by się wywaliło na braku pliku → rc=1; tu chcemy rc=0
        rc = main(_base_argv(ioc_file, tmp_path / "out"))
        assert rc == 0


# main() — error paths
class TestMainErrors:

    def test_no_profile_returns_2(self, capsys, ioc_file, tmp_path):
        # ani --chrome-profile ani --firefox-profile
        rc = main([
            "--ioc-file", str(ioc_file),
            "--output-dir", str(tmp_path / "out"),
        ])
        assert rc == 2
        assert "required" in capsys.readouterr().err.lower()

    def test_start_after_end_returns_2(self, capsys, ioc_file, tmp_path, stub_pipeline):
        rc = main(_base_argv(ioc_file, tmp_path / "out") + [
            "--start", "2024-01-20",
            "--end", "2024-01-15",
        ])
        assert rc == 2
        assert "<=" in capsys.readouterr().err or "start" in capsys.readouterr().err.lower()

    def test_missing_ioc_file_returns_1(self, capsys, tmp_path, stub_pipeline):
        rc = main([
            "--chrome-profile", "/fake/c",
            "--ioc-file", str(tmp_path / "does_not_exist.yaml"),
            "--output-dir", str(tmp_path / "out"),
        ])
        assert rc == 1

    def test_missing_artifact_returns_1(self, capsys, tmp_path, ioc_file, monkeypatch):
        # build_timeline propaguje FileNotFoundError z ekstraktorów
        def raise_fnf(**kwargs):
            raise FileNotFoundError("Artifact not found: /fake/chrome/History")
        monkeypatch.setattr(cli_main, "build_timeline", raise_fnf)

        rc = main(_base_argv(ioc_file, tmp_path / "out"))
        assert rc == 1
        assert "not found" in capsys.readouterr().err.lower()

    def test_invalid_iso_datetime_exits(self, ioc_file, tmp_path):
        # argparse robi sys.exit(2) na ArgumentTypeError
        with pytest.raises(SystemExit):
            main(_base_argv(ioc_file, tmp_path / "out") + ["--start", "totally-not-a-date"])


# main() — time-window filter
class TestTimeFilter:

    def test_filter_applied_when_start_given(self, tmp_path, ioc_file, stub_pipeline):
        main(_base_argv(ioc_file, tmp_path / "out") + ["--start", "2024-01-15"])
        assert len(stub_pipeline["filter_by_time"]) == 1
        call = stub_pipeline["filter_by_time"][0]
        assert call["start"] == datetime(2024, 1, 15, tzinfo=timezone.utc)
        assert call["end"] is None

    def test_filter_applied_when_end_given(self, tmp_path, ioc_file, stub_pipeline):
        main(_base_argv(ioc_file, tmp_path / "out") + ["--end", "2024-01-20"])
        assert len(stub_pipeline["filter_by_time"]) == 1
        call = stub_pipeline["filter_by_time"][0]
        assert call["start"] is None
        assert call["end"] == datetime(2024, 1, 20, tzinfo=timezone.utc)

    def test_filter_skipped_when_neither_given(self, tmp_path, ioc_file, stub_pipeline):
        main(_base_argv(ioc_file, tmp_path / "out"))
        assert stub_pipeline["filter_by_time"] == []

    def test_filter_applied_with_both_bounds(self, tmp_path, ioc_file, stub_pipeline):
        main(_base_argv(ioc_file, tmp_path / "out") + [
            "--start", "2024-01-15",
            "--end", "2024-01-20",
        ])
        assert len(stub_pipeline["filter_by_time"]) == 1