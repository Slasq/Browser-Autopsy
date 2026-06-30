"""
Tests for Chromium-family profile path detection in extractors/chrome.py.
"""
from pathlib import Path

import pytest

from extractors.chrome import (
    CHROMIUM_BROWSERS,
    detect_chromium_profiles,
    get_default_profile_path,
)


class TestChromiumBrowsers:
    def test_contains_core_browsers(self):
        for name in ("chrome", "edge", "brave", "opera", "vivaldi"):
            assert name in CHROMIUM_BROWSERS

    def test_all_entries_are_strings(self):
        assert all(isinstance(b, str) for b in CHROMIUM_BROWSERS)


class TestGetDefaultProfilePath:
    @pytest.mark.parametrize("system", ["Windows", "Darwin", "Linux"])
    def test_chrome_returns_path_on_all_platforms(self, system):
        result = get_default_profile_path("chrome", system=system)
        assert isinstance(result, Path)

    @pytest.mark.parametrize("browser", ["chrome", "edge", "brave", "opera", "vivaldi", "chromium", "yandex"])
    def test_all_browsers_have_path_on_windows(self, browser):
        result = get_default_profile_path(browser, system="Windows")
        assert result is not None

    @pytest.mark.parametrize("browser", ["chrome", "edge", "brave", "opera", "vivaldi", "chromium", "yandex"])
    def test_all_browsers_have_path_on_darwin(self, browser):
        result = get_default_profile_path(browser, system="Darwin")
        assert result is not None

    @pytest.mark.parametrize("browser", ["chrome", "edge", "brave", "opera", "vivaldi", "chromium", "yandex"])
    def test_all_browsers_have_path_on_linux(self, browser):
        result = get_default_profile_path(browser, system="Linux")
        assert result is not None

    def test_unknown_browser_returns_none(self):
        assert get_default_profile_path("netscape", system="Windows") is None
        assert get_default_profile_path("netscape", system="Linux") is None

    def test_unknown_platform_returns_none(self):
        assert get_default_profile_path("chrome", system="FreeBSD") is None

    def test_browser_name_case_insensitive(self):
        lower = get_default_profile_path("chrome", system="Linux")
        upper = get_default_profile_path("Chrome", system="Linux")
        assert lower == upper

    def test_windows_edge_contains_microsoft_edge(self):
        path = get_default_profile_path("edge", system="Windows")
        assert "Edge" in str(path) or "edge" in str(path).lower()

    def test_windows_brave_contains_brave(self):
        path = get_default_profile_path("brave", system="Windows")
        assert "Brave" in str(path) or "brave" in str(path).lower()

    def test_linux_paths_under_home(self):
        home = Path.home()
        for browser in CHROMIUM_BROWSERS:
            path = get_default_profile_path(browser, system="Linux")
            assert str(path).startswith(str(home)), (
                f"{browser} path {path} is not under home {home}"
            )

    def test_returned_path_is_absolute(self):
        for system in ("Windows", "Darwin", "Linux"):
            path = get_default_profile_path("chrome", system=system)
            assert path.is_absolute(), f"Path on {system} is not absolute: {path}"


class TestDetectChromiumProfiles:
    def test_returns_dict(self):
        result = detect_chromium_profiles()
        assert isinstance(result, dict)

    def test_unknown_platform_returns_empty(self):
        assert detect_chromium_profiles(system="FreeBSD") == {}

    def test_only_existing_paths_returned(self, tmp_path, monkeypatch):
        fake_chrome = tmp_path / "chrome_profile"
        fake_chrome.mkdir()

        def fake_resolver():
            return {
                "chrome": fake_chrome,
                "edge":   tmp_path / "nonexistent_edge",
            }

        import extractors.chrome as chrome_mod
        monkeypatch.setitem(chrome_mod._PLATFORM_RESOLVERS, "FakeOS", fake_resolver)

        result = detect_chromium_profiles(system="FakeOS")
        assert "chrome" in result
        assert result["chrome"] == fake_chrome
        assert "edge" not in result

    def test_values_are_paths(self, tmp_path, monkeypatch):
        fake_profile = tmp_path / "p"
        fake_profile.mkdir()

        import extractors.chrome as chrome_mod
        monkeypatch.setitem(
            chrome_mod._PLATFORM_RESOLVERS, "FakeOS2",
            lambda: {"chrome": fake_profile}
        )

        result = detect_chromium_profiles(system="FakeOS2")
        for v in result.values():
            assert isinstance(v, Path)
