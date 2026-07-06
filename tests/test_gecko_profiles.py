"""
Tests for Gecko-family profile path detection in extractors/firefox.py.
"""
from pathlib import Path

import pytest

import extractors.firefox as firefox_mod
from extractors.firefox import (
    GECKO_BROWSERS,
    detect_gecko_profiles,
    get_profile_roots,
)


class TestGeckoBrowsers:
    def test_contains_core_browsers(self):
        for name in ("firefox", "tor", "librewolf", "waterfox"):
            assert name in GECKO_BROWSERS

    def test_all_entries_are_strings(self):
        assert all(isinstance(b, str) for b in GECKO_BROWSERS)


class TestGetProfileRoots:
    @pytest.mark.parametrize("system", ["Windows", "Darwin", "Linux"])
    @pytest.mark.parametrize("browser", ["firefox", "tor", "librewolf", "waterfox"])
    def test_all_browsers_have_roots_on_all_platforms(self, system, browser):
        roots = get_profile_roots(browser, system=system)
        assert roots, f"{browser} has no candidate roots on {system}"
        assert all(isinstance(r, Path) for r in roots)

    def test_unknown_browser_returns_empty(self):
        assert get_profile_roots("netscape", system="Windows") == []
        assert get_profile_roots("netscape", system="Linux") == []

    def test_unknown_platform_returns_empty(self):
        assert get_profile_roots("firefox", system="FreeBSD") == []

    def test_browser_name_case_insensitive(self):
        lower = get_profile_roots("firefox", system="Linux")
        upper = get_profile_roots("Firefox", system="Linux")
        assert lower == upper

    @pytest.mark.parametrize("system", ["Windows", "Darwin", "Linux"])
    def test_roots_are_absolute(self, system):
        for browser in GECKO_BROWSERS:
            for root in get_profile_roots(browser, system=system):
                assert root.is_absolute(), (
                    f"{browser} root on {system} is not absolute: {root}"
                )

    def test_linux_roots_under_home(self):
        home = Path.home()
        for browser in GECKO_BROWSERS:
            for root in get_profile_roots(browser, system="Linux"):
                assert str(root).startswith(str(home)), (
                    f"{browser} root {root} is not under home {home}"
                )


def _make_profile(root: Path, name: str) -> Path:
    """Create root/name containing an (empty) places.sqlite."""
    profile = root / name
    profile.mkdir(parents=True)
    (profile / "places.sqlite").touch()
    return profile


class TestDetectGeckoProfiles:
    def test_returns_dict(self):
        result = detect_gecko_profiles()
        assert isinstance(result, dict)

    def test_unknown_platform_returns_empty(self):
        assert detect_gecko_profiles(system="FreeBSD") == {}

    def test_finds_profile_in_profiles_subdir(self, tmp_path, monkeypatch):
        root = tmp_path / "Profiles"
        profile = _make_profile(root, "ab12cd34.default-release")

        monkeypatch.setitem(
            firefox_mod._GECKO_PLATFORM_RESOLVERS, "FakeOS",
            lambda: {"firefox": [root]},
        )
        result = detect_gecko_profiles(system="FakeOS")
        assert result == {"firefox": profile}

    def test_root_itself_can_be_a_profile(self, tmp_path, monkeypatch):
        # Tor layout: the candidate root IS the profile (profile.default)
        root = tmp_path / "profile.default"
        root.mkdir()
        (root / "places.sqlite").touch()

        monkeypatch.setitem(
            firefox_mod._GECKO_PLATFORM_RESOLVERS, "FakeOS2",
            lambda: {"tor": [root]},
        )
        result = detect_gecko_profiles(system="FakeOS2")
        assert result == {"tor": root}

    def test_missing_root_is_skipped(self, tmp_path, monkeypatch):
        monkeypatch.setitem(
            firefox_mod._GECKO_PLATFORM_RESOLVERS, "FakeOS3",
            lambda: {"firefox": [tmp_path / "nonexistent"]},
        )
        assert detect_gecko_profiles(system="FakeOS3") == {}

    def test_dir_without_places_sqlite_is_not_a_profile(self, tmp_path, monkeypatch):
        root = tmp_path / "Profiles"
        (root / "empty-profile").mkdir(parents=True)

        monkeypatch.setitem(
            firefox_mod._GECKO_PLATFORM_RESOLVERS, "FakeOS4",
            lambda: {"firefox": [root]},
        )
        assert detect_gecko_profiles(system="FakeOS4") == {}

    def test_most_recent_profile_wins(self, tmp_path, monkeypatch):
        import os

        root = tmp_path / "Profiles"
        stale = _make_profile(root, "old.default")
        fresh = _make_profile(root, "new.default-release")
        os.utime(stale / "places.sqlite", (1_000_000, 1_000_000))
        os.utime(fresh / "places.sqlite", (2_000_000, 2_000_000))

        monkeypatch.setitem(
            firefox_mod._GECKO_PLATFORM_RESOLVERS, "FakeOS5",
            lambda: {"firefox": [root]},
        )
        result = detect_gecko_profiles(system="FakeOS5")
        assert result == {"firefox": fresh}
