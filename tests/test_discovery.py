"""
Tests for extractors/discovery.py — evidence-directory profile discovery.
"""
from pathlib import Path

import pytest

from extractors.discovery import DiscoveredProfile, _guess_label, discover_profiles


def _chromium_profile(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "History").touch()
    return directory


def _gecko_profile(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "places.sqlite").touch()
    return directory


class TestGuessLabel:
    @pytest.mark.parametrize("relative, engine, expected", [
        # nazwa przeglądarki jako podciąg innego słowa nie jest etykietą
        ("victor_laptop/abcd.default-release", "gecko", "firefox"),
        ("export_directory/profile", "gecko", "firefox"),
        ("case7/storage/p1", "gecko", "firefox"),
        ("knowledge_base/Default", "chromium", "chrome"),
        ("operations/Default", "chromium", "chrome"),
        # prawdziwe ścieżki instalacji, także sklejone z "Browser"/"Software"
        ("TorBrowser-Data/Browser/abcd.default", "gecko", "tor"),
        (r"Tor Browser\Browser\TorBrowser\Data\Browser\profile.default", "gecko", "tor"),
        (".mozilla/firefox/abcd.default-release", "gecko", "firefox"),
        ("YandexBrowser/User Data/Default", "chromium", "yandex"),
        ("BraveSoftware/Default", "chromium", "brave"),
        ("com.operasoftware.Opera", "chromium", "opera"),
        ("Microsoft/Edge/User Data/Default", "chromium", "edge"),
        ("Google/Chrome/User Data/Default", "chromium", "chrome"),
    ])
    def test_label_is_matched_as_whole_word(self, relative, engine, expected):
        assert _guess_label(relative, engine) == expected


class TestDiscoverProfiles:
    def test_missing_input_dir_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            discover_profiles(tmp_path / "nope")

    def test_empty_dir_returns_empty(self, tmp_path):
        assert discover_profiles(tmp_path) == []

    def test_input_dir_itself_can_be_a_profile(self, tmp_path):
        _chromium_profile(tmp_path)
        result = discover_profiles(tmp_path)
        assert len(result) == 1
        assert result[0].engine == "chromium"
        assert result[0].path == tmp_path

    def test_finds_chromium_and_gecko_side_by_side(self, tmp_path):
        _chromium_profile(tmp_path / "chrome_profile")
        _gecko_profile(tmp_path / "firefox_profile")
        result = discover_profiles(tmp_path)
        engines = {p.engine for p in result}
        assert engines == {"chromium", "gecko"}

    def test_finds_nested_profiles(self, tmp_path):
        _chromium_profile(tmp_path / "machine1" / "edge" / "Default")
        _gecko_profile(tmp_path / "machine2" / "ff" / "abcd.default-release")
        result = discover_profiles(tmp_path)
        assert len(result) == 2

    def test_label_guessed_from_path(self, tmp_path):
        _chromium_profile(tmp_path / "edge_backup" / "Default")
        _gecko_profile(tmp_path / "tor-browser-profile")
        by_engine = {p.engine: p for p in discover_profiles(tmp_path)}
        assert by_engine["chromium"].browser == "edge"
        assert by_engine["gecko"].browser == "tor"

    def test_chromium_wins_over_chrome_substring(self, tmp_path):
        _chromium_profile(tmp_path / "chromium_data")
        assert discover_profiles(tmp_path)[0].browser == "chromium"

    def test_unknown_names_fall_back_to_engine_default(self, tmp_path):
        _chromium_profile(tmp_path / "profil_szefa")
        _gecko_profile(tmp_path / "dowody_2026")
        by_engine = {p.engine: p for p in discover_profiles(tmp_path)}
        assert by_engine["chromium"].browser == "chrome"
        assert by_engine["gecko"].browser == "firefox"

    def test_does_not_descend_into_profiles(self, tmp_path):
        # profil z podfolderem, który też wygląda jak profil — nie schodzimy
        profile = _chromium_profile(tmp_path / "chrome")
        _chromium_profile(profile / "nested")
        result = discover_profiles(tmp_path)
        assert len(result) == 1
        assert result[0].path == profile

    def test_unreadable_directory_is_skipped(self, tmp_path, monkeypatch, capsys):
        # np. 'System Volume Information' na zamontowanym obrazie dysku
        _chromium_profile(tmp_path / "chrome")
        locked = tmp_path / "locked"
        locked.mkdir()
        real_iterdir = Path.iterdir

        def fake_iterdir(self):
            if self == locked:
                raise PermissionError(13, "Permission denied")
            return real_iterdir(self)
        monkeypatch.setattr(Path, "iterdir", fake_iterdir)

        result = discover_profiles(tmp_path)
        assert [p.path.name for p in result] == ["chrome"]
        assert "locked" in capsys.readouterr().out

    def test_deterministic_order(self, tmp_path):
        _chromium_profile(tmp_path / "b_chrome")
        _chromium_profile(tmp_path / "a_chrome")
        paths = [p.path.name for p in discover_profiles(tmp_path)]
        assert paths == sorted(paths)

    def test_result_is_frozen_dataclass(self, tmp_path):
        _chromium_profile(tmp_path / "chrome")
        prof = discover_profiles(tmp_path)[0]
        assert isinstance(prof, DiscoveredProfile)
        with pytest.raises(Exception):
            prof.engine = "x"
