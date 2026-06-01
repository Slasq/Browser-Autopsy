from datetime import datetime, timezone

import pytest

from extractors.base import basename, chrome_timestamp_to_utc, firefox_timestamp_to_utc

def test_chrome_known_value():
    # 2024-01-01 00:00:00 UTC w Chrome timestamp
    result = chrome_timestamp_to_utc(13_348_540_800_000_000)
    assert result == datetime(2024, 1, 1, tzinfo=timezone.utc)

def test_firefox_known_value():
    # 2024-01-01 00:00:00 UTC w Firefox timestamp  
    result = firefox_timestamp_to_utc(1_704_067_200_000_000)
    assert result == datetime(2024, 1, 1, tzinfo=timezone.utc)

def test_zero_returns_none():
    assert chrome_timestamp_to_utc(0) is None
    assert firefox_timestamp_to_utc(0) is None


# basename must behave identically on every OS
@pytest.mark.parametrize(
    "path, expected",
    [
        # Windows backslash paths (Chrome on Windows stores these literally)
        (r"C:\Users\user\Downloads\tool.exe", "tool.exe"),
        (r"C:\Downloads\payload.exe", "payload.exe"),
        (r"\\server\share\report.pdf", "report.pdf"),  # UNC path
        # POSIX forward-slash paths (Firefox file:// URIs decode to these)
        ("/home/user/Downloads/f.zip", "f.zip"),
        ("/tmp/a.bin", "a.bin"),
        # Mixed separators
        ("C:/Users/user/Downloads/mixed.exe", "mixed.exe"),
        (r"C:\Users/user\Downloads/odd.dat", "odd.dat"),
        # Bare filename / no separator
        ("just_a_file.txt", "just_a_file.txt"),
        # Edge cases
        ("", ""),
        ("/trailing/slash/", ""),
        (r"trailing\backslash\\", ""),
    ],
)
def test_basename_is_os_independent(path, expected):
    assert basename(path) == expected