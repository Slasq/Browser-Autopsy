from datetime import datetime, timezone

import pytest

import pytest

from extractors.base import _extract_query, basename, chrome_timestamp_to_utc, firefox_timestamp_to_utc

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


# _extract_query
class TestExtractQuery:

    @pytest.mark.parametrize("url, expected_engine, expected_query", [
        ("https://www.google.com/search?q=malware",           "google",          "malware"),
        ("https://www.bing.com/search?q=dfir",                "bing.com",        "dfir"),
        ("https://duckduckgo.com/?q=threat+intel",            "duckduckgo.com",  "threat intel"),
        ("https://search.yahoo.com/search?p=forensics",       "search.yahoo.com","forensics"),
        ("https://www.ecosia.org/search?q=osint",             "ecosia.org",      "osint"),
        ("https://search.brave.com/search?q=pivot",           "search.brave.com","pivot"),
        ("https://www.startpage.com/sp/search?q=vpn",         "startpage.com",   "vpn"),
        ("https://www.youtube.com/results?search_query=dfir", "youtube.com",     "dfir"),
        ("https://yandex.com/search/?text=sqlite",            "yandex",          "sqlite"),
    ])
    def test_all_search_engines(self, url, expected_engine, expected_query):
        result = _extract_query(url)
        assert result is not None
        engine, query = result
        assert engine == expected_engine
        assert query == expected_query

    def test_non_search_url_returns_none(self):
        assert _extract_query("https://example.com/article") is None

    def test_search_engine_without_query_param_returns_none(self):
        assert _extract_query("https://www.google.com/") is None

    def test_empty_query_param_returns_none(self):
        assert _extract_query("https://www.google.com/search?q=") is None

    def test_whitespace_only_query_returns_none(self):
        assert _extract_query("https://www.google.com/search?q=%20%20") is None

    def test_plus_encoded_spaces_decoded(self):
        _, query = _extract_query("https://www.google.com/search?q=hello+world")
        assert query == "hello world"

    def test_percent_encoded_utf8_decoded(self):
        _, query = _extract_query("https://www.google.com/search?q=z%C5%82o%C5%9Bliwy")
        assert query == "złośliwy"

    def test_malformed_url_returns_none(self):
        assert _extract_query("ht!tp://[niepoprawny") is None

    def test_url_without_hostname_returns_none(self):
        assert _extract_query("file:///local/path?q=x") is None

    def test_multiple_values_for_param_uses_first(self):
        # parse_qs returns a list; _extract_query takes values[0]
        result = _extract_query("https://www.google.com/search?q=first&q=second")
        assert result is not None
        _, query = result
        assert query == "first"