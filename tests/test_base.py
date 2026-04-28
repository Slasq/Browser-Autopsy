from datetime import datetime, timezone
from extractors.base import chrome_timestamp_to_utc, firefox_timestamp_to_utc

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