"""Tests for result caching."""

from demon.cache import cache_result, load_cache, delete_cache


def test_cache_round_trip(tmp_path, monkeypatch) -> None:
    """Test writing, reading, and deleting one cache result."""
    monkeypatch.setattr("demon.cache.cache_dir", lambda: tmp_path)
    cache_result("abc", "report", {"x": 1}, "benign")
    assert load_cache("abc")["ai_verdict"] == "benign"
    assert delete_cache("abc")
    assert load_cache("abc") is None

