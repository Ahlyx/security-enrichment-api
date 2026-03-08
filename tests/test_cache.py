from app.cache import get_cached, set_cached, delete_cached, clear_all_cache

def test_cache_set_and_get():
    clear_all_cache()
    data = {"ip": "8.8.8.8", "is_malicious": False}
    set_cached("ip", "8.8.8.8", data, success_count=4, source_count=4)
    result = get_cached("ip", "8.8.8.8")
    assert result is not None
    assert result["ip"] == "8.8.8.8"

def test_cache_miss_returns_none():
    clear_all_cache()
    result = get_cached("ip", "1.2.3.4")
    assert result is None

def test_cache_delete():
    clear_all_cache()
    data = {"ip": "8.8.8.8"}
    set_cached("ip", "8.8.8.8", data, success_count=4, source_count=4)
    delete_cached("ip", "8.8.8.8")
    result = get_cached("ip", "8.8.8.8")
    assert result is None

def test_cache_all_fail_not_cached():
    clear_all_cache()
    data = {"ip": "8.8.8.8"}
    set_cached("ip", "8.8.8.8", data, success_count=0, source_count=4)
    result = get_cached("ip", "8.8.8.8")
    assert result is None