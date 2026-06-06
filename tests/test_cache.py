import time

from osint_recon.cache import Store


def test_cache_put_get(tmp_path):
    store = Store(tmp_path / "c.sqlite")
    assert store.get("virustotal", "key") is None
    store.put("virustotal", "key", {"a": 1}, ttl=100)
    assert store.get("virustotal", "key") == {"a": 1}
    entry = store.get_entry("virustotal", "key")
    assert entry is not None
    assert entry.value == {"a": 1}
    assert entry.ttl == 100


def test_cache_ttl_expiry(tmp_path):
    store = Store(tmp_path / "c.sqlite")
    store.put("virustotal", "key", {"a": 1}, ttl=0.01)
    time.sleep(0.05)
    assert store.get("virustotal", "key") is None


def test_throttle_first_call_does_not_block(tmp_path):
    store = Store(tmp_path / "c.sqlite")
    start = time.time()
    store.throttle("rdap")
    assert time.time() - start < 0.5
