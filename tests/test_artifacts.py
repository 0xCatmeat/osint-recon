from osint_recon.artifacts import detect_artifact, expand_targets


def test_detect_artifact():
    assert detect_artifact("8.8.8.8") == "ip"
    assert detect_artifact("2606:4700:4700::1111") == "ip"
    assert detect_artifact("example.com") == "domain"
    assert detect_artifact("sub.example.co.uk") == "domain"
    assert detect_artifact("https://example.com/path") == "url"
    assert detect_artifact("http://x.io") == "url"
    assert detect_artifact("d41d8cd98f00b204e9800998ecf8427e") == "hash"  # md5
    assert detect_artifact("a" * 64) == "hash"  # sha256
    assert detect_artifact("not a target") is None
    assert detect_artifact("plainword") is None


def test_detect_evm_address():
    assert detect_artifact("0x0000000000000000000000000000000000000000") == "evm_address"
    assert detect_artifact("0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B") == "evm_address"
    # No 0x prefix means hash, not EVM address.
    assert detect_artifact("a" * 40) == "hash"
    # 0x is not enough; the rest must be hex.
    assert detect_artifact("0x" + "g" * 40) is None
    assert detect_artifact("0x" + "a" * 39) is None
    assert detect_artifact("0x" + "a" * 41) is None


def test_expand_targets_non_domain_is_identity():
    assert expand_targets("8.8.8.8", "ip") == [("8.8.8.8", "ip")]
    assert expand_targets("d41d8cd98f00b204e9800998ecf8427e", "hash")[0][1] == "hash"


def test_expand_targets_no_pivots():
    tasks = expand_targets("example.com", "domain", pivots=False)
    assert tasks == [("example.com", "domain")]


def test_expand_targets_max_pivots():
    tasks = expand_targets("example.com", "domain", pivots=True, max_pivots=1)
    assert tasks[0] == ("example.com", "domain")
    ip_tasks = [t for t in tasks if t[1] == "ip"]
    assert len(ip_tasks) <= 1
