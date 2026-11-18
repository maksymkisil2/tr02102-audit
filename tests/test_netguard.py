"""Target parsing and SSRF protection."""

import pytest

from tr02102_audit.netguard import (
    TargetError,
    is_public,
    parse_networks,
    parse_target,
    resolve,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("example.org", ("example.org", 443)),
        ("Example.ORG:8443", ("example.org", 8443)),
        ("https://example.org/path", ("example.org", 443)),
        ("[2001:db8::1]:444", ("2001:db8::1", 444)),
        ("192.0.2.1", ("192.0.2.1", 443)),
    ],
)
def test_parse_target(text: str, expected: tuple[str, int]) -> None:
    assert parse_target(text) == expected


@pytest.mark.parametrize(
    "text", ["", "exa mple.org", "host:99999", "host:abc", "-bad.org", "a" * 300, "<script>"]
)
def test_parse_target_rejects_garbage(text: str) -> None:
    with pytest.raises(TargetError):
        parse_target(text)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "224.0.0.1",
    ],
)
def test_non_public_addresses_are_recognised(address: str) -> None:
    assert not is_public(address)


def test_public_address() -> None:
    assert is_public("8.8.8.8") and is_public("2606:4700:4700::1111")


def test_resolve_blocks_loopback_unless_allowed() -> None:
    with pytest.raises(TargetError):
        resolve("localhost", 443, allow_private=False)
    with pytest.raises(TargetError):
        resolve("127.0.0.1", 443, allow_private=False)
    assert resolve("127.0.0.1", 443, allow_private=True).sni is None


def test_named_private_networks_may_be_checked_and_nothing_else() -> None:
    lab = parse_networks("172.30.80.0/24, 10.9.9.9")
    assert (
        resolve("172.30.80.5", 443, allow_private=False, allowed_networks=lab).ip == "172.30.80.5"
    )
    assert resolve("10.9.9.9", 443, allow_private=False, allowed_networks=lab).ip == "10.9.9.9"
    for outside in ("172.30.81.5", "10.9.9.8", "127.0.0.1", "169.254.169.254"):
        with pytest.raises(TargetError) as caught:
            resolve(outside, 443, allow_private=False, allowed_networks=lab)
        assert caught.value.reason == "private"


def test_network_list_parsing() -> None:
    assert parse_networks("") == ()
    assert [str(n) for n in parse_networks("192.168.1.0/24 fd00::/8,10.0.0.1")] == [
        "192.168.1.0/24",
        "fd00::/8",
        "10.0.0.1/32",
    ]
    with pytest.raises(ValueError, match="not a network"):
        parse_networks("lab.example")
