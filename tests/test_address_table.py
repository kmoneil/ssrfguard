"""What the table decides, and where it deliberately disagrees with the standard library.

The corpus below is the regression fence for the table itself. Every entry was measured rather
than assumed,
and the ones marked as disagreements are the reason this package ships a table at all.
"""

from __future__ import annotations

import ipaddress

import pytest

from ssrfguard import DEFAULT_DENIED, BlockedAddressError

# (address, blocked, what it is). Ordered by the reason it is here, not alphabetically.
CORPUS: tuple[tuple[str, bool, str], ...] = (
    # -- ordinary public destinations, which must keep working --
    ("8.8.8.8", False, "public IPv4"),
    ("1.1.1.1", False, "public IPv4"),
    ("2606:4700:4700::1111", False, "public IPv6"),
    # -- the classics --
    ("127.0.0.1", True, "loopback"),
    ("10.0.0.1", True, "RFC1918"),
    ("172.16.0.1", True, "RFC1918"),
    ("192.168.1.1", True, "RFC1918"),
    ("169.254.169.254", True, "cloud metadata"),
    ("0.0.0.0", True, "unspecified, which connects to localhost on Linux"),
    ("255.255.255.255", True, "limited broadcast"),
    ("::1", True, "IPv6 loopback"),
    ("::", True, "IPv6 unspecified"),
    ("fe80::1", True, "IPv6 link-local"),
    ("fc00::1", True, "IPv6 unique-local"),
    # -- where is_private alone says False --
    ("100.64.0.1", True, "CGNAT; is_private=False"),
    ("192.88.99.1", True, "deprecated 6to4 relay anycast; is_global=True"),
    ("fec0::1", True, "deprecated site-local; is_global=True"),
    ("ff02::1", True, "IPv6 all-nodes multicast; is_global=True"),
    ("224.0.0.1", True, "IPv4 all-hosts multicast; no stdlib private/global answer"),
    ("239.255.255.250", True, "SSDP multicast"),
    # -- where the registries alone say nothing --
    ("5f00::1", True, "SRv6 SIDs; IANA says not reachable, is_global=True"),
    ("100:0:0:1::1", True, "RFC9780 dummy prefix; is_global=True"),
    ("2001:2::1", True, "IPv6 benchmarking"),
    ("198.18.0.1", True, "IPv4 benchmarking"),
    ("192.0.2.1", True, "TEST-NET-1"),
    ("198.51.100.1", True, "TEST-NET-2"),
    ("203.0.113.1", True, "TEST-NET-3"),
    ("2001:db8::1", True, "documentation"),
    ("3fff::1", True, "documentation, allocated 2024"),
    ("240.0.0.1", True, "reserved"),
    ("100::1", True, "discard-only"),
    # -- translation prefixes carrying something internal --
    ("64:ff9b::7f00:1", True, "NAT64 carrying 127.0.0.1; is_global=True"),
    ("64:ff9b::a00:1", True, "NAT64 carrying 10.0.0.1"),
    ("64:ff9b::a9fe:a9fe", True, "NAT64 carrying 169.254.169.254"),
    ("2002:7f00:1::", True, "6to4 carrying 127.0.0.1"),
    ("2002:a9fe:a9fe::", True, "6to4 carrying 169.254.169.254"),
    ("::ffff:127.0.0.1", True, "IPv4-mapped carrying loopback"),
    ("::7f00:1", True, "IPv4-compatible carrying loopback; registries omit the prefix"),
    ("::a00:1", True, "IPv4-compatible carrying 10.0.0.1"),
    ("64:ff9b:1::7f00:1", True, "RFC8215 local-use translation prefix"),
    # -- translation prefixes carrying something public, which must NOT be refused --
    ("64:ff9b::808:808", False, "NAT64 carrying 8.8.8.8"),
    ("::ffff:8.8.8.8", False, "IPv4-mapped carrying 8.8.8.8"),
    ("2002:808:808::", False, "6to4 carrying 8.8.8.8"),
    # -- IANA marks these globally reachable and refusing them buys nothing --
    ("192.0.0.9", False, "Port Control Protocol anycast"),
    ("192.0.0.10", False, "TURN anycast"),
    ("192.31.196.1", False, "AS112-v4"),
    ("192.52.193.1", False, "AMT"),
    ("2001:1::1", False, "PCP anycast v6"),
    ("2001:4:112::1", False, "AS112-v6"),
    ("2620:4f:8000::1", False, "Direct Delegation AS112"),
)


@pytest.mark.parametrize(("address", "blocked", "what"), CORPUS, ids=[c[0] for c in CORPUS])
def test_corpus(address: str, blocked: bool, what: str) -> None:
    verdict = DEFAULT_DENIED.classify(address)
    assert verdict.blocked is blocked, f"{address} ({what})"


def test_a_refusal_names_the_block_and_the_rfc() -> None:
    verdict = DEFAULT_DENIED.classify("10.1.2.3")
    assert verdict.reason == "10.0.0.0/8 is Private-Use (RFC1918)"


def test_a_refusal_through_a_translation_prefix_names_both_ends() -> None:
    """The message says what was carried, or a user cannot tell why a public address lost."""
    verdict = DEFAULT_DENIED.classify("64:ff9b::7f00:1")
    assert verdict.reason == (
        "IPv4-IPv6 Translation 64:ff9b::/96 carries 127.0.0.1, "
        "and 127.0.0.0/8 is Loopback (RFC1122)"
    )


def test_raise_if_blocked_carries_the_address_and_the_reason() -> None:
    with pytest.raises(BlockedAddressError) as caught:
        DEFAULT_DENIED.classify("169.254.169.254").raise_if_blocked()
    assert caught.value.address == "169.254.169.254"
    assert "Cloud metadata (AWS, GCP, Azure IMDS)" in caught.value.reason
    assert caught.value.args[0] == (
        "169.254.169.254 is not permitted: "
        "169.254.169.254/32 is Cloud metadata (AWS, GCP, Azure IMDS) (RFC3927)"
    )


def test_a_permitted_address_raises_nothing() -> None:
    DEFAULT_DENIED.classify("8.8.8.8").raise_if_blocked()


def test_classify_accepts_a_parsed_address() -> None:
    assert DEFAULT_DENIED.classify(ipaddress.ip_address("127.0.0.1")).blocked


def test_classify_never_resolves_a_hostname() -> None:
    """`classify` does no I/O. A hostname is a programming error, not a lookup."""
    with pytest.raises(ValueError, match="does not appear to be an IPv4 or IPv6 address"):
        DEFAULT_DENIED.classify("localhost")


def test_longest_prefix_wins_over_table_order() -> None:
    """192.0.0.0/24 is refused while 192.0.0.9/32 inside it is a public anycast service."""
    assert DEFAULT_DENIED.classify("192.0.0.1").blocked
    assert not DEFAULT_DENIED.classify("192.0.0.9").blocked
    assert DEFAULT_DENIED.classify("192.0.0.170").blocked


def test_teredo_is_refused_when_either_embedded_address_is_internal() -> None:
    """RFC 4380 stores the client's address inverted; both ends have to be checked."""
    # server 65.54.227.120 (public), client 192.168.0.1 (private, stored inverted)
    client = ipaddress.ip_address("192.168.0.1")
    obscured = ~int(client) & 0xFFFFFFFF
    packed = (0x20010000 << 96) | (int(ipaddress.ip_address("65.54.227.120")) << 64) | obscured
    teredo = ipaddress.IPv6Address(packed)
    verdict = DEFAULT_DENIED.classify(teredo)
    assert verdict.blocked, f"{teredo} hides {client} in its low 32 bits"
    assert "192.168.0.0/16" in verdict.reason


def test_a_permitted_address_has_no_reason() -> None:
    """`reason` is the refusal text; a permitted address has nothing to say."""
    verdict = DEFAULT_DENIED.classify("8.8.8.8")
    assert verdict.reason == ""
    assert verdict.block is None
