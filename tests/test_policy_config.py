"""Constructing a `Policy`, and the configurations it refuses to be.

A policy that cannot be satisfied is a configuration error, and it should surface where it was
written rather than at the first request that needed it. Every check here runs at construction.
"""

from __future__ import annotations

import re
from ipaddress import ip_network

import pytest

from ssrfguard import (
    DEFAULT_DENIED,
    AddressTable,
    BlockedAddressError,
    BlockedURLError,
    Policy,
    Reach,
)
from ssrfguard._registry import TABLE


def test_the_defaults_are_the_ones_documented() -> None:
    """The defaults are load-bearing: most callers will never change them."""
    policy = Policy()
    assert policy.allowed_schemes == frozenset({"http", "https"})
    assert policy.allowed_ports == frozenset({80, 443})
    assert policy.allow_userinfo is False
    assert policy.on_partial_block == "reject"
    assert policy.max_redirects == 5
    assert policy.max_connection_attempts == 4
    assert policy.sensitive_headers == frozenset({"authorization", "proxy-authorization", "cookie"})
    assert policy.allow_proxy is False
    assert policy.allowed_networks == ()
    assert policy.max_url_length == 8192


def test_sensitive_header_names_are_normalised_rather_than_matched_case_sensitively() -> None:
    """A header name is case-insensitive on the wire, so a policy that was not would be a
    control defeated by typing `X-Api-Key` where the caller wrote `x-api-key`."""
    policy = Policy(sensitive_headers={"X-Api-Key", "Authorization"})
    assert policy.sensitive_headers == frozenset({"x-api-key", "authorization"})


def test_the_default_sensitive_headers_are_the_ones_a_specification_defines() -> None:
    """Deliberately not a guessed list of conventions.

    `x-api-key` is a credential because a shop decided it is; matching on a name this package
    invented would be the string-matching that every bypass in this package's README relies on.
    The three here are credentials by definition, and the field is where a caller names theirs.
    """
    assert "x-api-key" not in Policy().sensitive_headers


def test_schemes_are_normalised_rather_than_matched_case_sensitively() -> None:
    policy = Policy(allowed_schemes=frozenset({"HTTP", "Https"}))
    assert policy.allowed_schemes == frozenset({"http", "https"})
    assert policy.check_url("http://example.com/").scheme == "http"


def test_allowed_networks_accepts_strings_and_parsed_networks() -> None:
    """Configuration arrives as strings from files; requiring objects would be user-hostile."""
    policy = Policy(allowed_networks=("10.0.0.0/8", ip_network("192.168.0.0/16")))
    assert policy.allowed_networks == (ip_network("10.0.0.0/8"), ip_network("192.168.0.0/16"))
    policy.check_address("10.1.2.3")
    policy.check_address("192.168.1.1")
    with pytest.raises(BlockedAddressError):
        policy.check_address("172.16.0.1")


def test_a_malformed_network_fails_at_construction_not_at_the_request() -> None:
    with pytest.raises(ValueError, match="does not appear to be an IPv4 or IPv6 network"):
        Policy(allowed_networks=("10.0.0.0/8", "not-a-network"))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"allowed_schemes": frozenset()}, "allowed_schemes is empty"),
        ({"allowed_ports": frozenset()}, "allowed_ports is empty"),
        ({"allowed_ports": frozenset({0})}, "allowed_ports contains 0, which is not a port"),
        ({"allowed_ports": frozenset({70000})}, "allowed_ports contains 70000"),
        ({"on_partial_block": "shrug"}, "on_partial_block must be 'reject' or 'drop'"),
        ({"max_redirects": -1}, "max_redirects must not be negative"),
        ({"max_connection_attempts": 0}, "max_connection_attempts must be at least 1"),
        ({"max_connection_attempts": -1}, "max_connection_attempts must be at least 1"),
        ({"max_url_length": 0}, "max_url_length must be at least 1"),
        ({"max_url_length": -1}, "max_url_length must be at least 1"),
    ],
)
def test_a_policy_that_cannot_mean_anything_is_refused(kwargs: dict, message: str) -> None:
    with pytest.raises(ValueError, match=re.escape(message)):
        Policy(**kwargs)


def test_a_policy_is_immutable() -> None:
    """A policy that can be edited after construction is a policy nothing can rely on."""
    policy = Policy()
    with pytest.raises(AttributeError):
        policy.allow_userinfo = True  # type: ignore[misc]


def test_check_address_refuses_a_hostname() -> None:
    """This layer does no I/O, so a name here is a programming error rather than a lookup."""
    policy = Policy()
    with pytest.raises(ValueError, match="does not appear to be an IPv4 or IPv6 address"):
        policy.check_address("example.com")


def test_permits_address_is_the_predicate_form_and_agrees_with_check_address() -> None:
    """Resolution partitions answers, where a refusal is expected rather than exceptional."""
    policy = Policy(allowed_networks=("10.0.0.0/8",))
    for address, permitted in (("8.8.8.8", True), ("10.1.2.3", True), ("127.0.0.1", False)):
        assert policy.permits_address(address) is permitted
        if permitted:
            policy.check_address(address)
        else:
            with pytest.raises(BlockedAddressError):
                policy.check_address(address)


def test_an_allowed_network_of_the_other_family_does_not_leak_across() -> None:
    """`10.0.0.0/8` must not accidentally permit an IPv6 address, and vice versa."""
    policy = Policy(allowed_networks=("10.0.0.0/8",))
    assert not policy.permits_address("::1")
    assert not policy.permits_address("fc00::1")


def test_a_policy_can_be_widened_to_permit_everything_deliberately() -> None:
    """A caller who wants no address filtering must be able to say so explicitly.

    Not because it is a good idea, but because a control with no off switch gets replaced by no
    control at all, and an explicit `allowed_networks=("0.0.0.0/0",)` in a config file is
    reviewable, while a fork of this library is not.
    """
    wide = Policy(allowed_networks=("0.0.0.0/0", "::/0"))
    assert wide.permits_address("127.0.0.1")
    assert wide.permits_address("::1")
    assert wide.permits_address("169.254.169.254")


def test_a_scheme_with_no_default_port_must_name_one() -> None:
    """Allowing a scheme this package has no default for is legal, and then the URL needs a port.

    Refusing rather than guessing: a default invented here would be a connection to a port the
    caller never named, which is the opposite of what a deny-by-default port list is for.
    """
    policy = Policy(allowed_schemes=frozenset({"ftp"}), allowed_ports=frozenset({21}))
    assert policy.check_url("ftp://example.com:21/").port == 21
    with pytest.raises(BlockedURLError, match="names no port and scheme 'ftp' has no default"):
        policy.check_url("ftp://example.com/")


def test_a_name_the_resolver_could_not_encode_is_refused_with_the_codec_error() -> None:
    """An over-long label fails the `idna` codec, which is exactly how it would fail to resolve.

    Reported as a refusal rather than allowed to reach DNS, because the failure is deterministic
    and the message from here names the host while the resolver's would not.
    """
    policy = Policy()
    too_long = "ä" * 64 + ".example"
    with pytest.raises(BlockedURLError, match="is not a usable name") as caught:
        policy.check_url(f"http://{too_long}/")
    assert "too long" in caught.value.reason


@pytest.mark.parametrize(
    "entry",
    [
        "64:ff9b::/96",  # NAT64, the most important row in the table
        "64:ff9b::/104",  # a slice of it is no better
        "2002::/16",  # 6to4
        "2001::/32",  # Teredo
        "::ffff:0:0/96",  # IPv4-mapped
        "::ffff:7f00:1/128",  # and a single mapped address, which no other row decides
        "::/96",  # IPv4-compatible, deprecated
    ],
)
def test_allowing_a_translation_prefix_is_refused_at_construction(entry: str) -> None:
    """The allowlist is consulted before the table gets to decode, so this would be a bypass.

    `check_address` returns on the first allowed-network hit. An entry inside a wrapper therefore
    permits every IPv4 destination embedded in it, undecoded. `64:ff9b::a9fe:a9fe` is the
    metadata endpoint behind a NAT64 gateway, and it would have been permitted by one line of
    configuration that reads as "let NAT64 through".
    """
    with pytest.raises(ValueError, match="carries an IPv4 destination"):
        Policy(allowed_networks=(entry,))


def test_the_refusal_names_the_entry_the_block_and_a_way_forward() -> None:
    """A refusal a caller cannot act on gets configured around, which protects nothing."""
    with pytest.raises(ValueError) as refusal:
        Policy(allowed_networks=("64:ff9b::/96",))

    message = str(refusal.value)
    assert "64:ff9b::/96" in message
    assert "IPv4-IPv6 Translation" in message
    assert "allow the embedded IPv4 range instead" in message


def test_a_deliberately_wide_entry_that_merely_contains_one_is_honoured() -> None:
    """`subnet_of`, not `overlaps`, and the difference is the judgement.

    An entry *inside* a wrapper is somebody naming a prefix whose contents they have not thought
    about. An entry *containing* one is somebody painting with a roller, and refusing those
    would break the off switch the test above this asserts, which exists because a control with
    no off switch gets replaced by no control at all.
    """
    # `::/0` contains every wrapper. `2000::/3` is global unicast, which contains 6to4 and Teredo
    # but *not* NAT64, since `64:ff9b::` begins `000` rather than `001`, so it is checked against an
    # address it actually covers rather than against one it does not.
    assert Policy(allowed_networks=("::/0",)).permits_address("64:ff9b::7f00:1")
    assert Policy(allowed_networks=("2000::/3",)).permits_address("2002:7f00:1::")
    assert Policy(allowed_networks=("2000::/3",)).permits_address("2001:0:7f00:1::")
    assert DEFAULT_DENIED.classify("2002:7f00:1::").blocked  # denied without the entry


@pytest.mark.parametrize(
    ("entry", "decided_by"),
    [
        ("::1/128", "its own loopback row"),
        ("::/128", "its own unspecified row"),
        ("2001:1::1/128", "the Port Control Protocol anycast row, which is PERMITTED"),
        ("2001:1::2/128", "the TURN anycast row, which is PERMITTED"),
    ],
)
def test_an_entry_a_more_specific_row_decides_is_not_refused(entry: str, decided_by: str) -> None:
    """The check has to use the table's own longest-prefix rule or it produces wrong denies.

    `::1/128` sits inside `::/96`, the deprecated IPv4-compatible wrapper, and allowing IPv6
    loopback is an ordinary thing to do. The wrapper never decides it, because `::1/128` has its
    own row. An earlier version of this check asked "does the entry touch a translated block",
    which refused every one of these; the suite caught it on `::1/128`, which the connection
    tests use.

    Args:
        entry: The allowed network.
        decided_by: Which row actually decides it, for the failure message.
    """
    assert Policy(allowed_networks=(entry,)).allowed_networks, decided_by


def test_a_custom_table_with_no_translated_blocks_accepts_anything() -> None:
    """The check reads the policy's own table rather than the shipped one.

    A caller who built a table without translation decoding has no wrapper to be surprised by,
    and refusing them an entry on the strength of a block their table does not carry would be
    this package enforcing a rule it is not applying.
    """
    plain = AddressTable(tuple(b for b in TABLE if b.reach is not Reach.TRANSLATED))
    policy = Policy(denied_networks=plain, allowed_networks=("64:ff9b::/96",))

    assert policy.permits_address("64:ff9b::7f00:1")


def test_a_url_longer_than_the_policy_allows_is_refused_unread() -> None:
    """`check_url` had no ceiling, and SECURITY.md says one request must not consume unbounded
    wall-clock.

    Not a ReDoS: measured across four octaves, both paths are strictly linear and `_HOSTNAME`
    cannot backtrack, because every repetition in it must consume a literal dot. What it lacked
    was a bound. The non-ASCII path costs about 1.9 microseconds per character, because the
    `idna` codec runs nameprep per label, so a 10MB URL was roughly 19 CPU-seconds of one worker.
    """
    policy = Policy()
    url = "http://example.com/" + "a" * policy.max_url_length

    with pytest.raises(BlockedURLError, match="is longer than max_url_length") as refusal:
        policy.check_url(url)

    assert str(policy.max_url_length) in refusal.value.reason
    # The refused value is the length, not the URL. Echoing eight kilobytes of attacker-supplied
    # text into a log line is the second half of the problem this check exists for.
    assert refusal.value.url == f"<{len(url)} characters>"
    assert "aaaa" not in str(refusal.value)


def test_the_length_ceiling_is_checked_before_anything_reads_the_string() -> None:
    """A ceiling applied after a full scan has already paid for what it meant to prevent.

    Asserted through a URL that would fail *two* checks: it is over the limit and it contains a
    control character. The length refusal is the one that must come back, because it is the one
    that did not read the string to find out.
    """
    policy = Policy(max_url_length=32)

    with pytest.raises(BlockedURLError) as refusal:
        policy.check_url("http://example.com/\n" + "a" * 64)

    assert "is longer than max_url_length" in refusal.value.reason
    assert "control character" not in refusal.value.reason


def test_the_ceiling_is_the_policys_number_and_an_ordinary_url_is_unaffected() -> None:
    """A default that refused normal traffic would be a control that gets removed."""
    assert Policy().check_url("https://example.com/a/b?c=d").host == "example.com"


#: The longest name DNS can carry in presentation form, spelled here rather than imported. A test
#: that reads the limit from the code it is checking follows that limit wherever it goes.
LONGEST_HOSTNAME = 253


def _host_of(length: int) -> str:
    """Build a well-formed host of exactly ``length`` characters.

    Every label is at most 63 characters, so the only thing deciding the outcome is the total.
    A test that accidentally tripped the per-label limit would pass for the wrong reason.
    """
    labels = []
    remaining = length
    while remaining > 63:
        labels.append("a" * 63)
        remaining -= 64  # the label, and the dot that has to follow it
    labels.append("a" * remaining)
    return ".".join(labels)


@pytest.mark.parametrize(
    ("length", "accepted"),
    [(LONGEST_HOSTNAME - 1, True), (LONGEST_HOSTNAME, True), (LONGEST_HOSTNAME + 1, False)],
)
def test_a_host_longer_than_dns_can_carry_is_refused_at_the_boundary(
    length: int, accepted: bool
) -> None:
    """253 is the limit and 254 is over it, asserted either side rather than once.

    An off-by-one here is a wrong deny on a name that resolves, which is the more expensive of
    the two directions to get wrong: a guard that refuses working names gets removed.
    """
    host = _host_of(length)
    assert len(host) == length, "the fixture, not the code under test"
    policy = Policy()

    if accepted:
        assert policy.check_url(f"https://{host}/").host == host
    else:
        with pytest.raises(BlockedURLError, match="is longer than 253 characters"):
            policy.check_url(f"https://{host}/")


def test_the_host_ceiling_is_checked_before_the_idna_codec_runs() -> None:
    """The whole point of the host ceiling, and the half a length ceiling cannot cover.

    ``max_url_length`` counts characters of URL; the ``idna`` codec runs on characters of *host*
    at roughly two hundred and fifty times the price, once per label. So a URL comfortably inside
    an 8 KiB ceiling could still carry 389 non-ASCII labels and cost 14.9 milliseconds of one
    worker, measured, and be **accepted**, and then be handed to a lookup that could never
    succeed. Nothing about its length was unusual, which is why the length ceiling never saw it.

    Asserted through a host that would fail *two* checks: it is over the host limit and, once
    normalised, it is not a usable name. The length refusal is the one that must come back,
    because it is the one that did not run the codec to find out.
    """
    policy = Policy()
    host = ".".join(["é" * 20] * 389)

    with pytest.raises(BlockedURLError) as refusal:
        policy.check_url(f"https://{host}/")

    assert "is longer than 253 characters" in refusal.value.reason
    assert "not a usable name" not in refusal.value.reason
    # The refused value is the length, not the host, for the reason the URL ceiling quotes a
    # length: a refusal should not be the thing that puts attacker-supplied text in a log line.
    assert refusal.value.url == f"<host of {len(host)} characters>"
    assert "é" not in str(refusal.value)


def test_an_internationalised_name_of_ordinary_length_still_resolves_to_its_a_label() -> None:
    """The host ceiling must not cost IDN support, which is the wrong deny it could produce."""
    assert Policy().check_url("https://münchen.example.com/").host == "xn--mnchen-3ya.example.com"

    narrow = Policy(max_url_length=25)
    assert narrow.check_url("https://example.com/a/b").host == "example.com"
    with pytest.raises(BlockedURLError, match="max_url_length \\(25\\)"):
        narrow.check_url("https://example.com/a/b/c/d")
