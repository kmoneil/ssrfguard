"""Constructing a `Policy`, and the configurations it refuses to be.

A policy that cannot be satisfied is a configuration error, and it should surface where it was
written rather than at the first request that needed it. Every check here runs at construction.
"""

from __future__ import annotations

import re
from ipaddress import ip_network

import pytest

from ssrfguard import BlockedAddressError, BlockedURLError, Policy


def test_the_defaults_are_the_ones_documented() -> None:
    """The defaults are load-bearing: most callers will never change them."""
    policy = Policy()
    assert policy.allowed_schemes == frozenset({"http", "https"})
    assert policy.allowed_ports == frozenset({80, 443})
    assert policy.allow_userinfo is False
    assert policy.on_partial_block == "reject"
    assert policy.max_redirects == 5
    assert policy.allow_proxy is False
    assert policy.allowed_networks == ()


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
    control at all -- and an explicit `allowed_networks=("0.0.0.0/0",)` in a config file is
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
