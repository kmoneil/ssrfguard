"""Resolution: one lookup, every answer validated, the sockaddr kept intact.

Driven by a fake resolver rather than by the network. That is not a compromise -- it is the only
way to write the answers this layer has to handle: a name returning one public and one private
address, a name whose answers are all internal, an IPv6 answer carrying a scope identifier. None
of those can be arranged against a real resolver on demand, and the one thing a fake cannot show
is that a *second* lookup does not happen, which is D-5's rebinding fixture and a different test.
"""

from __future__ import annotations

import socket
from ipaddress import ip_address

import pytest

from ssrfguard import Address, BlockedAddressError, Policy, Target, resolve

POLICY = Policy()


def answers(*entries: tuple[str, int]) -> object:
    """Build a resolver returning fixed answers.

    Args:
        *entries: Pairs of (address, family), family being 4 or 6.

    Returns:
        A callable with `getaddrinfo`'s shape.
    """

    def fake(host: str, port: int, *_args: object) -> list[tuple]:
        rows = []
        for text, version in entries:
            if version == 6:
                rows.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (text, port, 0, 0)))
            else:
                rows.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (text, port)))
        return rows

    return fake


def target(url: str = "http://name.example/") -> object:
    return POLICY.check_url(url)


def test_every_answer_is_validated_not_just_the_first() -> None:
    """A name returning four addresses returns four chances to reach somewhere internal."""
    resolver = answers(("1.1.1.1", 4), ("8.8.8.8", 4), ("9.9.9.9", 4), ("127.0.0.1", 4))
    with pytest.raises(BlockedAddressError) as caught:
        resolve(target(), policy=POLICY, resolver=resolver)
    assert "127.0.0.1" in caught.value.reason


def test_a_name_whose_answers_are_all_public_returns_all_of_them() -> None:
    resolved = resolve(target(), policy=POLICY, resolver=answers(("1.1.1.1", 4), ("8.8.8.8", 4)))
    assert [str(a.ip) for a in resolved] == ["1.1.1.1", "8.8.8.8"]
    assert all(a.hostname == "name.example" for a in resolved)


def test_the_resolvers_own_ordering_is_preserved() -> None:
    """getaddrinfo already applies RFC 6724 selection; reordering discards that decision."""
    resolver = answers(("2606:4700::1111", 6), ("1.1.1.1", 4), ("8.8.8.8", 4))
    resolved = resolve(target(), policy=POLICY, resolver=resolver)
    assert [str(a.ip) for a in resolved] == ["2606:4700::1111", "1.1.1.1", "8.8.8.8"]


def test_an_ipv6_answer_keeps_its_four_tuple() -> None:
    """The flow label and the scope identifier live only in the sockaddr."""

    def scoped(host: str, port: int, *_args: object) -> list[tuple]:
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700::1111", port, 7, 3))]

    (resolved,) = resolve(target(), policy=POLICY, resolver=scoped)
    assert resolved.sockaddr == ("2606:4700::1111", 80, 7, 3), (
        "re-parsing sockaddr[0] into a string would silently drop the scope identifier"
    )
    assert resolved.port == 80
    assert resolved.family is socket.AF_INET6


def test_duplicate_answers_are_collapsed() -> None:
    """A resolver may repeat an address across protocols; connecting to it twice buys nothing."""
    resolver = answers(("1.1.1.1", 4), ("1.1.1.1", 4), ("8.8.8.8", 4))
    resolved = resolve(target(), policy=POLICY, resolver=resolver)
    assert [str(a.ip) for a in resolved] == ["1.1.1.1", "8.8.8.8"]


# -- partial block ---------------------------------------------------------------------------


def test_a_name_resolving_both_ways_is_refused_whole() -> None:
    """D-17, decided: an allowed address does not rescue a name whose other address is denied."""
    resolver = answers(("1.1.1.1", 4), ("169.254.169.254", 4))
    with pytest.raises(BlockedAddressError) as caught:
        resolve(target(), policy=POLICY, resolver=resolver)
    reason = caught.value.reason
    assert "resolves to both permitted and denied addresses" in reason
    assert "permitted: 1.1.1.1" in reason, "a user shown only the denied half cannot tell why"
    assert "169.254.169.254" in reason
    assert "signature of a DNS rebinding attempt" in reason
    assert "on_partial_block='drop'" in reason, "a refusal must name its own escape hatch"


def test_an_explicitly_allowed_network_does_not_rescue_a_partially_denied_name() -> None:
    """The decision D-17 records, asserted directly.

    `allowed_networks` governs addresses. `on_partial_block` governs names. A user who allowed
    10.0.0.0/8 allowed a network, not a name that also points at the metadata endpoint -- and
    the other reading would let an attacker launder any denied address by pairing it with an
    allowed one in the same answer set.
    """
    policy = Policy(allowed_networks=("10.0.0.0/8",))
    resolver = answers(("10.1.2.3", 4), ("169.254.169.254", 4))
    with pytest.raises(BlockedAddressError) as caught:
        resolve(target(), policy=policy, resolver=resolver)
    assert "permitted: 10.1.2.3" in caught.value.reason


def test_drop_keeps_the_permitted_answers() -> None:
    policy = Policy(on_partial_block="drop")
    resolver = answers(("1.1.1.1", 4), ("127.0.0.1", 4), ("8.8.8.8", 4))
    resolved = resolve(target(), policy=policy, resolver=resolver)
    assert [str(a.ip) for a in resolved] == ["1.1.1.1", "8.8.8.8"]


def test_drop_still_refuses_when_nothing_survives() -> None:
    """`drop` drops denied answers; it does not invent a permitted one."""
    policy = Policy(on_partial_block="drop")
    with pytest.raises(BlockedAddressError):
        resolve(target(), policy=policy, resolver=answers(("127.0.0.1", 4), ("10.0.0.1", 4)))


def test_a_single_denied_answer_is_refused_with_the_address_reason() -> None:
    """One bad answer reads as an ordinary refusal, not as a partial-block situation."""
    with pytest.raises(BlockedAddressError) as caught:
        resolve(target(), policy=POLICY, resolver=answers(("127.0.0.1", 4)))
    assert caught.value.address == "127.0.0.1"
    assert caught.value.reason == "127.0.0.0/8 is Loopback (RFC1122)"


def test_several_denied_answers_name_all_of_them() -> None:
    with pytest.raises(BlockedAddressError) as caught:
        resolve(target(), policy=POLICY, resolver=answers(("127.0.0.1", 4), ("10.0.0.1", 4)))
    assert caught.value.address == "name.example"
    assert "127.0.0.1" in caught.value.reason
    assert "10.0.0.1" in caught.value.reason


# -- literal addresses -----------------------------------------------------------------------


def test_a_literal_address_target_asks_for_no_lookup() -> None:
    """`AI_NUMERICHOST` is what makes "no DNS" structural rather than incidental.

    A numeric host would not reach DNS anyway, so the flag looks redundant -- and it is not.
    It makes ``getaddrinfo`` *fail* rather than resolve when the host is not numeric, which is
    the difference between failing closed and resolving an attacker-controlled name. See the
    forged-target test below, which is the case it exists for.
    """
    recorded: list[int] = []

    def recording(_host: str, port: int, *args: object) -> list[tuple]:
        recorded.append(int(args[3]))  # type: ignore[arg-type]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", port))]

    resolve(target("http://8.8.8.8/"), policy=POLICY, resolver=recording)
    assert recorded == [socket.AI_NUMERICHOST], "a literal target must forbid a lookup"

    recorded.clear()
    resolve(target(), policy=POLICY, resolver=recording)
    assert recorded == [0], (
        "a name must be looked up with no flags narrowing what DNS returns -- AI_ADDRCONFIG "
        "in particular would hide an address family from validation, and an answer we never "
        "saw is an answer we never refused"
    )


def test_a_literal_address_resolves_to_itself_through_the_real_resolver() -> None:
    (resolved,) = resolve(target("http://8.8.8.8/"), policy=POLICY)
    assert str(resolved.ip) == "8.8.8.8"
    assert resolved.sockaddr == ("8.8.8.8", 80)


def test_a_target_that_claims_to_be_literal_but_carries_a_name_fails_closed() -> None:
    """The case `AI_NUMERICHOST` exists for, and the one a forged target would exploit.

    `check_url` never builds this, so reaching it means somebody constructed a `Target` by hand
    -- which is allowed, the type is public. Without the flag, the name would be resolved and
    connected to; with it, the lookup refuses.
    """
    forged = Target(
        scheme="http",
        host="example.com",
        port=80,
        host_as_written="example.com",
        address=ip_address("8.8.8.8"),
    )
    with pytest.raises(socket.gaierror):
        resolve(forged, policy=POLICY)


def test_a_literal_address_is_revalidated_anyway() -> None:
    """A function returning validated addresses validates everything it returns.

    `check_url` already refused this one, so this path is only reachable by handing `resolve` a
    target built some other way -- which is exactly when the caller most needs the check.
    """
    forged = Target(
        scheme="http",
        host="127.0.0.1",
        port=80,
        host_as_written="127.0.0.1",
        address=ip_address("127.0.0.1"),
    )
    with pytest.raises(BlockedAddressError):
        resolve(forged, policy=POLICY)


def test_a_literal_ipv6_target_keeps_a_four_tuple() -> None:
    (resolved,) = resolve(target("http://[2606:4700:4700::1111]/"), policy=POLICY)
    assert len(resolved.sockaddr) == 4
    assert resolved.family is socket.AF_INET6


# -- failures that are not policy decisions --------------------------------------------------


def test_a_name_that_does_not_resolve_raises_the_resolver_error_unwrapped() -> None:
    """A DNS failure is not a refusal, and dressing it as one sends users hunting a ghost."""

    def missing(*_args: object) -> list[tuple]:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    with pytest.raises(socket.gaierror):
        resolve(target(), policy=POLICY, resolver=missing)


def test_address_renders_usefully() -> None:
    ipv4 = Address(socket.AF_INET, ("1.1.1.1", 80), ip_address("1.1.1.1"), "one.example")
    assert str(ipv4) == "1.1.1.1:80 (via one.example)"
    ipv6 = Address(socket.AF_INET6, ("::1", 443, 0, 0), ip_address("::1"), "::1")
    assert str(ipv6) == "[::1]:443", "a literal address does not need 'via' itself"
