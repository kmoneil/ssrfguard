"""Properties of resolution, generated over answer sets nobody would think to write down."""

from __future__ import annotations

import ipaddress
import socket

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from ssrfguard import BlockedAddressError, Policy, resolve

POLICY = Policy()
DROPPING = Policy(on_partial_block="drop")

v4 = st.integers(min_value=0, max_value=2**32 - 1).map(ipaddress.IPv4Address)
v6 = st.integers(min_value=0, max_value=2**128 - 1).map(ipaddress.IPv6Address)
answer_sets = st.lists(st.one_of(v4, v6), min_size=1, max_size=6)


def resolver_for(addresses: list[object]) -> object:
    """Build a resolver returning exactly these addresses.

    Args:
        addresses: The answers to return, in order.

    Returns:
        A callable with `getaddrinfo`'s shape.
    """

    def fake(host: str, port: int, *_args: object) -> list[tuple]:
        rows = []
        for address in addresses:
            if isinstance(address, ipaddress.IPv6Address):
                rows.append(
                    (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (str(address), port, 0, 0))
                )
            else:
                rows.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (str(address), port)))
        return rows

    return fake


def a_target() -> object:
    return POLICY.check_url("http://name.example/")


def refusal_for(resolver: object, policy: Policy = POLICY) -> BlockedAddressError | None:
    """Resolve and return the refusal, if there was one.

    Hypothesis properties are about *either* outcome, so `pytest.raises` does not fit: it
    asserts that a call raises, and here raising is one of two correct answers.

    Args:
        resolver: The stand-in resolver to drive.
        policy: The policy to resolve against.

    Returns:
        The refusal, or ``None`` if the name was permitted.
    """
    try:
        resolve(a_target(), policy=policy, resolver=resolver)
    except BlockedAddressError as refused:
        return refused
    return None


@settings(max_examples=400)
@given(answer_sets)
def test_nothing_denied_is_ever_returned(addresses: list[object]) -> None:
    """The invariant the whole layer exists for, under both partial-block settings.

    Whatever comes back from `resolve`, every one of them passes the policy. There is no
    setting, no answer set and no ordering under which a denied address is handed to `connect`.
    """
    for policy in (POLICY, DROPPING):
        try:
            resolved = resolve(a_target(), policy=policy, resolver=resolver_for(addresses))
        except BlockedAddressError:
            continue
        assert resolved, "a successful resolve must never return an empty tuple"
        for address in resolved:
            assert policy.permits_address(address.ip), f"{address.ip} was returned and is denied"


@settings(max_examples=300)
@given(answer_sets)
def test_reject_refuses_whenever_drop_would_have_dropped_anything(
    addresses: list[object],
) -> None:
    """`reject` is strictly stronger than `drop`, which is what makes it the safe default."""
    resolver = resolver_for(addresses)
    try:
        under_drop = resolve(a_target(), policy=DROPPING, resolver=resolver)
    except BlockedAddressError:
        return  # drop refused too, so reject certainly does
    dropped_something = len(under_drop) < len({str(a) for a in addresses})
    if not dropped_something:
        return
    try:
        resolve(a_target(), policy=POLICY, resolver=resolver)
    except BlockedAddressError:
        return
    raise AssertionError("drop discarded an answer and reject permitted the name anyway")


@settings(max_examples=300)
@given(answer_sets)
def test_a_refusal_always_names_something_actionable(addresses: list[object]) -> None:
    refused = refusal_for(resolver_for(addresses))
    if refused is None:
        return
    assert refused.reason
    assert refused.address
    assert any(str(a) in refused.reason or str(a) == refused.address for a in addresses), (
        "a refusal that names none of the answers cannot be acted on"
    )


@settings(max_examples=300)
@given(answer_sets)
def test_the_sockaddr_is_carried_through_unmodified(addresses: list[object]) -> None:
    """Whatever the resolver produced is what `connect` will get."""
    resolver = resolver_for(addresses)
    produced = {
        row[4]
        for row in resolver(  # type: ignore[operator]
            "name.example", 80, 0, socket.SOCK_STREAM, 0, 0
        )
    }
    try:
        resolved = resolve(a_target(), policy=DROPPING, resolver=resolver)
    except BlockedAddressError:
        return
    for address in resolved:
        assert address.sockaddr in produced


@settings(max_examples=200)
@given(answer_sets, answer_sets)
def test_order_of_denied_answers_never_changes_whether_a_name_is_permitted(
    permitted_seed: list[object], denied_seed: list[object]
) -> None:
    """A guard whose verdict depends on answer ordering has a race, not a policy."""
    addresses = permitted_seed + denied_seed
    assume(len(addresses) >= 2)
    forward = resolver_for(addresses)
    backward = resolver_for(list(reversed(addresses)))

    def verdict(resolver: object) -> bool:
        try:
            resolve(a_target(), policy=POLICY, resolver=resolver)
        except BlockedAddressError:
            return False
        return True

    assert verdict(forward) == verdict(backward)
