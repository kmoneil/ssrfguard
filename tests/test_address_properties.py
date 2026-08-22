"""Property tests over the address space.

The corpus in `test_address_table.py` is a list somebody wrote, so it covers what that person
thought of. These generate addresses instead, and assert things that must hold for *every*
address rather than for the ones we remembered.
"""

from __future__ import annotations

import ipaddress

from hypothesis import given, settings
from hypothesis import strategies as st

from ssrfguard import DEFAULT_DENIED, Reach
from ssrfguard._registry import TABLE

DENIED_V4 = tuple(b for b in TABLE if b.reach is Reach.DENIED and b.network.version == 4)
DENIED_V6 = tuple(b for b in TABLE if b.reach is Reach.DENIED and b.network.version == 6)

v4 = st.integers(min_value=0, max_value=2**32 - 1).map(ipaddress.IPv4Address)
v6 = st.integers(min_value=0, max_value=2**128 - 1).map(ipaddress.IPv6Address)


@st.composite
def address_inside(draw: st.DrawFn, blocks: tuple[object, ...]) -> ipaddress._BaseAddress:
    """Draw an address from inside one of the given blocks.

    Args:
        draw: Hypothesis draw function.
        blocks: The blocks to draw from.

    Returns:
        An address inside one of them.
    """
    block = draw(st.sampled_from(blocks))
    network = block.network  # type: ignore[attr-defined]
    offset = draw(st.integers(min_value=0, max_value=network.num_addresses - 1))
    return ipaddress.ip_address(int(network.network_address) + offset)


@settings(max_examples=400)
@given(address_inside(DENIED_V4))
def test_no_address_in_a_denied_ipv4_block_is_ever_permitted(
    address: ipaddress.IPv4Address,
) -> None:
    """The property the whole package rests on, for IPv4.

    A denied block that a more specific PERMITTED entry punches a hole in is still covered: the
    hole is what longest-prefix match is for, and this asserts the *denied entry's own* verdict
    survives wherever no such hole exists.
    """
    verdict = DEFAULT_DENIED.classify(address)
    match = DEFAULT_DENIED.match(address)
    assert match is not None
    if match.reach is Reach.DENIED:
        assert verdict.blocked, f"{address} sits in denied {match.network} and was permitted"


@settings(max_examples=400)
@given(address_inside(DENIED_V6))
def test_no_address_in_a_denied_ipv6_block_is_ever_permitted(
    address: ipaddress.IPv6Address,
) -> None:
    verdict = DEFAULT_DENIED.classify(address)
    match = DEFAULT_DENIED.match(address)
    assert match is not None
    if match.reach is Reach.DENIED:
        assert verdict.blocked, f"{address} sits in denied {match.network} and was permitted"


@settings(max_examples=500)
@given(st.one_of(v4, v6))
def test_classification_is_total_and_never_raises(address: ipaddress._BaseAddress) -> None:
    """Every address gets an answer. There is no third state and no crash path."""
    verdict = DEFAULT_DENIED.classify(address)
    assert isinstance(verdict.blocked, bool)
    assert verdict.address == address


@settings(max_examples=500)
@given(st.one_of(v4, v6))
def test_a_refusal_always_says_why(address: ipaddress._BaseAddress) -> None:
    """A refusal with an empty reason is a refusal a user cannot act on."""
    verdict = DEFAULT_DENIED.classify(address)
    if verdict.blocked:
        assert verdict.reason
        assert verdict.block is not None
        assert verdict.block.rfc in verdict.reason


@settings(max_examples=400)
@given(v4)
def test_wrapping_an_ipv4_address_never_launders_it(address: ipaddress.IPv4Address) -> None:
    """The core claim of the translation decoding, generated rather than enumerated.

    If an IPv4 address is refused, then every IPv6 form that carries it must be refused too --
    otherwise the wrapper is a bypass. This is the property behind the pydantic-ai advisories.
    """
    if not DEFAULT_DENIED.classify(address).blocked:
        return
    packed = int(address)
    wrapped = (
        ipaddress.IPv6Address((0xFFFF << 32) | packed),  # ::ffff:a.b.c.d
        ipaddress.IPv6Address(packed),  # ::a.b.c.d  (IPv4-compatible)
        ipaddress.IPv6Address((0x0064FF9B << 96) | packed),  # 64:ff9b::a.b.c.d
        ipaddress.IPv6Address((0x2002 << 112) | (packed << 80)),  # 2002:a.b.c.d::
    )
    for form in wrapped:
        assert DEFAULT_DENIED.classify(form).blocked, (
            f"{address} is refused but its wrapper {form} is not; the wrapper is a bypass"
        )


@settings(max_examples=300)
@given(v4)
def test_a_permitted_ipv4_address_stays_permitted_through_a_translation_prefix(
    address: ipaddress.IPv4Address,
) -> None:
    """The other direction: wrapping must not invent a refusal, or NAT64 networks lose the web."""
    if DEFAULT_DENIED.classify(address).blocked:
        return
    nat64 = ipaddress.IPv6Address((0x0064FF9B << 96) | int(address))
    assert not DEFAULT_DENIED.classify(nat64).blocked, (
        f"{address} is permitted but NAT64-wrapped {nat64} is refused; that is a wrong deny"
    )


@settings(max_examples=300)
@given(st.one_of(v4, v6))
def test_classification_agrees_with_itself_across_text_and_object(
    address: ipaddress._BaseAddress,
) -> None:
    """`classify` takes either form; a parser that disagreed with itself would be a bypass."""
    assert DEFAULT_DENIED.classify(str(address)).blocked == DEFAULT_DENIED.classify(address).blocked
