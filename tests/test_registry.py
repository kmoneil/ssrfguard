"""Integrity of the address table itself, independent of what it decides.

These are the assertions that would catch a bad regeneration. `scripts/refresh_registry.py`
reaches across the network and rewrites a security control; the diff is reviewed by a human, and
this file is what checks the things a human reading a 200-line diff will not.
"""

from __future__ import annotations

import re
from ipaddress import ip_address, ip_network

import pytest

from ssrfguard import DEFAULT_DENIED, REGISTRY_SNAPSHOT, Reach
from ssrfguard._registry import TABLE


def test_snapshot_is_a_date() -> None:
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", REGISTRY_SNAPSHOT)


def test_every_block_names_an_rfc() -> None:
    """A refusal that cannot cite a document is a refusal a user cannot check."""
    for block in TABLE:
        assert re.fullmatch(r"RFC\d+(, RFC\d+)*", block.rfc), (
            f"{block.network} has an unparseable RFC field: {block.rfc!r}"
        )


def test_no_block_appears_twice() -> None:
    """Two entries for one network means one of them silently never applies."""
    seen: dict[object, str] = {}
    for block in TABLE:
        assert block.network not in seen, (
            f"{block.network} appears as both {seen[block.network]!r} and {block.name!r}"
        )
        seen[block.network] = block.name


def test_every_departure_from_the_registries_explains_itself() -> None:
    """An entry IANA does not carry, or disagrees with, must say why in the table."""
    for block in TABLE:
        if block.reach is Reach.TRANSLATED or block.note:
            assert block.note, f"{block.network} departs from the registry with no note"
            assert len(block.note) > 40, f"{block.network}'s note is too short to be a reason"


def test_translated_blocks_are_the_closed_set_the_decoder_knows() -> None:
    """A TRANSLATED block the decoder cannot read is refused, so an unknown one is a wrong deny."""
    decodable = {
        ip_network("::ffff:0:0/96"),
        ip_network("::/96"),
        ip_network("64:ff9b::/96"),
        ip_network("2002::/16"),
        ip_network("2001::/32"),
    }
    translated = {b.network for b in TABLE if b.reach is Reach.TRANSLATED}
    assert translated == decodable, (
        "the table and the decoder disagree about which prefixes carry an IPv4 payload; "
        f"table has {translated ^ decodable} that the other does not"
    )


@pytest.mark.parametrize(
    ("metadata", "service"),
    [
        ("169.254.169.254", "AWS, GCP, Azure IMDS"),
        ("169.254.170.2", "AWS ECS task"),
        ("100.100.100.200", "Alibaba Cloud"),
        ("192.0.0.192", "Oracle Cloud"),
        ("fd00:ec2::254", "AWS IMDS over IPv6"),
    ],
)
def test_metadata_entries_are_a_message_not_a_mechanism(metadata: str, service: str) -> None:
    """Every metadata address must already be denied by an enclosing block.

    The named entries exist so a refusal can say *which service* it refused. If one of them were
    the only thing denying an address, deleting it during a regeneration would open a hole while
    looking like a cosmetic change. This asserts the mechanism is the enclosing block.
    """
    address = ip_address(metadata)
    named = DEFAULT_DENIED.match(address)
    assert named is not None
    assert service in named.name

    without_the_name = tuple(b for b in TABLE if b.network != named.network)
    enclosing = type(DEFAULT_DENIED)(without_the_name).classify(address)
    assert enclosing.blocked, (
        f"{metadata} is denied ONLY by its named entry; the enclosing block does not cover it"
    )
