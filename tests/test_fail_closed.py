"""The branches that only a custom table can reach, and they must all refuse.

`AddressTable` is public: a user with a different threat model builds their own rather than
mutating the shipped one. That makes the decoder's *unknown* cases reachable from outside this
package, and an unknown case that resolves to "permitted" would be a bypass anybody could build
by accident.

None of these branches is reachable through `DEFAULT_DENIED` -- `tests/test_registry.py` asserts
the shipped table's translated set is exactly the set the decoder understands. They are here
because that assertion protects the shipped table and not a user's, and because a fail-closed
path nobody has run is a path nobody has proven closes.
"""

from __future__ import annotations

import re
from ipaddress import ip_address, ip_network

import pytest

from ssrfguard import DEFAULT_DENIED, AddressTable, Block, Reach
from ssrfguard._registry import TABLE


def _table_with(extra: Block) -> AddressTable:
    """Build a table from the shipped one plus one more block.

    Args:
        extra: The block to add.

    Returns:
        A new table. The shipped table is not modified.
    """
    return AddressTable((*TABLE, extra))


def test_a_translated_prefix_the_decoder_does_not_know_is_refused() -> None:
    """An unreadable payload refuses the wrapper rather than waving it through."""
    table = _table_with(
        Block(
            network=ip_network("2001:beef::/32"),
            name="Invented translation prefix",
            rfc="RFC0000",
            reach=Reach.TRANSLATED,
            note="Not a real prefix; exists to reach the decoder's unknown branch.",
        )
    )
    verdict = table.classify("2001:beef::808:808")
    assert verdict.blocked, "a prefix whose payload cannot be read must refuse, not permit"
    assert "Invented translation prefix" in verdict.reason


def test_an_ipv4_block_marked_translated_is_refused() -> None:
    """There is no IPv4 wrapper format, so marking one translated is a table bug.

    It still must not permit. A misconfigured table is the most likely way this branch is ever
    reached in the field, and the safe answer to "I do not understand this entry" is no.
    """
    # A block the shipped table does not carry, so this entry is the only match. Using one it
    # *does* carry silently shadows nothing -- the shipped entry wins on stable sort order --
    # which is how the duplicate check below came to exist.
    table = _table_with(
        Block(
            network=ip_network("93.184.216.0/24"),
            name="IPv4 block wrongly marked translated",
            rfc="RFC5737",
            reach=Reach.TRANSLATED,
            note="Exists to prove a nonsensical table entry fails closed rather than open.",
        )
    )
    verdict = table.classify("93.184.216.5")
    assert verdict.blocked
    assert "wrongly marked translated" in verdict.reason


def test_the_translation_depth_bound_refuses_rather_than_recursing() -> None:
    """The depth bound is defence in depth, and it is unreachable with today's table.

    Every translation prefix decodes to an IPv4 address, and no IPv4 block can be a wrapper, so
    a chain never grows past one hop. That makes the bound untestable through the public API --
    and untested bounds are the ones that turn out not to bound anything, so it is exercised
    directly instead of being left as a comment.

    It exists for the prefix that has not been invented yet. If one is ever added that decodes to
    IPv6, this stops being unreachable and the assertion below is already in place.
    """
    nat64 = ip_network("64:ff9b::/96")
    block = next(b for b in TABLE if b.network == nat64)
    already_deep = ((block, ip_address("8.8.8.8")), (block, ip_address("8.8.4.4")))

    verdict = DEFAULT_DENIED._classify(ip_address("64:ff9b::808:808"), already_deep)  # noqa: SLF001  # the bound is unreachable through the public API by construction

    assert verdict.blocked, "past the bound the answer must be no, not another recursion"
    assert verdict.block is not None
    assert verdict.block.network == nat64


def test_a_custom_table_can_be_more_permissive_deliberately() -> None:
    """The extension point has to actually work, or people will edit the shipped table instead."""
    without_rfc1918 = AddressTable(tuple(b for b in TABLE if str(b.network) != "10.0.0.0/8"))
    assert not without_rfc1918.classify("10.1.2.3").blocked
    # and the shipped table is untouched by that
    assert DEFAULT_DENIED.classify("10.1.2.3").blocked


def test_a_table_with_a_duplicate_network_is_refused_at_construction() -> None:
    """A shadowed entry is a rule its author believes is in force and is not.

    Lookup is longest-prefix and Python's sort is stable, so two entries for one network resolve
    to "whichever was listed first" -- which is not a rule anyone wrote down. Refusing here means
    the mistake surfaces where it was made instead of at the one address that needed the entry
    that lost.
    """
    duplicate = Block(
        network=ip_network("10.0.0.0/8"),
        name="Second opinion about RFC1918",
        rfc="RFC1918",
        reach=Reach.PERMITTED,
        note="A duplicate, which is the point of this test.",
    )
    with pytest.raises(ValueError, match=re.escape("duplicate networks: 10.0.0.0/8")):
        AddressTable((*TABLE, duplicate))
