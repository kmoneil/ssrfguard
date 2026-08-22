"""Where this table disagrees with `ipaddress`, pinned by name.

This is the file that makes "version-stable" mean something. `ipaddress.is_private` and
`is_global` are the two predicates a guard would naturally reach for, and both are wrong for this
question in ways that have already moved once -- CVE-2024-4032 rewrote CPython's tables in
3.9.19, 3.10.14, 3.11.9 and 3.12.4.

So the disagreements are enumerated rather than tolerated. Every address in the corpus where our
answer differs from the standard library's must appear in `DISAGREEMENTS` with a reason, and
**every entry in `DISAGREEMENTS` must still actually disagree**. That second direction is the
one that earns its keep: when a CPython patch release changes one of these, the build fails with
the address named instead of our behaviour quietly shifting underneath us.

The `compat` lane runs this on every supported interpreter, which is the only way it can see a
disagreement that exists on one and not another.
"""

from __future__ import annotations

import ipaddress
import sys

import pytest

from ssrfguard import DEFAULT_DENIED

from .test_address_table import CORPUS

# address -> why we differ from BOTH stdlib predicates read the obvious way.
#
# "obvious way" means: a guard would refuse an address when `is_private` is True, or when
# `is_global` is False. An address is listed here when our verdict differs from at least one of
# those readings.
DISAGREEMENTS: dict[str, str] = {
    # -- the strongest stdlib guard PERMITS these; we refuse. This is the dangerous direction,
    #    and every one of them is reachable from a server that trusts `ipaddress`. --
    "64:ff9b::7f00:1": "NAT64 prefix carrying 127.0.0.1; is_global=True because the prefix "
    "genuinely is routable -- the packet is not",
    "64:ff9b::a00:1": "NAT64 prefix carrying 10.0.0.1",
    "64:ff9b::a9fe:a9fe": "NAT64 prefix carrying the cloud metadata address",
    "::7f00:1": "IPv4-compatible IPv6 carrying 127.0.0.1; RFC 4291 deprecated the prefix and "
    "both IANA and CPython dropped it, so nothing in the standard library sees it",
    "::a00:1": "IPv4-compatible IPv6 carrying 10.0.0.1",
    "ff02::1": "IPv6 all-nodes multicast; is_global=True and is_private=False",
    "224.0.0.1": "IPv4 all-hosts multicast; multicast has its own IANA registry and CPython's "
    "private/global tables do not consult it",
    "239.255.255.250": "IPv4 multicast, the SSDP group",
    "fec0::1": "site-local, deprecated by RFC 3879 and dropped from both tables; is_global=True",
    "192.88.99.1": "6to4 relay anycast, deprecated by RFC 7526; is_global=True",
    "5f00::1": "SRv6 SIDs (RFC 9602); IANA says not globally reachable, CPython says it is -- "
    "live drift, not a historical one",
    "100:0:0:1::1": "RFC 9780 dummy prefix; same live drift as 5f00::/16",
    # -- the stdlib REFUSES this and we permit: a wrong deny we fix rather than inherit. --
    "2002:808:808::": "6to4 carrying 8.8.8.8. CPython treats the whole of 2002::/16 as private, "
    "so a stdlib guard refuses a public destination; we decode and permit it",
}


def _stdlib_would_refuse(address: str) -> bool:
    """How a guard built on the standard library's predicates would answer.

    Args:
        address: The address to classify.

    Returns:
        Whether such a guard would refuse it. Refusing when `is_private` is true or `is_global`
        is false is the most conservative reading available from the two predicates, so this is
        the strongest stdlib-based guard, not a strawman.
    """
    parsed = ipaddress.ip_address(address)
    return bool(parsed.is_private) or not parsed.is_global


@pytest.mark.parametrize(("address", "blocked", "what"), CORPUS, ids=[c[0] for c in CORPUS])
def test_every_disagreement_is_declared(address: str, blocked: bool, what: str) -> None:
    """Our answer may differ from the standard library's only where we said it would."""
    ours = DEFAULT_DENIED.classify(address).blocked
    theirs = _stdlib_would_refuse(address)
    if ours == theirs:
        return
    assert address in DISAGREEMENTS, (
        f"{address} ({what}): we say blocked={ours}, the standard library's predicates say "
        f"{theirs}, and nothing in DISAGREEMENTS explains it. Either this is a bug in the "
        f"table, or it is a departure that has to be written down."
    )


@pytest.mark.parametrize("address", sorted(DISAGREEMENTS), ids=sorted(DISAGREEMENTS))
def test_every_declared_disagreement_still_disagrees(address: str) -> None:
    """A CPython release that changes one of these must fail the build, not pass it quietly.

    This is the direction that matters. If a patch release fixes `is_global` for `5f00::/16`,
    our table is unchanged and still correct -- but the *reason* recorded here has expired, and a
    note that no longer describes reality is how a table stops being reviewable.
    """
    ours = DEFAULT_DENIED.classify(address).blocked
    theirs = _stdlib_would_refuse(address)
    assert ours != theirs, (
        f"{address} no longer disagrees with the standard library on "
        f"CPython {sys.version.split()[0]}: both now say blocked={ours}. Remove it from "
        f"DISAGREEMENTS -- the recorded reason was {DISAGREEMENTS[address]!r}."
    )


def test_the_corpus_covers_every_disagreement() -> None:
    """A declared disagreement nothing exercises is a claim, not a test."""
    corpus = {address for address, _, _ in CORPUS}
    orphans = set(DISAGREEMENTS) - corpus
    assert not orphans, f"declared disagreements that no corpus row exercises: {sorted(orphans)}"


def test_the_stdlib_is_actually_wrong_about_the_headline_case() -> None:
    """The one example the README and the card both lead with, asserted directly."""
    nat64 = ipaddress.ip_address("64:ff9b::7f00:1")
    assert nat64.is_global is True
    assert nat64.is_private is False
    assert DEFAULT_DENIED.classify(nat64).blocked is True


def test_is_private_alone_is_weaker_still() -> None:
    """The most common mistake is checking `is_private` and nothing else.

    `_stdlib_would_refuse` models the *strongest* guard the two predicates can build, which is
    the fair comparison and the one `DISAGREEMENTS` is measured against. It is not what most
    code does. CGNAT is the cheapest demonstration: `is_private` is False for the whole of
    RFC 6598, so an `is_private`-only guard hands an attacker 4.2 million addresses that
    routinely front internal infrastructure.
    """
    cgnat = ipaddress.ip_address("100.64.0.1")
    assert cgnat.is_private is False, "an is_private-only guard permits CGNAT"
    assert cgnat.is_global is False, "which is why the combined reading is the fair baseline"
    assert DEFAULT_DENIED.classify(cgnat).blocked is True


def test_the_dangerous_direction_dominates() -> None:
    """Most of our disagreements are addresses the standard library would let through.

    Stated as a test so the shape of the table's value is asserted rather than claimed in a
    README. If this ever inverts -- if we start mostly disagreeing by refusing things the
    standard library permits for good reason -- the table has drifted into false positives and
    somebody should look at it.
    """
    permits_but_we_refuse = [
        address
        for address in DISAGREEMENTS
        if DEFAULT_DENIED.classify(address).blocked and not _stdlib_would_refuse(address)
    ]
    assert len(permits_but_we_refuse) >= 10
    assert len(permits_but_we_refuse) > len(DISAGREEMENTS) - len(permits_but_we_refuse)
