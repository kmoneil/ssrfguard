"""Every way of writing 127.0.0.1 that is not "127.0.0.1", refused twice.

**These pass because this package never string-matches a host. If this file starts failing,
somebody added a fast path.** That sentence is the entire reason the file exists: the property
it fences was never implemented, so nobody has a reason to know it is load-bearing, and the first
performance-minded change that compares a host against a list of known-bad strings deletes it
without noticing.

The class is not hypothetical. GHSA-jhqw-944x-xh94 is exactly this against FastGPT: hex,
decimal, IPv6 mapping and a trailing dot, each of which walked past a validator that was
comparing strings.

Two layers refuse these and **the corpus is split by which one does**, because the difference is
the argument:

* Some are refused by the *shape* of the host, before anything is looked up. A host made only of
  digits and dots that is not a valid address has no legitimate reading, because RFC 3696 rules
  out an all-numeric top-level label, so it is an encoding attempt by construction.
* The rest are refused by *resolution*, and this is the half that matters. ``0x7f.0.0.1`` is a
  well-formed hostname by every syntactic rule; nothing about it looks wrong. It is refused
  because the resolver decodes it to 127.0.0.1 and the address table says no. There is no code
  in this package that knows what hexadecimal is.

The forms are measured against the platform's own resolver rather than assumed, in the first
test, because the second half of the argument is a claim about ``getaddrinfo`` rather than about
us, and a platform that stopped decoding them would move where the defence comes from.
"""

from __future__ import annotations

import ipaddress
import socket
import sys
from dataclasses import dataclass

import pytest

from ssrfguard import BlockedAddressError, BlockedURLError, Policy, Target, resolve

POLICY = Policy()

#: When this corpus was last reviewed against the landscape it is drawn from.
REVIEWED = "2026-08-23"


@dataclass(frozen=True)
class Encoded:
    """One way of writing an address that is not the obvious way.

    Attributes:
        written: What an attacker types.
        url: The same thing inside a URL, bracketed where a URL needs it.
        decodes_to: What the platform's resolver turns it into. ``None`` when it does not
            resolve at all, which is itself a fact worth pinning.
        family: The encoding class, so the corpus can be asserted complete rather than long.
        why: What makes it work, in a few words.
    """

    written: str
    url: str
    decodes_to: str | None
    family: str
    why: str


def _plain(written: str, decodes_to: str | None, family: str, why: str) -> Encoded:
    """Build a row whose URL form is just the host.

    Args:
        written: The host as typed.
        decodes_to: What the resolver makes of it.
        family: The encoding class.
        why: What makes it work.

    Returns:
        The row.
    """
    return Encoded(written, f"http://{written}/", decodes_to, family, why)


def _bracketed(written: str, decodes_to: str, family: str, why: str) -> Encoded:
    """Build a row whose URL form needs brackets, as every IPv6 literal does.

    Args:
        written: The host as typed.
        decodes_to: What the resolver makes of it.
        family: The encoding class.
        why: What makes it work.

    Returns:
        The row.
    """
    return Encoded(written, f"http://[{written}]/", decodes_to, family, why)


#: Refused before anything is resolved, by the shape of the host. Every one of these is digits
#: and dots that is not a valid address, which no registered name can be.
REFUSED_BY_SHAPE = (
    _plain("0177.0.0.1", "127.0.0.1", "octal", "inet_aton reads a leading zero as octal"),
    _plain("2130706433", "127.0.0.1", "decimal", "a bare 32-bit integer is an address"),
    _plain("127.1", "127.0.0.1", "short-form", "inet_aton spreads the last part over the rest"),
    _plain("127.0.0.1.", None, "trailing-dot", "a trailing dot makes an address into a name"),
    _plain("0", "0.0.0.0", "zero", "one digit is a whole address, and it is this host"),
)

#: Refused by resolution, after being decoded. **These are the interesting half**: each is a
#: syntactically unremarkable host, and nothing here recognises the encoding.
REFUSED_BY_RESOLUTION = (
    _plain("0x7f.0.0.1", "127.0.0.1", "hex", "inet_aton reads 0x as hexadecimal"),
    _plain("localhost", "127.0.0.1", "name", "the oldest name for the oldest address"),
    _plain(
        "LOCALHOST", "127.0.0.1", "case", "a name is case-insensitive and this one is normalised"
    ),
    _plain(
        "localhost。",
        "127.0.0.1",
        "ideographic-dot",
        "IDNA treats U+3002 as a label separator, so this is `localhost.`",
    ),
)

#: Refused at the URL layer because normalisation turns them into an address the policy denies --
#: which is the same defence arriving one step earlier.
REFUSED_AFTER_NORMALISATION = (
    _plain(
        "①②⑦.0.0.1",
        "127.0.0.1",
        "unicode-digit",
        "IDNA/NFKC maps circled digits onto ASCII ones",
    ),
    _plain(
        "①②⑦。0。0。1",
        "127.0.0.1",
        "unicode-digit-and-dot",
        "both substitutions at once, which is how these are actually written",
    ),
    _bracketed(
        "::ffff:127.0.0.1", "::ffff:127.0.0.1", "mapped", "an IPv4 address inside an IPv6 one"
    ),
    _bracketed("0000:0000::1", "::1", "compressed", "the same loopback with the zeros written out"),
)

CORPUS = REFUSED_BY_SHAPE + REFUSED_BY_RESOLUTION + REFUSED_AFTER_NORMALISATION

#: Where a platform's resolver disagrees with glibc's, keyed by `sys.platform`.
#:
#: **`decodes_to` is a fact about a C library rather than about this package**, which this file's
#: own opening says, and then the corpus wrote glibc's answers down as though they were
#: everyone's. macOS does not read `0177.0.0.1`'s leading zero as octal. It strips the zero and
#: reads decimal, so the form reaches 177.0.0.1: a public address, with nothing wrong with it,
#: and nothing for the address table to refuse.
#:
#: That does not open a hole, and the shape rule is why. `0177.0.0.1` is digits and dots that is
#: not an address, so `check_url` refuses it before anything is looked up, on every platform.
#: What it does mean is that this one row has **one** defence on macOS rather than two, and the
#: point of writing that here is that it is the kind of thing a reader should be able to find
#: rather than rediscover.
PLATFORM_DECODES: dict[str, dict[str, str | None]] = {
    "darwin": {"0177.0.0.1": "177.0.0.1"},
}


def decoded(row: Encoded) -> str | None:
    """What the resolver on *this* platform makes of a form.

    Args:
        row: The corpus row.

    Returns:
        `row.decodes_to`, unless this platform is recorded above as disagreeing.
    """
    return PLATFORM_DECODES.get(sys.platform, {}).get(row.written, row.decodes_to)


#: Every class this corpus claims to cover. Asserted present, so the corpus is complete rather
#: than merely long, and so deleting a row is a decision rather than a slip.
FAMILIES = frozenset(
    {
        "octal",
        "decimal",
        "hex",
        "short-form",
        "trailing-dot",
        "zero",
        "name",
        "case",
        "ideographic-dot",
        "unicode-digit",
        "unicode-digit-and-dot",
        "mapped",
        "compressed",
    }
)


def _ids(rows: tuple[Encoded, ...]) -> list[str]:
    """Name each parameter after its family and its text.

    Args:
        rows: The rows being parameterised over.

    Returns:
        One id per row.
    """
    return [f"{row.family}:{row.written}" for row in rows]


def test_the_corpus_covers_every_class_it_claims_to() -> None:
    """A corpus that quietly loses a row is a corpus that proves less than it says."""
    assert {row.family for row in CORPUS} == FAMILIES
    assert len({row.written for row in CORPUS}) == len(CORPUS), "a form is in here twice"
    assert REVIEWED, "the corpus carries the date it was last read against the landscape"


@pytest.mark.parametrize("row", CORPUS, ids=_ids(CORPUS))
def test_the_platform_still_decodes_the_form(row: Encoded) -> None:
    """The half of the argument that belongs to the C library rather than to this package.

    Resolving before validating is what removes this entire class, and it works because
    ``getaddrinfo`` decodes these itself. If a platform stopped, the defence would come from the
    shape rule alone on some rows and from nothing at all on others, so this is pinned rather
    than assumed, the same way the address table is pinned against ``ipaddress``.
    """
    expected = decoded(row)
    try:
        answers = sorted({str(info[4][0]) for info in socket.getaddrinfo(row.written, 80)})
    except socket.gaierror:
        assert expected is None, (
            f"{row.written!r} no longer resolves; it used to decode to {expected}"
        )
        return
    assert expected in answers, (
        f"{row.written!r} decodes to {answers} on {sys.platform}, not {expected}. If that is a "
        f"platform difference rather than a regression, PLATFORM_DECODES is where it is recorded"
    )


@pytest.mark.parametrize("row", CORPUS, ids=_ids(CORPUS))
def test_every_form_is_refused(row: Encoded) -> None:
    """The claim in one line: no form survives both layers, whatever it was written as.

    Deliberately not "the URL layer refuses it". Four of these are hosts the URL layer has no
    business refusing, since ``0x7f.0.0.1`` is a well-formed name by every syntactic rule, and
    saying otherwise would be claiming a defence that is not there.
    """
    with pytest.raises((BlockedURLError, BlockedAddressError)):
        resolve(POLICY.check_url(row.url), policy=POLICY)


@pytest.mark.parametrize("row", REFUSED_BY_SHAPE, ids=_ids(REFUSED_BY_SHAPE))
def test_the_shape_rule_refuses_it_before_anything_is_looked_up(row: Encoded) -> None:
    """Digits and dots that are not an address. No registered name has this shape."""
    with pytest.raises(BlockedURLError) as refusal:
        POLICY.check_url(row.url)

    assert "digits and dots" in refusal.value.reason


@pytest.mark.parametrize("row", REFUSED_AFTER_NORMALISATION, ids=_ids(REFUSED_AFTER_NORMALISATION))
def test_normalisation_turns_it_into_an_address_the_policy_denies(row: Encoded) -> None:
    """The host is decoded by the same transformation the resolver would have applied.

    ``check_url`` normalises through the ``idna`` codec, which is what ``getaddrinfo`` does
    internally, so the name that is checked is the name that would be resolved, and the two
    cannot disagree.
    """
    with pytest.raises((BlockedURLError, BlockedAddressError)) as refusal:
        POLICY.check_url(row.url)

    assert "not permitted" in str(refusal.value)


@pytest.mark.parametrize("row", REFUSED_BY_RESOLUTION, ids=_ids(REFUSED_BY_RESOLUTION))
def test_the_url_layer_lets_it_through_and_resolution_refuses_it(row: Encoded) -> None:
    """The half that proves nothing here is matching strings.

    Each of these is a perfectly well-formed hostname. The URL layer has no reason to refuse it
    and does not. It is refused after the resolver decodes it, by the address table, which is
    the only component in this package that has an opinion about what an address means.
    """
    target = POLICY.check_url(row.url)
    assert target.host, "the URL layer refused a form this corpus says it accepts"

    with pytest.raises(BlockedAddressError) as refusal:
        resolve(target, policy=POLICY)

    assert row.decodes_to is not None
    assert row.decodes_to in refusal.value.reason or row.decodes_to == refusal.value.address


@pytest.mark.parametrize("row", REFUSED_BY_SHAPE, ids=_ids(REFUSED_BY_SHAPE))
def test_resolution_refuses_it_even_with_the_shape_rule_bypassed(row: Encoded) -> None:
    """Two independent defences, checked independently.

    A ``Target`` is a record of a decision rather than the decision itself, so one can be built
    by hand, and doing so grants nothing, because resolution re-checks every address it gets
    back. That is what this asserts: delete the shape rule tomorrow and every row here is still
    refused, by the layer that reads addresses rather than text.
    """
    forged = Target(scheme="http", host=row.written, port=80, host_as_written=row.written)
    here = decoded(row)

    if here is None:
        with pytest.raises(socket.gaierror):
            resolve(forged, policy=POLICY)
        return

    if POLICY.permits_address(ipaddress.ip_address(here)):
        # This platform decodes the form to somewhere there is no reason to refuse, so the
        # second defence has nothing to do and the shape rule is the whole of it for this row.
        # Asserted in that direction rather than skipped, because a row that stopped reaching a
        # permitted address would mean the platform had changed its mind and this file should say
        # so either way. See PLATFORM_DECODES.
        assert resolve(forged, policy=POLICY), (
            f"{row.written!r} decodes to {here} and resolved to nothing"
        )
        return

    with pytest.raises(BlockedAddressError) as refusal:
        resolve(forged, policy=POLICY)
    assert here in refusal.value.reason or here == refusal.value.address
