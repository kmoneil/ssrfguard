"""Regenerate `src/ssrfguard/_registry.py` from the IANA special-purpose registries.

Run by hand when IANA moves a registry, not in CI: the generated module is the committed
artifact and a build that reached across the network for its own security table would be a
build whose answer depends on the day it ran.

    python scripts/refresh_registry.py && git diff src/ssrfguard/_registry.py

**Read the diff.** A registry change is a change to what this package refuses, so it is reviewed
like any other change to a security control, and the drift test in `tests/test_address_table.py`
will fail on anything that also moves our disagreement with the standard library.

## What the transformation does

IANA's `Globally Reachable` column maps to our verdict, with three deliberate departures, each of
which is a case where the registry answers a different question than we are asking:

* **Blank or terminated** entries are deprecated allocations. IANA stops asserting anything;
  we refuse, because a deprecated special-purpose block is not something a server-side fetcher
  has any business reaching.
* **`N/A`** marks a prefix whose reachability depends on what is embedded in it. Those become
  ``TRANSLATED``: decode the embedded IPv4 address and ask the question again about that.
* **`64:ff9b::/96` is `True` and still becomes `TRANSLATED`.** IANA is right that the prefix is
  globally routable, but the question we are asking is where the packet ends up, and for a
  translation prefix that is the embedded address. This is the single most important line in
  this file; see `ADDITIONS` for the rest.

`ADDITIONS` carries what the special-purpose registries do not, and lives here rather than in the
generated file so that each entry's justification is regenerated with it.
"""

from __future__ import annotations

import csv
import datetime
import io
import re
import textwrap
import urllib.request
from ipaddress import ip_network
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET = REPO_ROOT / "src" / "ssrfguard" / "_registry.py"

SOURCES = {
    4: "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv",
    6: "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv",
}

# Prefixes that carry an IPv4 destination inside them. The registry cannot express "ask again
# about what is inside this", so the decision is ours, and each of these departs from IANA for
# a *different* reason, which is why the notes are per-prefix rather than one shared sentence.
TRANSLATED_PREFIXES: dict[str, str] = {
    "::ffff:0:0/96": (
        "IANA marks this not globally reachable, which read literally is a flat refusal. That "
        "would be a wrong deny: ::ffff:8.8.8.8 reaches 8.8.8.8, and getaddrinfo returns mapped "
        "addresses wherever AI_V4MAPPED is in play. Decoding is both safer and more permissive "
        "than the registry here, which is unusual and worth the note."
    ),
    "64:ff9b::/96": (
        "IANA marks this globally reachable and is right about routing: the prefix is public. "
        "We decode anyway, because the question here is not whether the address is routable but "
        "where the packet ends up, and 64:ff9b::7f00:1 ends up at 127.0.0.1. This is the single "
        "most important departure in the table; a guard that trusts is_global permits it."
    ),
    "2002::/16": (
        "IANA answers N/A precisely because reachability depends on the embedded address. 6to4 "
        "is deprecated for its relay anycast (RFC 7526) but the prefix still carries an IPv4 "
        "destination in bits 16 to 48, so 2002:7f00:1:: reaches 127.0.0.1."
    ),
    "2001::/32": (
        "IANA answers N/A for the same reason as 6to4. Teredo carries two IPv4 addresses: the "
        "server in bits 32 to 64 and the client, bit-inverted, in the low 32 (RFC 4380 section "
        "4). Either being internal is disqualifying, so both are decoded."
    ),
}

# What the special-purpose registries do not carry. Every one of these was measured to be
# *permitted* by a table built from the registries alone, which is why each is here.
ADDITIONS: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "::/96",
        "IPv4-Compatible (deprecated)",
        "RFC4291",
        "TRANSLATED",
        "Deprecated by RFC 4291 section 2.5.5.1 and removed from the registry, so a table built "
        "from IANA alone permits it, measured rather than assumed. It embeds an arbitrary IPv4 "
        "address in its low "
        "32 bits, so ::7f00:1 reaches 127.0.0.1. The more specific ::1/128 and ::/128 entries "
        "win on longest-prefix match, so loopback and unspecified keep their own names.",
    ),
    (
        "224.0.0.0/4",
        "Multicast",
        "RFC5771",
        "DENIED",
        "Multicast lives in its own IANA registry, so the special-purpose table does not carry "
        "it and a table built from that alone permits 224.0.0.1 and 239.255.255.250, measured "
        "rather than assumed. A fetcher has no reason to address a multicast group.",
    ),
    (
        "ff00::/8",
        "Multicast",
        "RFC4291",
        "DENIED",
        "Same gap on the IPv6 side, and worse: ff02::1 is all-nodes and the standard library "
        "reports is_global=True for it.",
    ),
    (
        "fec0::/10",
        "Site-Local (deprecated)",
        "RFC3879",
        "DENIED",
        "Deprecated by RFC 3879 and removed from the registry, so IANA alone permits it, and "
        "the standard library reports is_global=True. It is an internal-addressing prefix by "
        "construction.",
    ),
)

# IANA truncates one name in its own CSV. Expanded here rather than shipped verbatim, because
# "IPv4-IPv6 Translat." reads like a typo in a refusal message and a refusal a user distrusts is
# one they configure around. The only rename this generator performs.
RENAMES = {"IPv4-IPv6 Translat.": "IPv4-IPv6 Translation"}

# Metadata endpoints, carried only so a refusal can name what it refused. Every one of these is
# already inside a denied block; `tests/test_registry.py` asserts that, so removing an entry
# costs a good error message and never a denial.
METADATA: tuple[tuple[str, str, str], ...] = (
    ("169.254.169.254/32", "Cloud metadata (AWS, GCP, Azure IMDS)", "RFC3927"),
    ("169.254.170.2/32", "Cloud metadata (AWS ECS task)", "RFC3927"),
    ("100.100.100.200/32", "Cloud metadata (Alibaba Cloud)", "RFC6598"),
    ("192.0.0.192/32", "Cloud metadata (Oracle Cloud)", "RFC6890"),
    ("fd00:ec2::254/128", "Cloud metadata (AWS IMDS over IPv6)", "RFC4193"),
)

HEADER = '''"""The address table, transcribed from the IANA special-purpose registries.

**Generated. Do not edit by hand.** Run `python scripts/refresh_registry.py`, which carries the
provenance, the transformation rules and the justification for every entry IANA does not supply.

The point of this file is that it is *ours*. `ipaddress.is_private` and `ipaddress.is_global` are
both wrong for this question, in opposite directions, and they are wrong differently on different
patch releases of CPython, so a guard built on them answers a question that changes underneath
it. Measured examples, identical on 3.10, 3.11 and 3.13:

    64:ff9b::7f00:1   is_private=False  is_global=True    # 127.0.0.1 behind a NAT64 gateway
    ff02::1           is_private=False  is_global=True    # IPv6 all-nodes multicast
    5f00::1           is_private=False  is_global=True    # IANA says not globally reachable
    100.64.0.1        is_private=False  is_global=False   # CGNAT, which neither predicate denies

The third line is not a CPython bug: IANA genuinely marks `64:ff9b::/96` globally reachable, and
it is. `is_global` answers *is this address globally routable*; the question here is *where does
this packet end up*, and for a translation prefix those differ. No standard-library predicate
will ever answer the second one, which is why this table exists rather than a call to one.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network

__all__ = ["REGISTRY_SNAPSHOT", "TABLE", "Block", "Reach"]

#: The date the IANA registries below were fetched. Bumped by `scripts/refresh_registry.py`.
REGISTRY_SNAPSHOT = "{snapshot}"


class Reach(enum.Enum):
    """What this table says about a block.

    Attributes:
        DENIED: Refuse any address in this block.
        PERMITTED: Allow, overriding any enclosing denied block. IANA marks a handful of
            special-purpose blocks globally reachable, such as public anycast services, AS112
            and AMT, and refusing those would be a denial with no security benefit behind it.
        TRANSLATED: The block carries an IPv4 destination inside it. Decode the embedded address
            and ask the question again about that, rather than answering about the wrapper.
    """

    DENIED = "denied"
    PERMITTED = "permitted"
    TRANSLATED = "translated"


@dataclass(frozen=True)
class Block:
    """One row of the address table.

    Attributes:
        network: The address block.
        name: IANA's name for it, or ours for the entries IANA does not carry.
        rfc: The RFC that defines it, for the refusal message.
        reach: What this table says about it.
        note: Why this entry departs from the registries, empty when it does not.
    """

    network: IPv4Network | IPv6Network
    name: str
    rfc: str
    reach: Reach
    note: str = ""


def _b(cidr: str, name: str, rfc: str, reach: Reach, note: str = "") -> Block:
    """Build a block, parsing the CIDR once at import.

    Args:
        cidr: The address block in CIDR form.
        name: Human-readable name.
        rfc: Defining RFC.
        reach: The verdict for this block.
        note: Why this entry departs from the registries.

    Returns:
        The parsed block.
    """
    return Block(network=ip_network(cidr), name=name, rfc=rfc, reach=reach, note=note)


#: Every block this package knows about, in no particular order. Lookup is by longest prefix,
#: so ordering here carries no meaning and must not be relied on.
TABLE: tuple[Block, ...] = (
'''


def _verdict(row: dict[str, str], cidr: str) -> tuple[str, str]:
    """Map one registry row to a verdict.

    Args:
        row: The CSV row.
        cidr: The single block this call is about, already split and cleaned.

    Returns:
        A pair of (Reach member name, note).
    """
    if cidr in TRANSLATED_PREFIXES:
        return "TRANSLATED", TRANSLATED_PREFIXES[cidr]
    if row["Termination Date"].strip() not in {"N/A", ""}:
        return "DENIED", "Deprecated allocation; IANA stopped asserting reachability for it."
    reachable = row["Globally Reachable"].strip()
    if reachable == "":
        return "DENIED", "Registry asserts nothing for this block; refused rather than assumed."
    if reachable.startswith("True"):
        return "PERMITTED", ""
    return "DENIED", ""


def _rows(version: int) -> list[tuple[str, str, str, str, str]]:
    """Fetch and transcribe one registry.

    **Every block is parsed before it is emitted**, and that is a boundary rather than a
    nicety. What comes back from the network is written into a Python module that
    `import ssrfguard` executes, so a cell this function does not understand is a cell that
    should stop the generator rather than reach the file. The likely case is IANA changing a
    footnote format; the unlikely one is worse, and both are refused by the same line.

    Args:
        version: 4 or 6.

    Returns:
        Tuples of (cidr, name, rfc, reach, note).

    Raises:
        SystemExit: If a row's address block is not a network. Named loudly rather than skipped,
            because a block silently dropped from this table is an address silently permitted.
    """
    with urllib.request.urlopen(SOURCES[version], timeout=30) as response:  # noqa: S310  # constant https URL
        text = response.read().decode("utf-8")
    out: list[tuple[str, str, str, str, str]] = []
    for row in csv.DictReader(io.StringIO(text)):
        rfcs = ", ".join(sorted(set(re.findall(r"RFC\s?\d+", row["RFC"]))))
        name = " ".join(row["Name"].replace('"', "").split())
        name = RENAMES.get(name, name)
        for raw in row["Address Block"].split(","):
            cidr = re.sub(r"\s*\[\d+\]", "", raw).strip()
            if not cidr:
                continue
            try:
                ip_network(cidr)
            except ValueError as bad:
                raise SystemExit(
                    f"IPv{version} registry row {row['Name']!r} has an address block this "
                    f"generator cannot parse: {cidr!r} ({bad}). Read the registry before "
                    f"widening this, because the block is going into a table that decides what "
                    f"gets refused."
                ) from bad
            reach, note = _verdict(row, cidr)
            out.append((cidr, name, rfcs, reach, note))
    return out


def _emit(entries: list[tuple[str, str, str, str, str]]) -> str:
    """Render entries as `_b(...)` calls.

    Args:
        entries: Tuples of (cidr, name, rfc, reach, note).

    Returns:
        The rendered source fragment.
    """
    lines = []
    for cidr, name, rfc, reach, note in entries:
        # `repr` rather than an f-string wrapping the value in quote characters. Three of these
        # come from a CSV fetched over the network and are being written into Python source that
        # `import ssrfguard` executes, so a quote in one of them closed the literal and the
        # rest of the cell became code. `name` happened to be defended (its quotes are stripped
        # upstream) and `cidr` was not, which is the shape of every bug this package is about:
        # the field nobody thought of as input.
        parts = [repr(cidr), repr(name), repr(rfc), f"Reach.{reach}"]
        if note:
            # Wrapped into implicit-concatenated literals: `ruff format` will not split a long
            # string, so an unwrapped note fails E501 and the generated file cannot pass its own
            # lint gate.
            wrapped = "\n".join(f'        "{line} "' for line in textwrap.wrap(note, width=88))
            wrapped = wrapped.rstrip()[:-2] + '"'
            lines.append(f"    _b(\n        {', '.join(parts)},\n{wrapped},\n    ),")
        else:
            lines.append(f"    _b({', '.join(parts)}),")
    return "\n".join(lines)


def main() -> int:
    """Regenerate the registry module.

    Returns:
        Process exit status.
    """
    snapshot = datetime.datetime.now(tz=datetime.timezone.utc).date().isoformat()
    body = [HEADER.format(snapshot=snapshot)]

    for version in (4, 6):
        body.append(f"    # ---- IANA IPv{version} Special-Purpose Address Registry ----")
        body.append(_emit(_rows(version)))
        body.append("")

    body.append("    # ---- Not carried by the special-purpose registries; see the generator ----")
    body.append(_emit([(c, n, r, v, note) for c, n, r, v, note in ADDITIONS]))
    body.append("")
    body.append("    # ---- Named only so a refusal can say what it refused ----")
    body.append(
        _emit(
            [
                (
                    cidr,
                    name,
                    rfc,
                    "DENIED",
                    "Already inside a denied block; named so the message can say which service "
                    "this is. tests/test_registry.py asserts the enclosure, so removing this "
                    "costs a good message and never a denial.",
                )
                for cidr, name, rfc in METADATA
            ]
        )
    )
    body.append(")")
    body.append("")

    TARGET.write_text("\n".join(body), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
