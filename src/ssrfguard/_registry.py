"""The address table, transcribed from the IANA special-purpose registries.

**Generated. Do not edit by hand** -- run `python scripts/refresh_registry.py`, which carries the
provenance, the transformation rules and the justification for every entry IANA does not supply.

The point of this file is that it is *ours*. `ipaddress.is_private` and `ipaddress.is_global` are
both wrong for this question, in opposite directions, and they are wrong differently on different
patch releases of CPython -- so a guard built on them answers a question that changes underneath
it. Measured examples, identical on 3.10, 3.11 and 3.13:

    64:ff9b::7f00:1   is_private=False  is_global=True   -- 127.0.0.1 behind a NAT64 gateway
    ff02::1           is_private=False  is_global=True   -- IPv6 all-nodes multicast
    5f00::1           is_private=False  is_global=True   -- IANA says not globally reachable
    100.64.0.1        is_private=False  is_global=False  -- CGNAT, which neither predicate denies

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
REGISTRY_SNAPSHOT = "2026-08-22"


class Reach(enum.Enum):
    """What this table says about a block.

    Attributes:
        DENIED: Refuse any address in this block.
        PERMITTED: Allow, overriding any enclosing denied block. IANA marks a handful of
            special-purpose blocks globally reachable -- public anycast services, AS112, AMT --
            and refusing those would be a denial with no security benefit behind it.
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


#: Every block this package knows about, in no particular order -- lookup is by longest prefix,
#: so ordering here carries no meaning and must not be relied on.
TABLE: tuple[Block, ...] = (
    # ---- IANA IPv4 Special-Purpose Address Registry ----
    _b("0.0.0.0/8", "This network", "RFC791", Reach.DENIED),
    _b("0.0.0.0/32", "This host on this network", "RFC1122", Reach.DENIED),
    _b("10.0.0.0/8", "Private-Use", "RFC1918", Reach.DENIED),
    _b("100.64.0.0/10", "Shared Address Space", "RFC6598", Reach.DENIED),
    _b("127.0.0.0/8", "Loopback", "RFC1122", Reach.DENIED),
    _b("169.254.0.0/16", "Link Local", "RFC3927", Reach.DENIED),
    _b("172.16.0.0/12", "Private-Use", "RFC1918", Reach.DENIED),
    _b("192.0.0.0/24", "IETF Protocol Assignments", "RFC6890", Reach.DENIED),
    _b("192.0.0.0/29", "IPv4 Service Continuity Prefix", "RFC7335", Reach.DENIED),
    _b("192.0.0.8/32", "IPv4 dummy address", "RFC7600", Reach.DENIED),
    _b("192.0.0.9/32", "Port Control Protocol Anycast", "RFC7723", Reach.PERMITTED),
    _b("192.0.0.10/32", "Traversal Using Relays around NAT Anycast", "RFC8155", Reach.PERMITTED),
    _b("192.0.0.170/32", "NAT64/DNS64 Discovery", "RFC7050, RFC8880", Reach.DENIED),
    _b("192.0.0.171/32", "NAT64/DNS64 Discovery", "RFC7050, RFC8880", Reach.DENIED),
    _b("192.0.2.0/24", "Documentation (TEST-NET-1)", "RFC5737", Reach.DENIED),
    _b("192.31.196.0/24", "AS112-v4", "RFC7535", Reach.PERMITTED),
    _b("192.52.193.0/24", "AMT", "RFC7450", Reach.PERMITTED),
    _b(
        "192.88.99.0/24",
        "Deprecated (6to4 Relay Anycast)",
        "RFC7526",
        Reach.DENIED,
        "Deprecated allocation; IANA stopped asserting reachability for it.",
    ),
    _b("192.88.99.2/32", "6a44-relay anycast address", "RFC6751", Reach.DENIED),
    _b("192.168.0.0/16", "Private-Use", "RFC1918", Reach.DENIED),
    _b("192.175.48.0/24", "Direct Delegation AS112 Service", "RFC7534", Reach.PERMITTED),
    _b("198.18.0.0/15", "Benchmarking", "RFC2544", Reach.DENIED),
    _b("198.51.100.0/24", "Documentation (TEST-NET-2)", "RFC5737", Reach.DENIED),
    _b("203.0.113.0/24", "Documentation (TEST-NET-3)", "RFC5737", Reach.DENIED),
    _b("240.0.0.0/4", "Reserved", "RFC1112", Reach.DENIED),
    _b("255.255.255.255/32", "Limited Broadcast", "RFC8190, RFC919", Reach.DENIED),
    # ---- IANA IPv6 Special-Purpose Address Registry ----
    _b("::1/128", "Loopback Address", "RFC4291", Reach.DENIED),
    _b("::/128", "Unspecified Address", "RFC4291", Reach.DENIED),
    _b(
        "::ffff:0:0/96",
        "IPv4-mapped Address",
        "RFC4291",
        Reach.TRANSLATED,
        "IANA marks this not globally reachable, which read literally is a flat refusal. That "
        "would be a wrong deny: ::ffff:8.8.8.8 reaches 8.8.8.8, and getaddrinfo returns mapped "
        "addresses wherever AI_V4MAPPED is in play. Decoding is both safer and more permissive "
        "than the registry here, which is unusual and worth the note.",
    ),
    _b(
        "64:ff9b::/96",
        "IPv4-IPv6 Translation",
        "RFC6052",
        Reach.TRANSLATED,
        "IANA marks this globally reachable and is right about routing -- the prefix is public. "
        "We decode anyway, because the question here is not whether the address is routable but "
        "where the packet ends up, and 64:ff9b::7f00:1 ends up at 127.0.0.1. This is the single "
        "most important departure in the table; a guard that trusts is_global permits it.",
    ),
    _b("64:ff9b:1::/48", "IPv4-IPv6 Translation", "RFC8215", Reach.DENIED),
    _b("100::/64", "Discard-Only Address Block", "RFC6666", Reach.DENIED),
    _b("100:0:0:1::/64", "Dummy IPv6 Prefix", "RFC9780", Reach.DENIED),
    _b("2001::/23", "IETF Protocol Assignments", "RFC2928", Reach.DENIED),
    _b(
        "2001::/32",
        "TEREDO",
        "RFC4380, RFC8190",
        Reach.TRANSLATED,
        "IANA answers N/A for the same reason as 6to4. Teredo carries two IPv4 addresses -- the "
        "server in bits 32 to 64 and the client, bit-inverted, in the low 32 (RFC 4380 section 4) "
        "-- and either being internal is disqualifying, so both are decoded.",
    ),
    _b("2001:1::1/128", "Port Control Protocol Anycast", "RFC7723", Reach.PERMITTED),
    _b("2001:1::2/128", "Traversal Using Relays around NAT Anycast", "RFC8155", Reach.PERMITTED),
    _b("2001:1::3/128", "DNS-SD Service Registration Protocol Anycast", "RFC9665", Reach.PERMITTED),
    _b("2001:2::/48", "Benchmarking", "RFC5180", Reach.DENIED),
    _b("2001:3::/32", "AMT", "RFC7450", Reach.PERMITTED),
    _b("2001:4:112::/48", "AS112-v6", "RFC7535", Reach.PERMITTED),
    _b(
        "2001:10::/28",
        "Deprecated (previously ORCHID)",
        "RFC4843",
        Reach.DENIED,
        "Deprecated allocation; IANA stopped asserting reachability for it.",
    ),
    _b("2001:20::/28", "ORCHIDv2", "RFC7343", Reach.PERMITTED),
    _b(
        "2001:30::/28",
        "Drone Remote ID Protocol Entity Tags (DETs) Prefix",
        "RFC9374",
        Reach.PERMITTED,
    ),
    _b("2001:db8::/32", "Documentation", "RFC3849", Reach.DENIED),
    _b(
        "2002::/16",
        "6to4",
        "RFC3056",
        Reach.TRANSLATED,
        "IANA answers N/A precisely because reachability depends on the embedded address. 6to4 is "
        "deprecated for its relay anycast (RFC 7526) but the prefix still carries an IPv4 "
        "destination in bits 16 to 48, so 2002:7f00:1:: reaches 127.0.0.1.",
    ),
    _b("2620:4f:8000::/48", "Direct Delegation AS112 Service", "RFC7534", Reach.PERMITTED),
    _b("3fff::/20", "Documentation", "RFC9637", Reach.DENIED),
    _b("5f00::/16", "Segment Routing (SRv6) SIDs", "RFC9602", Reach.DENIED),
    _b("fc00::/7", "Unique-Local", "RFC4193, RFC8190", Reach.DENIED),
    _b("fe80::/10", "Link-Local Unicast", "RFC4291", Reach.DENIED),
    # ---- Not carried by the special-purpose registries; see the generator ----
    _b(
        "::/96",
        "IPv4-Compatible (deprecated)",
        "RFC4291",
        Reach.TRANSLATED,
        "Deprecated by RFC 4291 section 2.5.5.1 and removed from the registry, so a table built "
        "from IANA alone permits it -- measured. It embeds an arbitrary IPv4 address in its low "
        "32 bits, so ::7f00:1 reaches 127.0.0.1. The more specific ::1/128 and ::/128 entries win "
        "on longest-prefix match, so loopback and unspecified keep their own names.",
    ),
    _b(
        "224.0.0.0/4",
        "Multicast",
        "RFC5771",
        Reach.DENIED,
        "Multicast lives in its own IANA registry, so the special-purpose table does not carry it "
        "and a table built from that alone permits 224.0.0.1 and 239.255.255.250 -- measured. A "
        "fetcher has no reason to address a multicast group.",
    ),
    _b(
        "ff00::/8",
        "Multicast",
        "RFC4291",
        Reach.DENIED,
        "Same gap on the IPv6 side, and worse: ff02::1 is all-nodes and the standard library "
        "reports is_global=True for it.",
    ),
    _b(
        "fec0::/10",
        "Site-Local (deprecated)",
        "RFC3879",
        Reach.DENIED,
        "Deprecated by RFC 3879 and removed from the registry, so IANA alone permits it -- and "
        "the standard library reports is_global=True. It is an internal-addressing prefix by "
        "construction.",
    ),
    # ---- Named only so a refusal can say what it refused ----
    _b(
        "169.254.169.254/32",
        "Cloud metadata (AWS, GCP, Azure IMDS)",
        "RFC3927",
        Reach.DENIED,
        "Already inside a denied block; named so the message can say which service this is. "
        "tests/test_registry.py asserts the enclosure, so removing this costs a good message and "
        "never a denial.",
    ),
    _b(
        "169.254.170.2/32",
        "Cloud metadata (AWS ECS task)",
        "RFC3927",
        Reach.DENIED,
        "Already inside a denied block; named so the message can say which service this is. "
        "tests/test_registry.py asserts the enclosure, so removing this costs a good message and "
        "never a denial.",
    ),
    _b(
        "100.100.100.200/32",
        "Cloud metadata (Alibaba Cloud)",
        "RFC6598",
        Reach.DENIED,
        "Already inside a denied block; named so the message can say which service this is. "
        "tests/test_registry.py asserts the enclosure, so removing this costs a good message and "
        "never a denial.",
    ),
    _b(
        "192.0.0.192/32",
        "Cloud metadata (Oracle Cloud)",
        "RFC6890",
        Reach.DENIED,
        "Already inside a denied block; named so the message can say which service this is. "
        "tests/test_registry.py asserts the enclosure, so removing this costs a good message and "
        "never a denial.",
    ),
    _b(
        "fd00:ec2::254/128",
        "Cloud metadata (AWS IMDS over IPv6)",
        "RFC4193",
        Reach.DENIED,
        "Already inside a denied block; named so the message can say which service this is. "
        "tests/test_registry.py asserts the enclosure, so removing this costs a good message and "
        "never a denial.",
    ),
)
