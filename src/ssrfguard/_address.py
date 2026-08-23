"""Classifying an address, including what a translation prefix carries inside it.

The table in `_registry` says what a *block* means. This module answers the question actually
being asked, *may a fetcher connect here*, which for four prefixes is a question about
something else entirely. `64:ff9b::7f00:1` is a globally routable address whose packets arrive
at 127.0.0.1, and a guard that answers about the wrapper has answered the wrong question.

Two rules govern everything here:

* **Longest prefix wins.** IANA's structure is nested on purpose: `192.0.0.0/24` is refused
  while `192.0.0.9/32` inside it is a public anycast service, so a lookup that stopped at the
  first match would be wrong in both directions depending on table order.
* **Fail closed.** A translation prefix whose payload cannot be decoded is refused, not
  permitted. There is no address whose classification is unknown; there are only addresses that
  are refused for a reason that says so.
"""

from __future__ import annotations

from dataclasses import KW_ONLY, dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

from ssrfguard._registry import REGISTRY_SNAPSHOT, TABLE, Block, Reach
from ssrfguard.errors import BlockedAddressError

__all__ = ["DEFAULT_DENIED", "AddressTable", "Verdict"]

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network

# How many times an address may be unwrapped before we stop and refuse. An IPv4 payload cannot
# itself be a translation prefix, so one is the real depth and two is the margin. The limit is
# here so that a future prefix which *can* nest cannot turn this into unbounded recursion --
# a guard that hangs is a guard that gets removed.
_MAX_TRANSLATION_DEPTH = 2

# Compared as parsed networks, never as text. `str(ip_network("::ffff:0:0/96"))` is
# `"::ffff:0.0.0.0/96"`, because Python renders the last 32 bits in dotted-quad, so a string
# comparison here silently fails to match and the prefix stops being decoded. That is a
# *wrong deny*: `::ffff:8.8.8.8` gets refused as a wrapper instead of resolving to a public
# address. It was written that way first and the test corpus caught it.
_V4_MAPPED_LIKE = frozenset({ip_network("::ffff:0:0/96"), ip_network("::/96")})
_NAT64 = ip_network("64:ff9b::/96")
_SIXTOFOUR = ip_network("2002::/16")
_TEREDO = ip_network("2001::/32")


@dataclass(frozen=True)
class Verdict:
    """What the table says about one address.

    Attributes:
        address: The address the question was asked about.
        blocked: Whether a fetcher may connect to it.
        block: The table entry that decided it, or ``None`` when no entry matched and the
            address is therefore an ordinary public destination.
        chain: The translation hops walked to reach the deciding entry, outermost first. Empty
            for an address that decided on its own.
    """

    address: IPAddress
    blocked: bool
    block: Block | None = None
    chain: tuple[tuple[Block, IPAddress], ...] = ()

    @property
    def reason(self) -> str:
        """Why this address was refused, naming the block, its RFC and any translation.

        Returns:
            A sentence suitable for an exception message, or ``""`` when not blocked.
        """
        if not self.blocked:
            return ""
        if self.block is None:  # pragma: no cover - blocked always carries the deciding entry
            return "refused by policy"
        core = f"{self.block.network} is {self.block.name} ({self.block.rfc})"
        if not self.chain:
            return core
        hops = " -> ".join(
            f"{outer.name} {outer.network} carries {inner}" for outer, inner in self.chain
        )
        return f"{hops}, and {core}"

    def raise_if_blocked(self) -> None:
        """Raise if this address is not permitted.

        Raises:
            BlockedAddressError: If ``blocked`` is set.
        """
        if self.blocked:
            raise BlockedAddressError(str(self.address), self.reason)


def _embedded_v4(address: IPv6Address, network: IPNetwork) -> tuple[IPAddress, ...]:
    """Decode the IPv4 address or addresses a translation prefix carries.

    Args:
        address: The IPv6 address to unwrap.
        network: The matched block, which decides where the payload sits.

    Returns:
        Every IPv4 address embedded in it. Teredo yields two, the server and the client,
        because a packet to a Teredo address involves both and either being internal is
        disqualifying. Empty when the payload cannot be read.
    """
    packed = int(address)
    if network in _V4_MAPPED_LIKE or network == _NAT64:
        return (IPv4Address(packed & 0xFFFFFFFF),)
    if network == _SIXTOFOUR:
        return (IPv4Address((packed >> 80) & 0xFFFFFFFF),)
    if network == _TEREDO:
        server = IPv4Address((packed >> 64) & 0xFFFFFFFF)
        # RFC 4380 section 4: the client's address is stored with every bit inverted, so that a
        # NAT rewriting the packet cannot find it by pattern.
        client = IPv4Address(~packed & 0xFFFFFFFF)
        return (server, client)
    return ()  # pragma: no cover - unreachable while TRANSLATED is a closed set


@dataclass(frozen=True)
class AddressTable:
    """A set of blocks, and the question "may a fetcher connect to this address".

    Built once at import as :data:`DEFAULT_DENIED`. Users who need a different answer build
    their own rather than mutating this one, because a table that can be edited after the policy
    holding it was constructed is a policy whose behaviour depends on when it is asked.

    **Frozen so that sentence is a property rather than a request.** It used to be a plain class
    that said the same thing and enforced none of it: `DEFAULT_DENIED` is a module-level
    singleton and the default for every :class:`~ssrfguard.Policy`, so one assignment anywhere in
    a process changed what every policy in it refused, retroactively. The sharper form was
    quieter: ``blocks`` is the attribute with the public-looking name, every lookup reads the
    index derived from it, and a write to one left the table reporting a rule it did not enforce.
    That is this package's own failure mode, one layer down.

    Attributes:
        blocks: The blocks this table knows about.
        snapshot: The registry date these blocks were transcribed from. Keyword-only: it is a
            provenance stamp, not a second positional.
    """

    blocks: tuple[Block, ...]
    _: KW_ONLY
    snapshot: str = REGISTRY_SNAPSHOT
    # Sorted longest-prefix-first per family, so the first containing entry found is the most
    # specific one. Precomputed because this runs on every resolved address of every connection,
    # and derived rather than given, which is why it is not an argument.
    #
    # Measured 2026-08-23 on 3.13: 3.47us against 5.11us for a flat scan of all sixty blocks, so
    # splitting by family is worth about a third. It is worth keeping and it is *not* worth
    # improving further: this runs once per resolved address per connection, against a DNS lookup
    # and a handshake measured in milliseconds, so a prefix trie would trade an IANA transcription
    # anybody can audit for a structure nobody can, and buy microseconds nothing is waiting on.
    _by_version: dict[int, tuple[Block, ...]] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Refuse a duplicated network, then index for longest-prefix lookup.

        Raises:
            ValueError: If two blocks name the same network. Lookup is longest-prefix and
                stable, so a duplicate is not an error the table can express: one of the two
                entries simply never applies, and nothing anywhere says which. A custom table
                that shadows a shipped rule is a rule the author believes is in force and is
                not, so this refuses at construction rather than at the address that needed it.
        """
        seen: set[IPNetwork] = set()
        duplicates: list[str] = []
        for block in self.blocks:
            if block.network in seen:
                duplicates.append(str(block.network))
            seen.add(block.network)
        if duplicates:
            raise ValueError(
                f"address table has duplicate networks: {', '.join(sorted(duplicates))}"
            )
        object.__setattr__(
            self,
            "_by_version",
            {
                version: tuple(
                    sorted(
                        (b for b in self.blocks if b.network.version == version),
                        key=lambda b: b.network.prefixlen,
                        reverse=True,
                    )
                )
                for version in (4, 6)
            },
        )

    def __repr__(self) -> str:
        """Render a count and a provenance stamp rather than sixty blocks.

        The dataclass default spells every field out, and a table holds the whole registry, so
        the generated form is eleven kilobytes, and because a :class:`~ssrfguard.Policy` carries
        a table, it is eleven kilobytes *inside* every policy repr that reaches a log line, a
        traceback or a REPL. :meth:`ssrfguard.Target.__repr__` exists for the same reason and the
        argument is the same one: the rendering nobody chose is the rendering everybody sees.

        Returns:
            The size of the table and the registry date it was transcribed from.
        """
        return f"<AddressTable {len(self.blocks)} blocks, registry {self.snapshot}>"

    def match(self, address: IPAddress) -> Block | None:
        """Find the most specific block containing an address.

        Args:
            address: The address to look up.

        Returns:
            The matching block, or ``None`` if no entry contains it.
        """
        for block in self._by_version[address.version]:
            if address in block.network:
                return block
        return None

    def classify(self, address: str | IPAddress) -> Verdict:
        """Decide whether a fetcher may connect to an address.

        Args:
            address: The address, as text or already parsed. Text is parsed with
                ``ipaddress.ip_address``, which accepts no hostnames and no ports. This
                function never resolves anything.

        Returns:
            The verdict, carrying the deciding block and any translation hops.

        Raises:
            ValueError: If ``address`` is text that is not an IP address.
        """
        parsed = ip_address(address) if isinstance(address, str) else address
        return self._classify(parsed, ())

    def _classify(self, address: IPAddress, chain: tuple[tuple[Block, IPAddress], ...]) -> Verdict:
        """Classify an address, having already walked ``chain`` translation hops.

        Args:
            address: The address to classify.
            chain: Hops walked so far, outermost first.

        Returns:
            The verdict for the outermost address.
        """
        block = self.match(address)
        if block is None or block.reach is Reach.PERMITTED:
            return Verdict(address=address, blocked=False, block=block, chain=chain)
        if block.reach is Reach.DENIED:
            return Verdict(address=address, blocked=True, block=block, chain=chain)

        # Reach.TRANSLATED: the answer is about what is inside, not about the wrapper.
        if len(chain) >= _MAX_TRANSLATION_DEPTH or not isinstance(address, IPv6Address):
            return Verdict(address=address, blocked=True, block=block, chain=chain)
        inner_addresses = _embedded_v4(address, block.network)
        if not inner_addresses:
            return Verdict(address=address, blocked=True, block=block, chain=chain)
        for inner in inner_addresses:
            verdict = self._classify(inner, (*chain, (block, inner)))
            if verdict.blocked:
                return Verdict(
                    address=address, blocked=True, block=verdict.block, chain=verdict.chain
                )
        return Verdict(address=address, blocked=False, block=block, chain=chain)


#: The table this package ships, transcribed from the IANA special-purpose registries plus the
#: blocks those registries do not carry. See `scripts/refresh_registry.py` for provenance.
DEFAULT_DENIED = AddressTable(TABLE)
