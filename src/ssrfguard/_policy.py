"""The policy layer: everything decidable about a URL without touching the network.

**A policy check is necessary and it is not sufficient**, and that sentence is the reason this
module is shaped the way it is. Every SSRF advisory of 2026 describes the same code: a validator
that inspected a URL, approved it, and handed back something an HTTP client would accept. The
guard was not wrong; the *next line of code* was the vulnerability. mcp-atlassian's advisory puts
it exactly -- "the guard validates an IP it then discards; the connection re-resolves an unpinned
hostname" -- and crewAI's `validate_url` "resolves and blocklists the supplied hostname once,
then returns the original URL string".

So :meth:`Policy.check_url` returns a :class:`Target`, which is deliberately awkward to misuse.
It is an origin to connect to, not a request to make: it carries no path, no query, no fragment,
and it will not render as a URL. The only thing that consumes it is resolution.

What this layer *can* decide is real and worth having: the scheme, the port, whether credentials
are riding in the authority, whether the host is well-formed, and -- when the host is a literal
address rather than a name -- whether that address is permitted, with no DNS involved at all.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Literal
from urllib.parse import SplitResult, urlsplit

from ssrfguard._address import DEFAULT_DENIED, AddressTable, IPAddress, IPNetwork
from ssrfguard.errors import BlockedAddressError, BlockedURLError

__all__ = ["PartialBlock", "Policy", "Target"]

PartialBlock = Literal["reject", "drop"]

#: The range a TCP port can occupy. Named because it appears in two refusals and a bare 65535
#: in a security message reads as a magic number rather than as a protocol limit.
_LOWEST_PORT = 1
_HIGHEST_PORT = 65535

#: Default port per scheme, used when the authority does not carry one.
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

# urlsplit *silently strips* tab, newline and carriage return from anywhere in a URL, so the
# string a caller validated is not the string it parsed. That is a parser differential waiting
# to happen: another component -- a browser, a log sink, a second library -- may split the same
# bytes differently. Refused outright rather than normalised, because a URL containing a control
# character was not written by anything legitimate.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x20\x7f]")

# A hostname after normalisation: labels of letters, digits and hyphens, separated by dots, with
# an optional trailing dot. Deliberately narrow -- anything an A-label cannot contain is either
# an encoding attempt or a typo, and both should stop here.
_HOSTNAME = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9-]{1,63}\.?$", re.I)

# A host made only of digits and dots. Every one of these is either a valid IP literal, which is
# handled as an address, or an encoded one -- `0177.0.0.1`, `2130706433`, `127.1`. No registered
# hostname has this shape: RFC 3696 rules out an all-numeric top-level label.
_NUMERIC_SHAPED = re.compile(r"^[0-9.]+$")


@dataclass(frozen=True)
class Target:
    """An origin that survived the policy check -- not a URL, and not a substitute for one.

    A ``Target`` carries the scheme, the host and the port, and nothing else. The path, the
    query and the fragment are dropped on purpose: this type exists to be resolved and connected
    to, and a value that could be handed back to an HTTP client is precisely the shape that every
    SSRF advisory in this package's README describes.

    :meth:`__str__` renders a debug form rather than a URL for the same reason, and
    :meth:`__repr__` renders the same one -- a dataclass's generated repr is what actually
    reaches logs and tracebacks, so leaving it in place would have meant the careful rendering
    was the one nobody ever saw. There is no ``geturl``, no ``__fspath__`` and no ``url``
    attribute, and there will not be.

    Attributes:
        scheme: Lowercased scheme, guaranteed to be in the policy's allowed set.
        host: The host as the resolver will see it -- an A-label, so an internationalised name
            arrives here already punycoded. This is also the name TLS must verify against.
        port: The port, explicit or defaulted from the scheme.
        host_as_written: The host exactly as the caller supplied it, before normalisation. Kept
            only so a refusal can quote what was typed; never use it to connect.
        address: The parsed address when the host was a literal one, otherwise ``None``. A
            target carrying an address has already been checked against the policy and needs no
            resolution.
    """

    scheme: str
    host: str
    port: int
    host_as_written: str
    address: IPAddress | None = None

    def __str__(self) -> str:
        """Render a debug form that is deliberately not a URL.

        Returns:
            Something a reader can identify and an HTTP client will reject.
        """
        literal = " (literal address)" if self.address is not None else ""
        return f"<Target {self.scheme} host={self.host} port={self.port}{literal}>"

    def __repr__(self) -> str:
        """Render the same debug form :meth:`__str__` does.

        The dataclass default spells every field out, and **that** is the rendering that reaches
        a log line, a traceback, a REPL and any container a target is printed inside -- so
        leaving it in place meant the form this class was designed to show was the one form
        nobody saw. Defining it here rather than passing ``repr=False`` keeps one rendering
        instead of two that have to be kept in agreement.

        Returns:
            Something a reader can identify and an HTTP client will reject.
        """
        return str(self)

    @property
    def is_literal_address(self) -> bool:
        """Whether the host was an address rather than a name.

        Returns:
            ``True`` when no name resolution is needed.
        """
        return self.address is not None


def _as_networks(networks: Iterable[str | IPNetwork]) -> tuple[IPNetwork, ...]:
    """Normalise a mixed iterable of networks.

    Args:
        networks: CIDR strings or already-parsed networks.

    Returns:
        The parsed networks.

    Raises:
        ValueError: If a string is not a valid network. Raised at construction rather than at
            the address that needed it, so a typo in a configuration file surfaces on startup.
    """
    out: list[IPNetwork] = []
    for entry in networks:
        out.append(entry if isinstance(entry, (IPv4Network, IPv6Network)) else ip_network(entry))
    return tuple(out)


@dataclass(frozen=True)
class Policy:
    """What a caller is willing to reach, decided without any I/O.

    Every field is a deny-by-default narrowing. The defaults are what a webhook fetcher or a
    URL-preview service should want; widening any of them is a decision, and the refusal message
    names the field so that decision can be made from the error rather than from the source.

    Attributes:
        allowed_schemes: Schemes a URL may use. `file:`, `gopher:` and friends are absent by
            construction rather than blocklisted.
        denied_networks: The address table. See :data:`ssrfguard.DEFAULT_DENIED`.
        allowed_networks: Networks that are permitted even when the table denies them.
            **Explicit allow beats deny**, so this is how an internal-services fetcher reaches
            the internal services it is meant to.
        allowed_ports: Ports a URL may name. The default pair is the one most callers want and
            the one most likely to be widened; the refusal names both the port and this field.
        allow_userinfo: Whether credentials may ride in the authority. Off by default: they leak
            into logs and redirect chains, and `http://trusted.example@127.0.0.1/` is a very old
            trick that reads as a hostname to a human and parses as one to nobody.
        on_partial_block: What to do when a name resolves to both permitted and denied
            addresses. ``"reject"`` refuses the whole name, because that pattern is the
            signature of a rebinding attempt rather than of a misconfiguration. ``"drop"`` keeps
            the permitted answers. Consumed by resolution, validated here.
        max_redirects: How many hops a chain may take before it is refused. **Counted by this
            package rather than by the HTTP client**, whose own limit exists to stop loops, is
            an order of magnitude larger, and can be changed without touching the policy.
        max_connection_attempts: How many of a name's validated addresses to try before giving
            up. **This exists because ``timeout`` is per attempt and the answer count is not
            ours to choose.** A name whose authoritative server returns two hundred addresses,
            every one of them permitted by the policy and every one of them silently dropping
            packets, costs two hundred times the timeout the caller asked for -- one request,
            one held worker, no log line that reads as an attack. Four keeps the dual-stack
            failover that is the reason for trying more than one at all, and bounds the cost at
            four times what was asked for.
        sensitive_headers: Header names dropped when a redirect crosses to another origin,
            compared in lower case. The default is the three whose *definition* is credentials;
            a header like ``x-api-key`` is a naming convention rather than a specification, so
            it is named here by the caller who uses it rather than guessed at by this package.
            An upgrade from ``http`` to ``https`` on the same host is not a crossing, which is
            what both clients already do for ``Authorization`` and is not worth differing from.
        allow_proxy: Whether to proceed when a proxy is configured. Off by default, because a
            proxy resolves the target itself and pinning cannot reach it.
    """

    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    denied_networks: AddressTable = DEFAULT_DENIED
    allowed_networks: tuple[IPNetwork, ...] = field(default=())
    allowed_ports: frozenset[int] = frozenset({80, 443})
    allow_userinfo: bool = False
    on_partial_block: PartialBlock = "reject"
    max_redirects: int = 5
    max_connection_attempts: int = 4
    sensitive_headers: frozenset[str] = frozenset(
        {"authorization", "proxy-authorization", "cookie"}
    )
    allow_proxy: bool = False

    def __post_init__(self) -> None:
        """Normalise and validate the configuration.

        Raises:
            ValueError: If a field cannot mean anything. A policy that cannot be satisfied is a
                configuration error, and it surfaces here rather than at the first request.
        """
        object.__setattr__(
            self, "allowed_schemes", frozenset(s.lower() for s in self.allowed_schemes)
        )
        object.__setattr__(self, "allowed_networks", _as_networks(self.allowed_networks))
        object.__setattr__(self, "allowed_ports", frozenset(self.allowed_ports))
        object.__setattr__(
            self, "sensitive_headers", frozenset(h.lower() for h in self.sensitive_headers)
        )
        if not self.allowed_schemes:
            raise ValueError("allowed_schemes is empty, so no URL can ever be permitted")
        if not self.allowed_ports:
            raise ValueError("allowed_ports is empty, so no URL can ever be permitted")
        for port in self.allowed_ports:
            if not _LOWEST_PORT <= port <= _HIGHEST_PORT:
                raise ValueError(f"allowed_ports contains {port}, which is not a port")
        if self.on_partial_block not in ("reject", "drop"):
            raise ValueError(
                f"on_partial_block must be 'reject' or 'drop', not {self.on_partial_block!r}"
            )
        if self.max_redirects < 0:
            raise ValueError(f"max_redirects must not be negative, got {self.max_redirects}")
        if self.max_connection_attempts < 1:
            raise ValueError(
                f"max_connection_attempts must be at least 1, got "
                f"{self.max_connection_attempts}; a policy that permits no attempt can never "
                f"connect to anything"
            )

    # -- addresses -------------------------------------------------------------------------

    def check_address(self, address: str | IPAddress) -> None:
        """Decide whether an address may be connected to.

        Args:
            address: The address, as text or already parsed.

        Raises:
            BlockedAddressError: If the policy refuses it.
            ValueError: If ``address`` is text that is not an IP address. This function never
                resolves anything, so a hostname here is a programming error.
        """
        parsed = ip_address(address) if isinstance(address, str) else address
        for network in self.allowed_networks:
            if parsed.version == network.version and parsed in network:
                return
        self.denied_networks.classify(parsed).raise_if_blocked()

    def permits_address(self, address: str | IPAddress) -> bool:
        """Whether an address may be connected to, as a predicate.

        Args:
            address: The address, as text or already parsed.

        Returns:
            ``True`` if permitted. Resolution uses this to partition a set of answers, where a
            refusal is an expected outcome rather than an error.
        """
        try:
            self.check_address(address)
        except BlockedAddressError:
            return False
        return True

    # -- URLs ------------------------------------------------------------------------------

    def check_url(self, url: str) -> Target:
        """Decide everything about a URL that can be decided without the network.

        **This is necessary and it is not sufficient.** A URL that survives here has a permitted
        scheme, a permitted port, no credentials in its authority and a well-formed host -- and
        if that host was a literal address, that address is permitted too. What it does *not*
        have is any guarantee about where a *name* points, because nothing here resolves
        anything. Hand the result to resolution; do not hand it to an HTTP client.

        Args:
            url: The URL to check.

        Returns:
            The origin to resolve.

        Raises:
            BlockedURLError: If the URL is refused, naming the rule that refused it.
            BlockedAddressError: If the host was a literal address the policy denies.
            TypeError: If ``url`` is not a string. Passing something else is a programming
                error rather than a policy question.
        """
        if not isinstance(url, str):
            raise TypeError(f"check_url expects a string, got {type(url).__name__}")
        self._reject_control_characters(url)
        split = self._split(url)
        scheme = self._check_scheme(url, split)
        self._check_userinfo(url, split)
        host, as_written = self._check_host(url, split)
        port = self._check_port(url, split, scheme)

        address = _literal_address(host)
        if address is not None:
            try:
                self.check_address(address)
            except BlockedAddressError as blocked:
                raise BlockedURLError(url, blocked.reason) from blocked
        return Target(
            scheme=scheme, host=host, port=port, host_as_written=as_written, address=address
        )

    @staticmethod
    def _reject_control_characters(url: str) -> None:
        """Refuse a URL containing a character urlsplit would silently remove.

        Args:
            url: The URL as given.

        Raises:
            BlockedURLError: If a control character is present.
        """
        found = _CONTROL_CHARACTERS.search(url)
        if found is not None:
            raise BlockedURLError(
                url,
                f"contains the control character {found.group()!r} at offset {found.start()}, "
                f"which urlsplit strips silently -- so the URL that was checked would not be "
                f"the URL that was parsed",
            )

    @staticmethod
    def _split(url: str) -> SplitResult:
        """Parse a URL, turning a parse failure into a refusal.

        Args:
            url: The URL as given.

        Returns:
            The split result.

        Raises:
            BlockedURLError: If it cannot be parsed.
        """
        try:
            return urlsplit(url)
        except ValueError as bad:
            raise BlockedURLError(url, f"cannot be parsed as a URL: {bad}") from bad

    def _check_scheme(self, url: str, split: SplitResult) -> str:
        """Check the scheme against the policy.

        Args:
            url: The URL as given, for the message.
            split: The parsed URL.

        Returns:
            The lowercased scheme.

        Raises:
            BlockedURLError: If the scheme is missing or not allowed.
        """
        scheme = split.scheme.lower()
        if not scheme:
            raise BlockedURLError(url, "has no scheme; a relative URL names no origin to check")
        if scheme not in self.allowed_schemes:
            allowed = ", ".join(sorted(self.allowed_schemes))
            raise BlockedURLError(url, f"scheme {scheme!r} is not in allowed_schemes ({allowed})")
        return scheme

    def _check_userinfo(self, url: str, split: SplitResult) -> None:
        """Check for credentials in the authority.

        Args:
            url: The URL as given, for the message.
            split: The parsed URL.

        Raises:
            BlockedURLError: If credentials are present and not allowed.
        """
        if self.allow_userinfo:
            return
        if split.username is None and split.password is None:
            return
        raise BlockedURLError(
            url,
            "carries credentials in its authority and allow_userinfo is off; the text before "
            "'@' is not the host, which is what makes this a classic disguise",
        )

    @staticmethod
    def _check_host(url: str, split: SplitResult) -> tuple[str, str]:
        """Normalise and check the host.

        Normalisation uses the ``idna`` codec, which is the same transformation CPython's
        ``socket.getaddrinfo`` applies internally -- so the name checked here is exactly the name
        that will be resolved, and the two cannot disagree. It is also what turns
        ``①②⑦.0.0.1`` into ``127.0.0.1`` and ``ⓁⓄⒸⒶⓁⒽⓄⓈⓉ`` into ``localhost`` before anything
        looks at them.

        Args:
            url: The URL as given, for the message.
            split: The parsed URL.

        Returns:
            A pair of (normalised host, host as written).

        Raises:
            BlockedURLError: If the host is missing or malformed.
        """
        try:
            raw = split.hostname
        except ValueError as bad:  # pragma: no cover - urlsplit raises earlier in practice
            raise BlockedURLError(url, f"has an unparseable host: {bad}") from bad
        if not raw:
            raise BlockedURLError(url, "has no host")
        if "%" in raw:
            raise BlockedURLError(
                url,
                "host contains '%', which is either percent-encoding that the resolver will "
                "not decode or an IPv6 zone identifier, and neither belongs in a fetched URL",
            )
        host = _normalise(url, raw)
        if _literal_address(host) is not None:
            return host, raw
        if _NUMERIC_SHAPED.match(host):
            raise BlockedURLError(
                url,
                f"host {host!r} is made only of digits and dots but is not a valid address, so "
                f"it is an encoded one -- no registered hostname has this shape",
            )
        if not _HOSTNAME.match(host):
            raise BlockedURLError(url, f"host {host!r} is not a well-formed hostname")
        return host, raw

    def _check_port(self, url: str, split: SplitResult, scheme: str) -> int:
        """Check the port against the policy.

        Args:
            url: The URL as given, for the message.
            split: The parsed URL.
            scheme: The already-validated scheme, for its default port.

        Returns:
            The port to connect to.

        Raises:
            BlockedURLError: If the port is unparseable, out of range, or not allowed.
        """
        try:
            port = split.port
        except ValueError as bad:
            raise BlockedURLError(url, f"has an unusable port: {bad}") from bad
        if port is None:
            port = _DEFAULT_PORTS.get(scheme)
        if port is None:
            raise BlockedURLError(
                url, f"names no port and scheme {scheme!r} has no default this policy knows"
            )
        if not _LOWEST_PORT <= port <= _HIGHEST_PORT:
            raise BlockedURLError(url, f"port {port} is not a port")
        if port not in self.allowed_ports:
            allowed = ", ".join(str(p) for p in sorted(self.allowed_ports))
            raise BlockedURLError(url, f"port {port} is not in allowed_ports ({allowed})")
        return port


def _normalise(url: str, host: str) -> str:
    """Apply the resolver's own name normalisation.

    Args:
        url: The URL as given, for the message.
        host: The host as parsed.

    Returns:
        The A-label form, lowercased.

    Raises:
        BlockedURLError: If the name cannot be encoded, which is also how it would fail to
            resolve -- an over-long label, an empty one, a disallowed codepoint.
    """
    if host.isascii():
        return host.lower()
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as bad:
        raise BlockedURLError(url, f"host {host!r} is not a usable name: {bad}") from bad


def _literal_address(host: str) -> IPAddress | None:
    """Parse a host as a literal address if it is one.

    Args:
        host: The normalised host.

    Returns:
        The address, or ``None`` if the host is a name. Python's parser rejects the legacy
        encodings -- leading zeros, bare integers, short forms -- so those come back ``None``
        here and are refused by the numeric-shape check instead.
    """
    try:
        return ip_address(host)
    except ValueError:
        return None
