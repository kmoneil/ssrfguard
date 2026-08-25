"""The policy layer: everything decidable about a URL without touching the network.

**A policy check is necessary and it is not sufficient**, and that sentence is the reason this
module is shaped the way it is. Every SSRF advisory of 2026 describes the same code: a validator
that inspected a URL, approved it, and handed back something an HTTP client would accept. The
guard was not wrong; the *next line of code* was the vulnerability. mcp-atlassian's advisory puts
it exactly: "the guard validates an IP it then discards; the connection re-resolves an unpinned
hostname". crewAI's `validate_url` "resolves and blocklists the supplied hostname once,
then returns the original URL string".

So :meth:`Policy.check_url` returns a :class:`Target`, which is deliberately awkward to misuse.
It is an origin to connect to, not a request to make: it carries no path, no query, no fragment,
and it will not render as a URL. The only thing that consumes it is resolution.

What this layer *can* decide is real and worth having: the scheme, the port, whether credentials
are riding in the authority, whether the host is well-formed, and, when the host is a literal
address rather than a name, whether that address is permitted, with no DNS involved at all.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Literal
from urllib.parse import SplitResult, urlsplit

from ssrfguard._address import DEFAULT_DENIED, AddressTable, IPAddress, IPNetwork
from ssrfguard._observer import Decision, Observer, redacted, report
from ssrfguard._registry import Block, Reach
from ssrfguard.errors import BlockedAddressError, BlockedURLError, SSRFGuardError

__all__ = ["PartialBlock", "Policy", "Target"]

PartialBlock = Literal["reject", "drop"]

#: The range a TCP port can occupy. Named because it appears in two refusals and a bare 65535
#: in a security message reads as a magic number rather than as a protocol limit.
_LOWEST_PORT = 1
_HIGHEST_PORT = 65535

#: The longest name DNS can carry in presentation form: 255 octets on the wire, of which the
#: root label and one length byte are not text (RFC 1035 section 2.3.4).
#:
#: **A protocol limit rather than a policy field, and the difference is the whole justification
#: for hard-coding it.** Every other narrowing in :class:`Policy` is a choice a caller could
#: reasonably make differently. This one is not: a longer name cannot resolve, on any resolver,
#: so a field here would only offer the choice of paying more to reach the same refusal.
_LONGEST_HOSTNAME = 253

#: Default port per scheme, used when the authority does not carry one.
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

# urlsplit *silently strips* tab, newline and carriage return from anywhere in a URL, so the
# string a caller validated is not the string it parsed. That is a parser differential waiting
# to happen: another component, a browser or a log sink or a second library, may split the same
# bytes differently. Refused outright rather than normalised, because a URL containing a control
# character was not written by anything legitimate.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x20\x7f]")

# A hostname after normalisation: labels of letters, digits and hyphens, separated by dots, with
# an optional trailing dot. Deliberately narrow: anything an A-label cannot contain is either
# an encoding attempt or a typo, and both should stop here.
_HOSTNAME = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9-]{1,63}\.?$", re.I)

# A host made only of digits and dots. Every one of these is either a valid IP literal, which is
# handled as an address, or an encoded one such as `0177.0.0.1`, `2130706433` or `127.1`. No
# hostname has this shape: RFC 3696 rules out an all-numeric top-level label.
_NUMERIC_SHAPED = re.compile(r"^[0-9.]+$")


@dataclass(frozen=True)
class Target:
    """An origin that survived the policy check, not a URL and not a substitute for one.

    A ``Target`` carries the scheme, the host and the port, and nothing else. The path, the
    query and the fragment are dropped on purpose: this type exists to be resolved and connected
    to, and a value that could be handed back to an HTTP client is precisely the shape that every
    SSRF advisory in this package's README describes.

    :meth:`__str__` renders a debug form rather than a URL for the same reason, and
    :meth:`__repr__` renders the same one, because a dataclass's generated repr is what actually
    reaches logs and tracebacks, so leaving it in place would have meant the careful rendering
    was the one nobody ever saw. There is no ``geturl``, no ``__fspath__`` and no ``url``
    attribute, and there will not be.

    Attributes:
        scheme: Lowercased scheme, guaranteed to be in the policy's allowed set.
        host: The host as the resolver will see it, an A-label, so an internationalised name
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
        a log line, a traceback, a REPL and any container a target is printed inside, so
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

            Two consequences of *beats* are worth knowing before writing an entry, because
            neither is visible from the field name.

            An entry **inside a translation prefix is refused at construction**. ``64:ff9b::/96``
            reads as "let NAT64 through" and would mean "let anything through": it covers
            ``64:ff9b::7f00:1`` and ``64:ff9b::a9fe:a9fe``, which are loopback and the metadata
            endpoint behind a NAT64 gateway, and the allowlist is consulted before the table gets
            to decode them. Allow the embedded IPv4 range instead. An entry that merely
            *contains* a translation prefix, such as ``::/0``, is honoured, because at that breadth
            the caller asked for everything and is entitled to get it.

            An entry does **not** carry across address families: ``10.0.0.0/8`` does not permit
            ``::ffff:10.0.0.1``, because the check compares versions and the mapped form is
            version 6. That direction over-denies, so it stands; a caller who wants the mapped
            form says so.
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

            ``0`` means **a redirect is refused**, not "redirects are not followed", and the
            difference shows at the boundary: a single ``302`` raises :class:`
            ~ssrfguard.TooManyRedirectsError` even when the caller switched following off at the
            client. Both clients build the next request in order to expose it, httpx as
            ``response.next_request`` and requests as ``response.next``, and the cap fires on the
            build. To receive a redirect without following it, leave this at its default and
            switch following off at the call; to refuse one, set this to ``0``.
        max_connection_attempts: How many of a name's validated addresses to try before giving
            up. **This exists because ``timeout`` is per attempt and the answer count is not
            ours to choose.** A name whose authoritative server returns two hundred addresses,
            every one of them permitted by the policy and every one of them silently dropping
            packets, costs two hundred times the timeout the caller asked for: one request,
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
        max_url_length: How long a URL may be before it is refused, unread. Checked first,
            before anything that scans the string.

            **This is a ceiling, not a ReDoS fix.** Measured across four octaves, ``check_url``
            is strictly linear on both paths, since doubling the input doubles the time, and
            ``_HOSTNAME`` cannot backtrack because every repetition in it must consume a literal
            dot. What it did not have was a bound: re-measured 2026-08-23 on 3.13, the ASCII scan
            costs about 7 nanoseconds per character and the non-ASCII path about 1785 per
            character *of host*, because the ``idna`` codec runs nameprep per label, so a 10MB URL
            was about 19 CPU-seconds of one worker. ``SECURITY.md`` says any way one request can
            consume wall-clock without a ceiling is in scope, and this had none.

            The linearity is no longer argued from the regex alone: ``tests/test_cost.py``
            measures an 8 KiB URL against a 1 KiB one and fails if the ratio approaches what
            quadratic scanning would produce.

            8192 because that is where nginx, Apache and IIS converge for a request line, a
            number a caller can recognise rather than one this package invented.

            **It is one of two ceilings and it is not the one that bounds the cost.** This counts
            characters of URL, and the expensive characters are the ones in the *host*: the
            ``idna`` arm runs at roughly 250 times the price of the scan, per character, once per
            label. So a URL sitting comfortably inside 8192 could carry 389 non-ASCII labels and
            cost 14.9 milliseconds, and be accepted, and then be handed to a lookup that could
            never succeed. The host is therefore capped separately at the 253 characters DNS can
            carry, before normalisation rather than after, which is not configurable because a
            longer name cannot resolve on any resolver. Together they bound the work; this one
            alone did not.
    """

    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    denied_networks: AddressTable = DEFAULT_DENIED
    allowed_networks: tuple[IPNetwork, ...] = field(default=())
    allowed_ports: frozenset[int] = frozenset({80, 443})
    allowed_hosts: frozenset[str] = frozenset()
    allow_userinfo: bool = False
    on_partial_block: PartialBlock = "reject"
    max_redirects: int = 5
    max_connection_attempts: int = 4
    sensitive_headers: frozenset[str] = frozenset(
        {"authorization", "proxy-authorization", "cookie"}
    )
    allow_proxy: bool = False
    max_url_length: int = 8192

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
        object.__setattr__(self, "allowed_hosts", _as_host_patterns(self.allowed_hosts))
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
        if self.max_url_length < 1:
            raise ValueError(
                f"max_url_length must be at least 1, got {self.max_url_length}; a policy that "
                f"permits no URL can never fetch anything"
            )
        self._reject_allowing_a_translation_prefix()

    def _reject_allowing_a_translation_prefix(self) -> None:
        """Refuse an ``allowed_networks`` entry that would permit an undecoded wrapper.

        ``check_address`` consults ``allowed_networks`` first and returns on a hit, so the table
        never gets the chance to decode. An entry *inside* a translated block therefore permits
        every IPv4 destination embedded in it, loopback and every metadata endpoint included,
        and silently switches off the single most important row in the shipped table.

        **The test is the table's own longest-prefix rule, and getting that wrong is how this
        check produces false refusals.** The question is not "does this entry touch a translated
        block" but "is a translated block what would *decide* these addresses". Two cases make
        the difference concrete:

        * ``::1/128`` sits inside ``::/96``, the deprecated IPv4-compatible wrapper, but
          ``::1/128`` has its own, more specific row, so the wrapper never decides it. Allowing
          IPv6 loopback is an ordinary thing to do and refusing it would be a wrong deny.
        * ``::/96`` itself has no more specific row covering the whole of it, so the wrapper
          *is* the decider, and an entry for it permits ``::7f00:1`` undecoded.

        An entry merely *containing* a wrapper, such as ``::/0`` or ``2000::/3``, is somebody
        painting with a roller, and at that breadth "you get what is in it" is the honest
        reading rather than a surprise. Refusing those would break the deliberate off-switch
        this class documents, and a control with no off switch gets replaced by no control at all.

        Refused here rather than at the address that needed it, which is where every other
        unsatisfiable field in this class is refused: a typo in a configuration file should
        surface on startup, not as a permit nobody noticed.

        Raises:
            ValueError: If an allowed network sits inside a block the table would have decoded.
        """
        for network in self.allowed_networks:
            block = _deciding_block(self.denied_networks, network)
            if block is not None and block.reach is Reach.TRANSLATED:
                raise ValueError(
                    f"allowed_networks contains {network}, which overlaps {block.network} "
                    f"({block.name}, {block.rfc}), a prefix that carries an IPv4 destination "
                    f"inside it. An explicit allow beats the denied table, so this would permit "
                    f"every address embedded in that prefix without decoding any of them, "
                    f"including loopback and the cloud metadata endpoints. To reach specific "
                    f"internal hosts, allow the embedded IPv4 range instead; to turn address "
                    f"filtering off, pass a denied_networks table that says so rather than an "
                    f"allowed_networks entry wide enough to cover this"
                )

    # addresses ----------

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

    # hosts ----------

    def check_host(self, host: str) -> None:
        """Decide whether a host may be reached, at a layer that holds no URL.

        :meth:`check_url` asks this as one part of a larger question, and every client calls it
        once per request. **A client is not the only way in.**
        :class:`ssrfguard.httpx.SafeBackend` is public precisely so a caller can assemble their
        own connection pool around it, and a backend is handed a host and a port and never sees
        a URL. A narrowing that only ran one layer up would not be running for them, and would
        say nothing about it.

        So this is the half of :meth:`check_url` that a host is enough to answer. The scheme,
        the credentials in an authority and the length of a URL are not here, because a seam
        does not hold the information any of them needs; ``tests/test_adapter_seam_parity.py``
        carries that split as a table, so a field added to this class has to state which side it
        is on.

        **Measured 2026-08-24 on 3.13: 0.05us when ``allowed_hosts`` is empty, which is the
        default and therefore almost every caller, and 1.9us when it is not.** The second figure
        is nearly all :func:`_literal_address`, which answers by raising on a name, and
        :meth:`_check_host` avoids that with the cheap shape test above it. **That test is
        deliberately not repeated here**, because copying it would put the rule "everything
        ``ip_address`` accepts holds a colon or is only digits and dots" in a second place, to
        save 1.7us once per *connection* on a path this package already argues about: the
        requests seam runs the whole of :meth:`check_url` at its own seam, at 4 to 9us, against
        a handshake three orders of magnitude larger. The number is written down rather than
        optimised so the trade is visible if it ever stops being the right one.

        Args:
            host: The host as a resolver will see it: an A-label, lowercased, with no brackets
                around an IPv6 literal. That is the form both clients hold at their seams,
                because each punycodes and lowercases when it builds the origin.

        Raises:
            BlockedURLError: If ``allowed_hosts`` is set and the host matches none of its
                patterns. Named for the URL layer it was written for, and kept here rather than
                given a sibling: a caller catching one refusal for "this host is not permitted"
                should not have to catch two depending on which layer noticed.
        """
        if not self.allowed_hosts:
            return
        self._check_host_is_listed(host, host, literal=_literal_address(host) is not None)

    # URLs ----------

    def check_url(self, url: str, *, observer: Observer | None = None) -> Target:
        """Decide everything about a URL that can be decided without the network.

        **This is necessary and it is not sufficient.** A URL that survives here has a permitted
        scheme, a permitted port, no credentials in its authority and a well-formed host, and
        if that host was a literal address, that address is permitted too. What it does *not*
        have is any guarantee about where a *name* points, because nothing here resolves
        anything. Hand the result to resolution; do not hand it to an HTTP client.

        Args:
            url: The URL to check.
            observer: Where to report what was decided, or ``None`` to report nothing, which is
                the default and costs nothing: no record is built when there is nobody to hand
                it to. **Whatever it raises is swallowed**, because a sink that throws on a
                permitted URL would turn an allow into a deny.

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
        try:
            target = self._decide(url)
        except SSRFGuardError as refused:
            if observer is not None:
                report(
                    observer,
                    Decision(
                        stage="url",
                        outcome="refused",
                        reason=str(getattr(refused, "reason", refused)),
                        url=redacted(url),
                    ),
                )
            raise
        if observer is not None:
            report(
                observer,
                Decision(
                    stage="url",
                    outcome="permitted",
                    url=redacted(url),
                    host=target.host,
                    port=target.port,
                    address=target.address,
                ),
            )
        return target

    def _decide(self, url: str) -> Target:
        """Everything ``check_url`` decides, with nothing to report it to.

        Split out so the reporting in :meth:`check_url` is one ``try`` around the whole
        decision rather than a branch inside each rule, which is what keeps this function's
        shape the thing a reader checks the policy against.

        Args:
            url: The URL to check.

        Returns:
            The origin to resolve.

        Raises:
            BlockedURLError: If the URL is refused, naming the rule that refused it.
        """
        self._reject_overlong(url)
        self._reject_control_characters(url)
        split = self._split(url)
        scheme = self._check_scheme(url, split)
        self._check_userinfo(url, split)
        host, as_written, address = self._check_host(url, split)
        port = self._check_port(url, split, scheme)
        if self.allowed_hosts:
            self._check_host_is_listed(url, host, literal=address is not None)

        if address is not None:
            try:
                self.check_address(address)
            except BlockedAddressError as blocked:
                raise BlockedURLError(url, blocked.reason) from blocked
        return Target(
            scheme=scheme, host=host, port=port, host_as_written=as_written, address=address
        )

    def _reject_overlong(self, url: str) -> None:
        """Refuse a URL before anything reads it.

        **First, and that is the whole point.** Every other check here scans the string at least
        once, whether the control-character search, ``urlsplit`` or the ``idna`` codec, so a ceiling
        applied after any of them is a ceiling that already paid for the thing it was meant to
        prevent. ``len`` is the one question that costs nothing to ask.

        The refusal quotes the length rather than the URL, which every other refusal in this
        class does quote: echoing eight kilobytes of attacker-supplied text into a log line is
        the second half of the problem this check exists for.

        Args:
            url: The URL as given.

        Raises:
            BlockedURLError: If it is longer than the policy allows.
        """
        if len(url) > self.max_url_length:
            raise BlockedURLError(
                f"<{len(url)} characters>",
                f"is longer than max_url_length ({self.max_url_length}); refused unread, "
                f"because every check after this one reads the whole string",
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
                f"which urlsplit strips silently, so the URL that was checked would not be "
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
    def _check_host(url: str, split: SplitResult) -> tuple[str, str, IPAddress | None]:
        """Normalise and check the host, and say whether it turned out to be an address.

        Normalisation uses the ``idna`` codec, which is the same transformation CPython's
        ``socket.getaddrinfo`` applies internally, so the name checked here is exactly the name
        that will be resolved, and the two cannot disagree. It is also what turns
        ``①②⑦.0.0.1`` into ``127.0.0.1`` and ``ⓁⓄⒸⒶⓁⒽⓄⓈⓉ`` into ``localhost`` before anything
        looks at them.

        Args:
            url: The URL as given, for the message.
            split: The parsed URL.

        **The parsed address is returned rather than discarded**, which is the whole reason for
        the third element. This function has to know whether the host is a literal in order to
        decide whether the hostname rules apply to it, and :meth:`Policy.check_url` needs the
        value; handing back only the string meant parsing it twice, and on a name that is six
        raised exceptions to arrive at ``None`` both times.

        Returns:
            The normalised host, the host as written, and the parsed address when the host was
            a literal one rather than a name.

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
        _reject_overlong_host(raw)
        host = _normalise(url, raw)
        # **The cheap discriminating test first.** Everything `ip_address` accepts either holds
        # a colon or is nothing but digits and dots, so a host that is neither cannot be an
        # address and does not need to be handed to a parser that answers by raising. That is
        # the ordinary case, and it was the most expensive thing in this function.
        # `tests/test_policy_properties.py` holds the differential that says the two agree.
        numeric_shaped = _NUMERIC_SHAPED.match(host) is not None
        if numeric_shaped or ":" in host:
            address = _literal_address(host)
            if address is not None:
                return host, raw, address
        if numeric_shaped:
            raise BlockedURLError(
                url,
                f"host {host!r} is made only of digits and dots but is not a valid address, so "
                f"it is an encoded one; no registered hostname has this shape",
            )
        if not _HOSTNAME.match(host):
            raise BlockedURLError(url, f"host {host!r} is not a well-formed hostname")
        return host, raw, None

    def _check_host_is_listed(self, url: str, host: str, *, literal: bool) -> None:
        """Refuse a host the caller did not list, when they listed any.

        Only consulted when ``allowed_hosts`` is non-empty, so a policy that names no host is
        unaffected and pays nothing.

        Args:
            url: The URL as given, for the message.
            host: The normalised host.
            literal: Whether the host is an IP literal rather than a name.

        Raises:
            BlockedURLError: If the host matches no pattern.
        """
        if _host_is_allowed(host, self.allowed_hosts, literal=literal):
            return
        nearly = _nearest_pattern(host, self.allowed_hosts)
        hint = f"; the nearest entry is {nearly!r}" if nearly else ""
        raise BlockedURLError(
            url,
            f"host {host!r} is not in allowed_hosts, which lists "
            f"{sorted(self.allowed_hosts)}{hint}",
        )

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


def _reject_overlong_host(host: str) -> None:
    """Refuse a host longer than DNS can carry, before anything normalises it.

    **``max_url_length`` counts characters of URL and the cost is in characters of host**, and
    the two are not the same bound. Both paths through :func:`_normalise` are linear, but they
    are linear with constants two orders of magnitude apart: an ASCII URL costs about 7
    nanoseconds per character to scan, and a non-ASCII *host* costs about 1.8 microseconds per
    character, because the ``idna`` codec runs nameprep once per label. So a URL sitting well
    inside an 8192-character ceiling can still carry 389 non-ASCII labels and cost 14.9
    milliseconds of one worker, measured, which is roughly two thousand times an ordinary check.

    Nothing was gained for it either. 253 is what DNS can carry, so a longer name was going to
    be refused by ``getaddrinfo`` no matter how carefully it was punycoded first.

    **Before :func:`_normalise` rather than after**, which is the same argument
    :meth:`Policy._reject_overlong` makes one layer up: a ceiling applied after the expensive
    step has already paid for the thing it exists to prevent. And on ``host`` as written rather
    than on its A-label form, because punycode only ever grows a name, so this bounds the work
    without narrowing what can resolve.

    The refusal quotes the length rather than the host, for the reason
    :meth:`Policy._reject_overlong` does: echoing attacker-supplied text into a log line is the
    second half of the problem a ceiling exists for.

    Args:
        host: The host as parsed, before normalisation.

    Raises:
        BlockedURLError: If it is longer than a name DNS can carry.
    """
    if len(host) > _LONGEST_HOSTNAME:
        raise BlockedURLError(
            f"<host of {len(host)} characters>",
            f"is longer than {_LONGEST_HOSTNAME} characters, which is the longest name DNS "
            f"can carry, so it could never resolve; refused before normalisation, because the "
            f"idna codec runs nameprep per label and a long host is what makes that expensive",
        )


def _normalise(url: str, host: str) -> str:
    """Apply the resolver's own name normalisation.

    Args:
        url: The URL as given, for the message.
        host: The host as parsed.

    Returns:
        The A-label form, lowercased.

    Raises:
        BlockedURLError: If the name cannot be encoded, which is also how it would fail to
            resolve: an over-long label, an empty one, a disallowed codepoint.
    """
    if host.isascii():
        return host.lower()
    try:
        return host.encode("idna").decode("ascii").lower()
    # `UnicodeError` is a subclass of `ValueError`, so naming it here caught nothing extra and
    # only read as though it did. `ValueError` is the one to keep: the codec raises
    # `UnicodeError` in every path CPython takes today, and the broader name is what keeps a
    # future codec raising a plain `ValueError` arriving as a refusal rather than a crash.
    except ValueError as bad:
        raise BlockedURLError(url, f"host {host!r} is not a usable name: {bad}") from bad


def _wholly_inside(inner: IPNetwork, outer: IPNetwork) -> bool:
    """Whether one network is entirely contained in another, across the two families.

    ``subnet_of`` raises on a mixed-version pair and cannot be typed across the union, so the
    narrowing happens once here rather than at the call site. A mixed pair is ``False`` rather
    than an error: two families that cannot contain each other is an answer, not a mistake.

    Args:
        inner: The network that might be contained.
        outer: The network that might contain it.

    Returns:
        ``True`` if every address in ``inner`` is in ``outer``.
    """
    if isinstance(inner, IPv4Network) and isinstance(outer, IPv4Network):
        return inner.subnet_of(outer)
    if isinstance(inner, IPv6Network) and isinstance(outer, IPv6Network):
        return inner.subnet_of(outer)
    return False


def _deciding_block(table: AddressTable, network: IPNetwork) -> Block | None:
    """Find the block that decides every address in a network, if one block decides them all.

    :meth:`AddressTable.match` answers this for a single address. A whole network needs the
    stronger question, the most specific block containing *all* of it, because a block that
    covers only part of a range is not what that range's other addresses resolve against.

    Args:
        table: The table to ask.
        network: The network to look up.

    Returns:
        The most specific block containing the whole network, or ``None`` when no block does.
    """
    containing = [block for block in table.blocks if _wholly_inside(network, block.network)]
    if not containing:
        return None
    return max(containing, key=lambda block: block.network.prefixlen)


def _literal_address(host: str) -> IPAddress | None:
    """Parse a host as a literal address if it is one.

    Args:
        host: The normalised host.

    Returns:
        The address, or ``None`` if the host is a name. Python's parser rejects the legacy
        encodings of leading zeros, bare integers and short forms, so those come back ``None``
        here and are refused by the numeric-shape check instead.
    """
    try:
        return ip_address(host)
    except ValueError:
        return None


def _as_host_patterns(patterns: Iterable[str]) -> frozenset[str]:
    """Normalise host patterns the way a host itself is normalised.

    An entry and a URL's host have to be comparable, and a URL's host has already been through
    :func:`_normalise` by the time anything matches it: lowercased, and IDN-encoded to A-labels.
    So an entry gets the same treatment, which is what lets a caller write ``allowed_hosts` in
    the script they can read rather than in punycode.

    **A trailing dot is folded here and again on the host.** ``example.com.`` is the absolute
    form of the same name and resolves to the same place, and ``_HOSTNAME`` deliberately permits
    it, so a matcher that did not fold it would refuse a URL that is not merely legal but
    identical. That is a wrong deny rather than a bypass, which is the direction an allowlist
    fails in, and it is still wrong.

    Args:
        patterns: What the caller wrote.

    Returns:
        The normalised patterns.

    Raises:
        ValueError: If a pattern cannot mean anything: an empty entry, a bare ``*``, or a ``*``
            anywhere but the leftmost label. Refused at construction rather than silently
            ignored, because a pattern nobody can read is a pattern nobody can review.
    """
    out: set[str] = set()
    for pattern in patterns:
        entry = pattern.strip().rstrip(".")
        if not entry:
            raise ValueError(f"allowed_hosts contains {pattern!r}, which names no host")
        head, _, rest = entry.partition(".")
        if "*" in rest or ("*" in head and head != "*"):
            raise ValueError(
                f"allowed_hosts contains {pattern!r}; '*' is only meaningful as the whole of "
                f"the leftmost label, as in '*.example.com'"
            )
        if head == "*" and not rest:
            raise ValueError(
                f"allowed_hosts contains {pattern!r}, which would permit every host; leave "
                f"allowed_hosts empty instead, which is what 'no name restriction' means"
            )
        # **The `*` is kept away from the codec deliberately, and not because it would be
        # refused.** Measured: `"*.\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444"
        # .encode("idna")` succeeds and passes the `*` through, so today both spellings of this
        # line agree. That tolerance is incidental rather than promised: `*` is not a hostname
        # character, and a codec that tightened would take a working configuration with it.
        try:
            out.add(f"*.{_normalise(pattern, rest)}" if head == "*" else _normalise(pattern, entry))
        except BlockedURLError as unusable:
            # **A constructor raises `ValueError`, like every other check in `__post_init__`.**
            # `_normalise` refuses a name that could not resolve and says so as a *URL* refusal,
            # which is right where it is called from `check_url` and wrong here: there is no URL,
            # and a caller configuring a policy is not being told a request was blocked.
            raise ValueError(
                f"allowed_hosts contains {pattern!r}, which is not a usable name: {unusable.reason}"
            ) from unusable
    return frozenset(out)


def _host_is_allowed(host: str, patterns: frozenset[str], *, literal: bool) -> bool:
    """Whether a normalised host matches any of the patterns.

    **The whole of this card is this function not using ``endswith``.**
    ``"evil-github.com".endswith("github.com")`` is ``True``, and a suffix test is how an
    allowlist becomes a way in rather than a way to keep things out. Matching happens on label
    boundaries: a wildcard entry matches a host whose remainder, after removing the matched
    suffix, ends in a dot.

    Args:
        host: The host, already normalised by :func:`_normalise`.
        patterns: The policy's patterns, already normalised by :func:`_as_host_patterns`.
        literal: Whether the host is an IP literal. **A wildcard never matches one.** An entry
            is a name pattern, and letting ``*.0.1`` reach ``127.0.0.1`` would mean the caller
            wrote something about names and got something about addresses. A literal is
            permitted only by being listed exactly, which is also the only way to write one that
            a reader can check.

    Returns:
        Whether the host is permitted by name.
    """
    name = host.rstrip(".")
    for pattern in patterns:
        if literal:
            if name == pattern:
                return True
        elif pattern.startswith("*."):
            # Keeps the leading dot, so the label boundary is part of the comparison.
            suffix = pattern.removeprefix("*")
            if name.endswith(suffix) and len(name) > len(suffix):
                return True
        elif name == pattern:
            return True
    return False


def _nearest_pattern(host: str, patterns: frozenset[str]) -> str | None:
    """The listed entry a refused host most nearly matched, if any.

    Written for one mistake in particular, which is the one a caller makes first: listing
    ``example.com`` and then fetching ``api.example.com``. A bare entry is exact, deliberately,
    so that refusal is correct and completely baffling without a hint about *which* entry was
    close. `ssrfguard.errors` argues why a refusal a user cannot act on gets configured around.

    Args:
        host: The normalised host that was refused.
        patterns: The policy's patterns.

    There are three near misses and each is somebody's first mistake: the host is below a listed
    entry, **the host is a wildcard entry's own base**, or the entry is below the host. The
    second is the one this originally missed: listing ``*.example.com`` and then fetching
    ``example.com`` is refused correctly and is baffling without being told which entry was
    close.

    Returns:
        The nearest entry, or ``None`` when nothing is near.
    """
    name = host.rstrip(".")
    for pattern in sorted(patterns):
        bare = pattern.removeprefix("*.")
        if name == bare or name.endswith(f".{bare}") or bare.endswith(f".{name}"):
            return pattern
    return None
