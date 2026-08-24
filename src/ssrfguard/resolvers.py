"""Resolvers you can put a deadline on.

``socket.getaddrinfo`` has no timeout, and ``socket.setdefaulttimeout`` does not reach it. That
one fact is what ``SECURITY.md`` documents as a denial-of-service surface on the synchronous
clients, and what ``docs/threat-model.md`` describes on the asynchronous one as held lookups
accumulating until a client's resolver slots are gone. Both are downstream of the same decision:
the lookup belongs to the platform, and the platform's lookup takes no deadline.

:class:`UdpResolver` is the other choice. It speaks DNS over a datagram socket this package owns,
so a deadline is a ``settimeout`` call rather than a wish, and one call returns inside
:attr:`UdpResolver.timeout` whatever the far end does.

    >>> from ssrfguard import Policy                      # doctest: +SKIP
    >>> from ssrfguard.httpx import Client                # doctest: +SKIP
    >>> from ssrfguard.resolvers import UdpResolver       # doctest: +SKIP
    >>> client = Client(policy=Policy(), resolver=UdpResolver(timeout=2.0))   # doctest: +SKIP

**This adds no API.** ``Resolver`` shipped in 0.1.0 and ``resolver=`` is already a constructor
argument on all three clients; what was missing was something to pass. Nothing in
:func:`ssrfguard.resolve`, :func:`ssrfguard.connect` or the adapters changes.

**It is not the default and should not become one.** ``socket.getaddrinfo`` knows things this
does not: ``/etc/hosts``, ``nsswitch.conf``, search domains, mDNS, and on macOS the entire system
resolver configuration, which does not live in ``resolv.conf``. It also applies RFC 6724
destination-address selection, which is a better ordering decision than this module is in a
position to make. Choosing this resolver is choosing a bound over that knowledge, and a caller
should make that trade knowingly.

Four decisions in here are worth reading before changing anything.

**The parser is the risk and the whole of the risk.** It reads bytes an attacker chose. What it
cannot do is grant a permit: every address it returns is checked against the policy by
:func:`ssrfguard.resolve` before anything connects, which is stated on ``Resolver`` itself. So the
danger is not that a mis-parse reaches somewhere internal; it is that a mis-parse never returns.
Hence :data:`_MAX_JUMPS` and :data:`_MAX_NAME_BYTES`: two hard bounds whose product is the
guarantee that name decoding terminates on every input, not just the well-formed ones.

**An incomplete answer set is refused rather than used.** If the A query answers and the AAAA
query times out, this raises instead of returning the half it has. Returning the half looks safe,
because a shorter answer set can only ever reach fewer places, and it is not: ``on_partial_block``
defaults to ``"reject"`` precisely so that a name resolving to both permitted and denied addresses
is refused whole, and an attacker who can suppress one of the two queries could otherwise suppress
the denied half and with it the signal. Fewer addresses, in this one package, is not the same as
safer. See :meth:`UdpResolver.__call__`.

**The nameserver is infrastructure, not a target.** The policy is never applied to it. Every
sensible ``resolv.conf`` on Linux today names ``127.0.0.53``, which the address table denies, and
denying your own recursive resolver would make this module refuse to work everywhere it is most
wanted.

**The absolute form is folded once, at the edge.** `example.test.` and `example.test` are the
same name, and the trailing dot is a convention of the *text* form: the wire carries
length-prefixed labels and has nowhere to put one. :func:`_encode_name` strips it, and every name
compared after that came off the wire or out of :func:`_name_of`, which decodes the wire. So
nothing downstream re-folds, and a ``rstrip(".")`` added to the parser would be a line that can
never change an answer. `test_a_name_in_the_absolute_form_is_asked_about_in_the_relative_one` is
where that is held.

**A literal address is never put on the wire.** ``getaddrinfo`` parses one rather than looking it
up, this does the same, and it parses strictly: ``ipaddress`` refuses ``0177.0.0.1`` and
``2130706433``, where glibc decodes the first as octal. That is a difference from the platform,
it goes in the safe direction, and ``ssrfguard.Policy`` already refuses both forms at the URL
layer regardless.
"""

from __future__ import annotations

import ipaddress
import secrets
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

from ssrfguard._address import IPAddress
from ssrfguard._resolve import ResolverAnswer

__all__ = ["Record", "UdpResolver", "nameservers_from_resolv_conf"]

#: Record types. Only three are read: the two that carry addresses, and the one that redirects
#: the owner name to another one.
_TYPE_A = 1
_TYPE_CNAME = 5
_TYPE_AAAA = 28

#: The only class this asks for or accepts. `CHAOS` and `HESIOD` exist and are not the internet.
_CLASS_IN = 1

#: The DNS header: id, flags, and the four section counts.
_HEADER = struct.Struct("!HHHHHH")

#: A resource record's fixed part, after its owner name: type, class, TTL, and rdata length.
_RECORD = struct.Struct("!HHIH")

#: Query flags: a standard query with recursion desired.
_QUERY_FLAGS = 0x0100

#: Response flags this reads back.
_FLAG_RESPONSE = 0x8000
_FLAG_TRUNCATED = 0x0200
_RCODE_MASK = 0x000F

#: Response codes. `NXDOMAIN` is a definitive answer and is not retried; the rest of the
#: non-zero codes mean the server could not answer, which is worth asking somebody else.
_RCODE_NOERROR = 0
_RCODE_NXDOMAIN = 3

#: The two high bits of a label length. Set means a compression pointer; either one alone is
#: reserved and has never meant anything, so a message using one is malformed rather than new.
_LABEL_MASK = 0xC0

#: A name may be 255 bytes on the wire and a label 63, per RFC 1035. Enforced when decoding
#: rather than trusted, because the sender picked these numbers.
_MAX_NAME_BYTES = 255
_MAX_LABEL_BYTES = 63

#: How many compression pointers one name may follow. **This bound is why decoding terminates.**
#: A pointer that points at itself is the oldest denial of service in DNS, and a parser that
#: bounds only the name length still loops forever on a pointer cycle that consumes no labels.
#: Together the two bounds mean every input either decodes or raises, in bounded time.
_MAX_JUMPS = 64

#: What one datagram may carry. 512 is the classic ceiling and this sends no EDNS0 option, so a
#: correct server never exceeds it; the extra room is so an over-long reply is *seen* and refused
#: rather than silently truncated into something that parses.
_UDP_READ_LIMIT = 4096

#: What one TCP reply may carry. The length prefix is two bytes, so this is its own ceiling.
_TCP_READ_LIMIT = 65535

#: The fields a usable `nameserver` line has: the keyword, and an address.
_NAMESERVER_FIELDS = 2

#: Where the nameserver list comes from when a caller does not supply one.
_RESOLV_CONF = Path("/etc/resolv.conf")


class _MalformedError(Exception):
    """A message this server sent cannot be read. Try another server."""


class _WrongQuestionError(Exception):
    """A message that is well formed and is an answer to a different question.

    Kept distinct from :class:`_MalformedError` because the two want opposite responses. A reply
    carrying somebody else's transaction id, or a different question, is what an off-path
    attacker's forgery looks like, and the answer to it is to keep waiting for the real one
    until the deadline, not to give up on the server.
    """


class _ServerFailureError(Exception):
    """The server answered, and the answer is that it could not answer. Try another server."""


@dataclass(frozen=True)
class Record:
    """One address record, with the lifetime its zone claims for it.

    ``getaddrinfo`` discards the TTL and there is nowhere in ``ResolverAnswer`` to put one, so
    :meth:`UdpResolver.__call__` discards it too. :meth:`UdpResolver.records` is how a caller
    reaches it, and the reason it is exposed at all is that a name whose answers change inside
    their own TTL is the signature of a rebinding attempt rather than of a deployment.

    Attributes:
        ip: The address.
        ttl: Seconds the zone says this may be cached. Nothing in this package caches it.
    """

    ip: IPAddress
    ttl: int


@dataclass(frozen=True)
class _Answer:
    """One parsed response.

    Attributes:
        records: Every address record the response carried for the question asked.
        truncated: Whether the server set `TC`, meaning the reply did not fit in a datagram.
    """

    records: tuple[Record, ...]
    truncated: bool


def _encode_name(name: str) -> bytes:
    """Encode a domain name as length-prefixed labels.

    Args:
        name: The name, with or without a trailing dot. A trailing dot is the absolute form and
            means the same thing here, which matters because urllib3 preserves one and a name
            that reached this point carrying it must not be looked up as a different name.

    Returns:
        The wire form, null-terminated.

    Raises:
        ValueError: If the name cannot be put on the wire: an empty label, a label over 63
            bytes, a name over 255, or anything outside ASCII. Raised rather than sent, because
            a malformed query is a packet that gets an answer nobody can interpret.
    """
    stripped = name.rstrip(".")
    if not stripped:
        raise ValueError("cannot resolve the root or an empty name")
    out = bytearray()
    for label in stripped.split("."):
        try:
            encoded = label.encode("ascii")
        except UnicodeEncodeError as bad:
            raise ValueError(f"{name!r} is not an ASCII name: {bad}") from bad
        if not encoded:
            raise ValueError(f"{name!r} has an empty label")
        if len(encoded) > _MAX_LABEL_BYTES:
            raise ValueError(f"{name!r} has a label longer than {_MAX_LABEL_BYTES} bytes")
        out.append(len(encoded))
        out += encoded
    out.append(0)
    if len(out) > _MAX_NAME_BYTES:
        raise ValueError(f"{name!r} is longer than {_MAX_NAME_BYTES} bytes on the wire")
    return bytes(out)


def _decode_name(message: bytes, offset: int) -> tuple[str, int]:
    """Decode a domain name, following compression pointers, in bounded time.

    Args:
        message: The whole message, because a pointer is an offset into it.
        offset: Where the name starts.

    Returns:
        A pair of (name, the offset just past the name **in its original position**), which is
        not where decoding finished if a pointer was followed.

    Raises:
        _MalformedError: On anything that would not terminate or would read outside the message: a
            pointer cycle, a name over 255 bytes, a reserved label length, a truncated label, or
            a label that is not ASCII.
    """
    labels: list[str] = []
    total = 0
    jumps = 0
    after: int | None = None
    while True:
        if offset >= len(message):
            raise _MalformedError("a name runs past the end of the message")
        length = message[offset]
        if length & _LABEL_MASK == _LABEL_MASK:
            offset, after, jumps = _follow_pointer(message, offset, after, jumps)
            continue
        if length & _LABEL_MASK:
            raise _MalformedError(f"reserved label length {length:#04x}")
        offset += 1
        if length == 0:
            break
        total += length + 1
        if total > _MAX_NAME_BYTES:
            raise _MalformedError(f"a name is longer than {_MAX_NAME_BYTES} bytes")
        if offset + length > len(message):
            raise _MalformedError("a label runs past the end of the message")
        labels.append(_label_text(message[offset : offset + length]))
        offset += length
    return ".".join(labels), (offset if after is None else after)


def _follow_pointer(
    message: bytes, offset: int, after: int | None, jumps: int
) -> tuple[int, int | None, int]:
    """Take one compression pointer.

    Args:
        message: The whole message.
        offset: Where the pointer is.
        after: Where the name ends in its original position, once known.
        jumps: How many pointers have been followed for this name already.

    Returns:
        The new offset, where the name ends in its original position, and the jump count.

    Raises:
        _MalformedError: If the pointer is truncated, points outside the message, or is the
            :data:`_MAX_JUMPS` th one, which is what a pointer cycle looks like from in here.
    """
    if offset + 1 >= len(message):
        raise _MalformedError("a compression pointer runs past the end of the message")
    if jumps >= _MAX_JUMPS:
        raise _MalformedError(f"more than {_MAX_JUMPS} compression pointers in one name")
    target = struct.unpack_from("!H", message, offset)[0] & ~(_LABEL_MASK << 8)
    if target >= len(message):
        raise _MalformedError("a compression pointer points outside the message")
    return target, (offset + 2 if after is None else after), jumps + 1


def _label_text(raw: bytes) -> str:
    """Read one label as text.

    Args:
        raw: The label's bytes.

    Returns:
        The label.

    Raises:
        _MalformedError: If it is not ASCII. A hostname that reached this module is an A-label by
            construction, so anything else is either a server this cannot talk to or an attempt
            to find out what this does with bytes it did not expect.
    """
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as bad:
        raise _MalformedError(f"a label is not ASCII: {bad}") from bad


def _parse(message: bytes, *, txid: int, name: str, qtype: int) -> _Answer:
    """Read a response, having first established that it answers the question that was asked.

    Args:
        message: The datagram or TCP payload as received.
        txid: The transaction id that was sent.
        name: The name that was asked about.
        qtype: The record type that was asked for.

    Returns:
        The answer. A response with no matching records is an empty answer rather than an error,
        because `NODATA` and `NXDOMAIN` are answers.

    Raises:
        _WrongQuestionError: If the transaction id or the question does not match. This is
            the check that makes off-path forgery hard, together with an ephemeral source
            port and a random transaction id.
        _MalformedError: If the message cannot be read.
        _ServerFailureError: If the server reported a failure other than `NXDOMAIN`.
    """
    if len(message) < _HEADER.size:
        raise _MalformedError("a message is shorter than a DNS header")
    reply_id, flags, qdcount, ancount = _HEADER.unpack_from(message, 0)[:4]
    if reply_id != txid:
        raise _WrongQuestionError(f"transaction id {reply_id:#06x} is not {txid:#06x}")
    if not flags & _FLAG_RESPONSE:
        raise _WrongQuestionError("a query arrived where a response was expected")
    offset = _check_question(message, qdcount=qdcount, name=name, qtype=qtype)
    rcode = flags & _RCODE_MASK
    if rcode == _RCODE_NXDOMAIN:
        return _Answer(records=(), truncated=False)
    if rcode != _RCODE_NOERROR:
        raise _ServerFailureError(f"the server answered with rcode {rcode}")
    truncated = bool(flags & _FLAG_TRUNCATED)
    return _Answer(
        records=_read_records(message, offset, ancount, name=name, qtype=qtype),
        truncated=truncated,
    )


def _check_question(message: bytes, *, qdcount: int, name: str, qtype: int) -> int:
    """Confirm the response echoes the question that was asked.

    Args:
        message: The whole message.
        qdcount: The question count from the header.
        name: The name that was asked about.
        qtype: The record type that was asked for.

    Returns:
        The offset just past the question section, where the answers start.

    Raises:
        _WrongQuestionError: If the question is absent or is a different one.
        _MalformedError: If the question section cannot be read.
    """
    if qdcount != 1:
        raise _WrongQuestionError(f"a response carries {qdcount} questions rather than one")
    asked, offset = _decode_name(message, _HEADER.size)
    if offset + 4 > len(message):
        raise _MalformedError("a question runs past the end of the message")
    rtype, rclass = struct.unpack_from("!HH", message, offset)
    if asked.lower() != name.lower():
        raise _WrongQuestionError(f"a response answers {asked!r} rather than {name!r}")
    if rtype != qtype or rclass != _CLASS_IN:
        raise _WrongQuestionError(f"a response answers type {rtype} class {rclass}")
    return offset + 4


def _read_records(
    message: bytes, offset: int, count: int, *, name: str, qtype: int
) -> tuple[Record, ...]:
    """Read the answer section, taking only records the question actually reached.

    A recursive resolver answering for an aliased name returns the `CNAME` chain alongside the
    addresses, and the addresses are owned by the end of the chain rather than by the name that
    was asked about. So the chain is walked: a record is read only if its owner is the name asked
    for or a name some accepted `CNAME` pointed at. **A record for an unrelated owner is
    dropped**, which is the shape an off-path attacker uses to smuggle an extra answer into a
    reply that is otherwise legitimate.

    Args:
        message: The whole message.
        offset: Where the answer section starts.
        count: How many records the header claims.
        name: The name that was asked about.
        qtype: The record type that was asked for.

    Returns:
        The addresses, in the order the server gave them.

    Raises:
        _MalformedError: If a record cannot be read, or if a record of the type asked for carries an
            address of the wrong length.
    """
    accepted = {name.lower()}
    out: list[Record] = []
    for _ in range(count):
        owner, rtype, rclass, ttl, rdata, offset = _read_record(message, offset)
        if rclass != _CLASS_IN or owner not in accepted:
            continue
        if rtype == _TYPE_CNAME:
            target, _ = _decode_name(message, offset - len(rdata))
            accepted.add(target.lower())
        elif rtype == qtype:
            out.append(Record(ip=_address_from(rdata, qtype), ttl=ttl))
    return tuple(out)


def _read_record(message: bytes, offset: int) -> tuple[str, int, int, int, bytes, int]:
    """Read one resource record.

    Args:
        message: The whole message.
        offset: Where the record starts.

    Returns:
        Its owner name folded to lower case, type, class, TTL, rdata, and the offset just past
        it.

    Raises:
        _MalformedError: If the record runs past the end of the message.
    """
    owner, offset = _decode_name(message, offset)
    if offset + _RECORD.size > len(message):
        raise _MalformedError("a record header runs past the end of the message")
    rtype, rclass, ttl, rdlength = _RECORD.unpack_from(message, offset)
    offset += _RECORD.size
    if offset + rdlength > len(message):
        raise _MalformedError("a record's data runs past the end of the message")
    rdata = message[offset : offset + rdlength]
    return owner.lower(), rtype, rclass, ttl, rdata, offset + rdlength


def _address_from(rdata: bytes, qtype: int) -> IPAddress:
    """Read an address out of a record's data.

    Args:
        rdata: The record's data.
        qtype: The record type it was accepted as.

    Returns:
        The address.

    Raises:
        _MalformedError: If the length is wrong for the type. A four-byte `AAAA` is not a short
            address; it is a server saying something untrue about its own record.
    """
    expected = 4 if qtype == _TYPE_A else 16
    if len(rdata) != expected:
        raise _MalformedError(
            f"a type {qtype} record carries {len(rdata)} bytes rather than {expected}"
        )
    return ipaddress.ip_address(rdata)


def nameservers_from_resolv_conf(path: Path = _RESOLV_CONF) -> tuple[str, ...]:
    """Read the nameserver addresses out of a ``resolv.conf``.

    Args:
        path: The file to read.

    Returns:
        Every address on a ``nameserver`` line, in order.

    Raises:
        OSError: If the file cannot be read. Not softened into an empty list: a resolver with no
            servers fails every lookup, and it should say why once at construction rather than
            once per request.
        ValueError: If the file names no usable server. A ``nameserver`` line that is not an
            address is skipped, because a name here could only be resolved by the resolver that
            is being built.

    Note:
        **This is Linux's answer and not every platform's.** macOS keeps the system resolver
        configuration in the System Configuration database, and the ``resolv.conf`` it does have
        can be absent, stale, or a symlink to something that describes only part of the truth.
        Pass ``nameservers=`` explicitly there.
    """
    servers: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        # **No separate comment check.** A line beginning with `#` or `;` cannot also have
        # `nameserver` as its first field, so the keyword test below already refuses every
        # comment. The explicit one read as a second defence and was a line that could not
        # change an outcome; `test_a_commented_out_nameserver_is_not_a_nameserver` holds the
        # behaviour either way.
        parts = line.split()
        if len(parts) < _NAMESERVER_FIELDS or parts[0] != "nameserver":
            continue
        try:
            ipaddress.ip_address(parts[1])
        except ValueError:
            continue
        servers.append(parts[1])
    if not servers:
        raise ValueError(f"{path} names no usable nameserver; pass nameservers= explicitly")
    return tuple(servers)


@dataclass(frozen=True)
class UdpResolver:
    """A stub resolver with a deadline, in the shape :data:`ssrfguard.Resolver` asks for.

    Pass one as ``resolver=`` to any of the three clients, or to :func:`ssrfguard.resolve`. Every
    address it returns is validated by the policy afterwards, exactly as the platform resolver's
    are, so installing this grants nothing.

    Attributes:
        nameservers: Addresses of the recursive resolvers to ask, in order, tried until one
            answers. Read from ``/etc/resolv.conf`` when not given. **Addresses, not names**,
            because a name here would need a resolver to resolve it. The policy is deliberately
            not applied to these: they are infrastructure rather than a target, and the
            ``127.0.0.53`` that systemd-resolved puts in every Linux ``resolv.conf`` is denied by
            the shipped table.
        timeout: **The ceiling on one call**, in seconds, measured on a monotonic clock and
            covering every query, every retry and any TCP fallback. This is the guarantee the
            module exists for, and it is asserted against a server that never answers rather
            than argued from the ``settimeout`` call.
        attempt_timeout: How long to wait for one server before trying the next, in seconds.
            Never allowed to run past ``timeout``.
        attempts: How many times to ask each server before moving on.
        families: Which address families to ask about, and the order answers come back in.
            ``AF_INET6`` first matches what a dual-stack host prefers. **Narrowing this is the
            documented escape** from the fail-closed rule in :meth:`__call__` for a network that
            drops AAAA queries rather than answering them.
        nameserver_port: The port the resolvers listen on. 53 outside a test.
    """

    nameservers: tuple[str, ...] = field(default_factory=nameservers_from_resolv_conf)
    timeout: float = 5.0
    attempt_timeout: float = 1.0
    attempts: int = 2
    families: tuple[int, ...] = (socket.AF_INET6, socket.AF_INET)
    nameserver_port: int = 53

    def __post_init__(self) -> None:
        """Validate the configuration.

        Raises:
            ValueError: If a field is unusable. Each message names the value and the field, so
                the fix is readable out of the error.
        """
        if not self.nameservers:
            raise ValueError("nameservers is empty, so no lookup could succeed")
        for server in self.nameservers:
            try:
                ipaddress.ip_address(server)
            except ValueError as bad:
                raise ValueError(
                    f"nameserver {server!r} is not an IP address, and a name here could only be "
                    f"resolved by the resolver being configured"
                ) from bad
        if self.timeout <= 0:
            raise ValueError(f"timeout={self.timeout} must be positive")
        if self.attempt_timeout <= 0:
            raise ValueError(f"attempt_timeout={self.attempt_timeout} must be positive")
        if self.attempts < 1:
            raise ValueError(f"attempts={self.attempts} must be at least 1")
        if not self.families:
            raise ValueError("families is empty, so no query would be sent")
        for family in self.families:
            if family not in (socket.AF_INET, socket.AF_INET6):
                raise ValueError(f"family {family!r} is neither AF_INET nor AF_INET6")

    def __call__(
        self,
        host: str,
        port: int = 0,
        family: int = 0,
        socktype: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[ResolverAnswer]:
        """Resolve a name, in ``socket.getaddrinfo``'s shape and inside :attr:`timeout`.

        Args:
            host: The name, or a literal address, which is parsed rather than looked up.
            port: Carried into every sockaddr unchanged, the way ``getaddrinfo`` does.
            family: ``AF_INET`` or ``AF_INET6`` to ask about one, or 0 for both.
            socktype: Echoed back. Defaults to ``SOCK_STREAM`` when 0, which is what this
                package asks for.
            proto: Echoed back. Derived from ``socktype`` when 0.
            flags: Only ``AI_NUMERICHOST`` is read, and it means the host must be a literal.
                Everything else ``getaddrinfo`` understands is ignored, which is a real
                difference: ``AI_CANONNAME``, ``AI_ADDRCONFIG`` and ``AI_PASSIVE`` do nothing
                here.

        Returns:
            One row per address, IPv6 first, in :data:`ssrfguard.Resolver`'s shape.

        Raises:
            socket.gaierror: If the name does not resolve, if it resolves to nothing, or if no
                server answered inside the deadline. The same exception ``getaddrinfo`` raises,
                because :func:`ssrfguard.resolve` deliberately does not wrap it: a name that does
                not exist is not a policy decision.

        Note:
            **A query that does not complete fails the call, rather than returning the answers
            that did.** The half-answer looks like the safe outcome and is not. Reject-on-partial
            exists because a name resolving to both permitted and denied addresses is the
            signature of a rebinding attempt, and it can only see that signature if it is given
            every answer. A zone that answers A and stalls AAAA could otherwise hide the half
            that would have been refused. `NODATA` and `NXDOMAIN` are answers and do not trigger
            this: they are the server saying there is nothing, which is complete information.
        """
        deadline = time.monotonic() + self.timeout
        literal = _literal(host, numeric_only=bool(flags & socket.AI_NUMERICHOST))
        if literal is not None:
            return [_row(literal, port, socktype, proto)]
        addresses = self._lookup(host, family=family, deadline=deadline)
        if not addresses:
            raise socket.gaierror(socket.EAI_NONAME, f"{host}: no address records")
        return [_row(address, port, socktype, proto) for address in addresses]

    def records(self, host: str, family: int = 0) -> tuple[Record, ...]:
        """Resolve a name and keep the TTLs.

        The ``getaddrinfo`` shape has nowhere to carry a TTL, so :meth:`__call__` drops it. This
        is the same lookup with the lifetimes kept, for a caller comparing a name's answers over
        time. **Nothing in this package caches what it returns**, and a cache here would be its
        own bug: reusing an answer past its lifetime pins a name to an address it may no longer
        own.

        Args:
            host: The name to resolve.
            family: ``AF_INET`` or ``AF_INET6`` to ask about one, or 0 for both.

        Returns:
            Every address record, with its TTL, IPv6 first.

        Raises:
            socket.gaierror: As :meth:`__call__` does.
        """
        deadline = time.monotonic() + self.timeout
        return self._lookup(host, family=family, deadline=deadline)

    def _lookup(self, host: str, *, family: int, deadline: float) -> tuple[Record, ...]:
        """Ask for every family in scope, refusing to return an incomplete set.

        Args:
            host: The name to resolve.
            family: The family asked for, or 0 for every configured one.
            deadline: When this call must be finished, on the monotonic clock.

        Returns:
            The records, in :attr:`families` order.

        Raises:
            socket.gaierror: If a query could not be completed, or if the name is unusable.
        """
        try:
            question = _encode_name(host)
        except ValueError as bad:
            raise socket.gaierror(socket.EAI_NONAME, f"{host}: {bad}") from bad
        out: list[Record] = []
        for wanted in self.families:
            if family not in (0, wanted):
                continue
            qtype = _TYPE_AAAA if wanted == socket.AF_INET6 else _TYPE_A
            out.extend(self._query(host, question, qtype, deadline))
        return tuple(out)

    def _query(self, host: str, question: bytes, qtype: int, deadline: float) -> tuple[Record, ...]:
        """Ask every server, in order, until one answers.

        Args:
            host: The name, for the error message.
            question: The encoded name.
            qtype: The record type to ask for.
            deadline: When this call must be finished, on the monotonic clock.

        Returns:
            The records the first answering server gave, which may be none.

        Raises:
            socket.gaierror: If no server answered inside the deadline.
        """
        failures: list[str] = []
        for server in self.nameservers:
            for _attempt in range(self.attempts):
                if time.monotonic() >= deadline:
                    failures.append(f"{server}: the {self.timeout}s deadline passed")
                    return _give_up(host, qtype, failures)
                try:
                    return self._ask(server, question, qtype, deadline).records
                except (TimeoutError, OSError, _MalformedError, _ServerFailureError) as failed:
                    failures.append(f"{server}: {failed}")
        return _give_up(host, qtype, failures)

    def _ask(self, server: str, question: bytes, qtype: int, deadline: float) -> _Answer:
        """Put one question to one server, over UDP, falling back to TCP if truncated.

        Args:
            server: The nameserver's address.
            question: The encoded name.
            qtype: The record type to ask for.
            deadline: When this call must be finished, on the monotonic clock.

        Returns:
            The answer.

        Raises:
            TimeoutError: If the server did not answer in time.
            OSError: If the socket could not be used.
            _MalformedError: If the answer cannot be read.
            _ServerFailureError: If the server reported a failure.
        """
        txid = secrets.randbits(16)
        message = (
            _HEADER.pack(txid, _QUERY_FLAGS, 1, 0, 0, 0)
            + question
            + struct.pack("!HH", qtype, _CLASS_IN)
        )
        name = _name_of(question)
        answer = self._over_udp(server, message, txid=txid, name=name, qtype=qtype, until=deadline)
        if not answer.truncated:
            return answer
        return self._over_tcp(server, message, txid=txid, name=name, qtype=qtype, until=deadline)

    def _over_udp(
        self, server: str, message: bytes, *, txid: int, name: str, qtype: int, until: float
    ) -> _Answer:
        """Exchange one query over a datagram socket.

        Args:
            server: The nameserver's address.
            message: The encoded query.
            txid: The transaction id sent.
            name: The name asked about.
            qtype: The record type asked for.
            until: The call's deadline, on the monotonic clock.

        Returns:
            The answer.

        Raises:
            TimeoutError: If nothing answered the question in time. Replies for other questions
                do not end the wait, which is what makes a forged reply a delay rather than a
                substitution.
            OSError: If the socket could not be used.
            _MalformedError: If the answer cannot be read.
            _ServerFailureError: If the server reported a failure.
        """
        attempt_ends = min(until, time.monotonic() + self.attempt_timeout)
        with socket.socket(_family_of(server), socket.SOCK_DGRAM) as sock:
            # `connect` on a datagram socket makes the kernel drop replies from anywhere else,
            # which is one of the three things standing between this and an off-path forgery.
            # The other two are the random transaction id and the ephemeral source port the
            # kernel picks here.
            sock.connect((server, self.nameserver_port))
            sock.send(message)
            while True:
                sock.settimeout(_time_left(attempt_ends, "waiting for an answer"))
                try:
                    return _parse(sock.recv(_UDP_READ_LIMIT), txid=txid, name=name, qtype=qtype)
                except _WrongQuestionError:
                    continue

    def _over_tcp(
        self, server: str, message: bytes, *, txid: int, name: str, qtype: int, until: float
    ) -> _Answer:
        """Ask the same question again over TCP, for an answer that did not fit in a datagram.

        Args:
            server: The nameserver's address.
            message: The encoded query.
            txid: The transaction id sent.
            name: The name asked about.
            qtype: The record type asked for.
            until: The call's deadline, on the monotonic clock.

        Returns:
            The answer.

        Raises:
            TimeoutError: If the exchange did not finish in time.
            OSError: If the connection could not be made.
            _MalformedError: If the answer cannot be read, including a second truncated reply, which
                over TCP means a server that is not telling the truth about its own message.
            _ServerFailureError: If the server reported a failure.
            _WrongQuestionError: If the reply answers a different question. Over TCP nobody
                else can be on the connection, so this is the server misbehaving rather than
                a forgery.
        """
        remaining = min(_time_left(until, "before a TCP retry"), self.attempt_timeout)
        with socket.create_connection((server, self.nameserver_port), timeout=remaining) as sock:
            sock.sendall(struct.pack("!H", len(message)) + message)
            (length,) = struct.unpack("!H", _recv_exactly(sock, 2, until))
            if length > _TCP_READ_LIMIT:  # pragma: no cover - a two-byte length cannot exceed it
                raise _MalformedError(f"a TCP reply claims {length} bytes")
            answer = _parse(_recv_exactly(sock, length, until), txid=txid, name=name, qtype=qtype)
        if answer.truncated:
            raise _MalformedError("a TCP reply is marked truncated")
        return answer


def _time_left(until: float, whose: str) -> float:
    """How long is left before a deadline, refusing to return nothing.

    Three places need this and each had its own copy, two of which could only be reached by
    winning a race against the timeout ``recv`` raises on its own. One helper is one bound and
    one test.

    Args:
        until: The deadline, on the monotonic clock.
        whose: What the caller was doing, for the message.

    Returns:
        The seconds remaining, always positive.

    Raises:
        TimeoutError: If the deadline has passed.
    """
    remaining = until - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"the deadline passed {whose}")
    return remaining


def _recv_exactly(sock: socket.socket, count: int, until: float) -> bytes:
    """Read exactly this many bytes, or run out of time trying.

    Args:
        sock: The connected socket.
        count: How many bytes to read.
        until: The call's deadline, on the monotonic clock.

    Returns:
        The bytes.

    Raises:
        TimeoutError: If the deadline passed first.
        _MalformedError: If the peer closed before sending them all.
    """
    chunks: list[bytes] = []
    got = 0
    while got < count:
        sock.settimeout(_time_left(until, "mid-reply"))
        chunk = sock.recv(count - got)
        if not chunk:
            raise _MalformedError("the server closed the connection mid-reply")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def _give_up(host: str, qtype: int, failures: list[str]) -> tuple[Record, ...]:
    """Report that no server answered.

    Args:
        host: The name being resolved.
        qtype: The record type being asked for.
        failures: What each attempt did instead, in order.

    Returns:
        Never. Typed as the caller's return so it can be used in a return statement.

    Raises:
        socket.gaierror: Always, naming every attempt. A resolver that fails silently in the
            middle of a security control is a resolver nobody can debug.
    """
    record = "AAAA" if qtype == _TYPE_AAAA else "A"
    raise socket.gaierror(
        socket.EAI_AGAIN, f"{host}: no {record} answer; tried {'; '.join(failures)}"
    )


def _literal(host: str, *, numeric_only: bool) -> IPAddress | None:
    """Read the host as a literal address, if it is one.

    Args:
        host: The host from the URL.
        numeric_only: Whether the caller passed ``AI_NUMERICHOST``, which makes a name an error
            rather than something to look up.

    Returns:
        The address, or ``None`` when this is a name to be resolved.

    Raises:
        socket.gaierror: If ``AI_NUMERICHOST`` was given and this is not a literal.
    """
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError as bad:
        if numeric_only:
            raise socket.gaierror(
                socket.EAI_NONAME, f"{host}: AI_NUMERICHOST was given and this is not an address"
            ) from bad
        return None


def _row(address: IPAddress | Record, port: int, socktype: int, proto: int) -> ResolverAnswer:
    """Build one ``getaddrinfo`` row.

    Args:
        address: The address, or a record carrying one.
        port: The port to carry in the sockaddr.
        socktype: What the caller asked for, or 0.
        proto: What the caller asked for, or 0.

    Returns:
        The row. IPv6 gets the four-element sockaddr, with a zero flow label and scope id, which
        is what ``getaddrinfo`` returns for an address that carries neither.
    """
    ip = address.ip if isinstance(address, Record) else address
    kind = socktype or socket.SOCK_STREAM
    number = proto or (socket.IPPROTO_UDP if kind == socket.SOCK_DGRAM else socket.IPPROTO_TCP)
    if isinstance(ip, ipaddress.IPv6Address):
        return (socket.AF_INET6, kind, number, "", (str(ip), port, 0, 0))
    return (socket.AF_INET, kind, number, "", (str(ip), port))


def _family_of(server: str) -> socket.AddressFamily:
    """Which family a nameserver's address is in.

    Args:
        server: The address, already validated at construction.

    Returns:
        ``AF_INET`` or ``AF_INET6``.
    """
    parsed = ipaddress.ip_address(server)
    return socket.AF_INET6 if isinstance(parsed, ipaddress.IPv6Address) else socket.AF_INET


def _name_of(question: bytes) -> str:
    """Read back the name out of an encoded question.

    Carrying the encoded form and decoding it here, rather than passing the string alongside,
    means the name compared against a response is the name that was actually asked, which is the
    comparison that matters.

    Args:
        question: The encoded name.

    Returns:
        The name.
    """
    name, _ = _decode_name(question, 0)
    return name
