"""A DNS server on loopback whose answers change between queries.

This is the fixture D-5 is about. Everything else in this suite drives resolution with a Python
callable standing in for the resolver, which is right for testing what the policy decides -- and
structurally incapable of demonstrating the one claim on the front of this package's README,
because a stand-in cannot change its mind between two calls that a real attacker's nameserver
makes for a living.

So this speaks real DNS over a real UDP socket, and its answers live in a mutable dict. A test
resolves a name, changes the dict, and connects; if anything in the package looked the name up a
second time, it gets the new answer and the test fails.

The wire format handled here is the subset that matters: one question, A and AAAA answers, no
compression in what we *emit* (though the client tolerates it in what it reads, because a
pointer in a response we wrote ourselves would still be a pointer). It is not a DNS library and
must not grow into one.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading
from dataclasses import dataclass, field

# Record types, and the only two this serves.
TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1

# Answers are served with a zero TTL. Nothing here caches, and a non-zero value would be a
# statement this fixture is not entitled to make.
TTL = 0

_QUERY_RESPONSE = 0x8180  # response, recursion desired, recursion available, no error
_NAME_NOT_FOUND = 0x8183  # the same, with NXDOMAIN


@dataclass
class Zone:
    """The answers for one name.

    Attributes:
        a: IPv4 addresses, in the order they should be served.
        aaaa: IPv6 addresses, in the order they should be served.
    """

    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)


def _encode_name(name: str) -> bytes:
    """Encode a domain name as length-prefixed labels.

    Args:
        name: The name, with or without a trailing dot.

    Returns:
        The wire form, null-terminated.
    """
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out.append(len(encoded))
        out += encoded
    out.append(0)
    return bytes(out)


def _decode_name(message: bytes, offset: int) -> tuple[str, int]:
    """Decode a domain name, following compression pointers.

    Args:
        message: The whole message, needed to follow a pointer.
        offset: Where the name starts.

    Returns:
        A pair of (name, offset just past the name in the original position).
    """
    labels: list[str] = []
    original = offset
    jumped = False
    while True:
        length = message[offset]
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack_from("!H", message, offset)[0] & 0x3FFF
            if not jumped:
                original = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if length == 0:
            break
        labels.append(message[offset : offset + length].decode("ascii"))
        offset += length
    return ".".join(labels), (original if jumped else offset)


class FlippingDNS:
    """A nameserver that answers from a dict you can edit while a test is running.

    Attributes:
        zones: Name to :class:`Zone`. Edit it between calls; that is the whole point.
        queries: Every question received, as (name, qtype), in order.
    """

    def __init__(self) -> None:
        self.zones: dict[str, Zone] = {}
        self.sequences: dict[str, list[Zone]] = {}
        self._positions: dict[tuple[str, int], int] = {}
        self.queries: list[tuple[str, int]] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        # A timeout on the socket rather than a blocking recv, so the serving loop returns to
        # check `_stop` instead of parking in the kernel. Closing a socket from another thread
        # does not reliably interrupt a blocked call on Linux.
        self._sock.settimeout(0.05)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._lock = threading.Lock()

    @property
    def address(self) -> tuple[str, int]:
        """Where this server is listening.

        Returns:
            The loopback address and the port the kernel chose.
        """
        host, port = self._sock.getsockname()
        return str(host), int(port)

    @property
    def query_count(self) -> int:
        """How many questions have been asked.

        Returns:
            The count. This is the number that proves a second lookup did not happen.
        """
        with self._lock:
            return len(self.queries)

    def set(self, name: str, *, a: list[str] | None = None, aaaa: list[str] | None = None) -> None:
        """Set the answers for a name, replacing whatever was there.

        Args:
            name: The name to answer for.
            a: IPv4 addresses.
            aaaa: IPv6 addresses.
        """
        with self._lock:
            key = name.rstrip(".").lower()
            self.zones[key] = Zone(a=list(a or ()), aaaa=list(aaaa or ()))
            self.sequences.pop(key, None)

    def set_sequence(self, name: str, zones: list[Zone]) -> None:
        """Serve a different answer to each successive query for a name.

        This is what a rebinding nameserver actually does, and it is the only way to catch a
        lookup that happens *inside* one call. A test that edits the dict between calls cannot
        see a second query that both calls bracket -- measured: a `resolve` that looked up
        twice and re-validated both times passed every other test in this file.

        The last entry repeats once the sequence is exhausted, so a caller does not have to
        predict how many queries a stub resolver will make.

        **Position is tracked per record type**, so entry *n* is what the *n*th lookup of that
        record type sees. That matters because a stub resolver asks for AAAA and A separately:
        with one shared position, the first `resolve` would consume two entries and see the
        second answer immediately. It also happens to be how a real nameserver behaves -- moving
        an A record says nothing about the AAAA.

        Args:
            name: The name to answer for.
            zones: The answers, in the order they will be served.
        """
        key = name.rstrip(".").lower()
        with self._lock:
            self.sequences[key] = list(zones)
            self.zones.pop(key, None)
            for qtype in (TYPE_A, TYPE_AAAA):
                self._positions.pop((key, qtype), None)

    def start(self) -> None:
        """Begin serving."""
        self._thread.start()

    def stop(self) -> None:
        """Stop serving and release the socket."""
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                request, peer = self._sock.recvfrom(512)
            except TimeoutError:
                continue
            except OSError:  # pragma: no cover - only on a socket closed mid-recv
                return
            try:
                reply = self._answer(request)
            except (IndexError, struct.error, UnicodeDecodeError):  # pragma: no cover
                continue
            self._sock.sendto(reply, peer)

    def _answer(self, request: bytes) -> bytes:
        """Build a reply to one query.

        Args:
            request: The query as received.

        Returns:
            The reply.
        """
        (query_id,) = struct.unpack_from("!H", request, 0)
        name, offset = _decode_name(request, 12)
        qtype, qclass = struct.unpack_from("!HH", request, offset)
        with self._lock:
            self.queries.append((name.lower(), qtype))
            key = name.lower()
            sequence = self.sequences.get(key)
            if sequence is not None:
                position = self._positions.get((key, qtype), 0)
                zone = sequence[min(position, len(sequence) - 1)]
                self._positions[(key, qtype)] = position + 1
            else:
                zone = self.zones.get(key)

        question = request[12 : offset + 4]
        if zone is None or qclass != CLASS_IN:
            header = struct.pack("!HHHHHH", query_id, _NAME_NOT_FOUND, 1, 0, 0, 0)
            return header + question

        records = zone.aaaa if qtype == TYPE_AAAA else zone.a if qtype == TYPE_A else []
        body = bytearray()
        for text in records:
            packed = ipaddress.ip_address(text).packed
            body += _encode_name(name)
            body += struct.pack("!HHIH", qtype, CLASS_IN, TTL, len(packed))
            body += packed
        header = struct.pack("!HHHHHH", query_id, _QUERY_RESPONSE, 1, len(records), 0, 0)
        return header + question + bytes(body)


def resolver_using(server: FlippingDNS, *, timeout: float = 2.0) -> object:
    """Build a `getaddrinfo`-shaped callable that asks this server.

    Asks for AAAA and then A, which is the order and the pair a stub resolver uses, and returns
    the answers in that order -- so a test can rely on which address comes first without relying
    on the platform.

    Args:
        server: The nameserver to query.
        timeout: Seconds to wait for each reply.

    Returns:
        A callable with `socket.getaddrinfo`'s signature.
    """

    def query(name: str, qtype: int) -> list[str]:
        request_id = 0x1234
        message = struct.pack("!HHHHHH", request_id, 0x0100, 1, 0, 0, 0)
        message += _encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(message, server.address)
            reply, _ = sock.recvfrom(1024)
        _, _flags, qdcount, ancount = struct.unpack_from("!HHHH", reply, 0)
        offset = 12
        for _ in range(qdcount):
            _, offset = _decode_name(reply, offset)
            offset += 4
        out: list[str] = []
        for _ in range(ancount):
            _, offset = _decode_name(reply, offset)
            rtype, _rclass, _ttl, rdlength = struct.unpack_from("!HHIH", reply, offset)
            offset += 10
            if rtype == qtype:
                out.append(str(ipaddress.ip_address(reply[offset : offset + rdlength])))
            offset += rdlength
        return out

    def getaddrinfo(host: str, port: int, *_args: object) -> list[tuple]:
        rows: list[tuple] = []
        for text in query(host, TYPE_AAAA):
            rows.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (text, port, 0, 0)))
        for text in query(host, TYPE_A):
            rows.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (text, port)))
        if not rows:
            raise socket.gaierror(socket.EAI_NONAME, f"{host}: no answer")
        return rows

    return getaddrinfo
