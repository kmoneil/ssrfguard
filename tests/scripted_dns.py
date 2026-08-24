"""A nameserver that replies with exactly the bytes a test hands it.

`rebind_dns.FlippingDNS` is a *correct* server that changes its mind, which is the right shape
for proving the pin holds. It is the wrong shape for proving a parser is safe, because it can
only emit well-formed messages, and every interesting input to a parser is malformed.

So this one takes a callable. A test writes the reply it wants, byte for byte, including the ones
no real server would send: a compression pointer that points at itself, a name that never ends,
an `AAAA` record carrying four bytes, an answer to a question nobody asked. The builders below
make the well-formed cases short so the hostile ones stand out.

It serves UDP and TCP on the same port, because a truncated reply sends the resolver to TCP and a
test that could not follow it there would be asserting half the behaviour.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading
from collections.abc import Callable

TYPE_A = 1
TYPE_CNAME = 5
TYPE_AAAA = 28
CLASS_IN = 1

FLAG_RESPONSE = 0x8000
FLAG_TRUNCATED = 0x0200
FLAG_RECURSION = 0x0180

RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3

HEADER = struct.Struct("!HHHHHH")

#: The reply builder a test installs: it is handed the query as received and returns the bytes to
#: send back, or ``None`` to stay silent, which is what a stalling authoritative server does.
#: A list sends several datagrams for one query, which is the only way to test that a forged
#: reply arriving first does not end the wait for the real one.
Responder = Callable[[bytes], "bytes | list[bytes] | None"]


def encode_name(name: str) -> bytes:
    """Encode a name as length-prefixed labels, with no validation at all.

    Deliberately permissive: a test that wants an over-long label or an empty one has to be able
    to build it.
    """
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def question_of(query: bytes) -> tuple[str, int, int]:
    """Read back the name, type and offset just past the question of a query."""
    offset = HEADER.size
    labels = []
    while query[offset] != 0:
        length = query[offset]
        labels.append(query[offset + 1 : offset + 1 + length].decode("ascii"))
        offset += 1 + length
    offset += 1
    qtype, _qclass = struct.unpack_from("!HH", query, offset)
    return ".".join(labels), qtype, offset + 4


def txid_of(query: bytes) -> int:
    """The transaction id a query carries."""
    return int(struct.unpack_from("!H", query, 0)[0])


def answer(
    query: bytes,
    *,
    addresses: list[str] | None = None,
    ttl: int = 60,
    rcode: int = RCODE_NOERROR,
    truncated: bool = False,
    txid: int | None = None,
    owner: str | None = None,
    qtype: int | None = None,
    rdata: bytes | None = None,
    cnames: list[tuple[str, str]] | None = None,
) -> bytes:
    """Build a reply to `query`, with every field a test might want to lie about.

    Args:
        query: The query as received.
        addresses: Addresses to answer with.
        ttl: The TTL to claim for each.
        rcode: The response code.
        truncated: Whether to set `TC`, which sends the resolver to TCP.
        txid: A transaction id to use instead of the one that was asked with.
        owner: An owner name for the address records other than the one asked about.
        qtype: A record type to serve instead of the one asked for.
        rdata: Raw record data to serve instead of a packed address.
        cnames: `(owner, target)` pairs, emitted before the addresses.

    Returns:
        The reply.
    """
    name, asked, past = question_of(query)
    served = asked if qtype is None else qtype
    body = bytearray()
    count = 0
    for chain_owner, target in cnames or []:
        body += encode_name(chain_owner)
        encoded = encode_name(target)
        body += struct.pack("!HHIH", TYPE_CNAME, CLASS_IN, ttl, len(encoded)) + encoded
        count += 1
    for text in addresses or []:
        packed = ipaddress.ip_address(text).packed if rdata is None else rdata
        body += encode_name(owner or name)
        body += struct.pack("!HHIH", served, CLASS_IN, ttl, len(packed)) + packed
        count += 1
    flags = FLAG_RESPONSE | FLAG_RECURSION | rcode | (FLAG_TRUNCATED if truncated else 0)
    header = HEADER.pack(txid_of(query) if txid is None else txid, flags, 1, count, 0, 0)
    return header + query[HEADER.size : past] + bytes(body)


def raw_reply(query: bytes, payload: bytes, *, ancount: int = 1) -> bytes:
    """A reply whose header and question are correct and whose answer section is `payload`."""
    _name, _qtype, past = question_of(query)
    header = HEADER.pack(txid_of(query), FLAG_RESPONSE | FLAG_RECURSION, 1, ancount, 0, 0)
    return header + query[HEADER.size : past] + payload


class ScriptedDNS:
    """A nameserver whose every reply a test writes.

    Attributes:
        queries: Every query received, as raw bytes, in order.
        tcp_queries: The subset that arrived over TCP, which is how a test proves a fallback
            happened rather than assuming it.
    """

    def __init__(self, responder: Responder) -> None:
        self._responder = responder
        self.queries: list[bytes] = []
        self.tcp_queries: list[bytes] = []
        self.last_peer: tuple[str, int] | None = None
        self._lock = threading.Lock()
        self._udp, self._tcp, self._port = _bound_pair()
        self._udp.settimeout(0.05)
        self._tcp.listen(8)
        self._tcp.settimeout(0.05)
        self._stop = threading.Event()
        self._threads = [
            threading.Thread(target=self._serve_udp, daemon=True),
            threading.Thread(target=self._serve_tcp, daemon=True),
        ]

    @property
    def host(self) -> str:
        """The loopback address this is bound to."""
        return "127.0.0.1"

    @property
    def port(self) -> int:
        """The port the kernel chose, shared by the UDP and TCP listeners."""
        return self._port

    @property
    def query_count(self) -> int:
        """How many queries have arrived, over either transport."""
        with self._lock:
            return len(self.queries)

    def start(self) -> None:
        """Begin serving."""
        for thread in self._threads:
            thread.start()

    def stop(self) -> None:
        """Stop serving and release both sockets."""
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=2)
        self._udp.close()
        self._tcp.close()

    def __enter__(self) -> ScriptedDNS:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    def spoof(self, payload: bytes) -> None:
        """Send `payload` to the last querier from a socket that is not this server's.

        **This is how the third anti-forgery check gets tested.** A random transaction id and an
        echoed question can both be asserted from inside the parser; the source address cannot,
        because the resolver never sees a datagram that fails it. It calls `connect` on its
        datagram socket, so the kernel drops anything from another address or port before any
        Python runs. The only way to show that is to send one and watch nothing happen.
        """
        if self.last_peer is None:  # pragma: no cover - only if nothing has asked yet
            raise RuntimeError("nobody has queried this server, so there is nowhere to send")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as elsewhere:
            elsewhere.sendto(payload, self.last_peer)

    def _record(self, query: bytes, *, over_tcp: bool) -> None:
        with self._lock:
            self.queries.append(query)
            if over_tcp:
                self.tcp_queries.append(query)

    def _serve_udp(self) -> None:
        while not self._stop.is_set():
            try:
                query, peer = self._udp.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                return
            self._record(query, over_tcp=False)
            with self._lock:
                self.last_peer = (str(peer[0]), int(peer[1]))
            for reply in _each(self._responder(query)):
                self._udp.sendto(reply, peer)

    def _serve_tcp(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _peer = self._tcp.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with conn:
                conn.settimeout(1.0)
                try:
                    self._handle_tcp(conn)
                except (TimeoutError, OSError, struct.error):
                    continue

    def _handle_tcp(self, conn: socket.socket) -> None:
        prefix = conn.recv(2)
        if len(prefix) < 2:
            return
        (length,) = struct.unpack("!H", prefix)
        query = b""
        while len(query) < length:
            chunk = conn.recv(length - len(query))
            if not chunk:
                return
            query += chunk
        self._record(query, over_tcp=True)
        for reply in _each(self._responder(query)):
            conn.sendall(struct.pack("!H", len(reply)) + reply)


def _each(reply: bytes | list[bytes] | None) -> list[bytes]:
    """Normalise a responder's return into the datagrams to send."""
    if reply is None:
        return []
    if isinstance(reply, bytes):
        return [reply]
    return reply


def _bound_pair() -> tuple[socket.socket, socket.socket, int]:
    """Bind a UDP and a TCP socket on one loopback port, retrying until both take it.

    **UDP and TCP have independent port spaces**, so an ephemeral port the kernel handed out for
    a datagram socket can already be held by somebody else's stream socket. Binding UDP first and
    assuming TCP would follow is a flake that only shows up under load, which is where the
    mutation lane found it: a run that binds this hundreds of times in a row eventually loses the
    race, and the failure reads as a broken test rather than as a taken port.

    Returns:
        The datagram socket, the stream socket, and the port they share.

    Raises:
        OSError: If no port could be found for both, after enough tries that something else is
            wrong.
    """
    last: OSError | None = None
    for _attempt in range(32):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            udp.bind(("127.0.0.1", 0))
            port = int(udp.getsockname()[1])
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp.bind(("127.0.0.1", port))
        except OSError as clash:
            # Both, every time. Leaving the datagram socket open on the way out is what turned
            # this into a ResourceWarning as well as a failure, and `filterwarnings = error`
            # makes that a second, more confusing error.
            udp.close()
            tcp.close()
            last = clash
            continue
        return udp, tcp, port
    raise OSError(f"no loopback port was free for both UDP and TCP: {last}")
