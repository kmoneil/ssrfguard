"""Connecting to a validated address, against real sockets on loopback.

No fake socket layer here. The thing under test *is* the socket call, and a stand-in for it
would only confirm what its author already believed -- the sockaddr shape, the failover order
and the peer check are all properties of the real thing or of nothing.

Loopback is denied by the shipped table, so these use a policy that explicitly permits it. That
is not a workaround: it is the escape hatch working, and a test suite that needed a private door
into the library would be evidence the door exists.
"""

from __future__ import annotations

import gc
import socket
import struct
import threading
from collections.abc import Iterator
from ipaddress import ip_address

import pytest

from ssrfguard import Address, BlockedAddressError, Policy, connect

LOOPBACK_OK = Policy(allowed_networks=("127.0.0.0/8", "::1/128"))


@pytest.fixture
def listener() -> Iterator[tuple[str, int]]:
    """A TCP listener on loopback that accepts and immediately closes.

    Yields:
        The address and port it is listening on.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    # A timeout on the *listening* socket, so the accept loop returns to check `stop` instead
    # of blocking in the kernel. Closing a socket from another thread does not reliably wake a
    # blocked accept on Linux, which cost two seconds of teardown per test until this was here.
    server.settimeout(0.05)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                client, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            client.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield server.getsockname()
    finally:
        stop.set()
        server.close()
        thread.join(timeout=2)


def address_for(host: str, port: int, hostname: str = "listener.example") -> Address:
    """Build a validated-looking address without resolving anything.

    Args:
        host: The address to connect to.
        port: The port.
        hostname: The name to record on it.

    Returns:
        The address.
    """
    parsed = ip_address(host)
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    sockaddr = (host, port, 0, 0) if parsed.version == 6 else (host, port)
    return Address(family=family, sockaddr=sockaddr, ip=parsed, hostname=hostname)


def unused_port() -> int:
    """Find a port nothing is listening on.

    Returns:
        A port number that was free a moment ago.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_connects_to_the_pinned_sockaddr(listener: tuple[str, int]) -> None:
    host, port = listener
    with connect([address_for(host, port)], policy=LOOPBACK_OK, timeout=5) as sock:
        assert sock.getpeername()[:2] == (host, port)


def test_tries_addresses_in_order_and_falls_over(listener: tuple[str, int]) -> None:
    """The reason `connect` takes the whole tuple: the first answer is routinely unreachable."""
    host, port = listener
    dead = address_for(host, unused_port())
    live = address_for(host, port)
    with connect([dead, live], policy=LOOPBACK_OK, timeout=5) as sock:
        assert sock.getpeername()[1] == port


def test_reports_every_failure_when_nothing_is_reachable() -> None:
    """A message naming one of three attempts sends the reader to the wrong place."""
    ports = [unused_port() for _ in range(3)]
    addresses = [address_for("127.0.0.1", p) for p in ports]
    with pytest.raises(OSError) as caught:
        connect(addresses, policy=LOOPBACK_OK, timeout=5)
    message = str(caught.value)
    for port in ports:
        assert str(port) in message, "each attempted address has to appear in the failure"
    assert caught.value.__cause__ is not None, "the last failure is chained as the cause"


def test_an_empty_sequence_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="connect needs at least one address"):
        connect([], policy=LOOPBACK_OK)


def test_every_address_is_checked_again_before_anything_is_opened() -> None:
    """Defence in depth, and it must fail loudly rather than skipping to the next answer.

    For a sequence that came from `resolve` this cannot fire. It firing means the caller
    assembled the addresses some other way, which is exactly when a quiet fallback would hide
    the mistake that matters.
    """
    with pytest.raises(BlockedAddressError) as caught:
        connect([address_for("169.254.169.254", 80)], policy=Policy(), timeout=1)
    assert "Cloud metadata" in caught.value.reason


def test_a_denied_address_later_in_the_sequence_still_refuses(listener: tuple[str, int]) -> None:
    """Checked before *any* socket is opened, so a reachable first answer cannot mask a bad one."""
    host, port = listener
    permissive = Policy(allowed_networks=("127.0.0.0/8",))
    with pytest.raises(BlockedAddressError):
        connect(
            [address_for(host, port), address_for("169.254.169.254", 80)],
            policy=permissive,
            timeout=5,
        )


def test_connect_performs_no_name_resolution(listener: tuple[str, int]) -> None:
    """There is nothing to resolve; this asserts the claim rather than trusting the reading."""
    host, port = listener
    real = socket.getaddrinfo

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("connect must never resolve anything")

    socket.getaddrinfo = forbidden  # type: ignore[assignment]
    try:
        with connect([address_for(host, port)], policy=LOOPBACK_OK, timeout=5) as sock:
            assert sock.fileno() >= 0
    finally:
        socket.getaddrinfo = real  # type: ignore[assignment]


def test_socket_options_are_applied(listener: tuple[str, int]) -> None:
    """The adapters pass these through; dropping them silently changes connection behaviour."""
    host, port = listener
    options = [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]
    with connect(
        [address_for(host, port)], policy=LOOPBACK_OK, timeout=5, socket_options=options
    ) as sock:
        assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) == 1


def test_a_socket_option_carrying_bytes_is_applied_too(listener: tuple[str, int]) -> None:
    """`setsockopt` takes an int or a buffer, and both clients can express either.

    The int form is the common one and the one above covers. This is here because the type this
    accepts was widened to carry every shape httpcore and urllib3 can produce, and a widened
    contract that nothing exercises is a widened contract nobody knows is wrong.
    """
    host, port = listener
    options = [(socket.SOL_SOCKET, socket.SO_REUSEADDR, struct.pack("i", 1))]
    with connect(
        [address_for(host, port)], policy=LOOPBACK_OK, timeout=5, socket_options=options
    ) as sock:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) != 0


def test_a_source_address_is_bound(listener: tuple[str, int]) -> None:
    host, port = listener
    with connect(
        [address_for(host, port)], policy=LOOPBACK_OK, timeout=5, source_address=("127.0.0.1", 0)
    ) as sock:
        assert sock.getsockname()[0] == "127.0.0.1"


def test_a_failed_attempt_leaks_no_socket() -> None:
    """A guard that leaks a descriptor per refused host is a guard that exhausts the process."""
    before = len([o for o in gc.get_objects() if isinstance(o, socket.socket)])
    for _ in range(20):
        with pytest.raises(OSError):
            connect([address_for("127.0.0.1", unused_port())], policy=LOOPBACK_OK, timeout=2)
    gc.collect()
    after = len([o for o in gc.get_objects() if isinstance(o, socket.socket)])
    assert after <= before + 1, f"sockets leaked: {before} -> {after}"


def test_the_timeout_is_per_attempt_and_is_set_on_the_socket(listener: tuple[str, int]) -> None:
    host, port = listener
    with connect([address_for(host, port)], policy=LOOPBACK_OK, timeout=7.5) as sock:
        assert sock.gettimeout() == 7.5


def test_a_peer_that_is_not_the_validated_address_is_refused_and_the_socket_closed(
    listener: tuple[str, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check after the connection is up, exercised by making the peer disagree.

    `connect` to a specific address cannot land elsewhere, so nothing reachable through the
    public API triggers this. It is the answer to everything between this process and the wire
    -- a transparent proxy, a redirecting firewall rule -- and a defence nobody has run is a
    defence nobody has proven.
    """
    host, port = listener
    opened: list[socket.socket] = []

    # A subclass rather than a patched instance: `socket.socket` uses __slots__, so assigning
    # `getpeername` onto one raises AttributeError.
    class LyingSocket(socket.socket):
        def getpeername(self) -> tuple[str, int]:
            return ("203.0.113.9", port)

    def recording(*args: object, **kwargs: object) -> socket.socket:
        sock = LyingSocket(*args, **kwargs)  # type: ignore[arg-type]
        opened.append(sock)
        return sock

    monkeypatch.setattr(socket, "socket", recording)
    with pytest.raises(BlockedAddressError) as caught:
        connect([address_for(host, port)], policy=LOOPBACK_OK, timeout=5)
    assert "rewrote the destination" in caught.value.reason
    assert "203.0.113.9" in caught.value.reason
    assert all(sock.fileno() == -1 for sock in opened), (
        "a socket that failed the peer check must be closed, not left open and refused"
    )


def test_the_sockaddr_reaches_connect_byte_for_byte(
    listener: tuple[str, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tuple the resolver produced is the tuple `connect` gets, asserted directly.

    Written this way because the indirect version does not work. Every other test here uses
    IPv4, where a rebuilt `(str(ip), port)` is byte-for-byte what the resolver produced -- so
    replacing the pass-through with a rebuild changed nothing that any of them could see. The
    difference only appears for IPv6 with a non-zero scope identifier, which needs a
    link-local address on a real interface to arrange.

    So the property is asserted rather than a scenario that would expose it: whatever is on the
    `Address` is what reaches the socket. That covers the scope identifier, the flow label, and
    whatever a future address family puts in the tuple.
    """
    host, port = listener
    seen: list[object] = []
    real_connect = socket.socket.connect

    def recording(self: socket.socket, sockaddr: object) -> None:
        seen.append(sockaddr)
        real_connect(self, sockaddr)  # type: ignore[arg-type]

    monkeypatch.setattr(socket.socket, "connect", recording)
    address = address_for(host, port)
    with connect([address], policy=LOOPBACK_OK, timeout=5):
        pass
    assert seen == [address.sockaddr]

    # ...and the same for a four-element IPv6 tuple, where a rebuild would drop two elements.
    seen.clear()
    scoped = Address(
        family=socket.AF_INET6,
        sockaddr=("::1", port, 11, 22),
        ip=ip_address("::1"),
        hostname="scoped.example",
    )
    with pytest.raises(OSError):
        connect([scoped], policy=LOOPBACK_OK, timeout=2)
    assert seen == [("::1", port, 11, 22)], (
        "the flow label and scope identifier must survive to the socket layer"
    )


def test_connects_over_ipv6_loopback() -> None:
    """The AF_INET6 path, which the IPv4 fixture never exercises."""
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        server.bind(("::1", 0))
    except OSError:  # pragma: no cover - a host with no IPv6 loopback
        server.close()
        pytest.skip("this host has no IPv6 loopback")
    server.listen(4)
    try:
        port = server.getsockname()[1]
        address = Address(
            family=socket.AF_INET6,
            sockaddr=("::1", port, 0, 0),
            ip=ip_address("::1"),
            hostname="v6.example",
        )
        with connect([address], policy=LOOPBACK_OK, timeout=5) as sock:
            assert sock.family is socket.AF_INET6
            assert sock.getpeername()[:2] == ("::1", port)
    finally:
        server.close()
