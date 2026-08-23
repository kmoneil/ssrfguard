"""The async adapter, and the one thing about it that is not the sync adapter's problem.

Every guarantee this package makes is asserted against the async client too -- it is a third row
in ``tests/test_adapter_parity.py`` and in the redirect matrix, driven through a blocking portal
so it can run the same tests rather than a translated copy of them.

What is left here is the property that only exists because there is a loop. ``getaddrinfo``
blocks and has no timeout: ``socket.setdefaulttimeout`` does not apply to it, and a hostile
authoritative server can stall a lookup for as long as it likes. On the synchronous path that is
a documented denial-of-service surface and the caller's to supervise. On the async path a
backend that resolved inline would stall **the whole event loop**, so one hostile hostname would
freeze every unrelated request in the process -- and a security library that does that gets
removed, and a removed control protects nothing.

So: a resolver that blocks for a fifth of a second, a task counting ticks beside it, and an
assertion that the ticks happened.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterator

import anyio
import anyio.abc
import httpcore
import pytest

from ssrfguard import BlockedAddressError, Policy
from ssrfguard.errors import BlockedURLError, ProxyUnsupportedError
from ssrfguard.httpx import AsyncClient, AsyncSafeBackend, AsyncSafeTransport, SafeTransport

from .loopback_http import RecordingServer
from .stub_resolver import Resolver

pytestmark = pytest.mark.httpx_adapter

LOOPBACK = ("127.0.0.0/8",)

#: How long the deliberately slow resolver blocks for. Long enough that a loop which was blocked
#: alongside it could not possibly have ticked, short enough not to be felt in the suite.
STALL = 0.2


@pytest.fixture
def anyio_backend() -> str:
    """Which event loop these run on.

    trio is not installed, so this is asyncio. The implementation does not depend on which --
    it uses anyio's thread offloading rather than ``loop.getaddrinfo``, precisely because httpx
    supports both and ``loop.getaddrinfo`` exists on only one.

    Returns:
        The backend name anyio's pytest plugin wants.
    """
    return "asyncio"


@pytest.fixture(autouse=True)
def no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove any proxy this machine happens to have configured.

    Args:
        monkeypatch: pytest's environment patcher.
    """
    for name in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.upper(), raising=False)


@pytest.fixture
def server() -> Iterator[RecordingServer]:
    """A plaintext HTTP server on loopback.

    Yields:
        The running server.
    """
    with RecordingServer() as running:
        yield running


class Stalling(Resolver):
    """A resolver that blocks the way a hostile nameserver makes ``getaddrinfo`` block."""

    def __call__(self, host: str, port: int, *args: object) -> list[tuple]:
        """Answer, slowly.

        Args:
            host: The name to look up.
            port: The port.
            *args: The rest of ``getaddrinfo``'s signature.

        Returns:
            The answer, after a wait no event loop should have to sit through.
        """
        time.sleep(STALL)
        return super().__call__(host, port, *args)


@pytest.mark.anyio
async def test_a_stalled_lookup_does_not_stall_the_loop(server: RecordingServer) -> None:
    """Resolving off the loop, measured -- which is what separates having thought about it from
    having done it.

    The counter is the whole assertion. If resolution ran on the loop, the counting task would
    not be scheduled at all while the lookup blocked and the count would be zero. The bound is
    deliberately far below what an idle machine produces -- the claim being checked is "the loop
    kept running", not "the loop ran at a particular speed", and a test that asserted the latter
    would fail on a loaded runner and then be deleted.
    """
    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    resolver = Stalling(**{"slow.test": "127.0.0.1"})
    ticks = 0

    async def count() -> None:
        nonlocal ticks
        while True:
            await anyio.sleep(0.005)
            ticks += 1

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(count)
        async with AsyncClient(policy=policy, resolver=resolver) as client:
            response = await client.get(f"http://slow.test:{server.port}/stalled")
        tasks.cancel_scope.cancel()

    assert response.status_code == 200
    assert ticks >= 5, (
        f"the loop advanced {ticks} times while a lookup blocked for {STALL}s; resolution is "
        f"running on the loop, and one hostile hostname would freeze the process"
    )


@pytest.mark.anyio
async def test_two_stalled_lookups_overlap(server: RecordingServer) -> None:
    """Off the loop is not the same as one at a time, and the difference is measurable.

    Two requests to two names, each stalling for the same fifth of a second. Run concurrently
    they should finish in about one stall rather than two, because both waits are in threads.
    """
    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    resolver = Stalling(**{"one.test": "127.0.0.1", "two.test": "127.0.0.1"})

    started = time.monotonic()
    async with (
        AsyncClient(policy=policy, resolver=resolver) as client,
        anyio.create_task_group() as tasks,
    ):
        tasks.start_soon(client.get, f"http://one.test:{server.port}/a")
        tasks.start_soon(client.get, f"http://two.test:{server.port}/b")
    elapsed = time.monotonic() - started

    assert sorted(resolver.asked) == ["one.test", "two.test"]
    assert elapsed < STALL * 1.8, (
        f"two lookups took {elapsed:.2f}s, which is both of them end to end; they are being "
        f"serialised rather than run off the loop"
    )


@pytest.mark.anyio
async def test_a_unix_socket_is_refused_at_the_async_backend() -> None:
    """The same refusal as the sync backend, for the same reason, on the other path."""
    backend = AsyncSafeBackend(policy=Policy())

    with pytest.raises(BlockedURLError) as refusal:
        await backend.connect_unix_socket("/var/run/nothing.sock")

    assert "unix domain socket" in refusal.value.reason


@pytest.mark.anyio
async def test_the_backend_sleeps_without_blocking_anything(server: RecordingServer) -> None:
    """httpcore backs off between connection retries by asking the backend to sleep.

    Doing that with ``time.sleep`` would hold the loop for the length of the backoff, which is
    the same failure as resolving inline wearing different clothes.
    """
    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    backend = AsyncSafeBackend(policy=policy)
    ticks = 0

    async def count() -> None:
        nonlocal ticks
        while True:
            await anyio.sleep(0.005)
            ticks += 1

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(count)
        await backend.sleep(0.1)
        tasks.cancel_scope.cancel()

    assert ticks >= 5


def test_an_async_transport_refuses_a_proxy_and_a_unix_socket() -> None:
    """Built at construction time, so neither needs a loop to be refused."""
    with pytest.raises(ProxyUnsupportedError):
        AsyncSafeTransport(policy=Policy(), proxy="http://127.0.0.1:9")
    with pytest.raises(BlockedURLError):
        AsyncSafeTransport(policy=Policy(), uds="/var/run/nothing.sock")


def test_a_sync_transport_is_not_an_async_one() -> None:
    """The two clients take different transports, and mixing them is refused where it is said.

    An ``AsyncClient`` handed a synchronous transport would fail somewhere inside httpx on the
    first request. It fails here instead, naming the reason.
    """
    with pytest.raises(TypeError) as refusal:
        AsyncClient(transport=SafeTransport(policy=Policy()))  # type: ignore[arg-type]

    assert "does not pin" in str(refusal.value)


@pytest.mark.anyio
async def test_a_prebuilt_async_transport_carries_its_own_policy(server: RecordingServer) -> None:
    """The positive half of the test above, which is the half that had never been constructed.

    ``transport=`` is documented on this class as the path for a caller who configured one, and
    the synchronous twin has a test for it. This one had only the refusal -- so the branch that
    *accepts* a transport was never taken, and a statement-coverage gate reported 100% while the
    documented path on one of three shipped client surfaces went unexercised. The `fast` lane now
    measures branches for that reason.
    """
    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    transport = AsyncSafeTransport(policy=policy, resolver=Resolver(**{"pinned.test": "127.0.0.1"}))

    async with AsyncClient(transport=transport) as client:
        assert client.policy is transport.policy
        response = await client.get(f"http://pinned.test:{server.port}/")

    assert response.status_code == 200
    assert server.received[-1].host == f"pinned.test:{server.port}"

    with pytest.raises(TypeError) as refusal:
        AsyncClient(policy=Policy(), transport=AsyncSafeTransport(policy=Policy()))
    assert "two answers to one question" in str(refusal.value)


@pytest.mark.anyio
async def test_socket_options_reach_the_connection(server: RecordingServer) -> None:
    """httpx callers set these and expect them to arrive; a guarded path that dropped them
    silently would be a behaviour change nobody could attribute."""
    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    backend = AsyncSafeBackend(policy=policy, resolver=Resolver(**{"pinned.test": "127.0.0.1"}))

    stream = await backend.connect_tcp(
        "pinned.test",
        server.port,
        socket_options=[(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)],
    )
    try:
        raw = stream.get_extra_info("socket")
        assert raw.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
    finally:
        await stream.aclose()


@pytest.mark.anyio
async def test_a_socket_option_that_fails_does_not_leave_the_connection_open(
    server: RecordingServer,
) -> None:
    """Anything raising after the connection is up has to close it on the way out.

    A connection abandoned open is a connection that was validated for a request nobody is going
    to make, still attached to a host the policy has stopped being consulted about. The `leaks`
    lane is what proves this one rather than the assertion below.
    """
    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    backend = AsyncSafeBackend(policy=policy, resolver=Resolver(**{"pinned.test": "127.0.0.1"}))

    with pytest.raises(OSError):
        await backend.connect_tcp("pinned.test", server.port, socket_options=[(-1, -1, 1)])


@pytest.mark.anyio
async def test_a_connection_that_lands_elsewhere_is_refused(
    server: RecordingServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check after the connection is up, exercised by making the peer disagree.

    Connecting to an address cannot land elsewhere, so nothing reachable through the public API
    triggers this. It is the answer to everything between this process and the wire -- a
    transparent proxy, a redirecting firewall rule -- and a defence nobody has run is a defence
    nobody has proven.
    """

    class Lying:
        """A stream that reports a peer it is not connected to."""

        def __init__(self, wrapped: object) -> None:
            self._wrapped = wrapped

        def extra(self, attribute: object, default: object = None) -> object:
            if attribute is anyio.abc.SocketAttribute.remote_address:
                return ("203.0.113.9", server.port)
            # anyio's stream-attribute lookup, not Django's queryset method.
            return self._wrapped.extra(attribute, default)  # noqa: S610

        async def aclose(self) -> None:
            await self._wrapped.aclose()  # type: ignore[attr-defined]

    real = anyio.connect_tcp

    async def lying(**kwargs: object) -> object:
        return Lying(await real(**kwargs))  # type: ignore[arg-type]

    monkeypatch.setattr(anyio, "connect_tcp", lying)

    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    backend = AsyncSafeBackend(policy=policy, resolver=Resolver(**{"pinned.test": "127.0.0.1"}))

    with pytest.raises(BlockedAddressError) as refusal:
        await backend.connect_tcp("pinned.test", server.port)

    assert "rewrote the destination" in refusal.value.reason


@pytest.mark.anyio
async def test_a_connect_timeout_arrives_as_httpcores_own(
    server: RecordingServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Driven by making the connection take longer than it is allowed to.

    "An address that reliably blackholes" is not something a test suite can count on, and a
    security test that fails intermittently gets deleted.
    """

    async def never(**_kwargs: object) -> object:
        await anyio.sleep(5)
        raise AssertionError("unreachable")  # pragma: no cover

    monkeypatch.setattr(anyio, "connect_tcp", never)

    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    backend = AsyncSafeBackend(policy=policy, resolver=Resolver(**{"pinned.test": "127.0.0.1"}))

    with pytest.raises(httpcore.ConnectTimeout):
        await backend.connect_tcp("pinned.test", server.port, timeout=0.01)


@pytest.mark.anyio
async def test_a_name_that_does_not_resolve_arrives_as_httpcores_own(
    server: RecordingServer,
) -> None:
    """A DNS failure is the network's answer, and it crosses the thread boundary intact."""
    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    backend = AsyncSafeBackend(policy=policy, resolver=Resolver())

    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("nowhere.test", server.port)


@pytest.mark.anyio
async def test_every_validated_address_is_tried(server: RecordingServer) -> None:
    """Failing over matters as much here as on the synchronous path.

    The first answer for a dual-stack host is routinely unreachable, and a guard that gave up
    there would become a support burden and then get removed. The first address below is a
    loopback nothing is listening on; the second is the server.
    """
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed.close()

    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    resolver = Resolver(**{"failover.test": ["127.0.0.9", "127.0.0.1"]})
    backend = AsyncSafeBackend(policy=policy, resolver=resolver)

    # 127.0.0.9 has nothing listening on this port, so the first attempt is refused and the
    # second is the one that answers.
    stream = await backend.connect_tcp("failover.test", server.port)
    try:
        assert stream.get_extra_info("server_addr")[0] == "127.0.0.1"
    finally:
        await stream.aclose()


def test_allow_proxy_leaves_httpxs_own_proxy_pool_in_place_on_the_async_path() -> None:
    """The same semantics as the sync transport: enforcement really has moved."""
    policy = Policy(allow_proxy=True)
    transport = AsyncSafeTransport(policy=policy, proxy="http://127.0.0.1:9")
    assert isinstance(transport._pool, httpcore.AsyncHTTPProxy)


def test_an_environment_proxy_is_refused_by_the_async_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """And so is the one that arrives without anybody writing it down."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")

    with pytest.raises(ProxyUnsupportedError):
        AsyncClient(policy=Policy())


# ---------------------------------------------------------------------------------------------
# Failing over past a timeout, and the cap on how many times that may happen
#
# Injected rather than waited for, for the reason the connect-timeout test above gives.
# ---------------------------------------------------------------------------------------------


@pytest.mark.anyio
async def test_a_timed_out_address_is_failed_over_from(
    server: RecordingServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The synchronous path moves on from a timed-out answer and this one used to raise on it.

    A host answering with one dead address and one live one therefore worked on `Client` and
    failed on `AsyncClient` -- the two clients disagreeing about the same host, which is exactly
    what the shared matrix exists to prevent and what this file's own docstring calls the reason
    a guard becomes a support burden and then gets removed.
    """
    real = anyio.connect_tcp
    stalled: list[str] = []

    async def first_one_stalls(**kwargs: object) -> object:
        if str(kwargs["remote_host"]) == "127.0.0.9":
            stalled.append("127.0.0.9")
            await anyio.sleep(5)
            raise AssertionError("unreachable")  # pragma: no cover
        return await real(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(anyio, "connect_tcp", first_one_stalls)

    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    resolver = Resolver(**{"failover.test": ["127.0.0.9", "127.0.0.1"]})
    backend = AsyncSafeBackend(policy=policy, resolver=resolver)

    stream = await backend.connect_tcp("failover.test", server.port, timeout=0.5)
    await stream.aclose()

    assert stalled == ["127.0.0.9"], "the first answer has to have been tried and timed out"


@pytest.mark.anyio
async def test_no_more_than_max_connection_attempts_addresses_are_tried_on_the_async_path(
    server: RecordingServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same bound as the synchronous path, for the same reason and with the same message."""
    tried: list[str] = []

    async def never(**kwargs: object) -> object:
        tried.append(str(kwargs["remote_host"]))
        await anyio.sleep(5)
        raise AssertionError("unreachable")  # pragma: no cover

    monkeypatch.setattr(anyio, "connect_tcp", never)

    policy = Policy(
        allowed_ports=frozenset({server.port}),
        allowed_networks=LOOPBACK,
        max_connection_attempts=3,
    )
    resolver = Resolver(**{"fanout.test": [f"127.0.0.{n}" for n in range(1, 13)]})
    backend = AsyncSafeBackend(policy=policy, resolver=resolver)

    with pytest.raises(httpcore.ConnectTimeout) as caught:
        await backend.connect_tcp("fanout.test", server.port, timeout=0.01)

    assert len(tried) == 3
    assert "9 further address(es) not tried" in str(caught.value)
    assert "max_connection_attempts=3" in str(caught.value)


@pytest.mark.anyio
async def test_a_refusal_among_timeouts_arrives_as_a_connect_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refusal says the host is there and said no; a timeout says nothing at all. httpcore
    spells the two differently and the more informative one is the one that survives."""
    real = anyio.connect_tcp

    async def first_one_stalls(**kwargs: object) -> object:
        if str(kwargs["remote_host"]) == "127.0.0.9":
            await anyio.sleep(5)
            raise AssertionError("unreachable")  # pragma: no cover
        return await real(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(anyio, "connect_tcp", first_one_stalls)

    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    dead = int(closed.getsockname()[1])
    closed.close()

    policy = Policy(allowed_ports=frozenset({dead}), allowed_networks=LOOPBACK)
    resolver = Resolver(**{"mixed.test": ["127.0.0.9", "127.0.0.1"]})
    backend = AsyncSafeBackend(policy=policy, resolver=resolver)

    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("mixed.test", dead, timeout=0.5)
