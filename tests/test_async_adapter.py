"""The async adapter, and the one thing about it that is not the sync adapter's problem.

Every guarantee this package makes is asserted against the async client too. It is a third row
in ``tests/test_adapter_parity.py`` and in the redirect matrix, driven through a blocking portal
so it can run the same tests rather than a translated copy of them.

What is left here is the property that only exists because there is a loop. ``getaddrinfo``
blocks and has no timeout: ``socket.setdefaulttimeout`` does not apply to it, and a hostile
authoritative server can stall a lookup for as long as it likes. On the synchronous path that is
a documented denial-of-service surface and the caller's to supervise. On the async path a
backend that resolved inline would stall **the whole event loop**, so one hostile hostname would
freeze every unrelated request in the process. A security library that does that gets
removed, and a removed control protects nothing.

So: a resolver that blocks for a fifth of a second, a task counting ticks beside it, and an
assertion that the ticks happened.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from collections.abc import Iterator

import anyio
import anyio.abc
import httpcore
import httpx
import pytest

import ssrfguard.httpx as ssrfguard_httpx
from ssrfguard import BlockedAddressError, Decision, Policy
from ssrfguard.errors import BlockedURLError, ProxyUnsupportedError
from ssrfguard.httpx import AsyncClient, AsyncSafeBackend, AsyncSafeTransport, SafeTransport

from .loopback_http import RecordingServer
from .stub_resolver import Resolver

pytestmark = pytest.mark.httpx_adapter

LOOPBACK = ("127.0.0.0/8",)

#: How long the deliberately slow resolver blocks for. Long enough that a loop which was blocked
#: alongside it could not possibly have ticked, short enough not to be felt in the suite.
STALL = 0.2

#: How long a lookup waits for another one to join it before giving up.
#:
#: **This bounds a failure and is not a threshold.** Nothing passes because this number is large
#: enough; a passing run returns the instant the second lookup arrives, however slow the machine.
#: All it decides is how long a *broken* run takes to say so, which is why it can be generous
#: without being a judgement about anybody's runner.
RENDEZVOUS_DEADLINE = 10.0


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


class Rendezvous(Resolver):
    """A resolver that cannot answer until a second lookup is in flight beside it.

    **This replaces a stopwatch, and it is a stronger claim rather than a weaker one.** Timing
    two concurrent lookups and asserting they finished in less than both stalls end to end infers
    overlap from duration. A barrier observes it: two parties only pass when two threads are
    inside at once, so a run that gets through has *proved* the lookups were simultaneous rather
    than shown a number consistent with it.

    It also cannot flake. The old assertion had 1.8x of headroom on shared CI and went red on a
    macOS runner against a branch that changed one script and could not touch async resolution
    at all. **A clock in a gate measures the runner as much as the code**, which is why the cost
    gates in this suite are call counts and ratios measured in one run rather than durations;
    ``tests/test_cost.py`` is where that reasoning is written out.
    """

    def __init__(self, parties: int, **answers: str | list[str]) -> None:
        """Build the resolver.

        Args:
            parties: How many lookups must be in flight before any of them may answer.
            **answers: Host to address, as :class:`Resolver` takes them.
        """
        super().__init__(**answers)
        self.barrier = threading.Barrier(parties, timeout=RENDEZVOUS_DEADLINE)

    def __call__(self, host: str, port: int, *args: object) -> list[tuple]:
        """Answer, once somebody else is here too.

        Args:
            host: The name to look up.
            port: The port.
            *args: The rest of ``getaddrinfo``'s signature.

        Returns:
            The answer.

        Raises:
            AssertionError: If no other lookup arrived. Raised here rather than left as a bare
                ``BrokenBarrierError`` so the failure names what it means, since a barrier
                timing out is not self-explanatory at the far end of an event loop.
        """
        try:
            self.barrier.wait()
        except threading.BrokenBarrierError:
            raise AssertionError(
                f"the lookup for {host!r} waited {RENDEZVOUS_DEADLINE}s and no second lookup "
                f"joined it, so resolution is serialised rather than run off the loop"
            ) from None
        return super().__call__(host, port, *args)


@pytest.mark.anyio
async def test_a_stalled_lookup_does_not_stall_the_loop(server: RecordingServer) -> None:
    """Resolving off the loop, measured, which is what separates having thought about it from
    having done it.

    The counter is the whole assertion. If resolution ran on the loop, the counting task would
    not be scheduled at all while the lookup blocked and the count would be zero. The bound is
    deliberately far below what an idle machine produces. The claim being checked is "the loop
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
async def test_two_lookups_are_in_flight_at_the_same_time(server: RecordingServer) -> None:
    """Off the loop is not the same as one at a time, and the difference is observable.

    Two requests to two names. Neither resolver call may return until the other one has started,
    so **reaching the assertions at all is the result**: a serialised implementation cannot get
    here, because the first lookup would still be waiting for a second that has not begun.

    This used to time the pair and require them to finish inside 1.8 stalls. That measured the
    runner as much as the code and flaked on macOS. What it was reaching for is a property of
    scheduling rather than of duration, and a barrier states it directly.
    """
    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    resolver = Rendezvous(2, **{"one.test": "127.0.0.1", "two.test": "127.0.0.1"})

    async with (
        AsyncClient(policy=policy, resolver=resolver) as client,
        anyio.create_task_group() as tasks,
    ):
        tasks.start_soon(client.get, f"http://one.test:{server.port}/a")
        tasks.start_soon(client.get, f"http://two.test:{server.port}/b")

    assert sorted(resolver.asked) == ["one.test", "two.test"]
    assert [request.path for request in sorted(server.received, key=lambda r: r.path)] == [
        "/a",
        "/b",
    ]


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
    the synchronous twin has a test for it. This one had only the refusal, so the branch that
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
    silently would be a behaviour change nobody could attribute.

    Nonzero rather than 1, for the reason `tests/test_connect.py` gives: "set" is a kernel's own
    bit pattern, 1 on Linux and 8 for `SO_KEEPALIVE` on macOS, and this asserts the option landed
    rather than which platform ran the test.
    """
    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    backend = AsyncSafeBackend(policy=policy, resolver=Resolver(**{"pinned.test": "127.0.0.1"}))

    stream = await backend.connect_tcp(
        "pinned.test",
        server.port,
        socket_options=[(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)],
    )
    try:
        raw = stream.get_extra_info("socket")
        assert raw.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) != 0
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
@pytest.mark.parametrize("watching", [False, True], ids=["unobserved", "observed"])
async def test_a_connection_that_lands_elsewhere_is_refused(
    server: RecordingServer, monkeypatch: pytest.MonkeyPatch, watching: bool
) -> None:
    """The check after the connection is up, exercised by making the peer disagree.

    Connecting to an address cannot land elsewhere, so nothing reachable through the public API
    triggers this. It is the answer to everything between this process and the wire, such as a
    transparent proxy or a redirecting firewall rule, and a defence nobody has run is a defence
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
    seen: list[Decision] = []
    backend = AsyncSafeBackend(
        policy=policy,
        resolver=Resolver(**{"pinned.test": "127.0.0.1"}),
        observer=seen.append if watching else None,
    )

    with pytest.raises(BlockedAddressError) as refusal:
        await backend.connect_tcp("pinned.test", server.port)

    assert "rewrote the destination" in refusal.value.reason
    assert refusal.value.address == "203.0.113.9"

    # **The refusal is the same either way, and that is the half worth parametrising for.**
    # Reporting may not change what is decided, so the unobserved row is not redundant with the
    # observed one: it is the assertion that adding a sink changed nothing.
    peer = [decision for decision in seen if decision.stage == "peer"]
    if not watching:
        assert peer == []
        return
    # The asynchronous client does not call `ssrfguard.connect`, so its peer check is its own
    # code and its reporting is too. A stage present on two surfaces and missing on the third is
    # the drift the parity matrix exists for, and nothing fails when a record goes missing.
    assert [decision.outcome for decision in peer] == ["refused"]
    assert str(peer[0].address) == "203.0.113.9"
    # **The record's own fields, not the exception's.** A sink reads these; asserting only
    # `refusal.value.reason` leaves the record free to carry nothing and stay green.
    assert "rewrote the destination" in (peer[0].reason or "")
    assert peer[0].host == "pinned.test"
    assert peer[0].port == server.port


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
    failed on `AsyncClient`, the two clients disagreeing about the same host, which is exactly
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


class Held(Resolver):
    """A resolver that answers immediately for one name and never for the others.

    The stand-in for a hostile authoritative server: `getaddrinfo` has no timeout and a thread
    blocked in it cannot be cancelled, so a lookup that never returns holds its worker for as
    long as the attacker cares to hold it.
    """

    def __init__(self, release: threading.Event, **hosts: str) -> None:
        """Build the resolver.

        Args:
            release: Cleared while the test runs; set to let the held lookups finish so the
                worker threads are not left blocked after the test.
            **hosts: Name to address, as the base resolver takes them.
        """
        super().__init__(**hosts)
        self._release = release

    def __call__(self, host: str, port: int, *args: object) -> list[tuple]:
        """Answer at once for `free.test`, and not at all for anything else.

        Args:
            host: The name to look up.
            port: The port.
            *args: The rest of `getaddrinfo`'s signature.

        Returns:
            The answer, once this lookup is allowed to return.
        """
        if not host.startswith("free"):
            self._release.wait(HELD_LOOKUP_CEILING)
        return super().__call__(host, port, *args)


#: How long a held lookup waits before giving up on its own, so a failing assertion leaves no
#: thread blocked for the rest of the session.
HELD_LOOKUP_CEILING = 30.0

#: How many slots the client under test gets. Small, because the property is about the boundary
#: rather than about the number, and forty threads per assertion is a slow way to prove it.
SLOTS = 3


@pytest.mark.anyio
async def test_held_lookups_bound_new_names_and_nothing_else(server: RecordingServer) -> None:
    """The bound on the off-the-loop lookup, asserted at the edge where it starts to bite.

    Resolving off the loop fixed the failure where **one** hostile name froze every task in the
    process. It did not make a stalled lookup cancellable, because nothing can: `getaddrinfo`
    has no timeout and the thread stays in it. So there is still a number at which held lookups
    stop further connection setup, and the point of the client owning its own limiter is that
    the number is this client's rather than a process-wide default shared with whatever else on
    the loop reaches for a worker thread.

    Three assertions, and they only mean anything together:

    * one slot short of full, a new name resolves, so the limiter is not simply broken;
    * every slot held, a new name waits, so the bound is real and is this client's;
    * every slot held, a connection already in the pool still serves, so the bound is on
      *lookups* and not on requests. That last one is the difference between a limit and an
      outage, and it is the reason the second assertion is acceptable at all.
    """
    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    release = threading.Event()
    names = {f"held{i}.test": "127.0.0.1" for i in range(SLOTS)}
    free = {"free-one.test": "127.0.0.1", "free-two.test": "127.0.0.1"}
    resolver = Held(release, **names, **free)

    try:
        async with (
            AsyncClient(policy=policy, resolver=resolver, resolver_slots=SLOTS) as client,
            anyio.create_task_group() as tasks,
        ):
            for held in list(names)[: SLOTS - 1]:
                tasks.start_soon(_hold, client, held, server.port)
            await _settle()

            with anyio.fail_after(5):
                one_short = await client.get(f"http://free-one.test:{server.port}/a")

            tasks.start_soon(_hold, client, list(names)[-1], server.port)
            await _settle()

            # A name nothing has resolved yet, so this needs a slot and there is none.
            with anyio.move_on_after(1) as new_name:
                await client.get(f"http://free-two.test:{server.port}/b")

            # The same origin as `one_short`, whose connection is still in the pool, so this
            # needs no lookup at all and the full resolver must not touch it.
            with anyio.fail_after(5):
                pooled = await client.get(f"http://free-one.test:{server.port}/c")

            release.set()
            tasks.cancel_scope.cancel()
    finally:
        release.set()

    assert one_short.status_code == 200, "a slot was free and the request still did not go"
    assert new_name.cancelled_caught, (
        f"{SLOTS} held lookups filled every resolver slot and a request to an unresolved name "
        f"still completed; the limiter is not the one this client was given"
    )
    assert pooled.status_code == 200, (
        "a full resolver blocked a request over a connection that was already open, which "
        "makes the bound an outage rather than a limit"
    )


async def _hold(client: AsyncClient, host: str, port: int) -> None:
    """Start a request whose lookup will not return, and swallow whatever ends it.

    Args:
        client: The client to make it on.
        host: The name whose lookup is held.
        port: The server's port.
    """
    with contextlib.suppress(Exception):
        await client.get(f"http://{host}:{port}/held")


async def _settle() -> None:
    """Give the started requests time to reach the resolver and take their slots."""
    await anyio.sleep(0.3)


@pytest.mark.parametrize("slots", [0, -1])
def test_a_client_that_permits_no_lookup_is_refused_at_construction(slots: int) -> None:
    """Refused where every other unsatisfiable setting in this package is refused.

    A limiter of zero is a client that can never resolve anything, which is a configuration
    error rather than a policy, and it should surface on startup rather than as a request that
    waits forever with no explanation.
    """
    with pytest.raises(ValueError, match="resolver_slots must be at least 1"):
        AsyncSafeBackend(policy=Policy(), resolver_slots=slots)


@pytest.mark.parametrize(
    ("max_connections", "requested", "expected"),
    [
        (25, None, 25),
        (25, 4, 4),
        (None, None, ssrfguard_httpx._RESOLVER_SLOTS),
        (None, 4, 4),
    ],
)
def test_the_resolver_takes_its_size_from_the_pool_unless_told_otherwise(
    max_connections: int | None, requested: int | None, expected: int
) -> None:
    """The pool's own number wins over a default, and the caller's wins over both.

    Deriving from `max_connections` is the part worth pinning: a resolver bound tighter than the
    pool would start refusing to open connections the pool was still willing to make, which is a
    second queue nobody configured and one that reads as a hang rather than as a limit.
    """
    limits = httpx.Limits(max_connections=max_connections)
    assert ssrfguard_httpx._resolver_slots_for(limits, requested) == expected
