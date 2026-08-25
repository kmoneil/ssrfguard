"""The three connection seams, behind one interface, so a shared matrix can run against all of
them without a client anywhere.

``tests/adapters_under_test.py`` does this one layer up, for the three *clients*, and the
guarantees that cross live in ``tests/test_adapter_parity.py``. **A client is not the only way in.**
:class:`ssrfguard.httpx.SafeBackend` is public because a caller assembling their own
``httpcore.ConnectionPool`` needs it, and the requests adapter's pool classes are reachable the
same way, so the layer below the clients is a supported entry point with a matrix of its own.

That matrix is not decoration. The two httpx backends and the requests seam make *different*
choices about how much of the policy they enforce -- the requests one runs the whole URL check
in ``_pinned_socket`` deliberately, and the httpx ones check the port -- and a difference nobody
tests is a difference that becomes a gap. It already had: ``allowed_hosts`` was decided in
``check_url`` and consulted at one seam of three.

**What a seam has to supply is smaller than what a client does**: no session, no redirect
handling and no request. It is handed a host and a port and either opens a socket or refuses,
which is exactly the question these tests ask.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass

import anyio

from ssrfguard import Observer, Policy
from ssrfguard.httpx import AsyncSafeBackend, SafeBackend
from ssrfguard.requests import SafeAdapter

from .stub_resolver import Resolver


@dataclass(frozen=True)
class Seam:
    """One connection seam under test.

    Attributes:
        name: What a parameter id shows.
        reach: Open a connection to ``(host, port)`` under a policy, and close it again. Raises
            whatever the seam raises, which is the whole subject: a refusal must arrive as this
            package's own error rather than as the connection failure a client would report.
    """

    name: str
    reach: Callable[..., None]


def _httpx_seam(
    policy: Policy, resolver: Resolver, host: str, port: int, observer: Observer | None = None
) -> None:
    """Reach a host through the synchronous httpx backend.

    Args:
        policy: What the backend is willing to reach.
        resolver: A stand-in for ``socket.getaddrinfo``.
        host: The host to reach, as httpcore would hold it: an A-label, no brackets.
        port: The port to reach it on.
        observer: Where to report decisions, or ``None``.
    """
    stream = SafeBackend(policy=policy, resolver=resolver, observer=observer).connect_tcp(
        host, port, timeout=5
    )
    stream.close()


def _httpx_async_seam(
    policy: Policy, resolver: Resolver, host: str, port: int, observer: Observer | None = None
) -> None:
    """Reach a host through the asynchronous httpx backend.

    Run on a loop of its own rather than through a blocking portal: a seam call opens and closes
    one connection and keeps no pool, so there is no state for a shared loop to preserve.

    Args:
        policy: What the backend is willing to reach.
        resolver: A stand-in for ``socket.getaddrinfo``.
        host: The host to reach.
        port: The port to reach it on.
        observer: Where to report decisions, or ``None``.
    """

    async def once() -> None:
        backend = AsyncSafeBackend(policy=policy, resolver=resolver, observer=observer)
        stream = await backend.connect_tcp(host, port, timeout=5)
        await stream.aclose()

    anyio.run(once)


def _requests_seam(
    policy: Policy, resolver: Resolver, host: str, port: int, observer: Observer | None = None
) -> None:
    """Reach a host through the requests adapter's pinned connection class.

    Built from the adapter's own pool table rather than from ``_pool_classes`` directly, which is
    the route ``tests/test_requests_adapter.py`` already takes: it is the same object a pool
    would hand a connection, reached the way a caller assembling one would reach it.

    Args:
        policy: What the adapter is willing to reach.
        resolver: A stand-in for ``socket.getaddrinfo``.
        host: The host to reach.
        port: The port to reach it on.
        observer: Where to report decisions, or ``None``.
    """
    adapter = SafeAdapter(policy=policy, resolver=resolver, observer=observer)
    try:
        pool_class = adapter.poolmanager.pool_classes_by_scheme["http"]
        connection = pool_class.ConnectionCls(host=host, port=port)
        try:
            connection.connect()
        finally:
            connection.close()
    finally:
        adapter.close()


SEAMS = (
    Seam(name="httpx-backend", reach=_httpx_seam),
    Seam(name="httpx-async-backend", reach=_httpx_async_seam),
    Seam(name="requests-connection", reach=_requests_seam),
)

#: Parameter ids, so a failure names the seam it came from.
SEAM_IDS = [seam.name for seam in SEAMS]

#: Loopback, which every seam test has to reach and the shipped table denies. Named here rather
#: than written out per test, for the reason `tests/test_requests_adapter.py` names its own: a
#: test about the host allowlist must not be decided by the address table.
LOOPBACK = ("127.0.0.0/8",)


def listener() -> socket.socket:
    """Stand up a loopback server that accepts connections and does nothing with them.

    A seam opens a socket and this is what it opens it to. Deliberately not
    ``RecordingServer``: these tests assert whether a connection *happened*, not what was sent
    over it, and a seam sends nothing because there is no request at this layer.

    Returns:
        The listening socket. The caller closes it.
    """
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    return server
