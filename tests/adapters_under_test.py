"""The adapters, behind one interface, so a shared matrix can run against both.

This exists because the two seams share no code. httpx is pinned at ``httpcore``'s network
backend and requests at ``urllib3``'s ``_new_conn``; a behaviour fixed in one is not fixed in the
other, and the way that surfaces is a user reporting that one adapter refuses something the other
allows -- which is the wrong way round to find out.

So the guarantees that cross live in one parameterised file, and **adding an adapter means adding
a row here rather than writing a suite**. What each row has to supply is the small set of things
the two clients genuinely spell differently: how a guarded client is built, how a request is
made, and where the client's *own* connect path lives so a test can make it raise.

The guarantees that genuinely cannot cross are named in ``tests/test_adapter_parity.py`` and
asserted there, so an asymmetry is a thing on a list rather than a thing somebody assumed.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from typing import Any

import anyio.from_thread
import urllib3.util.connection
from httpcore._backends.anyio import AnyIOBackend

from ssrfguard import Policy
from ssrfguard.httpx import AsyncClient, Client
from ssrfguard.requests import Session

from .stub_resolver import Resolver


@dataclass(frozen=True)
class Trust:
    """A throwaway authority, in both spellings the clients want.

    Attributes:
        path: The PEM on disk, which is what requests takes.
        context: A client context that trusts it, which is what httpx takes -- httpx deprecated
            the path form.
    """

    path: str
    context: ssl.SSLContext


@dataclass(frozen=True)
class Adapter:
    """One client under test.

    Attributes:
        name: What a parameter id shows.
        opened: Build a guarded client as a context manager.
        fetch: Make one request, following redirects.
        native: The ``(owner, attribute)`` of the client's *own* connect function -- the one
            the seam replaces. A test makes it raise to prove nothing fell through to it. The
            owner is a module for two of these and a class for the third, which is only where
            each client happens to keep it.
    """

    name: str
    opened: Callable[..., Any]
    fetch: Callable[..., Any]
    native: tuple[Any, str]


@contextmanager
def _requests_client(
    policy: Policy, resolver: Resolver, trust: Trust | None = None
) -> Generator[Session, None, None]:
    """Open a guarded requests session.

    Args:
        policy: What it is willing to reach.
        resolver: A stand-in for ``socket.getaddrinfo``.
        trust: A throwaway authority to trust, if the test needs TLS.

    Yields:
        The session.
    """
    with Session(policy=policy, resolver=resolver) as session:
        if trust is not None:
            session.verify = trust.path
        yield session


@contextmanager
def _httpx_client(
    policy: Policy, resolver: Resolver, trust: Trust | None = None
) -> Generator[Client, None, None]:
    """Open a guarded httpx client.

    Args:
        policy: What it is willing to reach.
        resolver: A stand-in for ``socket.getaddrinfo``.
        trust: A throwaway authority to trust, if the test needs TLS.

    Yields:
        The client.
    """
    extra = {} if trust is None else {"verify": trust.context}
    with Client(policy=policy, resolver=resolver, **extra) as client:
        yield client


class Portalled:
    """An async client driven from synchronous code, so it can run the shared matrix.

    The alternative was a third copy of every guarantee, written in ``async def``. anyio's
    blocking portal runs one event loop in a background thread and submits coroutines to it, so
    the async client keeps its pool across calls -- which matters, because "a pooled second
    request asks nothing" is one of the rows.

    Attributes:
        client: The client being driven.
    """

    def __init__(self, client: AsyncClient, portal: anyio.from_thread.BlockingPortal) -> None:
        """Wrap a client and the loop it belongs to.

        Args:
            client: The async client.
            portal: The portal its loop is reachable through.
        """
        object.__setattr__(self, "client", client)
        object.__setattr__(self, "_portal", portal)

    def get(self, url: str, **kwargs: Any) -> Any:
        """Make one request, on the loop the client belongs to.

        Args:
            url: Where to send it.
            **kwargs: Passed to the client.

        Returns:
            The response.
        """
        return self._portal.call(partial(self.client.get, url, **kwargs))

    def __getattr__(self, name: str) -> Any:
        """Read anything else off the client itself.

        Args:
            name: The attribute wanted.

        Returns:
            Whatever the client has.
        """
        return getattr(self.client, name)

    def __setattr__(self, name: str, value: Any) -> None:
        """Write anything else through to the client.

        Args:
            name: The attribute to set.
            value: What to set it to.
        """
        setattr(self.client, name, value)


@contextmanager
def _async_client(
    policy: Policy, resolver: Resolver, trust: Trust | None = None
) -> Generator[Portalled, None, None]:
    """Open a guarded async client and a loop to drive it from.

    Args:
        policy: What it is willing to reach.
        resolver: A stand-in for ``socket.getaddrinfo``.
        trust: A throwaway authority to trust, if the test needs TLS.

    Yields:
        The client, wrapped so synchronous code can call it.
    """
    extra = {} if trust is None else {"verify": trust.context}
    with anyio.from_thread.start_blocking_portal() as portal:
        client = AsyncClient(policy=policy, resolver=resolver, **extra)
        try:
            yield Portalled(client, portal)
        finally:
            portal.call(client.aclose)


ADAPTERS = (
    Adapter(
        name="requests",
        opened=_requests_client,
        fetch=lambda client, url, headers=None: client.get(url, headers=headers or {}),
        native=(urllib3.util.connection, "create_connection"),
    ),
    Adapter(
        name="httpx",
        opened=_httpx_client,
        fetch=lambda client, url, headers=None: client.get(
            url, headers=headers or {}, follow_redirects=True
        ),
        native=(socket, "create_connection"),
    ),
    Adapter(
        name="httpx-async",
        opened=_async_client,
        fetch=lambda client, url, headers=None: client.get(
            url, headers=headers or {}, follow_redirects=True
        ),
        # Not `socket.create_connection`: the async path never goes near it, so patching that
        # would assert nothing. httpcore's own async backend is what a bypass would fall
        # through to.
        native=(AnyIOBackend, "connect_tcp"),
    ),
)

#: Parameter ids, so a failure names the client it came from.
ADAPTER_IDS = [adapter.name for adapter in ADAPTERS]
