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
from typing import Any

import urllib3.util.connection

from ssrfguard import Policy
from ssrfguard.httpx import Client
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
        native: The ``(module, attribute)`` of the client's *own* connect function -- the one
            the seam replaces. A test makes it raise to prove nothing fell through to it.
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
)

#: Parameter ids, so a failure names the client it came from.
ADAPTER_IDS = [adapter.name for adapter in ADAPTERS]
