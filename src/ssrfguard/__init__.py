"""SSRF protection that connects to the address it validated.

Every SSRF guard in Python validates a hostname and then hands the URL to an HTTP client that
resolves DNS a second time. The attacker moves the record in between. This package resolves
once, validates every answer, and connects to the address it validated -- never to a name.

The address table, the policy layer, resolution, the connection layer and all three client
surfaces -- :class:`ssrfguard.httpx.Client`, :class:`ssrfguard.httpx.AsyncClient` and
:class:`ssrfguard.requests.Session` -- are built. Start with a client; the pieces below are
what one is assembled from::

    >>> from ssrfguard import Policy
    >>> policy = Policy()
    >>> policy.check_url("https://example.com/a/b?c=d")
    <Target https host=example.com port=443>
    >>> policy.check_url("http://\u2460\u2461\u2466.0.0.1/")   # circled digits are 127.0.0.1
    Traceback (most recent call last):
    ssrfguard.errors.BlockedURLError: ...

**A policy check is necessary and not sufficient.** ``check_url`` returns a
:class:`~ssrfguard.Target`, not a URL, because handing back something an HTTP client would
accept is the shape of every advisory this package exists to answer -- the guard is not what
fails, the next line of code is.

**This package has no runtime dependencies and never will.** That is enforced by
`tests/test_zero_deps.py` and, against a built wheel in a clean interpreter, by the `zero-deps`
lane -- not by intent.
"""

from __future__ import annotations

from ssrfguard._address import DEFAULT_DENIED, AddressTable, Verdict
from ssrfguard._connect import SocketOption, connect
from ssrfguard._policy import PartialBlock, Policy, Target
from ssrfguard._registry import REGISTRY_SNAPSHOT, Block, Reach
from ssrfguard._resolve import Address, Resolver, resolve
from ssrfguard.errors import (
    BlockedAddressError,
    BlockedURLError,
    ProxyUnsupportedError,
    SSRFGuardError,
    TooManyRedirectsError,
)

__all__ = [
    "DEFAULT_DENIED",
    "REGISTRY_SNAPSHOT",
    "Address",
    "AddressTable",
    "Block",
    "BlockedAddressError",
    "BlockedURLError",
    "PartialBlock",
    "Policy",
    "ProxyUnsupportedError",
    "Reach",
    "Resolver",
    "SSRFGuardError",
    "SocketOption",
    "Target",
    "TooManyRedirectsError",
    "Verdict",
    "__version__",
    "connect",
    "resolve",
]

__version__ = "0.0.0"
