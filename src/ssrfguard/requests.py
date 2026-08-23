"""The requests adapter: pinning at ``_new_conn``, and nowhere near ``.host``.

The obvious way to pin urllib3 is wrong, and it is wrong in the direction this package exists to
prevent. The approach this module was originally specified to take was: *set ``_dns_host`` to
the validated address and leave ``.host`` as the hostname, because urllib3 maintains that split
for precisely this purpose.* **It does not.** From ``urllib3/connection.py``::

    @property
    def host(self) -> str:
        return self._dns_host.rstrip(".")

    @host.setter
    def host(self, value: str) -> None:
        self._dns_host = value

``.host`` is *derived from* ``_dns_host``. The split exists for trailing dots -- the property's
own docstring says so -- so writing an address into ``_dns_host`` writes it into ``.host`` too,
and ``HTTPSConnection.connect`` reads ``server_hostname`` straight off ``.host``. Measured
against a loopback server holding a certificate for one name while the connection is pinned to
127.0.0.1, that produces three outcomes and none of them is the one that was intended:

* **As specified, every request fails** with ``certificate verify failed: IP address mismatch,
  certificate is not valid for '127.0.0.1'``. The certificate is being checked against the pin.
* **The one-line repair for that failure is ``assert_hostname=False``, and it connects** --
  ``200``, with a certificate for a name nobody checked. The trap is not that the specified
  approach quietly fails open; it is that it fails loudly and the nearest thing that makes it
  work again turns hostname verification off entirely.
* ``assert_hostname=<the hostname>`` restores the name check, and the request still leaves with
  ``Host: 127.0.0.1:<port>`` and an IP in the SNI extension -- so name-based virtual hosting
  breaks and the pinned address leaks into the request.

``tests/test_requests_adapter.py`` holds all three as a regression. They are properties of
urllib3 rather than of this package, and nothing here would notice them changing.

**The seam is** :meth:`urllib3.connection.HTTPConnection._new_conn`. It is the only place the
address is used: it resolves ``_dns_host`` and returns a socket, and everything downstream --
TLS, the ``Host:`` header, the audit event -- reads ``.host``, which it never touches.
Overriding it to return a socket that is *already connected* to a validated address is
therefore the whole of the change. Verifying a certificate against an IP address is not
something this module has to remember not to do; there is no line in it that could.

The alternative shape, which some libraries in this space use, is to rewrite the URL to the
validated address and re-set ``Host:`` and SNI by hand. That works, and it costs three things
this seam does not: the address lands in ``request.url``, where it reaches logs, hooks and retry
keys; a relative ``Location:`` then resolves against the rewritten URL, so ``/admin`` from a
redirect now targets the pinned address; and correct TLS becomes a rule to follow on every code
path rather than a property of one function.

**On importing requests at module scope.** The promise on the front of this package is that
``import ssrfguard`` loads no third-party module, and it is kept by ``ssrfguard/__init__.py``
not importing this module -- not by deferring the import inside it. Anyone who has reached
``ssrfguard.requests`` has requests installed by definition. The `zero-deps` lane checks the
promise that matters by importing the package in an interpreter where neither client exists.
"""

from __future__ import annotations

import socket
import sys
from collections.abc import Generator
from typing import Any

import requests
from requests.adapters import (
    DEFAULT_POOLBLOCK,
    DEFAULT_POOLSIZE,
    DEFAULT_RETRIES,
    BaseAdapter,
    HTTPAdapter,
)
from requests.utils import select_proxy
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError
from urllib3.util.retry import Retry

from ssrfguard._connect import connect
from ssrfguard._policy import Policy
from ssrfguard._resolve import Resolver, resolve
from ssrfguard.errors import ProxyUnsupportedError, TooManyRedirectsError

__all__ = ["SafeAdapter", "Session"]


def _origin(scheme: str, host: str, port: int) -> str:
    """Render the origin urllib3 was about to reach, in a form the policy can read.

    Args:
        scheme: The pool's scheme, which decides what the policy allows.
        host: The name urllib3 was about to resolve -- ``_dns_host``, trailing dot and all.
        port: The port it was about to connect to.

    Returns:
        A URL naming that origin and nothing else.
    """
    literal = f"[{host}]" if ":" in host else host
    return f"{scheme}://{literal}:{port}/"


def _pinned_socket(
    connection: HTTPConnection,
    *,
    scheme: str,
    dns_host: str,
    tunnel_host: str | None,
    policy: Policy,
    resolver: Resolver | None,
) -> socket.socket:
    """Resolve, validate, and connect -- the only place this adapter chooses an address.

    The host is taken from ``_dns_host`` rather than from ``.host`` because ``_dns_host`` is
    what urllib3 itself would have handed to ``getaddrinfo``: it keeps a trailing dot, which is
    a request for an absolute lookup and changes what the name resolves to. Validating the name
    that is actually about to be looked up is what leaves no gap between the two.

    The whole URL check runs here, not only the address check, and that is deliberate. It costs
    nothing -- it is pure, and it happens once per new connection rather than once per request
    -- and it means the scheme and the port are enforced by the function that creates the
    socket. A pool reached by some route that never went through :meth:`SafeAdapter.send` is
    still bound by the policy.

    Args:
        connection: The connection asking for a socket. Only its public attributes are read.
        scheme: ``"http"`` or ``"https"``, from the pool class this connection belongs to.
        dns_host: The connection's ``_dns_host``.
        tunnel_host: The connection's ``_tunnel_host``, set when a proxy has been asked to
            ``CONNECT`` somewhere on this socket.
        policy: The policy to validate against.
        resolver: A stand-in for ``socket.getaddrinfo``, or ``None`` for the real one.

    Returns:
        A socket connected to an address the policy permitted.

    Raises:
        ProxyUnsupportedError: If this connection is tunnelling. ``.host`` is then the *proxy*,
            so pinning it would validate the wrong host and report success. Unreachable through
            :class:`SafeAdapter`, which refuses a proxy before a connection is made; this is
            what makes the refusal a property of the socket rather than of the call path.
        BlockedURLError: If the origin is not permitted -- its scheme, its port, or a literal
            address the policy denies.
        BlockedAddressError: If the name resolves to nothing permitted.
        NameResolutionError: If the name does not resolve, matching what urllib3 raises.
        ConnectTimeoutError: If the connection timed out, matching what urllib3 raises.
        NewConnectionError: If every validated address refused the connection, matching what
            urllib3 raises.
    """
    if tunnel_host is not None:
        raise ProxyUnsupportedError(f"{connection.host}:{connection.port}")

    target = policy.check_url(_origin(scheme, dns_host, connection.port))
    try:
        addresses = resolve(target, policy=policy, resolver=resolver)
        opened = connect(
            addresses,
            policy=policy,
            # urllib3 resolves its own "use the default" sentinel before this point, so this is
            # a number or None. `connect` reads None as "leave the socket at whatever
            # `socket.getdefaulttimeout` returns", where urllib3 would call `settimeout(None)`
            # and block regardless of it. The two differ only in a process that set a global
            # default, and there this is the stricter of the two.
            timeout=connection.timeout,
            source_address=connection.source_address,
            socket_options=connection.socket_options,
        )
    except socket.gaierror as unresolvable:
        raise NameResolutionError(connection.host, connection, unresolvable) from unresolvable
    except TimeoutError as timed_out:
        raise ConnectTimeoutError(
            connection,
            f"Connection to {connection.host} timed out. (connect timeout={connection.timeout})",
        ) from timed_out
    except OSError as refused:
        raise NewConnectionError(
            connection, f"Failed to establish a new connection: {refused}"
        ) from refused

    # urllib3 raises this from inside the method being replaced, so not raising it here would
    # silently retire an event that exists to let a process see its own outbound connections.
    sys.audit("http.client.connect", connection, connection.host, connection.port)
    return opened


def _pool_classes(policy: Policy, resolver: Resolver | None) -> dict[str, type[HTTPConnectionPool]]:
    """Build the scheme-to-pool-class table for one adapter.

    The classes are built per adapter and close over the policy because there is no supported
    way to carry a value down to a connection: :class:`urllib3.PoolManager` hashes
    ``connection_pool_kw`` into a pool key with a fixed set of fields, and a key it does not
    know raises there. A closure needs none of that machinery, and it makes the policy a
    property of the class rather than of a mutable attribute somebody could reassign.

    Args:
        policy: The policy every connection from these pools will validate against.
        resolver: A stand-in for ``socket.getaddrinfo``, or ``None`` for the real one.

    Returns:
        A table to install as a pool manager's ``pool_classes_by_scheme``.
    """

    class PinnedHTTPConnection(HTTPConnection):
        """An HTTP connection that opens its socket to a validated address."""

        def _new_conn(self) -> socket.socket:
            """Open the socket for this connection.

            Returns:
                A socket connected to an address the policy permitted.
            """
            return _pinned_socket(
                self,
                scheme="http",
                dns_host=self._dns_host,
                tunnel_host=self._tunnel_host,
                policy=policy,
                resolver=resolver,
            )

    class PinnedHTTPSConnection(HTTPSConnection):
        """An HTTPS connection that opens its socket to a validated address.

        Nothing here touches TLS. ``connect`` sets ``server_hostname`` from ``.host`` a few
        lines after calling ``_new_conn``, and ``.host`` still holds the hostname, so the
        certificate is verified against the name the caller asked for.
        """

        def _new_conn(self) -> socket.socket:
            """Open the socket for this connection.

            Returns:
                A socket connected to an address the policy permitted.
            """
            return _pinned_socket(
                self,
                scheme="https",
                dns_host=self._dns_host,
                tunnel_host=self._tunnel_host,
                policy=policy,
                resolver=resolver,
            )

    class PinnedHTTPConnectionPool(HTTPConnectionPool):
        """A pool whose connections pin."""

        ConnectionCls = PinnedHTTPConnection

    class PinnedHTTPSConnectionPool(HTTPSConnectionPool):
        """A TLS pool whose connections pin."""

        ConnectionCls = PinnedHTTPSConnection

    return {"http": PinnedHTTPConnectionPool, "https": PinnedHTTPSConnectionPool}


class SafeAdapter(HTTPAdapter):
    """A ``requests`` transport adapter that connects only to addresses it validated.

    Mount it on a session, or let :class:`Session` do that. Every connection this adapter opens
    resolves the name once, checks every answer against the policy, and connects to one of the
    answers it checked -- so a record that moves between the check and the connection moves
    nothing.

    What is *not* covered is worth stating plainly, because an adapter is only mounted against
    the prefixes it was mounted against. A session that mounts this on ``https://`` and leaves
    ``http://`` with the stock adapter is guarded on one scheme, and a redirect is how it will
    find out. :class:`Session` mounts both.

    Attributes:
        policy: What this adapter is willing to reach.
        resolver: A stand-in for ``socket.getaddrinfo``. Whatever it returns is validated, so
            supplying one grants no permission.
    """

    # `HTTPAdapter.__getstate__` saves exactly this list, and `__setstate__` rebuilds the pool
    # manager from it. Without these two names a session that was pickled comes back with an
    # adapter that cannot build its pools.
    #
    # `ClassVar`, which is what RUF012 asks for, is not available: requests declares this as an
    # annotated instance attribute, and narrowing an inherited one to a class variable is a
    # type error. It is read and never mutated, which is the property the rule is protecting.
    __attrs__: list[str] = [*HTTPAdapter.__attrs__, "policy", "resolver"]  # noqa: RUF012

    def __init__(
        self,
        *,
        policy: Policy,
        resolver: Resolver | None = None,
        pool_connections: int = DEFAULT_POOLSIZE,
        pool_maxsize: int = DEFAULT_POOLSIZE,
        max_retries: Retry | int = DEFAULT_RETRIES,
        pool_block: bool = DEFAULT_POOLBLOCK,
    ) -> None:
        """Build the adapter.

        Args:
            policy: What this adapter is willing to reach.
            resolver: A stand-in for ``socket.getaddrinfo``, for tests and for callers with
                their own.
            pool_connections: How many connection pools to cache.
            pool_maxsize: How many connections to keep in a pool.
            max_retries: Retries for connection failures, as
                :class:`requests.adapters.HTTPAdapter` defines them. A refusal by this package
                is not retried: it is not an ``OSError``, which is what the retry machinery
                counts.
            pool_block: Whether to block when a pool is full.
        """
        # Assigned before `super().__init__`, which calls `init_poolmanager` before returning.
        self.policy = policy
        self.resolver = resolver
        super().__init__(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=max_retries,
            pool_block=pool_block,
        )

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = DEFAULT_POOLBLOCK,
        **pool_kwargs: object,
    ) -> None:
        """Build the pool manager, and replace the classes it will build pools from.

        Args:
            connections: How many pools to cache.
            maxsize: How many connections to keep per pool.
            block: Whether to block when a pool is full.
            **pool_kwargs: Passed to :class:`urllib3.PoolManager`.
        """
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)
        # Replacing the scheme table on the manager, rather than passing the classes in, is the
        # hook `urllib3.contrib.socks` uses for the same purpose, so it is a supported shape
        # rather than a reach into an internal.
        #
        # **Replaced, never mutated.** `PoolManager.__init__` assigns the module-level table
        # itself rather than a copy of it -- unlike the key table on the line below it, which
        # it does copy -- so writing a key into the manager's mapping would rewrite urllib3's
        # default for every other client in the process.
        #
        # The ignore is a limitation in one of the two type checkers rather than a doubt about
        # the assignment: urllib3 leaves that table unannotated, so its type is inferred from a
        # literal holding two specific class objects, and no subclass of either can satisfy it.
        self.poolmanager.pool_classes_by_scheme = _pool_classes(  # ty: ignore[invalid-assignment]
            self.policy, self.resolver
        )

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        # The three pass-through parameters carry requests' own aliases, spelled out rather
        # than imported: `requests._types` says in as many words that it is not public API,
        # and an alias that moved would silently change this signature. Written this way they
        # are identical to what the base class declares, so nothing is narrowed.
        timeout: float | tuple[float | None, float | None] | None = None,
        verify: bool | str = True,
        cert: str | tuple[str, str] | None = None,
        proxies: dict[str, str] | None = None,
    ) -> requests.Response:
        """Refuse a proxied request, then send it.

        A proxy resolves the target itself and opens the socket to it. Pinning happens in this
        process and the proxy is not in it, so a request sent through one is a request this
        adapter cannot make any promise about -- and requests would route it through a pool
        manager of its own, which has never heard of the policy. Refusing is the honest answer;
        ``allow_proxy=True`` on the policy accepts that enforcement has moved to the proxy.

        The proxy is selected with the same function requests uses to select one, so the
        question asked here is exactly the question that decides whether one gets used --
        including ``no_proxy``, which is why an environment variable that does not apply to
        this host does not refuse it.

        Args:
            request: The prepared request.
            stream: Whether to stream the response body.
            timeout: Connect and read timeouts.
            verify: TLS verification, as requests defines it.
            cert: A client certificate.
            proxies: The merged proxy mapping, environment variables included.

        Returns:
            The response.

        Raises:
            ProxyUnsupportedError: If a proxy applies to this request and the policy does not
                permit one.
        """
        # `request.url` is typed as optional and is never unset by the time an adapter is
        # reached. An empty string still asks the question, and an "all://" proxy still
        # answers it, so the unreachable case refuses rather than skipping the check.
        proxy = select_proxy(request.url or "", dict(proxies or {}))
        if proxy and not self.policy.allow_proxy:
            raise ProxyUnsupportedError(proxy)
        return super().send(
            request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies
        )


class Session(requests.Session):
    """A ``requests`` session that connects only to addresses it validated.

    This is the entry point. It is a :class:`requests.Session` with a :class:`SafeAdapter`
    mounted on both schemes, so everything a session does -- redirects, retries, pooled
    connections, ``Session.request`` and the verb helpers -- goes through the seam::

        >>> from ssrfguard import Policy
        >>> from ssrfguard.requests import Session
        >>> with Session(policy=Policy()) as session:      # doctest: +SKIP
        ...     session.get(untrusted_url)

    Mounting an adapter of your own over either prefix removes the guard from that prefix.
    There is no way to prevent that and no attempt to; it is stated here because the failure is
    silent.
    """

    def __init__(
        self,
        *,
        policy: Policy,
        resolver: Resolver | None = None,
        pool_connections: int = DEFAULT_POOLSIZE,
        pool_maxsize: int = DEFAULT_POOLSIZE,
        max_retries: Retry | int = DEFAULT_RETRIES,
        pool_block: bool = DEFAULT_POOLBLOCK,
    ) -> None:
        """Build the session.

        Args:
            policy: What this session is willing to reach.
            resolver: A stand-in for ``socket.getaddrinfo``, for tests and for callers with
                their own.
            pool_connections: How many connection pools to cache.
            pool_maxsize: How many connections to keep in a pool.
            max_retries: Retries for connection failures.
            pool_block: Whether to block when a pool is full.
        """
        super().__init__()
        self.policy = policy
        # Set for anyone reading the attribute; enforced in `resolve_redirects`, which is what
        # makes it the policy's number rather than a default somebody can reassign past.
        self.max_redirects = policy.max_redirects
        adapter = SafeAdapter(
            policy=policy,
            resolver=resolver,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=max_retries,
            pool_block=pool_block,
        )
        # Replaces the two stock adapters `requests.Session.__init__` mounted, rather than
        # sitting alongside them: `get_adapter` picks the longest matching prefix, and these
        # are the same two prefixes.
        self.mount("http://", adapter)
        self.mount("https://", adapter)

    def get_adapter(self, url: str) -> BaseAdapter:
        """Check the whole URL, then pick the adapter for it.

        This is the per-request URL check, and ``requests`` calls it for every hop of a redirect
        chain. Doing it here rather than in the adapter is what makes a hop to a scheme the
        policy refuses arrive as a refusal from this package: nothing is mounted for ``file://``,
        so without this the answer would be requests' own "no connection adapters were found",
        which is a different sentence about a different thing.

        Args:
            url: The URL about to be sent to.

        Returns:
            The adapter mounted for it.

        Raises:
            BlockedURLError: If the URL is not permitted.
            BlockedAddressError: If the host was a literal address the policy denies.
        """
        self.policy.check_url(url)
        return super().get_adapter(url)

    def resolve_redirects(
        self,
        resp: requests.Response,
        req: requests.PreparedRequest,
        stream: bool = False,
        timeout: float | tuple[float | None, float | None] | None = None,
        verify: bool | str = True,
        cert: str | tuple[str, str] | None = None,
        proxies: dict[str, str] | None = None,
        yield_requests: bool = False,
        # requests' own per-hop extras, forwarded unchanged.
        **adapter_kwargs: Any,  # noqa: ANN401
    ) -> Generator[requests.Response, None, None]:
        """Walk a redirect chain under this package's own limit.

        The cap is re-asserted here rather than only at construction, so that it is the policy's
        number at the moment it is used whatever has been assigned to the attribute since. The
        client's own limit is not a security control: it exists to stop loops, it defaults to
        thirty, and it is configurable independently of everything this package decides.

        Args:
            resp: The response that redirected.
            req: The request that produced it.
            stream: Whether to stream each hop's body.
            timeout: Connect and read timeouts.
            verify: TLS verification, as requests defines it.
            cert: A client certificate.
            proxies: The merged proxy mapping.
            yield_requests: Yield requests rather than responses, as requests defines it.
            **adapter_kwargs: Passed through to the adapter.

        Yields:
            One response per hop.

        Raises:
            TooManyRedirectsError: If the chain is longer than the policy allows. Raised before
                the over-limit hop is sent, because requests checks its limit before sending.
        """
        self.max_redirects = self.policy.max_redirects
        try:
            yield from super().resolve_redirects(
                resp,
                req,
                stream=stream,
                timeout=timeout,
                verify=verify,
                cert=cert,
                proxies=proxies,
                yield_requests=yield_requests,
                **adapter_kwargs,
            )
        except requests.TooManyRedirects as exceeded:
            walked = exceeded.response
            chain = (
                ()
                if walked is None  # pragma: no cover - requests always names the response
                else tuple(str(hop.url) for hop in [*walked.history, walked])
            )
            raise TooManyRedirectsError(self.policy.max_redirects, chain) from exceeded

    def rebuild_auth(
        self, prepared_request: requests.PreparedRequest, response: requests.Response
    ) -> None:
        """Drop the policy's sensitive headers when a redirect leaves the origin.

        requests already drops ``Authorization`` here, and this widens that to whatever the
        caller told the policy is a credential. The decision of *whether* this hop leaves the
        origin is requests' own, so this can only ever strip more than requests would, never
        less.

        Args:
            prepared_request: The request about to be sent to the redirect target.
            response: The response that redirected.
        """
        super().rebuild_auth(prepared_request, response)
        if not self.should_strip_auth(str(response.request.url), str(prepared_request.url)):
            return
        for name in list(prepared_request.headers):
            if name.lower() in self.policy.sensitive_headers:
                del prepared_request.headers[name]
