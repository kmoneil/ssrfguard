"""The httpx adapter: pinning at httpcore's network backend, where TLS is not ours to touch.

httpcore splits "open a socket to this origin" from "start TLS on it" and calls them one after
the other, from ``httpcore/_sync/connection.py``::

    stream = self._network_backend.connect_tcp(host=..., port=..., ...)
    if self._origin.scheme in (b"https", b"wss"):
        stream = stream.start_tls(
            ssl_context=..., server_hostname=sni_hostname or self._origin.host.decode("ascii"),
        )

**httpcore passes the origin hostname to ``start_tls`` itself.** Implementing ``connect_tcp`` and
returning a connected stream is therefore the whole of the change, and the failure that trades an
SSRF hole for a worse one -- verifying the certificate against the address that was pinned -- is
not something this module has to remember not to do. There is no line here that could do it.

That argument is worth one more step than it looks. The stream this backend returns is
**httpcore's own** ``SyncStream``, not one written here, so ``start_tls`` and the read and write
paths are httpcore's code running unmodified. A hand-written stream would have to pass
``server_hostname`` through by hand, and that line -- correct today, one careless edit from
being an address tomorrow -- is exactly the line this seam exists to not have. The import is
therefore deliberate, and a test asserts the returned stream is that class.

**The whole URL policy runs in ``handle_request``**, not in the backend. A network backend is
handed a host and a port and never learns the scheme, so the scheme, the port, credentials in the
authority and the shape of the host are decided at the transport, once per request -- which is
also what makes a redirect hop a policy question rather than a client one. The backend
independently checks the port and every resolved address, so a pool assembled around it directly
still refuses what the policy refuses.

The alternative shape, which some libraries in this space use, is to rewrite the URL to the
validated address and re-set ``Host:`` and SNI by hand. It costs three things this seam does not:
the address lands in ``request.url``, where it reaches logs, event hooks and retry keys; a
relative ``Location:`` then resolves against the rewritten URL, so ``/admin`` from a redirect now
targets the pinned address; and correct TLS becomes a rule to follow on every code path rather
than a property of one function.

**On importing httpx at module scope.** The promise on the front of this package is that
``import ssrfguard`` loads no third-party module, and it is kept by ``ssrfguard/__init__.py`` not
importing this module. Anyone who has reached ``ssrfguard.httpx`` has httpx installed by
definition.
"""

from __future__ import annotations

import functools
import socket
import ssl
from collections.abc import Iterable
from ipaddress import ip_address
from typing import Any

import anyio
import anyio.abc
import anyio.to_thread
import httpcore
import httpx

# httpcore's own stream, so that the TLS path in this package is httpcore's code rather than a
# copy of it. See the module docstring: the copy would contain a `server_hostname` argument, and
# not containing one is the entire argument for this seam.
from httpcore._backends.anyio import AnyIOStream
from httpcore._backends.sync import SyncStream

# httpx's own answer to "did this hop leave the origin", so that headers are stripped on
# exactly the hops httpx already strips `Authorization` on -- this can then only ever strip
# more than httpx would, never less.
#
# httpx's own reading of the proxy environment, so that `NO_PROXY` means exactly what it
# means to httpx -- including `NO_PROXY=*`, which switches the environment off entirely and
# must therefore not produce a refusal. Re-deriving it here would be a second parser to keep
# in agreement with the first.
from httpx._client import _is_https_redirect, _same_origin
from httpx._utils import get_environment_proxies

from ssrfguard._connect import connect, exhausted
from ssrfguard._policy import Policy, Target, _literal_address
from ssrfguard._resolve import Address, Resolver, resolve
from ssrfguard.errors import (
    BlockedAddressError,
    BlockedURLError,
    ProxyUnsupportedError,
    TooManyRedirectsError,
)

__all__ = [
    "AsyncClient",
    "AsyncSafeBackend",
    "AsyncSafeTransport",
    "Client",
    "SafeBackend",
    "SafeTransport",
]

#: What httpcore adds to every socket it opens, and therefore what this must add too. httpx
#: users get Nagle disabled from the stock backend; a guarded one that quietly re-enabled it
#: would be a performance regression nobody could attribute.
_NODELAY: httpcore.SOCKET_OPTION = (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

#: The scheme recorded on a target built inside the backend. A network backend genuinely does not
#: know the scheme -- httpcore decides whether to start TLS *after* this returns -- and this
#: value is never checked against a policy, because the URL was already checked at the transport.
#: It is spelled honestly rather than guessed at, and it is not a scheme any policy allows, so
#: anything that did check it would refuse rather than wave it through.
_TCP = "tcp"

#: Why a unix socket is refused, in one place because four things say it. There is no flag
#: to permit one: the question a policy answers -- may this process reach this address --
#: has no meaning for a path in the filesystem, and a guard that waved it through would be
#: reporting a decision it never made.
_NO_UNIX_SOCKETS = (
    "is a unix domain socket, which has no address for this policy to check; every "
    "guarantee this package makes is about which address a connection reaches, and a "
    "socket in the filesystem has none"
)


def _origin_target(host: str, port: int) -> Target:
    """Record the origin httpcore is about to reach, in the form resolution wants.

    A hand-built :class:`~ssrfguard.Target` grants no permission: it is a record of a decision
    rather than the decision itself, and resolution re-checks every address it gets back.

    Args:
        host: The host httpcore was about to resolve, already an A-label -- httpx punycodes a
            name when it builds the URL.
        port: The port it was about to connect to.

    Returns:
        The target to resolve.
    """
    return Target(
        scheme=_TCP,
        host=host,
        port=port,
        host_as_written=host,
        address=_literal_address(host),
    )


def _check_port(policy: Policy, port: int) -> None:
    """Check a port against the policy, at the layer that has no URL to check.

    Done in the backends rather than left to the transports, so that a backend used with a pool
    of somebody else's assembling is still bound by the policy.

    Args:
        policy: The policy to check against.
        port: The port about to be connected to.

    Raises:
        BlockedURLError: If the policy does not allow it.
    """
    if port not in policy.allowed_ports:
        allowed = ", ".join(str(p) for p in sorted(policy.allowed_ports))
        raise BlockedURLError(
            f"{_TCP}://{port}", f"port {port} is not in allowed_ports ({allowed})"
        )


def _verify_peer(stream: anyio.abc.SocketStream, address: Address) -> None:
    """Check that the connection reached the address that was validated.

    The synchronous path does this on the socket it opened itself; this does it on the one anyio
    opened. Connecting to an address cannot land elsewhere, so it looks redundant -- it is the
    cheapest possible answer to everything between this process and the wire.

    Args:
        stream: The connected stream.
        address: The address it was supposed to reach.

    Raises:
        BlockedAddressError: If the peer is somewhere else.
    """
    # `extra` here is anyio's stream-attribute lookup; the rule that fires on the name is
    # about Django's queryset method, which this is not.
    remote = stream.extra(anyio.abc.SocketAttribute.remote_address, None)  # noqa: S610
    if remote is None:  # pragma: no cover - a connected TCP stream always has one
        return
    peer = ip_address(str(remote[0]))
    if peer != address.ip:
        raise BlockedAddressError(
            str(peer),
            f"the connection was made to {peer} after {address.ip} was validated, so something "
            f"between this process and the network rewrote the destination",
        )


def _check_redirect_cap(policy: Policy, response: httpx.Response) -> None:
    """Refuse a chain longer than the policy allows, before the next hop is built.

    Counted here rather than left to ``max_redirects``, because the client's own limit is not a
    security control: it exists to stop loops, it defaults to twenty, and it can be changed
    without touching the policy. httpx has already set ``response.history`` by the time this
    runs, so the chain and the count come from its own bookkeeping.

    Args:
        policy: The policy the chain is being walked under.
        response: The response that redirected. Its ``history`` is the chain so far.

    Raises:
        TooManyRedirectsError: If this hop would take the chain past the policy's limit.
    """
    walked = [*response.history, response]
    if len(walked) > policy.max_redirects:
        raise TooManyRedirectsError(policy.max_redirects, tuple(str(hop.url) for hop in walked))


def _stripped_headers(
    policy: Policy, headers: httpx.Headers, request: httpx.Request, url: httpx.URL
) -> httpx.Headers:
    """Drop the policy's sensitive headers when a redirect leaves the origin.

    httpx already drops ``Authorization`` and reads cookies from its own jar rather than from the
    outgoing request. This widens that to whatever the caller told the policy is a credential --
    an ``X-Api-Key`` is a credential by convention rather than by specification, so it is named
    by the caller who uses it rather than guessed at here.

    The decision of *whether* this hop left the origin is httpx's own, so this can only ever
    strip more than httpx would, never less.

    Args:
        policy: The policy walking the chain.
        headers: What httpx would have sent.
        request: The request that was redirected.
        url: Where it is being redirected to.

    Returns:
        The headers for the next hop.
    """
    if _same_origin(url, request.url) or _is_https_redirect(request.url, url):
        return headers
    for name in list(headers):
        if name.lower() in policy.sensitive_headers:
            del headers[name]
    return headers


class SafeBackend(httpcore.NetworkBackend):
    """An httpcore network backend that connects only to addresses it validated.

    This is the seam. It resolves once, checks every answer against the policy, and connects to
    one of the answers it checked -- so a record that moves between the check and the connection
    moves nothing.

    It is public because a caller assembling their own :class:`httpcore.ConnectionPool` needs it,
    and it is **not** the recommended entry point: a backend sees a host and a port, never a URL,
    so the scheme and the credentials in an authority are not decided here. Use
    :class:`SafeTransport`, which decides those before a request reaches this.

    Attributes:
        policy: What this backend is willing to reach.
        resolver: A stand-in for ``socket.getaddrinfo``. Whatever it returns is validated, so
            supplying one grants no permission.
    """

    def __init__(self, *, policy: Policy, resolver: Resolver | None = None) -> None:
        """Build the backend.

        Args:
            policy: What this backend is willing to reach.
            resolver: A stand-in for ``socket.getaddrinfo``, for tests and for callers with
                their own.
        """
        self.policy = policy
        self.resolver = resolver

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        """Resolve, validate, and connect.

        Args:
            host: The origin's host, as httpcore holds it.
            port: The origin's port.
            timeout: Seconds to wait for the connection.
            local_address: Address to bind before connecting.
            socket_options: ``setsockopt`` triples to apply.

        Returns:
            httpcore's own stream, wrapping a socket connected to a validated address.

        Raises:
            BlockedURLError: If the port is not one the policy allows.
            BlockedAddressError: If the name resolves to nothing permitted.
            ConnectTimeout: If the connection timed out, matching what httpcore raises.
            ConnectError: If the name does not resolve, or every validated address refused the
                connection -- again matching httpcore, so httpx maps it as it always has.
        """
        _check_port(self.policy, port)
        target = _origin_target(host, port)
        try:
            addresses = resolve(target, policy=self.policy, resolver=self.resolver)
            sock = connect(
                addresses,
                policy=self.policy,
                # httpcore reads None as "no timeout" where `connect` reads it as "leave the
                # socket at socket.getdefaulttimeout()". The two differ only in a process that
                # set a global default, and there this is the stricter of the two.
                timeout=timeout,
                source_address=None if local_address is None else (local_address, 0),
                socket_options=[*(socket_options or ()), _NODELAY],
            )
        except TimeoutError as timed_out:
            raise httpcore.ConnectTimeout(str(timed_out)) from timed_out
        except OSError as failed:
            raise httpcore.ConnectError(str(failed)) from failed
        return SyncStream(sock)

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        """Refuse. A unix socket has no address for a policy to have an opinion about.

        Args:
            path: The socket path that was asked for.
            timeout: Ignored.
            socket_options: Ignored.

        Returns:
            Never returns.

        Raises:
            BlockedURLError: Always. There is no ``allow_`` flag for this, because the question
                a policy answers -- may this process reach this address -- has no meaning for a
                path in the filesystem, and a guard that waved it through would be reporting a
                decision it never made.
        """
        raise BlockedURLError(path, _NO_UNIX_SOCKETS)


class SafeTransport(httpx.HTTPTransport):
    """An httpx transport that connects only to addresses it validated.

    **A transport is not a client, and that gap is a real one.** Passing this to
    ``httpx.Client(transport=...)`` does neutralise ``HTTP_PROXY`` -- httpx computes
    ``allow_env_proxies = trust_env and transport is None`` -- but an explicit ``proxy=`` or
    ``mounts=`` on the client builds a *separate* transport that ``_transport_for_url`` prefers,
    and a request routed to it never reaches this one. Measured, not deduced. A client that owns
    its own construction is the answer to that, and it is the documented entry point; this class
    is for callers assembling a client themselves, who have to know the above.

    Everything else about it is an ``httpx.HTTPTransport``: the same TLS configuration, the same
    limits, the same response handling. Only where the socket comes from is different.

    Attributes:
        policy: What this transport is willing to reach.
    """

    # This signature is `httpx.HTTPTransport`'s, plus the two arguments that make it safe. The
    # project-wide argument ceiling is about designs of our own; narrowing *this* one would mean
    # a guarded transport that cannot be configured the way the unguarded one can, and the
    # unguarded one is right there.
    def __init__(  # noqa: PLR0913
        self,
        *,
        policy: Policy,
        resolver: Resolver | None = None,
        verify: ssl.SSLContext | str | bool = True,
        cert: str | tuple[str, str] | tuple[str, str, str] | None = None,
        trust_env: bool = True,
        http1: bool = True,
        http2: bool = False,
        limits: httpx.Limits | None = None,
        proxy: httpx.Proxy | httpx.URL | str | None = None,
        uds: str | None = None,
        local_address: str | None = None,
        retries: int = 0,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> None:
        """Build the transport.

        Args:
            policy: What this transport is willing to reach.
            resolver: A stand-in for ``socket.getaddrinfo``, for tests and for callers with
                their own.
            verify: TLS verification, as httpx defines it. Prefer an ``ssl.SSLContext``:
                httpx deprecated the string and boolean-with-``cert`` forms.
            cert: A client certificate.
            trust_env: Whether to read TLS settings from the environment.
            http1: Whether to offer HTTP/1.1.
            http2: Whether to offer HTTP/2. Off by default because that is httpx's default,
                **not** because of a doubt about the pin. The doubt was connection coalescing --
                an HTTP/2 client reusing one connection for a second authority whose name the
                certificate also covers, which would make the pin per-connection while the
                policy is per-request. httpcore does not do it: every connection class it has
                gates reuse on an exact origin match, which is asserted in
                ``tests/test_adapter_http2.py`` along with ALPN surviving the pinned stream.
            limits: Pool limits, or ``None`` for httpx's defaults.
            proxy: A proxy. Refused unless the policy permits one, because a proxy resolves the
                target itself and opens the socket to it, so nothing this transport does can
                reach it.
            uds: A unix domain socket. Always refused.
            local_address: Address to bind before connecting.
            retries: Connection retries, as httpcore counts them. A refusal by this package is
                not retried: it is not a ``ConnectError``, which is what httpcore counts.
            socket_options: ``setsockopt`` triples applied to every connection.

        Raises:
            ProxyUnsupportedError: If a proxy is configured and ``policy.allow_proxy`` is off.
            BlockedURLError: If ``uds`` is set.
        """
        if uds is not None:
            raise BlockedURLError(uds, _NO_UNIX_SOCKETS)
        if proxy is not None and not policy.allow_proxy:
            raise ProxyUnsupportedError(str(proxy))

        self.policy = policy
        limits = httpx.Limits() if limits is None else limits
        # Built once and handed to both, rather than letting each build its own: `verify=<str>`
        # and `cert=` are deprecated in httpx and warn when they are resolved, so resolving
        # twice would warn twice about one call. Prefer `verify=<ssl.SSLContext>`.
        ssl_context = httpx.create_ssl_context(verify=verify, cert=cert, trust_env=trust_env)
        super().__init__(
            verify=ssl_context,
            trust_env=trust_env,
            http1=http1,
            http2=http2,
            limits=limits,
            proxy=proxy,
            local_address=local_address,
            retries=retries,
            socket_options=socket_options,
        )
        if proxy is not None:
            # `allow_proxy` accepted that enforcement has moved to the proxy, so httpx's own
            # proxy pool is left in place. Replacing it with a pinning pool would pin the
            # *proxy's* address and leave the target unchecked, which is a guard reporting a
            # decision it did not make.
            return
        # **Replaced rather than reached into.** `httpcore.ConnectionPool` takes the backend as
        # a constructor argument, so this uses public API and fails loudly if that argument ever
        # goes away -- where swapping the pool's private backend attribute would fail silently,
        # by pinning nothing and saying nothing.
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=http1,
            http2=http2,
            local_address=local_address,
            retries=retries,
            socket_options=socket_options,
            network_backend=SafeBackend(policy=policy, resolver=resolver),
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Check the whole URL, then send the request.

        This is where the scheme, the port, credentials in the authority and the shape of the
        host are decided, because it is the last place a URL exists -- the backend below is
        handed a host and a port and never learns which scheme they belong to. It runs once per
        request rather than once per connection, so a redirect hop is checked even when it
        travels over a connection that is already open.

        Args:
            request: The request httpx built.

        Returns:
            The response.

        Raises:
            BlockedURLError: If the URL is not permitted.
            BlockedAddressError: If the host was a literal address the policy denies.
        """
        self.policy.check_url(str(request.url))
        return super().handle_request(request)


#: What ``httpx.Client`` accepts that only configures the transport it would otherwise have
#: built. **Handing these to a client that was given a transport does nothing at all**, silently,
#: which for ``verify`` is a security-relevant no-op -- so :class:`Client` routes them to the
#: transport it builds rather than passing them on to httpx.
_TRANSPORT_OPTIONS = frozenset(
    {"verify", "cert", "http1", "http2", "limits", "local_address", "retries", "socket_options"}
)

#: Meaningful to both, so both get it.
_SHARED_OPTIONS = frozenset({"trust_env"})

#: The two arguments that decide where a request is *routed*, which is the whole subject of this
#: class. Refused unless the policy accepts that enforcement has moved.
_ROUTING_OPTIONS = frozenset({"proxy", "mounts"})

#: Everything else ``httpx.Client`` takes, forwarded unchanged.
_CLIENT_OPTIONS = frozenset(
    {
        "auth",
        "base_url",
        "cookies",
        "default_encoding",
        "event_hooks",
        "follow_redirects",
        "headers",
        "max_redirects",
        "params",
        "timeout",
    }
)


def _environment_proxy(*, trust_env: bool) -> str | None:
    """Find a proxy the environment would apply, if there is one.

    Asked with httpx's own parser rather than by reading ``HTTP_PROXY`` here, so ``NO_PROXY``
    means exactly what it means to httpx -- including ``NO_PROXY=*``, which switches the
    environment off entirely and must not produce a refusal.

    Args:
        trust_env: Whether the environment is being consulted at all.

    Returns:
        The first proxy that would apply, or ``None``.
    """
    if not trust_env:
        return None
    for proxy in get_environment_proxies().values():
        if proxy is not None:
            return str(proxy)
    return None


def _configured_proxy(client_options: dict[str, Any], *, trust_env: bool) -> str | None:
    """Find the proxy that would carry this client's requests, if any.

    Args:
        client_options: The options destined for ``httpx.Client``.
        trust_env: Whether the environment is being consulted.

    Returns:
        A proxy, or ``None``.
    """
    explicit = client_options.get("proxy") or client_options.get("mounts")
    if explicit:
        return str(explicit)
    return _environment_proxy(trust_env=trust_env)


def _policy_from(
    policy: Policy | None,
    resolver: Resolver | None,
    transport: SafeTransport | AsyncSafeTransport | None,
    expected: type,
) -> Policy:
    """Work out which policy is in force, refusing every ambiguous combination.

    Args:
        policy: The policy argument, if given.
        resolver: The resolver argument, if given.
        transport: The transport argument, if given.
        expected: The transport class this client accepts. A synchronous client handed an
            asynchronous transport is refused here rather than at the first request.

    Returns:
        The policy to enforce.

    Raises:
        TypeError: If the arguments do not name exactly one policy.
    """
    if transport is None:
        if policy is None:
            raise TypeError("Client needs a policy, or a transport that already has one")
        return policy
    if not isinstance(transport, expected):
        raise TypeError(
            f"transport is a {type(transport).__name__}, which does not pin anything; "
            f"this class exists to make that impossible to pass in by accident"
        )
    if policy is not None or resolver is not None:
        raise TypeError(
            "transport already carries a policy and a resolver, so passing either "
            "alongside it would leave two answers to one question"
        )
    return transport.policy


def _split_options(options: dict[str, object]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Route each option to the thing it actually configures.

    Args:
        options: Everything the caller passed.

    Returns:
        A pair of (transport options, client options).

    Raises:
        TypeError: If an option belongs to neither.
    """
    unknown = set(options) - _TRANSPORT_OPTIONS - _SHARED_OPTIONS - _ROUTING_OPTIONS
    unknown -= _CLIENT_OPTIONS
    if unknown:
        named = ", ".join(sorted(unknown))
        raise TypeError(
            f"Client does not know what to do with {named}; if httpx has grown an argument "
            f"since this was written, it needs a decision here rather than to be passed "
            f"through, because the ones that route a request are the whole subject"
        )
    transport_options: dict[str, Any] = {
        name: value
        for name, value in options.items()
        if name in _TRANSPORT_OPTIONS or name in _SHARED_OPTIONS
    }
    client_options: dict[str, Any] = {
        name: value for name, value in options.items() if name not in _TRANSPORT_OPTIONS
    }
    return transport_options, client_options


class Client(httpx.Client):
    """An httpx client that connects only to addresses it validated.

    This is the entry point, and it is a client rather than a transport for one measured reason.
    ``httpx.Client(transport=SafeTransport(...))`` does neutralise ``HTTP_PROXY`` -- httpx
    computes ``allow_env_proxies = trust_env and transport is None`` -- but an explicit
    ``proxy=`` or ``mounts=`` builds a *separate* transport that ``_transport_for_url`` prefers,
    and the request never reaches the guarded one. A class that owns its own construction is the
    only place that can be refused::

        >>> from ssrfguard import Policy
        >>> from ssrfguard.httpx import Client
        >>> with Client(policy=Policy()) as client:      # doctest: +SKIP
        ...     client.get(untrusted_url)

    It also closes a quieter trap. ``verify``, ``cert``, ``http1``, ``http2`` and ``limits``
    configure the transport httpx *would have built*, so passing them to a client that was given
    a transport does nothing -- silently, and for ``verify`` that means a caller believing they
    configured certificate verification when they did not. They are routed to the transport here.

    Attributes:
        policy: What this client is willing to reach.
    """

    def __init__(
        self,
        *,
        policy: Policy | None = None,
        resolver: Resolver | None = None,
        transport: SafeTransport | None = None,
        **options: object,
    ) -> None:
        """Build the client.

        Args:
            policy: What this client is willing to reach. Required unless ``transport`` is given,
                in which case the transport's policy is used.
            resolver: A stand-in for ``socket.getaddrinfo``, for tests and for callers with
                their own.
            transport: An already-built :class:`SafeTransport`, for a caller who configured one.
            **options: Everything ``httpx.Client`` accepts, plus the transport's own
                ``local_address``, ``retries`` and ``socket_options``. Each is routed to
                whichever of the two it actually configures.

        Raises:
            TypeError: If the arguments cannot be reconciled -- neither a policy nor a transport,
                both, a transport that is not a guarded one, or an option neither httpx nor this
                package knows. An unknown option is refused rather than dropped, because httpx
                growing a new way to route a request is a decision for this class rather than
                something to inherit.
            ProxyUnsupportedError: If a proxy applies and the policy does not permit one.
        """
        policy = _policy_from(policy, resolver, transport, SafeTransport)
        self.policy = policy
        transport_options, client_options = _split_options(options)

        trust_env = bool(client_options.get("trust_env", True))
        configured = _configured_proxy(client_options, trust_env=trust_env)
        if configured is not None and not policy.allow_proxy:
            raise ProxyUnsupportedError(configured)

        if transport is None:
            transport = SafeTransport(policy=policy, resolver=resolver, **transport_options)
        super().__init__(transport=transport, **client_options)

    def _build_redirect_request(
        self, request: httpx.Request, response: httpx.Response
    ) -> httpx.Request:
        """Count the hop before building it, and refuse a chain longer than the policy allows.

        Counted here rather than left to ``max_redirects``, because the client's own limit is
        not a security control: it exists to stop loops, it defaults to twenty, and it can be
        changed without touching the policy. This runs before the over-limit request is built,
        so the hop that exceeds the cap is never sent.

        Args:
            request: The request that was redirected.
            response: The response that redirected it. Its ``history`` is the chain so far.

        Returns:
            The request for the next hop.

        Raises:
            TooManyRedirectsError: If this hop would take the chain past the policy's limit.
        """
        _check_redirect_cap(self.policy, response)
        return super()._build_redirect_request(request, response)

    def _redirect_headers(
        self, request: httpx.Request, url: httpx.URL, method: str
    ) -> httpx.Headers:
        """Drop the policy's sensitive headers when a redirect leaves the origin.

        httpx already drops ``Authorization`` and reads cookies from its own jar rather than
        from the outgoing request. This widens that to whatever the caller told the policy is a
        credential -- an ``X-Api-Key`` is a credential by convention rather than by
        specification, so it is named by the caller who uses it rather than guessed at here.

        Args:
            request: The request that was redirected.
            url: Where it is being redirected to.
            method: The method the next hop will use.

        Returns:
            The headers for the next hop.
        """
        headers = super()._redirect_headers(request, url, method)
        return _stripped_headers(self.policy, headers, request, url)


class AsyncSafeBackend(httpcore.AsyncNetworkBackend):
    """The same seam for the async client, with the blocking half kept off the event loop.

    ``socket.getaddrinfo`` blocks and has no timeout -- ``socket.setdefaulttimeout`` does not
    apply to it -- so a hostile authoritative server can stall a lookup for as long as it likes.
    On the synchronous path that is the caller's to supervise. Here it is not: a backend that
    resolved inline would stall **the whole event loop**, so one hostile hostname would freeze
    every unrelated request in the process. That turns a security library into an outage, which
    is the fastest route to it being removed, and a removed control protects nothing.

    So resolution runs in a worker thread through ``anyio.to_thread.run_sync``. anyio rather
    than ``loop.getaddrinfo`` because httpx supports trio as well as asyncio, and
    ``loop.getaddrinfo`` exists on only one of them -- and because anyio is already a hard
    dependency of httpx, so it costs nothing.

    **The connection is anyio's, and it is handed an address rather than a name.** Measured:
    ``anyio.connect_tcp`` given something ``ipaddress`` can parse skips name resolution
    altogether -- it takes the family and the compressed form and connects. The stream that
    comes back is wrapped in httpcore's own ``AnyIOStream``, so ``start_tls`` is again httpcore's
    code and this module has no ``server_hostname`` to get wrong.

    One thing is *not* the same as the synchronous path and is worth knowing. There is the whole
    ``sockaddr`` was passed to the socket untouched; here the address is handed to anyio, which
    rebuilds it. A scope identifier survives -- it is part of an ``IPv6Address`` and of its
    compressed form -- and a flow label does not. There is no public way to hand an
    already-connected socket to an anyio stream, so the alternative was writing the stream, and
    with it the ``server_hostname`` line that this seam exists not to have.

    Attributes:
        policy: What this backend is willing to reach.
        resolver: A stand-in for ``socket.getaddrinfo``. Whatever it returns is validated.
    """

    def __init__(self, *, policy: Policy, resolver: Resolver | None = None) -> None:
        """Build the backend.

        Args:
            policy: What this backend is willing to reach.
            resolver: A stand-in for ``socket.getaddrinfo``, for tests and for callers with
                their own.
        """
        self.policy = policy
        self.resolver = resolver

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109  # httpcore's signature, matched
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Resolve off the loop, validate, and connect to an address.

        Args:
            host: The origin's host, as httpcore holds it.
            port: The origin's port.
            timeout: Seconds to wait for the connection.
            local_address: Address to bind before connecting.
            socket_options: ``setsockopt`` triples to apply once connected.

        Returns:
            httpcore's own stream, wrapping a connection to a validated address.

        Raises:
            BlockedURLError: If the port is not one the policy allows.
            BlockedAddressError: If the name resolves to nothing permitted, or if the connection
                did not land on the address that was validated.
            ConnectTimeout: If the connection timed out, matching what httpcore raises.
            ConnectError: If the name does not resolve, or every validated address refused the
                connection.
        """
        _check_port(self.policy, port)
        target = _origin_target(host, port)
        lookup = functools.partial(resolve, target, policy=self.policy, resolver=self.resolver)
        try:
            addresses = await anyio.to_thread.run_sync(lookup)
        except socket.gaierror as unresolvable:
            raise httpcore.ConnectError(str(unresolvable)) from unresolvable

        # Re-checked before a socket exists, for the same reason the synchronous path does it:
        # there is no route through this package to a connection that skipped the check.
        for address in addresses:
            self.policy.check_address(address.ip)
        return await self._first_reachable(addresses, timeout, local_address, socket_options)

    async def _first_reachable(
        self,
        addresses: tuple[Address, ...],
        timeout: float | None,  # noqa: ASYNC109  # httpcore's signature, matched
        local_address: str | None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None,
    ) -> httpcore.AsyncNetworkStream:
        """Connect to the first validated address that answers.

        Failing over matters as much here as on the synchronous path: the first answer for a
        dual-stack host is routinely unreachable, and a guard that gives up there becomes a
        support burden and then gets removed. It is only safe because a partially-denied name
        never reaches this. **A timed-out attempt is failed over from too**, which the first
        version of this did not do -- it raised on the first timeout while the synchronous path
        moved on, so the two clients disagreed about a host that answers with one dead address
        and one live one.

        The attempt count is capped by ``policy.max_connection_attempts`` for the reason
        :func:`ssrfguard.connect` is: the timeout is per attempt and the number of answers
        belongs to whoever runs the name's authoritative server.

        Args:
            addresses: The validated answers, in the resolver's own order.
            timeout: Seconds to wait per attempt.
            local_address: Address to bind before connecting.
            socket_options: ``setsockopt`` triples to apply once connected.

        Returns:
            The connected stream.

        Raises:
            ConnectTimeout: If every attempt timed out.
            ConnectError: If any attempt was refused and none succeeded.
        """
        attempted = addresses[: self.policy.max_connection_attempts]
        failures: list[str] = []
        last: OSError | None = None
        # See the same variable in `ssrfguard._connect.connect`, whose reasoning this mirrors.
        only_timeouts = True
        for address in attempted:
            try:
                with anyio.fail_after(timeout):
                    stream = await anyio.connect_tcp(
                        remote_host=address.ip, remote_port=address.port, local_host=local_address
                    )
            # Before `except OSError`, which it is a subclass of. Appended and continued rather
            # than raised, because a timed-out first answer is the ordinary dual-stack case and
            # giving up on it here would fail requests the synchronous client completes.
            except TimeoutError as timed_out:
                failures.append(f"{address} (timed out)")
                last = timed_out
                continue
            except OSError as failed:
                failures.append(f"{address} ({failed})")
                last = failed
                only_timeouts = False
                continue
            try:
                for option in socket_options or ():
                    raw = stream.extra(anyio.abc.SocketAttribute.raw_socket)  # noqa: S610
                    raw.setsockopt(*option)
                _verify_peer(stream, address)
            except BaseException:
                await stream.aclose()
                raise
            return AnyIOStream(stream)

        message = exhausted(
            failures, len(addresses) - len(attempted), self.policy.max_connection_attempts
        )
        # **`from last`, which this did not do.** The synchronous path chains the underlying
        # `OSError`; this raised outside any `except`, so `__cause__` and `__context__` were both
        # None and an operator reading the traceback got "could not connect to any validated
        # address" with nothing under it. Two clients, one promise, and the diagnosis differed.
        raise (
            httpcore.ConnectTimeout(message) if only_timeouts else httpcore.ConnectError(message)
        ) from last

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109  # httpcore's signature, matched
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Refuse, for the reason the synchronous backend refuses.

        Args:
            path: The socket path that was asked for.
            timeout: Ignored.
            socket_options: Ignored.

        Returns:
            Never returns.

        Raises:
            BlockedURLError: Always.
        """
        raise BlockedURLError(path, _NO_UNIX_SOCKETS)

    async def sleep(self, seconds: float) -> None:
        """Wait, without blocking anything else.

        Args:
            seconds: How long httpcore wants to back off for.
        """
        await anyio.sleep(seconds)


class AsyncSafeTransport(httpx.AsyncHTTPTransport):
    """An async httpx transport that connects only to addresses it validated.

    The asynchronous twin of :class:`SafeTransport`, and it carries the same warning: a transport
    is not a client. ``httpx.AsyncClient(transport=...)`` ignores ``HTTP_PROXY``, and an explicit
    ``proxy=`` still builds a separate transport that httpx prefers. :class:`AsyncClient` is the
    entry point.

    Attributes:
        policy: What this transport is willing to reach.
    """

    def __init__(  # noqa: PLR0913
        self,
        *,
        policy: Policy,
        resolver: Resolver | None = None,
        verify: ssl.SSLContext | str | bool = True,
        cert: str | tuple[str, str] | tuple[str, str, str] | None = None,
        trust_env: bool = True,
        http1: bool = True,
        http2: bool = False,
        limits: httpx.Limits | None = None,
        proxy: httpx.Proxy | httpx.URL | str | None = None,
        uds: str | None = None,
        local_address: str | None = None,
        retries: int = 0,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> None:
        """Build the transport.

        Args:
            policy: What this transport is willing to reach.
            resolver: A stand-in for ``socket.getaddrinfo``.
            verify: TLS verification, as httpx defines it. Prefer an ``ssl.SSLContext``.
            cert: A client certificate.
            trust_env: Whether to read TLS settings from the environment.
            http1: Whether to offer HTTP/1.1.
            http2: Whether to offer HTTP/2. Off by default, for the reason on
                :class:`SafeTransport`, which is httpx's default rather than a doubt.
            limits: Pool limits, or ``None`` for httpx's defaults.
            proxy: A proxy. Refused unless the policy permits one.
            uds: A unix domain socket. Always refused.
            local_address: Address to bind before connecting.
            retries: Connection retries, as httpcore counts them.
            socket_options: ``setsockopt`` triples applied to every connection.

        Raises:
            ProxyUnsupportedError: If a proxy is configured and ``policy.allow_proxy`` is off.
            BlockedURLError: If ``uds`` is set.
        """
        if uds is not None:
            raise BlockedURLError(uds, _NO_UNIX_SOCKETS)
        if proxy is not None and not policy.allow_proxy:
            raise ProxyUnsupportedError(str(proxy))

        self.policy = policy
        limits = httpx.Limits() if limits is None else limits
        ssl_context = httpx.create_ssl_context(verify=verify, cert=cert, trust_env=trust_env)
        super().__init__(
            verify=ssl_context,
            trust_env=trust_env,
            http1=http1,
            http2=http2,
            limits=limits,
            proxy=proxy,
            local_address=local_address,
            retries=retries,
            socket_options=socket_options,
        )
        if proxy is not None:
            return
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=http1,
            http2=http2,
            local_address=local_address,
            retries=retries,
            socket_options=socket_options,
            network_backend=AsyncSafeBackend(policy=policy, resolver=resolver),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Check the whole URL, then send the request.

        Args:
            request: The request httpx built.

        Returns:
            The response.

        Raises:
            BlockedURLError: If the URL is not permitted.
            BlockedAddressError: If the host was a literal address the policy denies.
        """
        self.policy.check_url(str(request.url))
        return await super().handle_async_request(request)


class AsyncClient(httpx.AsyncClient):
    """An async httpx client that connects only to addresses it validated.

    The asynchronous twin of :class:`Client`, refusing the same things for the same reasons::

        >>> from ssrfguard import Policy
        >>> from ssrfguard.httpx import AsyncClient
        >>> async with AsyncClient(policy=Policy()) as client:      # doctest: +SKIP
        ...     await client.get(untrusted_url)

    Attributes:
        policy: What this client is willing to reach.
    """

    def __init__(
        self,
        *,
        policy: Policy | None = None,
        resolver: Resolver | None = None,
        transport: AsyncSafeTransport | None = None,
        **options: object,
    ) -> None:
        """Build the client.

        Args:
            policy: What this client is willing to reach. Required unless ``transport`` is given.
            resolver: A stand-in for ``socket.getaddrinfo``.
            transport: An already-built :class:`AsyncSafeTransport`.
            **options: Everything ``httpx.AsyncClient`` accepts, plus the transport's own
                ``local_address``, ``retries`` and ``socket_options``.

        Raises:
            TypeError: If the arguments cannot be reconciled, or an option is one neither httpx
                nor this package knows.
            ProxyUnsupportedError: If a proxy applies and the policy does not permit one.
        """
        policy = _policy_from(policy, resolver, transport, AsyncSafeTransport)
        self.policy = policy
        transport_options, client_options = _split_options(options)

        trust_env = bool(client_options.get("trust_env", True))
        configured = _configured_proxy(client_options, trust_env=trust_env)
        if configured is not None and not policy.allow_proxy:
            raise ProxyUnsupportedError(configured)

        if transport is None:
            transport = AsyncSafeTransport(policy=policy, resolver=resolver, **transport_options)
        super().__init__(transport=transport, **client_options)

    def _build_redirect_request(
        self, request: httpx.Request, response: httpx.Response
    ) -> httpx.Request:
        """Count the hop before building it, as the synchronous client does.

        Args:
            request: The request that was redirected.
            response: The response that redirected it.

        Returns:
            The request for the next hop.

        Raises:
            TooManyRedirectsError: If this hop would take the chain past the policy's limit.
        """
        _check_redirect_cap(self.policy, response)
        return super()._build_redirect_request(request, response)

    def _redirect_headers(
        self, request: httpx.Request, url: httpx.URL, method: str
    ) -> httpx.Headers:
        """Drop the policy's sensitive headers when a redirect leaves the origin.

        Args:
            request: The request that was redirected.
            url: Where it is being redirected to.
            method: The method the next hop will use.

        Returns:
            The headers for the next hop.
        """
        headers = super()._redirect_headers(request, url, method)
        return _stripped_headers(self.policy, headers, request, url)
