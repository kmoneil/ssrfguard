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

import socket
import ssl
from collections.abc import Iterable

import httpcore
import httpx

# httpcore's own stream, so that the TLS path in this package is httpcore's code rather than a
# copy of it. See the module docstring: the copy would contain a `server_hostname` argument, and
# not containing one is the entire argument for this seam.
from httpcore._backends.sync import SyncStream

from ssrfguard._connect import connect
from ssrfguard._policy import Policy, Target, _literal_address
from ssrfguard._resolve import Resolver, resolve
from ssrfguard.errors import BlockedURLError, ProxyUnsupportedError

__all__ = ["SafeBackend", "SafeTransport"]

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
        self._check_port(port)
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
        raise BlockedURLError(
            path,
            "is a unix domain socket, which has no address for this policy to check; every "
            "guarantee this package makes is about which address a connection reaches, and a "
            "socket in the filesystem has none",
        )

    def _check_port(self, port: int) -> None:
        """Check the port against the policy.

        Duplicated here rather than left to :meth:`SafeTransport.handle_request`, so that a
        backend used with a pool of somebody else's assembling is still bound by it.

        Args:
            port: The port about to be connected to.

        Raises:
            BlockedURLError: If the policy does not allow it.
        """
        if port not in self.policy.allowed_ports:
            allowed = ", ".join(str(p) for p in sorted(self.policy.allowed_ports))
            raise BlockedURLError(
                f"{_TCP}://{port}", f"port {port} is not in allowed_ports ({allowed})"
            )


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
            http2: Whether to offer HTTP/2. Off by default, and deliberately: nothing has yet
                measured whether httpcore coalesces two authorities onto one HTTP/2 connection,
                and if it does then the pin is per-connection while the policy is per-request.
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
            raise BlockedURLError(
                uds,
                "is a unix domain socket, which has no address for this policy to check; every "
                "guarantee this package makes is about which address a connection reaches, and "
                "a socket in the filesystem has none",
            )
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
