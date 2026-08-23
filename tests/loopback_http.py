"""A recording HTTP server on loopback, with TLS when it is handed a context.

The adapter suites need to see what actually left the client, not what the client says it sent.
Three of the assertions this package must never fail are only observable at the other end of the
socket: the ``Host:`` header, the name in the TLS ``server_name`` extension, and whether the
request arrived at all. So this records them from the server side and the tests read them there.

**The SNI is recorded on the wire rather than by patching the client.** A server-side
``sni_callback`` sees exactly what the client sent, and a client that sends an address instead of
a name sends nothing at all, because Python will not put an IP literal in ``server_name``:
RFC 6066 does not allow one. `sni` coming back ``None`` is therefore the signature of a pinned
address having reached TLS, which is the failure the adapter exists to make impossible.

Deliberately not an HTTP server implementation: it answers from a route table and a default, and
must not grow past what an assertion needs.
"""

from __future__ import annotations

import http.server
import ssl
import sys
import threading
from dataclasses import dataclass, field
from types import TracebackType

#: What a route answers with: status, headers, body.
Route = tuple[int, dict[str, str], bytes]

#: What every other path answers with.
DEFAULT_ROUTE: Route = (200, {}, b"ok")


@dataclass(frozen=True)
class Received:
    """One request, as the server saw it.

    Attributes:
        method: The HTTP method.
        path: The request target.
        host: The ``Host`` header, which is the hostname unless something replaced it with the
            address that was connected to.
        sni: The name the client put in the TLS ``server_name`` extension, or ``None`` for a
            plaintext connection *and* for a TLS one whose client offered an address.
        headers: Every header, keyed in lower case. Present so that a test can ask what a
            redirect carried to the host it was redirected to, which is the half of a redirect
            that no client handles the same way as another.
    """

    method: str
    path: str
    host: str
    sni: str | None
    headers: dict[str, str]


@dataclass
class _State:
    """What the handler reads and writes, shared with the test through the server object."""

    received: list[Received] = field(default_factory=list)
    routes: dict[str, Route] = field(default_factory=dict)
    sni_by_peer: dict[tuple[str, int], str | None] = field(default_factory=dict)
    errors: list[BaseException] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


class _Handler(http.server.BaseHTTPRequestHandler):
    """Answers from the route table and records what it was asked."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # the name http.server dispatches to
        """Record the request and answer it."""
        state: _State = self.server.state
        peer = self.connection.getpeername()
        with state.lock:
            state.received.append(
                Received(
                    method=self.command,
                    path=self.path,
                    host=self.headers.get("Host", ""),
                    sni=state.sni_by_peer.get((str(peer[0]), int(peer[1]))),
                    headers={name.lower(): value for name, value in self.headers.items()},
                )
            )
            status, headers, body = state.routes.get(self.path, DEFAULT_ROUTE)
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Say nothing. The tests read `received`, and stderr is for failures."""


class _Server(http.server.ThreadingHTTPServer):
    """A threading server that records its own errors instead of printing them."""

    daemon_threads = True
    state: _State

    def handle_error(self, request: object, client_address: object) -> None:
        """Record a failed exchange rather than writing a traceback to stderr.

        Half of the TLS assertions here are about a handshake *failing*, and the default
        behaviour prints a page of traceback for each one, which trains a reader to ignore
        tracebacks in this suite's output.

        Args:
            request: The socket the exchange was on.
            client_address: Where it came from.
        """
        _, exception, _ = sys.exc_info()
        if exception is not None:
            with self.state.lock:
                self.state.errors.append(exception)


class RecordingServer:
    """An HTTP server on loopback that records what reached it.

    Attributes:
        host: The loopback address it is bound to.
        routes: Path to (status, headers, body). Any path not named answers ``200 ok``.
    """

    def __init__(self, *, ssl_context: ssl.SSLContext | None = None, host: str = "127.0.0.1"):
        """Bind and start serving.

        Args:
            ssl_context: A server-side context to wrap the listening socket in, or ``None`` for
                plaintext.
            host: The loopback address to bind.
        """
        self.host = host
        self._state = _State()
        self._server = _Server((host, 0), _Handler)
        self._server.state = self._state
        if ssl_context is not None:
            ssl_context.sni_callback = self._record_sni
            self._server.socket = ssl_context.wrap_socket(self._server.socket, server_side=True)
        # The poll interval is `shutdown`'s latency, not the server's: `serve_forever` checks
        # for a stop request between selects, and the default 0.5s is paid by every test that
        # closes a server. Twenty-six of them is thirteen seconds of waiting for nothing.
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self._thread.start()

    def _record_sni(self, sock: ssl.SSLSocket, name: str | None, context: ssl.SSLContext) -> None:
        """Note what the client asked for, keyed by where it asked from.

        Args:
            sock: The socket mid-handshake.
            name: The ``server_name`` the client offered, or ``None`` if it offered none.
            context: The context in use, which this does not change.
        """
        peer = sock.getpeername()
        with self._state.lock:
            self._state.sni_by_peer[(str(peer[0]), int(peer[1]))] = name

    @property
    def port(self) -> int:
        """The port the kernel chose."""
        return int(self._server.server_address[1])

    @property
    def received(self) -> list[Received]:
        """Every request that reached this server, in order."""
        with self._state.lock:
            return list(self._state.received)

    @property
    def routes(self) -> dict[str, Route]:
        """The route table, to write into before making a request."""
        return self._state.routes

    def close(self) -> None:
        """Stop serving and release the socket."""
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> RecordingServer:
        """Return the running server."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Stop serving."""
        self.close()
