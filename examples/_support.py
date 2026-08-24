"""The scaffolding the examples share: a loopback HTTP server and a scripted resolver.

Every example in this directory runs with no arguments, no network and no fixtures, which means
each one needs somewhere to send a request and something to answer a name lookup. Those two
pieces live here rather than in nine copies, so that each example is about its own subject and
not about how to start a web server.

**Nothing here is part of the package.** `ssrfguard` ships no test server and no resolver; these
are forty lines of standard library so the examples can be run rather than read. The resolver in
particular is a stand-in for `socket.getaddrinfo`, which the package accepts everywhere for
exactly this reason: whatever a resolver returns is validated before it is used, so handing one
in grants no permission.
"""

from __future__ import annotations

import http.server
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass
class Server:
    """A running loopback HTTP server, and what it saw.

    Attributes:
        port: The port it bound, chosen by the kernel so examples never collide.
        requests: The paths it was asked for, in order.
        headers: The headers of each request, in the same order.
    """

    port: int
    requests: list[str] = field(default_factory=list)
    headers: list[dict[str, str]] = field(default_factory=list)

    @property
    def origin(self) -> str:
        """The origin to fetch, as a URL prefix.

        Returns:
            ``http://127.0.0.1:<port>``.
        """
        return f"http://127.0.0.1:{self.port}"


@contextmanager
def loopback_server(redirects: dict[str, str] | None = None) -> Iterator[Server]:
    """Serve `200 ok` on loopback, with an optional redirect table.

    Args:
        redirects: Path to `Location`, for the examples about redirect chains. A path not in it
            answers `200`.

    Yields:
        The running server, which stops when the block exits.
    """
    table = redirects or {}
    state = Server(port=0)

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            state.requests.append(self.path)
            state.headers.append({k.lower(): v for k, v in self.headers.items()})
            location = table.get(self.path)
            if location is not None:
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            """Stay quiet, so an example's output is the example's output."""

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


class ScriptedResolver:
    """A `getaddrinfo` stand-in that answers from a script and counts what it was asked.

    The count is the interesting part. "Resolve once and connect to that address" is a claim
    about *how many times a name is looked up*, so an example that asserts it needs a resolver
    that can be asked.

    Attributes:
        answers: The addresses to serve, one per call. The last is repeated once the script
            runs out, so an example need only list the answers it cares about.
        calls: How many lookups have been made, in total.
        asked: The names looked up, in order.
    """

    def __init__(self, *answers: str) -> None:
        """Build the resolver.

        Args:
            *answers: One address per call, in order. `ScriptedResolver("127.0.0.1",
                "169.254.169.254")` is a nameserver that tells the truth once and then moves the
                record, which is what a rebinding attack is.
        """
        self.answers = list(answers)
        self.calls = 0
        self.asked: list[str] = []

    def __call__(self, host: str, port: int, *_rest: object) -> list[tuple]:
        """Answer one lookup.

        Args:
            host: The name being looked up.
            port: The port, carried into the sockaddr the way `getaddrinfo` carries it.
            *_rest: The remainder of `getaddrinfo`'s signature, unused.

        Returns:
            One answer row, in `getaddrinfo` shape.
        """
        address = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        self.asked.append(host)
        if ":" in address:
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, port, 0, 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]


def heading(text: str) -> None:
    """Print a section heading, so a run of an example reads as sections rather than as lines.

    Args:
        text: The heading.
    """
    print(f"\n{text}\n{'-' * len(text)}")
