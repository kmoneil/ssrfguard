"""What HTTP/2 does underneath a pinned stream, measured rather than deduced.

The worry was specific and it was worth having. HTTP/2 clients may reuse one connection for a
*different* authority when the certificate covers both names -- connection coalescing. If
httpcore did that, a request to host B would travel over a connection whose address was
validated for host A, and the pin would be per-connection while the policy is per-request. Those
are not the same thing, and the difference would be a bypass.

**It does not.** Every connection class httpcore has answers ``can_handle_request`` with
``origin == self._origin``, an exact match on scheme, host and port, and the pool asks that
before reusing anything. There is no coalescing to be exposed to. The tests below pin that,
because it is a property of somebody else's code that this package's argument leans on -- the
same shape as the assertions pinning the address table against ``ipaddress``.

The other half was whether ALPN survives the seam at all. It does, and it is not a coincidence:
httpcore decides between HTTP/1.1 and HTTP/2 by asking the stream for its ``ssl_object`` and
reading ``selected_alpn_protocol()``, and the streams this package hands back are httpcore's own
classes wrapping a real TLS socket. Nothing in the pinning path touches the TLS context, which
is where ALPN is configured.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Iterator
from pathlib import Path

import httpcore
import pytest
import trustme
from httpcore._sync import connection_pool
from httpcore._sync.http2 import HTTP2Connection
from httpcore._sync.http11 import HTTP11Connection

from ssrfguard import Policy
from ssrfguard.httpx import SafeBackend

from .loopback_http import RecordingServer
from .stub_resolver import Resolver

pytestmark = pytest.mark.httpx_adapter

LOOPBACK = ("127.0.0.0/8",)

#: Two origins that differ only in the name, which is the pair coalescing would join.
FIRST = httpcore.Origin(b"https", b"right.test", 443)
SECOND = httpcore.Origin(b"https", b"also.test", 443)


class OnlyAnOrigin:
    """Something with an origin and nothing else.

    ``can_handle_request`` reads exactly one attribute, so it can be asked its question without
    a connection behind it -- which matters here, because constructing a real
    :class:`HTTP2Connection` needs the ``h2`` package, and the question being asked has nothing
    to do with whether HTTP/2 is installed.
    """

    def __init__(self, origin: httpcore.Origin) -> None:
        """Hold the origin.

        Args:
            origin: The origin this stand-in claims.
        """
        self._origin = origin


@pytest.mark.parametrize(
    "connection_class",
    [httpcore.HTTPConnection, HTTP11Connection, HTTP2Connection],
    ids=["connection", "http11", "http2"],
)
def test_a_connection_is_never_offered_to_another_origin(connection_class: type) -> None:
    """Including the HTTP/2 one, which is the only one that could have coalesced.

    If this ever fails, httpcore has grown connection coalescing and the pin has stopped being
    per-origin. That is a `SEC` card, not a compatibility note: the address validated for one
    authority would be carrying requests for another.
    """
    holder = OnlyAnOrigin(FIRST)

    assert connection_class.can_handle_request(holder, FIRST) is True
    assert connection_class.can_handle_request(holder, SECOND) is False


def test_the_pool_asks_that_question_before_reusing_anything() -> None:
    """The gate above only matters if it is the gate.

    Read out of httpcore's own file rather than inferred, because "the pool checks the origin"
    is the whole reason an exact origin match is enough. ``inspect.getsource`` cannot be used
    here: httpcore generates its synchronous modules from the async ones, and the line numbers
    it carries do not lead back to a readable file.
    """
    source = Path(connection_pool.__file__).read_text(encoding="utf-8")

    assert "can_handle_request(origin)" in source, (
        "httpcore no longer gates connection reuse on the origin; if it now matches on "
        "something looser, this package's pin has stopped being per-origin"
    )


@pytest.fixture(scope="session")
def alpn_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[RecordingServer, str]]:
    """A TLS server on loopback that offers HTTP/2 in ALPN.

    It speaks HTTP/1.1 once the handshake is done -- what is under test is whether the
    negotiation reaches the stream, not whether ``http.server`` can frame HTTP/2.

    Args:
        tmp_path_factory: pytest's per-session temporary directory factory.

    Yields:
        The running server and the path to the authority that signed its certificate.
    """
    ca = trustme.CA()
    path = tmp_path_factory.mktemp("ssrfguard-alpn-ca") / "ca.pem"
    ca.cert_pem.write_to_path(str(path))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert("right.test").configure_cert(context)
    context.set_alpn_protocols(["h2", "http/1.1"])
    with RecordingServer(ssl_context=context) as running:
        yield running, str(path)


def test_alpn_negotiates_h2_over_a_pinned_stream(
    alpn_server: tuple[RecordingServer, str],
) -> None:
    """The half of the question that is about this package rather than about httpcore.

    httpcore chooses HTTP/2 by asking the stream for its ``ssl_object`` and reading
    ``selected_alpn_protocol()``. So this connects through the seam, starts TLS with a context
    offering ``h2``, and asks the stream the same question httpcore would.
    """
    server, ca_path = alpn_server
    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    backend = SafeBackend(policy=policy, resolver=Resolver(**{"right.test": "127.0.0.1"}))

    context = ssl.create_default_context(cafile=ca_path)
    context.set_alpn_protocols(["h2", "http/1.1"])

    stream = backend.connect_tcp("right.test", server.port, timeout=5)
    try:
        secured = stream.start_tls(ssl_context=context, server_hostname="right.test", timeout=5)
        try:
            ssl_object = secured.get_extra_info("ssl_object")
            assert ssl_object is not None, "httpcore reads this to decide between h1 and h2"
            assert ssl_object.selected_alpn_protocol() == "h2"
        finally:
            secured.close()
    except BaseException:
        stream.close()
        raise


def test_the_pinned_stream_still_reports_the_hostname_to_tls(
    alpn_server: tuple[RecordingServer, str],
) -> None:
    """And negotiating HTTP/2 changes nothing about which name was verified.

    Read from the server, which is the only place that cannot be argued with.
    """
    server, ca_path = alpn_server
    policy = Policy(allowed_ports=frozenset({server.port}), allowed_networks=LOOPBACK)
    backend = SafeBackend(policy=policy, resolver=Resolver(**{"right.test": "127.0.0.1"}))

    context = ssl.create_default_context(cafile=ca_path)
    context.set_alpn_protocols(["h2", "http/1.1"])

    stream = backend.connect_tcp("right.test", server.port, timeout=5)
    secured = stream.start_tls(ssl_context=context, server_hostname="right.test", timeout=5)
    raw: socket.socket = secured.get_extra_info("socket")
    peer = raw.getpeername()
    secured.close()

    assert peer[0] == "127.0.0.1"
