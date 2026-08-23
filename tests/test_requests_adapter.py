"""The requests adapter, and the trap it exists not to fall into.

This suite has two halves and they are about different things.

The first half is the adapter: a request through it reaches the address that was validated, the
``Host:`` header is the hostname, the TLS handshake carries the hostname, and a certificate
issued to some other name is still refused. Those are read **off the server**, not off the
client -- a client can be asked what it thinks it sent, and the answer is worth nothing.

The second half is a set of tests of **urllib3**, not of this package. Writing the validated
address into ``_dns_host`` -- the approach this adapter was originally specified to take -- takes
``.host`` with it, because ``.host`` is derived from it; and ``HTTPSConnection.connect`` reads
``server_hostname`` off ``.host``. Those tests pin what that actually does, measured rather than
argued: the request fails on a certificate check against the pinned *address*, and the one-line
repair for that failure turns hostname verification off. They are here so that a future urllib3
that changes any of it fails this build rather than quietly making the argument for this
adapter's shape untrue.

**Where the pin is proved and where it is not.** A resolver stand-in cannot demonstrate DNS
rebinding -- that is done against a real nameserver in ``tests/test_rebinding.py``, at the layer
that does the resolving. What is demonstrated *here* is the property that matters for an
adapter: urllib3's own connection-and-resolution path is never entered at all, asserted by
making it raise if it is.
"""

from __future__ import annotations

import pickle
import socket
import ssl
from collections.abc import Iterator
from pathlib import Path

import pytest
import requests
import trustme
import urllib3.poolmanager
import urllib3.util.connection
from urllib3.connection import HTTPSConnection

from ssrfguard import BlockedAddressError, BlockedURLError, Policy, ProxyUnsupportedError
from ssrfguard.requests import SafeAdapter, Session

from .loopback_http import RecordingServer

pytestmark = pytest.mark.requests_adapter

#: Permits loopback, so a test can reach a server it started. Everything else this suite points
#: a name at is still refused, which is what the refusal tests turn on.
LOOPBACK = ("127.0.0.0/8",)

#: Where the denied tests point. Refused by the table, and the address every advisory in this
#: package's README is ultimately about.
METADATA = "169.254.169.254"


class Resolver:
    """A ``getaddrinfo`` stand-in that answers from a dict and counts what it was asked.

    The dict is writable while a test runs. That does not demonstrate rebinding -- see this
    module's docstring -- but it does let a test give a *second* connection a different answer
    from the first, which is how "each connection is validated on its own merits" is checked.
    """

    def __init__(self, **answers: str) -> None:
        self.answers: dict[str, str] = dict(answers)
        self.asked: list[str] = []

    def __call__(self, host: str, port: int, *_args: object) -> list[tuple]:
        self.asked.append(host)
        address = self.answers.get(host)
        if address is None:
            raise socket.gaierror(socket.EAI_NONAME, f"{host}: no answer")
        if ":" in address:
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, port, 0, 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]


@pytest.fixture(autouse=True)
def no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove any proxy this machine happens to have configured.

    requests reads the environment on every request, so a developer with `HTTP_PROXY` exported
    would watch most of this file refuse -- correctly, which is the problem: a suite that fails
    because of a shell variable teaches its reader that red means nothing. The proxy tests set
    what they need after this has run.

    Args:
        monkeypatch: pytest's environment patcher.
    """
    for name in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.upper(), raising=False)


@pytest.fixture
def server() -> Iterator[RecordingServer]:
    """A plaintext HTTP server on loopback.

    Yields:
        The running server.
    """
    with RecordingServer() as running:
        yield running


@pytest.fixture(scope="session")
def authority(tmp_path_factory: pytest.TempPathFactory) -> tuple[trustme.CA, Path]:
    """A throwaway certificate authority, and its certificate on disk for ``verify=``.

    Session-scoped because generating a key is the slowest thing in this file by an order of
    magnitude, and nothing here mutates it.

    Args:
        tmp_path_factory: pytest's per-session temporary directory factory.

    Returns:
        The authority and the path to its PEM.
    """
    ca = trustme.CA()
    path = tmp_path_factory.mktemp("ssrfguard-ca") / "ca.pem"
    ca.cert_pem.write_to_path(str(path))
    return ca, path


@pytest.fixture
def ca_path(authority: tuple[trustme.CA, Path]) -> str:
    """Where to point ``verify=`` so the throwaway authority is trusted.

    Args:
        authority: The session's authority.

    Returns:
        The path, as requests wants it.
    """
    return str(authority[1])


@pytest.fixture
def tls_server(authority: tuple[trustme.CA, Path]) -> Iterator[RecordingServer]:
    """An HTTPS server on loopback holding a certificate for ``right.test`` and nothing else.

    Args:
        authority: The session's authority.

    Yields:
        The running server.
    """
    ca, _ = authority
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert("right.test").configure_cert(context)
    with RecordingServer(ssl_context=context) as running:
        yield running


def policy_for(port: int, **overrides: object) -> Policy:
    """Build a policy that permits loopback and this test's port.

    Args:
        port: The ephemeral port a server got.
        **overrides: Passed to :class:`ssrfguard.Policy`.

    Returns:
        The policy.
    """
    fields: dict[str, object] = {
        "allowed_ports": frozenset({port}),
        "allowed_networks": LOOPBACK,
    }
    fields.update(overrides)
    return Policy(**fields)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------------------------
# The adapter
# ---------------------------------------------------------------------------------------------


def test_the_request_reaches_the_address_that_was_validated(
    server: RecordingServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A request goes out, arrives, and nothing in urllib3 ever resolves or connects.

    The second half is the one worth reading. ``urllib3.util.connection.create_connection`` is
    the function the seam replaces, and it is the only place urllib3 would look a name up. Made
    to raise for the duration, it turns "we believe the override took" into "if anything had
    fallen through to urllib3's own path, this test would fail".
    """

    def refuse(*_args: object, **_kwargs: object) -> socket.socket:
        raise AssertionError("urllib3 resolved and connected on its own; the seam was bypassed")

    monkeypatch.setattr(urllib3.util.connection, "create_connection", refuse)

    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    with Session(policy=policy_for(server.port), resolver=resolver) as session:
        response = session.get(f"http://pinned.test:{server.port}/asked")

    assert response.status_code == 200
    assert [r.path for r in server.received] == ["/asked"]
    assert resolver.asked == ["pinned.test"]


def test_the_host_header_is_the_hostname_and_not_the_pinned_address(
    server: RecordingServer,
) -> None:
    """``Host:`` is built from ``.host``, which the seam does not touch.

    An adapter that pinned by writing the address into the connection would send
    ``Host: 127.0.0.1:<port>`` here, which breaks name-based virtual hosting and tells the
    server which address the client resolved -- see the urllib3 tests further down, where that
    is exactly what happens.
    """
    resolver = Resolver(**{"vhost.test": "127.0.0.1"})
    with Session(policy=policy_for(server.port), resolver=resolver) as session:
        session.get(f"http://vhost.test:{server.port}/")

    assert server.received[-1].host == f"vhost.test:{server.port}"


def test_a_second_request_reuses_the_connection_and_asks_nothing(
    server: RecordingServer,
) -> None:
    """Pooling is not a hole: a reused connection was validated when it was opened."""
    resolver = Resolver(**{"pooled.test": "127.0.0.1"})
    with Session(policy=policy_for(server.port), resolver=resolver) as session:
        session.get(f"http://pooled.test:{server.port}/one")
        session.get(f"http://pooled.test:{server.port}/two")

    assert [r.path for r in server.received] == ["/one", "/two"]
    assert resolver.asked == ["pooled.test"], "the pooled connection was validated twice or none"


def test_every_new_connection_is_validated_on_its_own_merits(server: RecordingServer) -> None:
    """A pin holds for the connection it was made for, and the next one starts over.

    The record moves to the metadata endpoint after the first request. Nothing can move the
    connection that is already open -- and nothing tries to keep the old answer alive for the
    next one either, which is the other half of being correct here.
    """
    resolver = Resolver(**{"moving.test": "127.0.0.1"})
    with Session(policy=policy_for(server.port), resolver=resolver) as session:
        session.get(f"http://moving.test:{server.port}/before")
        resolver.answers["moving.test"] = METADATA
        session.close()  # drop the pool, so the next request has to open a connection

        with pytest.raises(BlockedAddressError) as refusal:
            session.get(f"http://moving.test:{server.port}/after")

    assert refusal.value.address == METADATA
    assert [r.path for r in server.received] == ["/before"]


def test_a_denied_address_is_refused_before_a_socket_is_opened(server: RecordingServer) -> None:
    """The name resolves to somewhere the policy refuses, so the request never leaves."""
    resolver = Resolver(**{"metadata.test": METADATA})
    with (
        Session(policy=policy_for(server.port), resolver=resolver) as session,
        pytest.raises(BlockedAddressError) as refusal,
    ):
        session.get(f"http://metadata.test:{server.port}/")

    assert refusal.value.address == METADATA
    assert server.received == []


def test_the_port_is_checked_by_the_thing_that_opens_the_socket(server: RecordingServer) -> None:
    """The whole URL policy runs at the seam, not only the address half.

    A port the policy does not allow is refused by the function that creates the socket, so it
    is refused however the pool was reached rather than only when somebody remembered to check
    the URL first.
    """
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    policy = Policy(allowed_ports=frozenset({server.port + 1}), allowed_networks=LOOPBACK)
    with (
        Session(policy=policy, resolver=resolver) as session,
        pytest.raises(BlockedURLError) as refusal,
    ):
        session.get(f"http://pinned.test:{server.port}/")

    assert "allowed_ports" in refusal.value.reason
    assert server.received == []


def test_the_scheme_is_checked_by_the_thing_that_opens_the_socket(
    server: RecordingServer,
) -> None:
    """A policy that allows only https refuses an http connection at the socket."""
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    policy = policy_for(server.port, allowed_schemes=frozenset({"https"}))
    with (
        Session(policy=policy, resolver=resolver) as session,
        pytest.raises(BlockedURLError) as refusal,
    ):
        session.get(f"http://pinned.test:{server.port}/")

    assert "allowed_schemes" in refusal.value.reason


def test_a_literal_address_in_the_url_is_checked_too(server: RecordingServer) -> None:
    """An IPv6 literal survives the round trip into a URL the policy can read, and is refused.

    urllib3 carries the address unbracketed; a URL needs the brackets back or it does not parse
    as one. Getting that wrong would refuse every IPv6 origin, which is the kind of false
    refusal that gets a security library removed.
    """
    with (
        Session(policy=policy_for(server.port)) as session,
        pytest.raises(BlockedURLError) as refusal,
    ):
        session.get(f"http://[::1]:{server.port}/")

    assert "loopback" in refusal.value.reason.lower()


def test_a_name_that_does_not_resolve_fails_the_way_requests_users_expect(
    server: RecordingServer,
) -> None:
    """A DNS failure is not a policy decision and must not arrive dressed as one."""
    with (
        Session(policy=policy_for(server.port), resolver=Resolver()) as session,
        pytest.raises(requests.exceptions.ConnectionError) as failure,
    ):
        session.get(f"http://nowhere.test:{server.port}/")

    assert "nowhere.test" in str(failure.value)


def test_a_refused_connection_fails_the_way_requests_users_expect() -> None:
    """So is a closed port. Both are the network's answer, not the policy's."""
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = int(closed.getsockname()[1])
    closed.close()

    resolver = Resolver(**{"closed.test": "127.0.0.1"})
    with (
        Session(policy=policy_for(port), resolver=resolver) as session,
        pytest.raises(requests.exceptions.ConnectionError),
    ):
        session.get(f"http://closed.test:{port}/")


def test_a_timeout_arrives_as_urllib3s_own_timeout(
    server: RecordingServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A connect timeout has to be the error urllib3's callers already handle.

    Driven by making the connection time out rather than by finding an address that will,
    because "an address that reliably blackholes" is not a thing a test suite can count on and
    a security test that fails intermittently gets deleted.
    """

    def time_out(*_args: object, **_kwargs: object) -> socket.socket:
        raise TimeoutError("timed out")

    monkeypatch.setattr("ssrfguard.requests.connect", time_out)

    resolver = Resolver(**{"slow.test": "127.0.0.1"})
    with (
        Session(policy=policy_for(server.port), resolver=resolver) as session,
        pytest.raises(requests.exceptions.ConnectTimeout),
    ):
        session.get(f"http://slow.test:{server.port}/")


# ---------------------------------------------------------------------------------------------
# TLS -- the three assertions this adapter may never fail
# ---------------------------------------------------------------------------------------------


def test_the_handshake_carries_the_hostname_and_not_the_pinned_address(
    tls_server: RecordingServer, ca_path: str
) -> None:
    """Read off the wire: the server was asked for ``right.test``, not for an address.

    Python will not put an IP literal in the ``server_name`` extension, so a client that had
    been pinned by rewriting the host would have sent no name at all. ``sni`` coming back with
    the hostname is that failure being absent rather than being handled.
    """
    resolver = Resolver(**{"right.test": "127.0.0.1"})
    with Session(policy=policy_for(tls_server.port), resolver=resolver) as session:
        response = session.get(f"https://right.test:{tls_server.port}/tls", verify=ca_path)

    assert response.status_code == 200
    received = tls_server.received[-1]
    assert received.sni == "right.test"
    assert received.host == f"right.test:{tls_server.port}"


def test_a_certificate_issued_to_another_name_is_still_refused(
    tls_server: RecordingServer, ca_path: str
) -> None:
    """Pinning must not buy a way past hostname verification.

    The server holds a certificate for ``right.test`` and this asks for ``wrong.test``, pinned
    to the same address. A guard that verified against the address it connected to would accept
    this, which is the worse hole traded for the one this package closes.
    """
    resolver = Resolver(**{"wrong.test": "127.0.0.1"})
    with (
        Session(policy=policy_for(tls_server.port), resolver=resolver) as session,
        pytest.raises(requests.exceptions.SSLError) as refusal,
    ):
        session.get(f"https://wrong.test:{tls_server.port}/", verify=ca_path)

    assert "wrong.test" in str(refusal.value), "the check was not made against the name asked for"
    assert tls_server.received == []


def test_an_untrusted_authority_is_still_refused(tls_server: RecordingServer) -> None:
    """And nothing about pinning loosens the chain check either."""
    resolver = Resolver(**{"right.test": "127.0.0.1"})
    with (
        Session(policy=policy_for(tls_server.port), resolver=resolver) as session,
        pytest.raises(requests.exceptions.SSLError),
    ):
        session.get(f"https://right.test:{tls_server.port}/")

    assert tls_server.received == []


# ---------------------------------------------------------------------------------------------
# Proxies
# ---------------------------------------------------------------------------------------------


def test_an_explicit_proxy_is_refused(server: RecordingServer) -> None:
    """A proxy resolves the target itself, so the pin cannot reach it.

    Refusing is the honest answer. Passing the request through would leave a caller believing
    in a control that stopped running, which is worse than having no control.
    """
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    with (
        Session(policy=policy_for(server.port), resolver=resolver) as session,
        pytest.raises(ProxyUnsupportedError) as refusal,
    ):
        session.get(
            f"http://pinned.test:{server.port}/",
            proxies={"http": "http://127.0.0.1:9"},
        )

    assert refusal.value.proxy == "http://127.0.0.1:9"
    assert server.received == []


def test_a_proxy_from_the_environment_is_refused(
    server: RecordingServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The environment is the way a proxy usually arrives, and it is the way it usually arrives
    six months after the code was reviewed."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    with (
        Session(policy=policy_for(server.port), resolver=resolver) as session,
        pytest.raises(ProxyUnsupportedError),
    ):
        session.get(f"http://pinned.test:{server.port}/")

    assert server.received == []


def test_a_proxy_the_environment_excludes_is_not_refused(
    server: RecordingServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The question asked is the one requests asks, ``no_proxy`` included.

    Refusing a request that was never going to use the proxy would be a false refusal, and a
    false refusal is how a control gets configured around.
    """
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "pinned.test")
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    with Session(policy=policy_for(server.port), resolver=resolver) as session:
        response = session.get(f"http://pinned.test:{server.port}/direct")

    assert response.status_code == 200
    assert [r.path for r in server.received] == ["/direct"]


def test_allow_proxy_accepts_that_enforcement_has_moved(
    server: RecordingServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With ``allow_proxy``, the request goes to the proxy and this package is out of the path.

    Asserted here so the semantics are on the record: what comes back is the network's answer
    about the proxy, not a refusal, and nothing about the target was checked.
    """
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    policy = policy_for(server.port, allow_proxy=True)
    with (
        Session(policy=policy, resolver=resolver) as session,
        pytest.raises(requests.exceptions.ConnectionError),
    ):
        session.get(f"http://pinned.test:{server.port}/")

    assert resolver.asked == [], "the target was never resolved by us; the proxy would have"


def test_a_tunnel_is_refused_by_the_socket_itself(server: RecordingServer) -> None:
    """The refusal is a property of the connection, not of the call path that reached it.

    ``SafeAdapter`` refuses a proxy before a connection is made, so this is unreachable through
    it. It is here because a connection asked to ``CONNECT`` somewhere has the *proxy* in
    ``.host``: pinning it would validate the wrong host and report success.
    """
    adapter = SafeAdapter(policy=policy_for(server.port))
    pool_class = adapter.poolmanager.pool_classes_by_scheme["https"]
    connection = pool_class.ConnectionCls(host="127.0.0.1", port=server.port)
    connection.set_tunnel("metadata.test", 443)

    with pytest.raises(ProxyUnsupportedError) as refusal:
        connection.connect()

    assert refusal.value.proxy == f"127.0.0.1:{server.port}"
    connection.close()
    adapter.close()


# ---------------------------------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------------------------------


def test_a_redirect_re_enters_the_seam(server: RecordingServer) -> None:
    """Every hop opens its own connection, so every hop is validated.

    This is the property that makes redirects safe here rather than a second thing to remember:
    requests follows a redirect by sending another request through the same adapter, and an
    adapter that validates when it opens a socket therefore validates the hop. The chain cap,
    per-hop credential stripping and relative-``Location`` handling are separate questions and
    are not answered here.
    """
    resolver = Resolver(
        **{"hop.test": "127.0.0.1", "metadata.test": METADATA},
    )
    server.routes["/redirect"] = (
        302,
        {"Location": f"http://metadata.test:{server.port}/"},
        b"",
    )

    with (
        Session(policy=policy_for(server.port), resolver=resolver) as session,
        pytest.raises(BlockedAddressError) as refusal,
    ):
        session.get(f"http://hop.test:{server.port}/redirect")

    assert refusal.value.address == METADATA
    assert [r.path for r in server.received] == ["/redirect"]
    assert resolver.asked == ["hop.test", "metadata.test"]


# ---------------------------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------------------------


def test_the_session_guards_both_schemes() -> None:
    """A session guarded on one scheme is a session a redirect walks out of."""
    with Session(policy=Policy()) as session:
        assert isinstance(session.get_adapter("http://example.com/"), SafeAdapter)
        assert isinstance(session.get_adapter("https://example.com/"), SafeAdapter)


def test_installing_the_guarded_pools_leaves_urllib3s_own_table_alone() -> None:
    """``PoolManager`` keeps the module-level table by reference rather than copying it.

    So the table has to be *replaced*. Writing a key into the one the manager was handed would
    change urllib3's default for every other client in the process -- a security library
    silently rewriting an unrelated one's connection class.
    """
    before = dict(urllib3.poolmanager.pool_classes_by_scheme)
    adapter = SafeAdapter(policy=Policy())
    try:
        installed = adapter.poolmanager.pool_classes_by_scheme
        assert installed is not urllib3.poolmanager.pool_classes_by_scheme
        assert urllib3.poolmanager.pool_classes_by_scheme == before
    finally:
        adapter.close()


def test_an_adapter_survives_being_pickled() -> None:
    """requests pickles adapters through a fixed attribute list, and rebuilds the pools from it.

    Without the policy in that list, a session that was pickled comes back with an adapter that
    cannot build a pool at all.
    """
    policy = Policy(allowed_ports=frozenset({443}), allowed_networks=LOOPBACK)
    restored = pickle.loads(pickle.dumps(SafeAdapter(policy=policy)))  # noqa: S301
    try:
        # Compared by what the policy decides rather than by equality: the address table is not
        # a value type, so two copies of the same table are not equal to each other.
        assert restored.policy.allowed_ports == frozenset({443})
        assert restored.policy.permits_address("127.0.0.1")
        assert not restored.policy.permits_address(METADATA)
        assert restored.poolmanager.pool_classes_by_scheme["https"].ConnectionCls is not None
    finally:
        restored.close()


# ---------------------------------------------------------------------------------------------
# urllib3, not this package: what the approach this adapter did not take actually does
# ---------------------------------------------------------------------------------------------


def test_writing_the_address_into_dns_host_takes_the_hostname_with_it(
    tls_server: RecordingServer, ca_path: str
) -> None:
    """``.host`` is a property over ``_dns_host``; there is no split to pin through.

    If this ever fails, urllib3 has grown a real separation between the name to resolve and the
    name to verify, and the three tests below stop describing anything.
    """
    connection = HTTPSConnection("right.test", tls_server.port, ca_certs=ca_path)
    connection._dns_host = "127.0.0.1"
    assert connection.host == "127.0.0.1"
    connection.close()


def test_that_approach_verifies_the_certificate_against_the_pinned_address(
    tls_server: RecordingServer, ca_path: str
) -> None:
    """Which means it fails, loudly, on every request to a host with an ordinary certificate.

    ``HTTPSConnection.connect`` reads ``server_hostname`` off ``.host``, so the address is what
    gets checked. The server's certificate is for ``right.test`` and the check is against
    127.0.0.1, so there is nothing to match.
    """
    connection = HTTPSConnection(
        "right.test", tls_server.port, ca_certs=ca_path, cert_reqs="CERT_REQUIRED"
    )
    connection._dns_host = "127.0.0.1"
    try:
        with pytest.raises(ssl.SSLCertVerificationError) as failure:
            connection.request("GET", "/")
        assert "127.0.0.1" in str(failure.value)
    finally:
        connection.close()
    assert tls_server.received == []


def test_the_one_line_repair_for_that_turns_hostname_verification_off(
    tls_server: RecordingServer, ca_path: str
) -> None:
    """And this is the actual danger. The failure above has an obvious fix, and it is a hole.

    ``assert_hostname=False`` is what a developer reaches for when every request starts failing
    on an IP-address mismatch. It connects: a certificate issued to ``right.test``, accepted by
    a client that asked for 127.0.0.1 and checked nothing. The trap is not that the approach
    fails open on its own -- it is that it fails closed in a way whose nearest repair fails open.

    The request that goes out is worth reading too: no name in the handshake, and the pinned
    address in the ``Host`` header.
    """
    connection = HTTPSConnection(
        "right.test",
        tls_server.port,
        ca_certs=ca_path,
        cert_reqs="CERT_REQUIRED",
        assert_hostname=False,
    )
    connection._dns_host = "127.0.0.1"
    try:
        connection.request("GET", "/repaired")
        response = connection.getresponse()
        response.read()
    finally:
        connection.close()

    assert response.status == 200, "hostname verification is off, so anything gets through"
    received = tls_server.received[-1]
    assert received.sni is None, "an address cannot be sent as a server name, so none was sent"
    assert received.host == f"127.0.0.1:{tls_server.port}"
