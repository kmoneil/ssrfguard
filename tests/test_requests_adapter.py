"""The requests adapter: what is true of *urllib3* rather than of this package.

The guarantees this package makes are asserted once, against both adapters, in
``tests/test_adapter_parity.py``. What is left here is the part that only means something for
this seam.

Most of it is a set of tests of **urllib3 itself**. Writing the validated address into
``_dns_host``, the approach this adapter was originally specified to take, takes ``.host``
with it, because ``.host`` is derived from it; and ``HTTPSConnection.connect`` reads
``server_hostname`` off ``.host``. Those tests pin what that actually does, measured rather than
argued: the request fails on a certificate check against the pinned *address*, and the one-line
repair for that failure turns hostname verification off. They are here so that a future urllib3
which changes any of it fails this build rather than quietly making the argument for this
adapter's shape untrue.

The rest is the wiring only this client has: a pool table that must be replaced rather than
mutated, a proxy visible in ``send`` where httpx's is not, a ``CONNECT`` tunnel refused at the
socket, and an adapter that survives being pickled.
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

from ssrfguard import BlockedURLError, Policy, ProxyUnsupportedError
from ssrfguard.requests import SafeAdapter, Session

from .loopback_http import RecordingServer
from .stub_resolver import Resolver

pytestmark = pytest.mark.requests_adapter

#: Permits loopback, so a test can reach a server it started. Everything else this suite points
#: a name at is still refused, which is what the refusal tests turn on.
LOOPBACK = ("127.0.0.0/8",)

#: Where the denied tests point. Refused by the table, and the address every advisory in this
#: package's README is ultimately about.
METADATA = "169.254.169.254"


@pytest.fixture(autouse=True)
def no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove any proxy this machine happens to have configured.

    requests reads the environment on every request, so a developer with `HTTP_PROXY` exported
    would watch most of this file refuse, correctly, which is the problem: a suite that fails
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


def test_the_connection_checks_the_whole_url_and_not_only_the_address(
    server: RecordingServer,
) -> None:
    """The seam runs the URL policy itself, so a pool reached by any route is bound by it.

    The session checks every URL before it picks an adapter, and the parity matrix covers what
    a caller sees. This asserts the layer *below* that: a connection built straight from the
    adapter's pool classes, with no session anywhere, still refuses a port the policy does not
    allow. That is what makes the refusal a property of the socket rather than of the path that
    reached it.
    """
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    policy = Policy(allowed_ports=frozenset({server.port + 1}), allowed_networks=LOOPBACK)
    adapter = SafeAdapter(policy=policy, resolver=resolver)
    pool_class = adapter.poolmanager.pool_classes_by_scheme["http"]
    connection = pool_class.ConnectionCls(host="pinned.test", port=server.port)

    with pytest.raises(BlockedURLError) as refusal:
        connection.connect()

    assert "allowed_ports" in refusal.value.reason
    assert resolver.asked == [], "the port was checked after the lookup rather than before it"
    connection.close()
    adapter.close()


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
# TLS: the three assertions this adapter may never fail
# ---------------------------------------------------------------------------------------------


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
    change urllib3's default for every other client in the process, which is a security library
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
    fails open on its own. It is that it fails closed in a way whose nearest repair fails open.

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
