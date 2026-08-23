"""The httpx adapter: what is true of *httpx* rather than of this package.

The guarantees this package makes are asserted once, against both adapters, in
``tests/test_adapter_parity.py``. What is left here is the part that only means something for
this seam.

Two things in particular. **The stream the backend returns is httpcore's own class** -- that is
what keeps "this package cannot verify a certificate against the address it pinned" true, because
a stream written here would carry a ``server_hostname`` argument of its own, correct today and
one careless edit from being an address. And **the client factory**, which exists because a
transport is not a client: httpx builds a second transport for an explicit ``proxy=`` and never
consults ours, so the only place that can be refused is a class that owns its own construction.
"""

from __future__ import annotations

import inspect
import socket
import ssl
from collections.abc import Iterator
from pathlib import Path

import httpcore
import httpx
import pytest
import trustme
from httpcore._backends.sync import SyncStream
from httpx._utils import get_environment_proxies

from ssrfguard import BlockedAddressError, BlockedURLError, Policy, ProxyUnsupportedError
from ssrfguard.httpx import (
    _CLIENT_OPTIONS,
    _ROUTING_OPTIONS,
    _SHARED_OPTIONS,
    _TRANSPORT_OPTIONS,
    Client,
    SafeBackend,
    SafeTransport,
    _environment_proxy,
)

from .loopback_http import RecordingServer
from .stub_resolver import Resolver

pytestmark = pytest.mark.httpx_adapter

#: Permits loopback, so a test can reach a server it started. Everything else this suite points a
#: name at is still refused, which is what the refusal tests turn on.
LOOPBACK = ("127.0.0.0/8",)

#: Where the denied tests point.
METADATA = "169.254.169.254"


@pytest.fixture(autouse=True)
def no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove any proxy this machine happens to have configured.

    httpx reads the environment when a client is built without a transport. Nothing here builds
    one that way, but a developer with `HTTPS_PROXY` exported should not have to know that to
    read a failure.

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

    Args:
        tmp_path_factory: pytest's per-session temporary directory factory.

    Returns:
        The authority and the path to its PEM.
    """
    ca = trustme.CA()
    path = tmp_path_factory.mktemp("ssrfguard-httpx-ca") / "ca.pem"
    ca.cert_pem.write_to_path(str(path))
    return ca, path


@pytest.fixture
def trusted(authority: tuple[trustme.CA, Path]) -> ssl.SSLContext:
    """A client TLS context that trusts the throwaway authority and nothing else new.

    An ``SSLContext`` rather than a path, because httpx deprecated ``verify=<str>``.

    Args:
        authority: The session's authority.

    Returns:
        The context to hand to ``verify=``.
    """
    return ssl.create_default_context(cafile=str(authority[1]))


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


def client_for(
    policy: Policy, resolver: Resolver | None = None, **transport: object
) -> httpx.Client:
    """Build a client whose only transport is a guarded one.

    Args:
        policy: What the transport is willing to reach.
        resolver: A stand-in for ``socket.getaddrinfo``.
        **transport: Passed to :class:`ssrfguard.httpx.SafeTransport`.

    Returns:
        The client, for use as a context manager.
    """
    return httpx.Client(transport=SafeTransport(policy=policy, resolver=resolver, **transport))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------------------------
# The seam
# ---------------------------------------------------------------------------------------------


def test_the_backend_returns_httpcores_own_stream(server: RecordingServer) -> None:
    """The TLS path stays httpcore's code, and this is what says so.

    ``start_tls`` is where a hostname becomes a certificate check. This package does not
    implement it -- the stream handed back is httpcore's, so ``server_hostname`` never passes
    through a line anybody here wrote. If that stops being true, this fails and whoever changed
    it has to make the argument again.
    """
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    backend = SafeBackend(policy=policy_for(server.port), resolver=resolver)
    stream = backend.connect_tcp("pinned.test", server.port, timeout=5)
    try:
        assert type(stream) is SyncStream
    finally:
        stream.close()


def test_a_refusal_is_not_dressed_as_a_transport_error(server: RecordingServer) -> None:
    """httpx maps httpcore's exceptions onto its own and re-raises anything else untouched.

    That is the behaviour this package depends on: a policy refusal must arrive as a policy
    refusal, not as ``httpx.ConnectError``, or a caller's ``except httpx.ConnectError`` swallows
    it as a network blip and retries.
    """
    resolver = Resolver(**{"metadata.test": METADATA})
    with (
        client_for(policy_for(server.port), resolver) as client,
        pytest.raises(BlockedAddressError) as refusal,
    ):
        client.get(f"http://metadata.test:{server.port}/")

    assert not isinstance(refusal.value, httpx.HTTPError)


# ---------------------------------------------------------------------------------------------
# The URL policy, which lives at the transport
# ---------------------------------------------------------------------------------------------


def test_the_port_is_checked_again_by_the_backend(server: RecordingServer) -> None:
    """A backend used with a pool of somebody else's assembling is still bound by the policy.

    The transport is the recommended entry point and it checks the whole URL. This asserts the
    layer below it is not merely trusting that, because a network backend is a public thing to
    hand to :class:`httpcore.ConnectionPool`.
    """
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    policy = Policy(allowed_ports=frozenset({server.port + 1}), allowed_networks=LOOPBACK)
    backend = SafeBackend(policy=policy, resolver=resolver)

    with pytest.raises(BlockedURLError) as refusal:
        backend.connect_tcp("pinned.test", server.port, timeout=5)

    assert "allowed_ports" in refusal.value.reason
    assert resolver.asked == [], "the port was checked after the lookup rather than before it"


# ---------------------------------------------------------------------------------------------
# Failures that are the network's, not the policy's
# ---------------------------------------------------------------------------------------------


def test_a_timeout_arrives_as_httpxs_own_timeout(
    server: RecordingServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Driven by making the connection time out rather than by finding an address that will.

    "An address that reliably blackholes" is not something a test suite can count on, and a
    security test that fails intermittently gets deleted.
    """

    def time_out(*_args: object, **_kwargs: object) -> socket.socket:
        raise TimeoutError("timed out")

    monkeypatch.setattr("ssrfguard.httpx.connect", time_out)

    resolver = Resolver(**{"slow.test": "127.0.0.1"})
    with (
        client_for(policy_for(server.port), resolver) as client,
        pytest.raises(httpx.ConnectTimeout),
    ):
        client.get(f"http://slow.test:{server.port}/")


# ---------------------------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------
# Sockets the policy cannot see
# ---------------------------------------------------------------------------------------------


def test_a_unix_socket_is_refused_at_construction() -> None:
    """``uds=`` names a destination that has no address, so there is nothing to check."""
    with pytest.raises(BlockedURLError) as refusal:
        SafeTransport(policy=Policy(), uds="/var/run/nothing.sock")

    assert "unix domain socket" in refusal.value.reason


def test_a_unix_socket_is_refused_at_the_backend() -> None:
    """And again one layer down, so the refusal is a property of the backend rather than of the
    path that reached it."""
    backend = SafeBackend(policy=Policy())

    with pytest.raises(BlockedURLError) as refusal:
        backend.connect_unix_socket("/var/run/nothing.sock")

    assert "unix domain socket" in refusal.value.reason


# ---------------------------------------------------------------------------------------------
# Proxies
# ---------------------------------------------------------------------------------------------


def test_a_proxy_on_the_transport_is_refused() -> None:
    """A proxy resolves the target itself, so nothing this transport does can reach it."""
    with pytest.raises(ProxyUnsupportedError) as refusal:
        SafeTransport(policy=Policy(), proxy="http://127.0.0.1:9")

    assert refusal.value.proxy == "http://127.0.0.1:9"


def test_allow_proxy_leaves_httpxs_own_proxy_pool_in_place(server: RecordingServer) -> None:
    """With ``allow_proxy``, enforcement really has moved -- and this says what that means.

    The pool is httpx's, not a pinning one. Replacing it would pin the *proxy's* address while
    leaving the target unchecked, which is a guard reporting a decision it never made.
    """
    policy = policy_for(server.port, allow_proxy=True)
    transport = SafeTransport(policy=policy, proxy="http://127.0.0.1:9")
    try:
        assert isinstance(transport._pool, httpcore.HTTPProxy)
    finally:
        transport.close()


def test_an_environment_proxy_does_not_reach_a_client_given_a_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """httpx computes ``allow_env_proxies = trust_env and transport is None``.

    So handing it a transport already neutralises ``HTTP_PROXY`` -- which is good, and is not
    enough on its own, because an explicit ``proxy=`` on the *client* builds a separate
    transport that this one never sees. That gap is the client factory's to close.
    """
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    with client_for(Policy()) as client:
        assert client._mounts == {}, "an environment proxy was mounted despite the transport"


# ---------------------------------------------------------------------------------------------
# The client, which exists because a transport is not one
# ---------------------------------------------------------------------------------------------


def test_a_request_through_the_client_reaches_the_validated_address(
    server: RecordingServer,
) -> None:
    """The documented entry point does what the transport does, with the routing closed."""
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    with Client(policy=policy_for(server.port), resolver=resolver) as client:
        response = client.get(f"http://pinned.test:{server.port}/asked")

    assert response.status_code == 200
    assert [r.path for r in server.received] == ["/asked"]


def test_an_explicit_proxy_on_the_client_is_refused() -> None:
    """The gap this class exists to close: httpx prefers a proxy transport over the one given."""
    with pytest.raises(ProxyUnsupportedError) as refusal:
        Client(policy=Policy(), proxy="http://127.0.0.1:9")

    assert refusal.value.proxy == "http://127.0.0.1:9"


def test_mounts_on_the_client_are_refused() -> None:
    """``mounts=`` is the same gap spelled differently, and is refused the same way."""
    with pytest.raises(ProxyUnsupportedError):
        Client(policy=Policy(), mounts={"all://": httpx.HTTPTransport()})


def test_a_proxy_from_the_environment_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Handing httpx a transport already neutralises this. Neutralising is not the same as
    refusing, and quietly not using the proxy an operator configured is its own surprise --
    it can put traffic outside an egress control that was assumed to be carrying it."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")

    with pytest.raises(ProxyUnsupportedError) as refusal:
        Client(policy=Policy())

    assert "127.0.0.1:9" in refusal.value.proxy


def test_an_environment_that_proxies_nothing_is_not_a_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``NO_PROXY=*`` switches the environment off, and a refusal there would be a false one.

    Decided with httpx's own parser rather than by reading the variables here, so the answer
    cannot drift from the answer httpx would have given.
    """
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "*")

    with Client(policy=Policy()) as client:
        assert isinstance(client._transport, SafeTransport)


def test_a_no_proxy_entry_on_its_own_is_not_a_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """``NO_PROXY`` without a proxy still puts an entry in httpx's map, and its value is ``None``.

    The sibling above covers ``NO_PROXY=*``, which makes httpx return an *empty* map -- so the
    loop in ``_environment_proxy`` never runs and the ``None`` entry is never seen. This is the
    case where it is: one entry, no proxy behind it, and the loop has to keep looking rather than
    read "there is a key here" as "a proxy applies". Getting that wrong refuses every client on
    a machine whose operator excluded one hostname.
    """
    monkeypatch.setenv("NO_PROXY", "example.com")

    assert get_environment_proxies() == {"all://*example.com": None}
    assert _environment_proxy(trust_env=True) is None

    with Client(policy=Policy()) as client:
        assert isinstance(client._transport, SafeTransport)


def test_trust_env_off_ignores_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """And so does saying so directly."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")

    with Client(policy=Policy(), trust_env=False) as client:
        assert isinstance(client._transport, SafeTransport)


def test_allow_proxy_lets_an_explicit_proxy_through(server: RecordingServer) -> None:
    """With ``allow_proxy``, the proxy is honoured and those requests are not pinned.

    Asserted through what httpx will actually route with, because that is where the decision
    lives: a mount matching the request wins over the transport the client was given.
    """
    policy = policy_for(server.port, allow_proxy=True)
    with Client(policy=policy, proxy="http://127.0.0.1:9") as client:
        routed = client._transport_for_url(httpx.URL(f"http://pinned.test:{server.port}/"))
        assert not isinstance(routed, SafeTransport)


def test_the_transport_alone_is_bypassed_by_an_explicit_proxy(server: RecordingServer) -> None:
    """The measurement this class is the answer to, asserted rather than described.

    This is not a test of a bug that will be fixed. It documents that assembling a client by
    hand around :class:`SafeTransport` leaves a way round it, so that the limitation in that
    class's docstring is checked rather than believed.
    """
    transport = SafeTransport(policy=policy_for(server.port))
    with httpx.Client(transport=transport, proxy="http://127.0.0.1:9") as client:
        routed = client._transport_for_url(httpx.URL(f"http://pinned.test:{server.port}/"))

    assert routed is not transport, "the bypass this class exists for has closed on its own"
    assert isinstance(routed, httpx.HTTPTransport)


def test_verify_reaches_the_transport_rather_than_being_ignored(
    tls_server: RecordingServer, trusted: ssl.SSLContext
) -> None:
    """``verify`` on an httpx client that was given a transport configures nothing at all.

    Silently. For an argument whose whole job is certificate verification, a caller believing
    they set it when they did not is the worst possible no-op, so this class routes it to the
    transport -- and this asserts the routing by making a handshake that only succeeds if it
    arrived.
    """
    resolver = Resolver(**{"right.test": "127.0.0.1"})
    with Client(policy=policy_for(tls_server.port), resolver=resolver, verify=trusted) as client:
        response = client.get(f"https://right.test:{tls_server.port}/tls")

    assert response.status_code == 200
    assert tls_server.received[-1].sni == "right.test"


def test_an_option_neither_side_knows_is_refused() -> None:
    """Refused rather than dropped: httpx growing an argument is a decision, not an inheritance."""
    with pytest.raises(TypeError) as refusal:
        Client(policy=Policy(), some_new_httpx_knob=True)

    assert "some_new_httpx_knob" in str(refusal.value)


def test_a_transport_that_does_not_pin_is_refused() -> None:
    """The one argument that could quietly replace the guard with nothing."""
    with pytest.raises(TypeError) as refusal:
        Client(transport=httpx.HTTPTransport())  # type: ignore[arg-type]

    assert "does not pin" in str(refusal.value)


def test_a_prebuilt_transport_carries_its_own_policy(server: RecordingServer) -> None:
    """A caller who configured a transport does not restate its policy, and cannot contradict it."""
    transport = SafeTransport(policy=policy_for(server.port))
    with Client(transport=transport) as client:
        assert client.policy is transport.policy

    with pytest.raises(TypeError) as refusal:
        Client(policy=Policy(), transport=SafeTransport(policy=Policy()))
    assert "two answers to one question" in str(refusal.value)


def test_the_client_needs_a_policy_or_a_transport() -> None:
    """Neither is not a default, because there is no safe policy to assume."""
    with pytest.raises(TypeError) as refusal:
        Client()

    assert "needs a policy" in str(refusal.value)


def test_httpx_has_not_grown_an_argument_this_class_has_not_considered() -> None:
    """The drift fence. A new ``httpx.Client`` argument must be routed deliberately.

    The ones that decide *where a request goes* are the entire subject of this class, so
    inheriting a new one by passing it through unexamined is how the guard quietly stops being
    in the path. Failing here is not a bug in httpx; it is a decision arriving.
    """
    declared = set(inspect.signature(httpx.Client.__init__).parameters) - {"self"}
    considered = (
        _TRANSPORT_OPTIONS | _SHARED_OPTIONS | _ROUTING_OPTIONS | _CLIENT_OPTIONS | {"transport"}
    )
    assert declared <= considered, (
        f"httpx.Client grew {sorted(declared - considered)}; route it deliberately -- if it "
        f"decides where a request goes, it belongs in the refused set"
    )
