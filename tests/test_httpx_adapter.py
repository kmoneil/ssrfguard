"""The httpx adapter, and the property that makes its seam the right one.

httpcore hands the origin hostname to ``start_tls`` itself, a few lines after asking the network
backend for a socket. So an adapter that only implements ``connect_tcp`` has no opportunity to
verify a certificate against the address it pinned -- and the tests here are what turns that
sentence into something checked. They read from the server: what the ``Host:`` header said, and
what name the client offered in the TLS ``server_name`` extension.

One assertion is about code rather than behaviour: the stream the backend returns is httpcore's
own class. That is what keeps the argument true. A stream written here would carry a
``server_hostname`` argument of its own, correct today and one careless edit from being an
address; not having that line is the whole point.

**Where the pin is proved and where it is not.** A resolver stand-in cannot demonstrate DNS
rebinding -- that is done against a real nameserver in ``tests/test_rebinding.py``. What is
demonstrated here is the property that matters for an adapter: httpcore's own connect path is
never entered, asserted by making the function it would have used raise.
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

from ssrfguard import BlockedAddressError, BlockedURLError, Policy, ProxyUnsupportedError
from ssrfguard.httpx import (
    _CLIENT_OPTIONS,
    _ROUTING_OPTIONS,
    _SHARED_OPTIONS,
    _TRANSPORT_OPTIONS,
    Client,
    SafeBackend,
    SafeTransport,
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


def test_the_request_reaches_the_address_that_was_validated(
    server: RecordingServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A request goes out, arrives, and httpcore's own connect path is never entered.

    ``socket.create_connection`` is the one call httpcore's stock backend makes and the one this
    backend replaces. Made to raise for the duration, it turns "we believe the backend took"
    into "if anything had fallen through to httpcore's own path, this test would fail".
    """

    def refuse(*_args: object, **_kwargs: object) -> socket.socket:
        raise AssertionError("httpcore resolved and connected on its own; the seam was bypassed")

    monkeypatch.setattr(socket, "create_connection", refuse)

    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    with client_for(policy_for(server.port), resolver) as client:
        response = client.get(f"http://pinned.test:{server.port}/asked")

    assert response.status_code == 200
    assert [r.path for r in server.received] == ["/asked"]
    assert resolver.asked == ["pinned.test"]


def test_the_host_header_is_the_hostname_and_not_the_pinned_address(
    server: RecordingServer,
) -> None:
    """Nothing here rewrites the URL, so nothing downstream of it sees an address."""
    resolver = Resolver(**{"vhost.test": "127.0.0.1"})
    with client_for(policy_for(server.port), resolver) as client:
        client.get(f"http://vhost.test:{server.port}/")

    assert server.received[-1].host == f"vhost.test:{server.port}"


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


def test_a_second_request_reuses_the_connection_and_asks_nothing(
    server: RecordingServer,
) -> None:
    """Pooling is not a hole: a reused connection was validated when it was opened."""
    resolver = Resolver(**{"pooled.test": "127.0.0.1"})
    with client_for(policy_for(server.port), resolver) as client:
        client.get(f"http://pooled.test:{server.port}/one")
        client.get(f"http://pooled.test:{server.port}/two")

    assert [r.path for r in server.received] == ["/one", "/two"]
    assert resolver.asked == ["pooled.test"], "the pooled connection was validated twice or none"


def test_every_new_connection_is_validated_on_its_own_merits(server: RecordingServer) -> None:
    """The record moves after the first request; the connection already open does not move, and
    the next one is judged afresh."""
    resolver = Resolver(**{"moving.test": "127.0.0.1"})
    transport = SafeTransport(policy=policy_for(server.port), resolver=resolver)
    with httpx.Client(transport=transport) as client:
        client.get(f"http://moving.test:{server.port}/before")
        resolver.answers["moving.test"] = METADATA
        transport.close()  # drop the pool, so the next request has to open a connection

        with pytest.raises(BlockedAddressError) as refusal:
            client.get(f"http://moving.test:{server.port}/after")

    assert refusal.value.address == METADATA
    assert [r.path for r in server.received] == ["/before"]


def test_a_denied_address_is_refused_before_a_socket_is_opened(server: RecordingServer) -> None:
    """The name resolves to somewhere the policy refuses, so the request never leaves."""
    resolver = Resolver(**{"metadata.test": METADATA})
    with (
        client_for(policy_for(server.port), resolver) as client,
        pytest.raises(BlockedAddressError) as refusal,
    ):
        client.get(f"http://metadata.test:{server.port}/")

    assert refusal.value.address == METADATA
    assert server.received == []


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


def test_the_port_is_checked_at_the_transport(server: RecordingServer) -> None:
    """A port the policy does not allow never reaches the network."""
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    policy = Policy(allowed_ports=frozenset({server.port + 1}), allowed_networks=LOOPBACK)
    with client_for(policy, resolver) as client, pytest.raises(BlockedURLError) as refusal:
        client.get(f"http://pinned.test:{server.port}/")

    assert "allowed_ports" in refusal.value.reason
    assert server.received == []


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


def test_the_scheme_is_checked_at_the_transport(server: RecordingServer) -> None:
    """A backend never learns the scheme, so the transport is where a scheme is decided."""
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    policy = policy_for(server.port, allowed_schemes=frozenset({"https"}))
    with client_for(policy, resolver) as client, pytest.raises(BlockedURLError) as refusal:
        client.get(f"http://pinned.test:{server.port}/")

    assert "allowed_schemes" in refusal.value.reason


def test_credentials_in_the_authority_are_refused(server: RecordingServer) -> None:
    """httpx keeps userinfo in the request URL, so the transport can see it and refuse it.

    ``http://trusted.example@127.0.0.1/`` reads as a hostname to a human and parses as one to
    nobody, which is why the policy refuses credentials in an authority by default.
    """
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    with (
        client_for(policy_for(server.port), resolver) as client,
        pytest.raises(BlockedURLError) as refusal,
    ):
        client.get(f"http://user:secret@pinned.test:{server.port}/")

    assert "allow_userinfo" in refusal.value.reason
    assert server.received == []


def test_a_literal_address_in_the_url_is_checked_too(server: RecordingServer) -> None:
    """An IPv6 literal is refused as loopback without a socket being opened."""
    with client_for(policy_for(server.port)) as client, pytest.raises(BlockedURLError) as refusal:
        client.get(f"http://[::1]:{server.port}/")

    assert "loopback" in refusal.value.reason.lower()


# ---------------------------------------------------------------------------------------------
# Failures that are the network's, not the policy's
# ---------------------------------------------------------------------------------------------


def test_a_name_that_does_not_resolve_fails_the_way_httpx_users_expect(
    server: RecordingServer,
) -> None:
    """A DNS failure is not a policy decision and must not arrive dressed as one."""
    with (
        client_for(policy_for(server.port), Resolver()) as client,
        pytest.raises(httpx.ConnectError),
    ):
        client.get(f"http://nowhere.test:{server.port}/")


def test_a_refused_connection_fails_the_way_httpx_users_expect() -> None:
    """So is a closed port."""
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = int(closed.getsockname()[1])
    closed.close()

    resolver = Resolver(**{"closed.test": "127.0.0.1"})
    with client_for(policy_for(port), resolver) as client, pytest.raises(httpx.ConnectError):
        client.get(f"http://closed.test:{port}/")


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


def test_the_handshake_carries_the_hostname_and_not_the_pinned_address(
    tls_server: RecordingServer, trusted: ssl.SSLContext
) -> None:
    """Read off the wire: the server was asked for ``right.test``, not for an address.

    Python will not put an IP literal in the ``server_name`` extension, so a client pinned by
    rewriting its origin would have sent no name at all.
    """
    resolver = Resolver(**{"right.test": "127.0.0.1"})
    with client_for(policy_for(tls_server.port), resolver, verify=trusted) as client:
        response = client.get(f"https://right.test:{tls_server.port}/tls")

    assert response.status_code == 200
    received = tls_server.received[-1]
    assert received.sni == "right.test"
    assert received.host == f"right.test:{tls_server.port}"


def test_a_certificate_issued_to_another_name_is_still_refused(
    tls_server: RecordingServer, trusted: ssl.SSLContext
) -> None:
    """Pinning must not buy a way past hostname verification."""
    resolver = Resolver(**{"wrong.test": "127.0.0.1"})
    with (
        client_for(policy_for(tls_server.port), resolver, verify=trusted) as client,
        pytest.raises(httpx.ConnectError) as refusal,
    ):
        client.get(f"https://wrong.test:{tls_server.port}/")

    assert "Hostname mismatch" in str(refusal.value) or "wrong.test" in str(refusal.value)
    assert tls_server.received == []


def test_an_untrusted_authority_is_still_refused(tls_server: RecordingServer) -> None:
    """And nothing about pinning loosens the chain check either."""
    resolver = Resolver(**{"right.test": "127.0.0.1"})
    with (
        client_for(policy_for(tls_server.port), resolver) as client,
        pytest.raises(httpx.ConnectError),
    ):
        client.get(f"https://right.test:{tls_server.port}/")

    assert tls_server.received == []


# ---------------------------------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------------------------------


def test_a_redirect_re_enters_the_seam(server: RecordingServer) -> None:
    """httpx picks a transport per hop, so every hop is checked and every hop is pinned."""
    resolver = Resolver(**{"hop.test": "127.0.0.1", "metadata.test": METADATA})
    server.routes["/redirect"] = (
        302,
        {"Location": f"http://metadata.test:{server.port}/"},
        b"",
    )

    transport = SafeTransport(policy=policy_for(server.port), resolver=resolver)
    with (
        httpx.Client(transport=transport, follow_redirects=True) as client,
        pytest.raises(BlockedAddressError) as refusal,
    ):
        client.get(f"http://hop.test:{server.port}/redirect")

    assert refusal.value.address == METADATA
    assert [r.path for r in server.received] == ["/redirect"]
    assert resolver.asked == ["hop.test", "metadata.test"]


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
