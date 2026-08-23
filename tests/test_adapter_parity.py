"""One matrix, all three client surfaces, so the two seams cannot drift apart.

httpx is pinned at ``httpcore``'s network backend and requests at ``urllib3``'s ``_new_conn``.
The two share no code and nothing structural keeps them honest, so every guarantee that is
supposed to hold of *this package* rather than of one client is asserted here, once, against
both. A behaviour fixed in one adapter and not the other shows up as a failure in this file
rather than as a bug report saying one of them allows something the other refuses.

**The asymmetries are a list, not an assumption.** Two guarantees genuinely do not cross, and
each has a test below asserting that it still does not -- so an exception is visible rather than
inferred from a suite that quietly only tests one side:

1. *A unix socket is refused only where one can be asked for.* httpx takes ``uds=`` and httpcore
   has ``connect_unix_socket``; urllib3 has no unix-socket path at all, so requests has nothing
   to refuse rather than something it fails to.
2. *The low-level object is enough for requests and not for httpx.* ``SafeAdapter`` is handed
   the merged proxy mapping by requests and can refuse it alone. ``SafeTransport`` cannot: httpx
   builds a second transport for an explicit ``proxy=`` and never consults ours, which is why
   the httpx surface needs a client and the requests surface does not.

Anything else that differs is a defect, and the way to add a guarantee is to add it here.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Iterator

import httpx
import pytest
import requests
import trustme
import urllib3.poolmanager

from ssrfguard import BlockedAddressError, BlockedURLError, Policy, SSRFGuardError
from ssrfguard.httpx import SafeBackend, SafeTransport
from ssrfguard.requests import SafeAdapter

from .adapters_under_test import ADAPTER_IDS, ADAPTERS, Adapter, Trust
from .loopback_http import RecordingServer
from .stub_resolver import Resolver

pytestmark = [pytest.mark.httpx_adapter, pytest.mark.requests_adapter]

LOOPBACK = ("127.0.0.0/8",)
METADATA = "169.254.169.254"

#: What a refused handshake arrives as. The two clients wrap the same `ssl` failure in their
#: own exception, and which one is not a guarantee this package makes -- that it is refused
#: at all is.
TLS_REFUSED = (requests.exceptions.SSLError, httpx.ConnectError)


@pytest.fixture(params=ADAPTERS, ids=ADAPTER_IDS)
def adapter(request: pytest.FixtureRequest) -> Adapter:
    """Every test in this file runs once per client.

    Args:
        request: pytest's parameter carrier.

    Returns:
        The client under test.
    """
    return request.param  # type: ignore[no-any-return]


@pytest.fixture(autouse=True)
def no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both clients refuse when the environment configures a proxy, so remove one if it does.

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
def authority(tmp_path_factory: pytest.TempPathFactory) -> tuple[trustme.CA, Trust]:
    """A throwaway certificate authority, in both spellings the clients want.

    Args:
        tmp_path_factory: pytest's per-session temporary directory factory.

    Returns:
        The authority and the trust material.
    """
    ca = trustme.CA()
    path = tmp_path_factory.mktemp("ssrfguard-parity-ca") / "ca.pem"
    ca.cert_pem.write_to_path(str(path))
    return ca, Trust(path=str(path), context=ssl.create_default_context(cafile=str(path)))


@pytest.fixture
def trust(authority: tuple[trustme.CA, Trust]) -> Trust:
    """What to hand a client so the throwaway authority is trusted.

    Args:
        authority: The session's authority.

    Returns:
        The trust material.
    """
    return authority[1]


@pytest.fixture
def tls_server(authority: tuple[trustme.CA, Trust]) -> Iterator[RecordingServer]:
    """An HTTPS server holding a certificate for ``right.test`` and nothing else.

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
    """Build a policy permitting loopback and this test's port.

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
# The pin
# ---------------------------------------------------------------------------------------------


def test_the_clients_own_connect_path_is_never_entered(
    adapter: Adapter, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two claims, both made by breaking what would have to be used if either were false.

    Each client has one function that resolves a name and opens a socket, and each seam replaces
    it -- so making that raise turns "we believe the override took" into a checked claim.

    And ``socket.getaddrinfo`` is made to refuse any host that is not already an address. That
    is the *behavioural* half and it is the one that generalises: whatever a client does
    internally, a name reaching the platform resolver is a lookup this package did not make and
    did not validate. Numeric hosts are still allowed through, because a numeric parse is not a
    lookup -- it is how an address becomes a sockaddr.
    """

    def refuse(*_args: object, **_kwargs: object) -> socket.socket:
        raise AssertionError(f"{adapter.name} connected on its own; the seam was bypassed")

    owner, attribute = adapter.native
    monkeypatch.setattr(owner, attribute, refuse)

    real_getaddrinfo = socket.getaddrinfo

    def only_addresses(host: str, port: int, *args: object, **kwargs: object) -> list[tuple]:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise AssertionError(f"{adapter.name} looked up the name {host!r}") from None
        return real_getaddrinfo(host, port, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "getaddrinfo", only_addresses)

    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    with adapter.opened(policy_for(server.port), resolver) as client:
        response = adapter.fetch(client, f"http://pinned.test:{server.port}/asked")

    assert response.status_code == 200
    assert [r.path for r in server.received] == ["/asked"]
    assert resolver.asked == ["pinned.test"]


def test_the_host_header_is_the_hostname_and_not_the_pinned_address(
    adapter: Adapter, server: RecordingServer
) -> None:
    """Neither seam rewrites a URL, so nothing downstream of one sees an address."""
    resolver = Resolver(**{"vhost.test": "127.0.0.1"})
    with adapter.opened(policy_for(server.port), resolver) as client:
        adapter.fetch(client, f"http://vhost.test:{server.port}/")

    assert server.received[-1].host == f"vhost.test:{server.port}"


def test_a_pooled_second_request_asks_nothing(adapter: Adapter, server: RecordingServer) -> None:
    """A reused connection was validated when it was opened, and is not re-resolved."""
    resolver = Resolver(**{"pooled.test": "127.0.0.1"})
    with adapter.opened(policy_for(server.port), resolver) as client:
        adapter.fetch(client, f"http://pooled.test:{server.port}/one")
        adapter.fetch(client, f"http://pooled.test:{server.port}/two")

    assert [r.path for r in server.received] == ["/one", "/two"]
    assert resolver.asked == ["pooled.test"]


# ---------------------------------------------------------------------------------------------
# TLS -- the assertion neither adapter may ever fail
# ---------------------------------------------------------------------------------------------


def test_the_handshake_carries_the_hostname_and_never_the_address(
    adapter: Adapter, tls_server: RecordingServer, trust: Trust
) -> None:
    """Read off the wire. Python will not put an IP literal in ``server_name``, so a client
    pinned by rewriting its origin would have sent no name at all -- and a certificate checked
    against an address is the one failure this package must never produce."""
    resolver = Resolver(**{"right.test": "127.0.0.1"})
    with adapter.opened(policy_for(tls_server.port), resolver, trust) as client:
        response = adapter.fetch(client, f"https://right.test:{tls_server.port}/tls")

    assert response.status_code == 200
    received = tls_server.received[-1]
    assert received.sni == "right.test"
    assert received.host == f"right.test:{tls_server.port}"


def test_a_certificate_issued_to_another_name_is_still_refused(
    adapter: Adapter, tls_server: RecordingServer, trust: Trust
) -> None:
    """Pinning must not buy a way past hostname verification, on either seam."""
    resolver = Resolver(**{"wrong.test": "127.0.0.1"})
    with (
        adapter.opened(policy_for(tls_server.port), resolver, trust) as client,
        pytest.raises(TLS_REFUSED) as refusal,
    ):
        adapter.fetch(client, f"https://wrong.test:{tls_server.port}/")

    assert "certificate" in str(refusal.value).lower()
    assert tls_server.received == []


def test_an_untrusted_authority_is_still_refused(
    adapter: Adapter, tls_server: RecordingServer
) -> None:
    """And nothing about pinning loosens the chain check either."""
    resolver = Resolver(**{"right.test": "127.0.0.1"})
    with (
        adapter.opened(policy_for(tls_server.port), resolver) as client,
        pytest.raises(TLS_REFUSED) as refusal,
    ):
        adapter.fetch(client, f"https://right.test:{tls_server.port}/")

    assert "certificate" in str(refusal.value).lower()
    assert tls_server.received == []


# ---------------------------------------------------------------------------------------------
# What gets refused, and with which error
# ---------------------------------------------------------------------------------------------


def test_a_denied_address_is_refused_before_a_socket_is_opened(
    adapter: Adapter, server: RecordingServer
) -> None:
    """The name resolves somewhere the policy refuses, so the request never leaves."""
    resolver = Resolver(**{"metadata.test": METADATA})
    with (
        adapter.opened(policy_for(server.port), resolver) as client,
        pytest.raises(BlockedAddressError) as refusal,
    ):
        adapter.fetch(client, f"http://metadata.test:{server.port}/")

    assert refusal.value.address == METADATA
    assert server.received == []


def test_a_port_outside_the_policy_is_refused(adapter: Adapter, server: RecordingServer) -> None:
    """Same refusal, same error, same field named in the reason."""
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    policy = Policy(allowed_ports=frozenset({server.port + 1}), allowed_networks=LOOPBACK)
    with adapter.opened(policy, resolver) as client, pytest.raises(BlockedURLError) as refusal:
        adapter.fetch(client, f"http://pinned.test:{server.port}/")

    assert "allowed_ports" in refusal.value.reason
    assert server.received == []


def test_a_scheme_outside_the_policy_is_refused(adapter: Adapter, server: RecordingServer) -> None:
    """A policy allowing only https refuses an http request on either client."""
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    policy = policy_for(server.port, allowed_schemes=frozenset({"https"}))
    with adapter.opened(policy, resolver) as client, pytest.raises(BlockedURLError) as refusal:
        adapter.fetch(client, f"http://pinned.test:{server.port}/")

    assert "allowed_schemes" in refusal.value.reason


def test_credentials_in_the_authority_are_refused(
    adapter: Adapter, server: RecordingServer
) -> None:
    """Both clients keep userinfo in the prepared URL, so both adapters can see it and refuse.

    Measured rather than assumed -- if either client ever moved credentials into a header before
    the URL reached us, this would stop being a guarantee that crosses and would have to become
    an entry on the asymmetry list instead.
    """
    resolver = Resolver(**{"pinned.test": "127.0.0.1"})
    # A test that credentials in an authority are refused has to contain some. The marker
    # travels with the line rather than with a line number in a baseline file.
    url = f"http://user:secret@pinned.test:{server.port}/"  # pragma: allowlist secret
    with (
        adapter.opened(policy_for(server.port), resolver) as client,
        pytest.raises(BlockedURLError) as refusal,
    ):
        adapter.fetch(client, url)

    assert "allow_userinfo" in refusal.value.reason
    assert server.received == []


def test_a_denied_literal_address_is_refused(adapter: Adapter, server: RecordingServer) -> None:
    """An address in the URL needs no resolution and is checked without one."""
    with (
        adapter.opened(policy_for(server.port), Resolver()) as client,
        pytest.raises(BlockedURLError) as refusal,
    ):
        adapter.fetch(client, f"http://[::1]:{server.port}/")

    assert "loopback" in refusal.value.reason.lower()


def test_a_network_failure_is_not_dressed_as_a_policy_refusal(
    adapter: Adapter, server: RecordingServer
) -> None:
    """A name that does not resolve is the network's answer, not the policy's.

    The exception *type* is the client's own and deliberately differs between them; what has to
    be the same is that neither reports a DNS failure as something this package refused, which
    would send a user looking for a security problem they do not have.
    """
    with (
        adapter.opened(policy_for(server.port), Resolver()) as client,
        pytest.raises((requests.ConnectionError, httpx.ConnectError)) as failure,
    ):
        adapter.fetch(client, f"http://nowhere.test:{server.port}/")

    assert not isinstance(failure.value, SSRFGuardError)


def test_a_refused_connection_is_not_dressed_as_a_policy_refusal(adapter: Adapter) -> None:
    """A closed port is the network's answer too, and arrives as the client's own error."""
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = int(closed.getsockname()[1])
    closed.close()

    resolver = Resolver(**{"closed.test": "127.0.0.1"})
    with (
        adapter.opened(policy_for(port), resolver) as client,
        pytest.raises((requests.ConnectionError, httpx.ConnectError)) as failure,
    ):
        adapter.fetch(client, f"http://closed.test:{port}/")

    assert not isinstance(failure.value, SSRFGuardError)


def test_every_new_connection_is_validated_on_its_own_merits(
    adapter: Adapter, server: RecordingServer
) -> None:
    """A pin holds for the connection it was made for, and the next one starts over.

    The record moves after the first request. Nothing can move a connection that is already
    open -- and nothing keeps the old answer alive for the next one either, which is the other
    half of being correct here.
    """
    resolver = Resolver(**{"moving.test": "127.0.0.1"})
    # `Connection: close` is how a test makes the next request open a *new* connection without
    # reaching into either client's pool: both honour it, and neither reuses the socket.
    server.routes["/before"] = (200, {"Connection": "close"}, b"ok")

    with adapter.opened(policy_for(server.port), resolver) as client:
        adapter.fetch(client, f"http://moving.test:{server.port}/before")
        resolver.answers["moving.test"] = METADATA

        with pytest.raises(BlockedAddressError) as refusal:
            adapter.fetch(client, f"http://moving.test:{server.port}/after")

    assert refusal.value.address == METADATA
    assert [r.path for r in server.received] == ["/before"]


# ---------------------------------------------------------------------------------------------
# The partial-block rule, which is a property of resolution and has to survive the adapters
# ---------------------------------------------------------------------------------------------


def test_a_name_resolving_both_ways_is_refused_whole(
    adapter: Adapter, server: RecordingServer
) -> None:
    """``on_partial_block="reject"`` is the default, and it has to reach this far.

    A name answering with one permitted and one denied address is the signature of a rebinding
    attempt rather than of a misconfiguration, so the whole name is refused -- including the
    answer that would have been fine.
    """
    resolver = Resolver(**{"both.test": ["127.0.0.1", METADATA]})
    with (
        adapter.opened(policy_for(server.port), resolver) as client,
        pytest.raises(BlockedAddressError) as refusal,
    ):
        adapter.fetch(client, f"http://both.test:{server.port}/")

    assert "signature of a DNS rebinding attempt" in refusal.value.reason
    assert server.received == []


def test_drop_keeps_the_permitted_answer(adapter: Adapter, server: RecordingServer) -> None:
    """And the documented escape hatch behaves the same way on both."""
    resolver = Resolver(**{"both.test": ["127.0.0.1", METADATA]})
    policy = policy_for(server.port, on_partial_block="drop")
    with adapter.opened(policy, resolver) as client:
        response = adapter.fetch(client, f"http://both.test:{server.port}/dropped")

    assert response.status_code == 200
    assert [r.path for r in server.received] == ["/dropped"]


# ---------------------------------------------------------------------------------------------
# The asymmetries, named and asserted
# ---------------------------------------------------------------------------------------------


def test_only_httpx_can_be_asked_for_a_unix_socket() -> None:
    """Asymmetry 1, and why it is not a gap in the requests adapter.

    httpx takes ``uds=`` and httpcore's backend interface has ``connect_unix_socket``, so there
    is something to refuse and it is refused. urllib3 routes by scheme and has no unix entry at
    all, so requests has nothing to refuse rather than something it fails to.
    """
    with pytest.raises(BlockedURLError):
        SafeTransport(policy=Policy(), uds="/var/run/nothing.sock")
    with pytest.raises(BlockedURLError):
        SafeBackend(policy=Policy()).connect_unix_socket("/var/run/nothing.sock")

    assert set(urllib3.poolmanager.pool_classes_by_scheme) == {"http", "https"}, (
        "urllib3 grew a scheme; if one of them is a unix socket, requests needs the refusal too"
    )


def test_only_requests_can_refuse_a_proxy_from_the_low_level_object(
    server: RecordingServer,
) -> None:
    """Asymmetry 2, and why the httpx surface is a client while the requests surface is not.

    requests hands the adapter the merged proxy mapping, so the adapter alone can refuse. httpx
    builds a *second* transport for an explicit ``proxy=`` and prefers it, so the guarded
    transport is never asked. That is the whole reason ``ssrfguard.httpx.Client`` exists.
    """
    adapter = SafeAdapter(policy=policy_for(server.port))
    try:
        with requests.Session() as session:
            session.mount("http://", adapter)
            with pytest.raises(SSRFGuardError):
                session.get(
                    f"http://pinned.test:{server.port}/",
                    proxies={"http": "http://127.0.0.1:9"},
                )
    finally:
        adapter.close()

    transport = SafeTransport(policy=policy_for(server.port))
    with httpx.Client(transport=transport, proxy="http://127.0.0.1:9") as client:
        routed = client._transport_for_url(httpx.URL(f"http://pinned.test:{server.port}/"))
    assert routed is not transport, "httpx stopped preferring the proxy transport; re-read this"
