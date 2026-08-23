"""Redirects, against both adapters at once.

Re-entering the seam per hop is the easy half and both clients do it for free. The hard half is
everything else, and it is the shape of CVE-2026-62240: a guard that validated once and then let
the client follow a redirect with no re-validation, so *a URL pointing at a public host that
30x-redirects to an internal address fully bypasses it*.

So this file is one matrix run against both adapters rather than two suites that agree today.
Every row here is a hop shape, and the two clients have to answer each one the same way, which
is not automatic: measured before any of this was written, requests answered a hop to ``file:``
with its own "no connection adapters were found" while httpx answered with a policy refusal, and
both capped the chain with their own counter (thirty and twenty) rather than the policy's five.

**What each client already did, measured rather than assumed**, so that what is added here is
only what was missing: both re-enter the connection seam per hop, both resolve a relative
``Location`` against the hostname URL rather than an address, and both already strip
``Authorization`` when a hop leaves the origin. What neither did was cap the chain by the
policy's number, refuse a scheme the policy does not allow with a policy error on both sides, or
drop a credential header that is a credential by convention rather than by specification.
"""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest
import requests

from ssrfguard import (
    BlockedAddressError,
    BlockedURLError,
    Policy,
    TooManyRedirectsError,
)

from .adapters_under_test import ADAPTER_IDS, ADAPTERS, Adapter
from .loopback_http import RecordingServer
from .stub_resolver import Resolver

pytestmark = [pytest.mark.httpx_adapter, pytest.mark.requests_adapter]

LOOPBACK = ("127.0.0.0/8",)
METADATA = "169.254.169.254"


@pytest.fixture(params=ADAPTERS, ids=ADAPTER_IDS)
def adapter(request: pytest.FixtureRequest) -> Adapter:
    """Each test in this file runs once per client.

    Args:
        request: pytest's parameter carrier.

    Returns:
        The client under test.
    """
    return request.param  # type: ignore[no-any-return]


@pytest.fixture(autouse=True)
def no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both clients read the environment for proxies, and both refuse when one applies.

    Args:
        monkeypatch: pytest's environment patcher.
    """
    for name in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.upper(), raising=False)


@pytest.fixture
def first() -> Iterator[RecordingServer]:
    """The origin a request starts at.

    Yields:
        The running server.
    """
    with RecordingServer() as running:
        yield running


@pytest.fixture
def second() -> Iterator[RecordingServer]:
    """A second origin, for the hops that cross one.

    Yields:
        The running server.
    """
    with RecordingServer() as running:
        yield running


def policy_for(*servers: RecordingServer, **overrides: object) -> Policy:
    """Build a policy permitting loopback and this test's ports.

    Args:
        *servers: The servers whose ports to permit.
        **overrides: Passed to :class:`ssrfguard.Policy`.

    Returns:
        The policy.
    """
    fields: dict[str, object] = {
        "allowed_ports": frozenset(server.port for server in servers),
        "allowed_networks": LOOPBACK,
    }
    fields.update(overrides)
    return Policy(**fields)  # type: ignore[arg-type]


def names(**extra: str) -> Resolver:
    """A resolver that answers for this file's names.

    Args:
        **extra: Additional name-to-address entries.

    Returns:
        The resolver.
    """
    return Resolver(**{"first.test": "127.0.0.1", "second.test": "127.0.0.1", **extra})


def chain_of(server: RecordingServer, hops: int) -> str:
    """Route ``hops`` redirects on one server and return where the chain starts.

    Args:
        server: The server to route on.
        hops: How many redirect responses the chain should contain.

    Returns:
        The URL to start at.
    """
    for step in range(hops):
        server.routes[f"/hop{step}"] = (
            302,
            {"Location": f"http://first.test:{server.port}/hop{step + 1}"},
            b"",
        )
    return f"http://first.test:{server.port}/hop0"


# ---------------------------------------------------------------------------------------------
# The hop shapes
# ---------------------------------------------------------------------------------------------


def test_a_hop_to_a_denied_address_is_refused(adapter: Adapter, first: RecordingServer) -> None:
    """The headline shape, and the one the CVE this file is about describes.

    A public host that redirects to an internal address. The first hop is served and the second
    never leaves, because every hop opens a connection and every connection validates.
    """
    first.routes["/redirect"] = (302, {"Location": f"http://metadata.test:{first.port}/"}, b"")
    resolver = names(**{"metadata.test": METADATA})

    with (
        adapter.opened(policy_for(first), resolver) as client,
        pytest.raises(BlockedAddressError) as refusal,
    ):
        adapter.fetch(client, f"http://first.test:{first.port}/redirect")

    assert refusal.value.address == METADATA
    assert [r.path for r in first.received] == ["/redirect"]


def test_a_hop_to_a_refused_scheme_is_refused_by_this_package(
    adapter: Adapter, first: RecordingServer
) -> None:
    """A hop that changes the scheme is a policy question, not a client question.

    Measured before this was written: requests answered this with `InvalidSchema`, its own
    error about its own mounts, meaning nothing about a policy, because nothing is mounted for
    `file://`. A caller catching `SSRFGuardError` would have missed it entirely.
    """
    first.routes["/tofile"] = (302, {"Location": "file:///etc/passwd"}, b"")

    with (
        adapter.opened(policy_for(first), names()) as client,
        pytest.raises(BlockedURLError) as refusal,
    ):
        adapter.fetch(client, f"http://first.test:{first.port}/tofile")

    assert "allowed_schemes" in refusal.value.reason


def test_a_loop_is_cut_by_the_policys_limit(adapter: Adapter, first: RecordingServer) -> None:
    """A redirect that points at itself, stopped at the policy's number rather than the client's.

    The counter matters as much as the cut. Both clients default to an order of magnitude more
    hops, thirty for requests and twenty for httpx, and both can be reconfigured without
    touching the policy, which is what stops their limit being a control.
    """
    policy = policy_for(first, max_redirects=3)
    first.routes["/loop"] = (302, {"Location": f"http://first.test:{first.port}/loop"}, b"")

    with (
        adapter.opened(policy, names()) as client,
        pytest.raises(TooManyRedirectsError) as refusal,
    ):
        adapter.fetch(client, f"http://first.test:{first.port}/loop")

    assert refusal.value.limit == 3
    assert len(first.received) == 4, "the chain ran past the policy's limit before it was cut"


def test_a_chain_exactly_at_the_limit_is_followed(adapter: Adapter, first: RecordingServer) -> None:
    """The other half of a limit: it has to permit what it says it permits.

    A cap that is off by one is a false refusal, and a false refusal is how a control gets
    configured around rather than fixed.
    """
    policy = policy_for(first, max_redirects=3)
    start = chain_of(first, hops=3)

    with adapter.opened(policy, names()) as client:
        response = adapter.fetch(client, start)

    assert response.status_code == 200
    assert str(response.url).endswith("/hop3")


def test_a_chain_one_past_the_limit_is_refused(adapter: Adapter, first: RecordingServer) -> None:
    """And it has to refuse what it says it refuses, naming what was walked."""
    policy = policy_for(first, max_redirects=3)
    start = chain_of(first, hops=4)

    with (
        adapter.opened(policy, names()) as client,
        pytest.raises(TooManyRedirectsError) as refusal,
    ):
        adapter.fetch(client, start)

    assert refusal.value.limit == 3
    assert len(refusal.value.chain) == 4, refusal.value.chain
    assert refusal.value.chain[0].endswith("/hop0")


def test_a_relative_location_resolves_against_the_hostname(
    adapter: Adapter, first: RecordingServer
) -> None:
    """The failure the URL-rewrite approach to pinning has, asserted absent from this one.

    A guard that pinned by rewriting the request URL to the validated address would resolve
    ``Location: /admin`` against *that*, so the next hop targets the address directly and the
    name it was checked under is gone. Nothing here rewrites a URL, so there is nothing to
    resolve against but the hostname, which is a property of the seam rather than a rule
    anybody follows.
    """
    first.routes["/rel"] = (302, {"Location": "/relative-target"}, b"")

    with adapter.opened(policy_for(first), names()) as client:
        response = adapter.fetch(client, f"http://first.test:{first.port}/rel")

    assert str(response.url) == f"http://first.test:{first.port}/relative-target"
    assert first.received[-1].host == f"first.test:{first.port}"


# ---------------------------------------------------------------------------------------------
# What a hop carries
# ---------------------------------------------------------------------------------------------


def test_a_cross_origin_hop_drops_the_policys_sensitive_headers(
    adapter: Adapter, first: RecordingServer, second: RecordingServer
) -> None:
    """Both clients already drop `Authorization`. Neither drops a credential named by convention.

    ``X-Api-Key`` is a credential because a shop decided it is, not because a specification says
    so, which is why the policy takes the name from the caller rather than this package
    guessing at a list. Measured before this was written: it travelled to the second origin
    under both clients.
    """
    policy = policy_for(first, second, sensitive_headers={"authorization", "x-api-key"})
    first.routes["/cross"] = (302, {"Location": f"http://second.test:{second.port}/landed"}, b"")
    carried = {"Authorization": "Bearer secret", "X-Api-Key": "key", "X-Trace": "keep-me"}

    with adapter.opened(policy, names()) as client:
        adapter.fetch(client, f"http://first.test:{first.port}/cross", headers=carried)

    landed = [r for r in second.received if r.path == "/landed"][-1]
    assert "authorization" not in landed.headers
    assert "x-api-key" not in landed.headers
    assert landed.headers.get("x-trace") == "keep-me", "stripping is not a reason to lose the rest"


def test_a_same_origin_hop_keeps_them(adapter: Adapter, first: RecordingServer) -> None:
    """Stripping on every hop would be a false refusal wearing a security hat.

    A redirect within one origin is the ordinary case, a trailing slash or a canonical path,
    and dropping credentials there breaks every authenticated client for no gain.
    """
    policy = policy_for(first, sensitive_headers={"authorization", "x-api-key"})
    first.routes["/same"] = (302, {"Location": f"http://first.test:{first.port}/here"}, b"")
    carried = {"Authorization": "Bearer secret", "X-Api-Key": "key"}

    with adapter.opened(policy, names()) as client:
        adapter.fetch(client, f"http://first.test:{first.port}/same", headers=carried)

    landed = [r for r in first.received if r.path == "/here"][-1]
    assert landed.headers.get("authorization") == "Bearer secret"
    assert landed.headers.get("x-api-key") == "key"


def test_a_cross_origin_hop_is_validated_like_any_other(
    adapter: Adapter, first: RecordingServer, second: RecordingServer
) -> None:
    """A hop to a second origin opens a second connection, and that connection validates.

    The name is resolved for the hop rather than carried over from the first one, which is what
    makes "the policy allowed that host for a different reason" not a way in.
    """
    resolver = names()
    policy = policy_for(first, second)
    first.routes["/cross"] = (302, {"Location": f"http://second.test:{second.port}/landed"}, b"")

    with adapter.opened(policy, resolver) as client:
        response = adapter.fetch(client, f"http://first.test:{first.port}/cross")

    assert response.status_code == 200
    assert resolver.asked == ["first.test", "second.test"]
    assert [r.path for r in second.received] == ["/landed"]
    assert second.received[-1].host == f"second.test:{second.port}"


# ---------------------------------------------------------------------------------------------
# The clients' own limits are not the control
# ---------------------------------------------------------------------------------------------


def test_the_clients_own_limit_is_not_what_stops_a_chain(
    adapter: Adapter, first: RecordingServer
) -> None:
    """Raised past the policy's number, the client's counter changes nothing.

    This is the difference between a control and a coincidence. `requests.Session.max_redirects`
    and `httpx.Client.max_redirects` are ordinary attributes; if the policy's limit were being
    served by them, moving them would move the answer.
    """
    policy = policy_for(first, max_redirects=2)
    first.routes["/loop"] = (302, {"Location": f"http://first.test:{first.port}/loop"}, b"")

    with adapter.opened(policy, names()) as client:
        client.max_redirects = 99
        with pytest.raises(TooManyRedirectsError) as refusal:
            adapter.fetch(client, f"http://first.test:{first.port}/loop")

    assert refusal.value.limit == 2
    assert len(first.received) == 3


def test_the_refusal_is_one_this_packages_users_already_catch(
    adapter: Adapter, first: RecordingServer
) -> None:
    """`except SSRFGuardError` has to cover the redirect cap, or it covers the interesting half."""
    policy = policy_for(first, max_redirects=1)
    first.routes["/loop"] = (302, {"Location": f"http://first.test:{first.port}/loop"}, b"")

    with (
        adapter.opened(policy, names()) as client,
        pytest.raises(TooManyRedirectsError) as refusal,
    ):
        adapter.fetch(client, f"http://first.test:{first.port}/loop")

    assert not isinstance(refusal.value, (requests.RequestException, httpx.HTTPError))


def _get_without_following(adapter: Adapter, client: object, url: str) -> object:
    """One request that must not follow a redirect, spelled the way each client spells it.

    Args:
        adapter: The client under test.
        client: The opened client.
        url: Where to send the request.

    Returns:
        The response.
    """
    if adapter.name == "requests":
        return client.get(url, allow_redirects=False)  # type: ignore[attr-defined]
    return client.get(url, follow_redirects=False)  # type: ignore[attr-defined]


def test_a_policy_of_zero_refuses_a_redirect_it_was_never_going_to_follow(
    adapter: Adapter, first: RecordingServer
) -> None:
    """The boundary, pinned because it is defensible *and* surprising.

    `max_redirects=0` reads as "do not follow redirects" and means "a redirect is refused". Even
    with following switched off at the call, a single 302 raises, because both clients build
    the next request in order to expose it (`response.next_request` on httpx,
    `response.next` on requests) and the cap fires on the build rather than on the send.

    **The two agree, so this is not a parity bug.** It is a semantic that would otherwise be
    rediscovered and "fixed" by somebody who did not know it had been decided. A caller who wants
    the 302 back leaves the cap alone and switches following off at the call, which the test
    below this one is.
    """
    first.routes["/hop0"] = (302, {"Location": f"http://first.test:{first.port}/landed"}, b"")
    first.routes["/landed"] = (200, {}, b"ok")
    policy = policy_for(first, max_redirects=0)

    with adapter.opened(policy, names()) as client, pytest.raises(TooManyRedirectsError):
        _get_without_following(adapter, client, f"http://first.test:{first.port}/hop0")

    assert [r.path for r in first.received] == ["/hop0"], "the hop must not have been sent"


def test_a_redirect_comes_back_unfollowed_when_the_cap_permits_one(
    adapter: Adapter, first: RecordingServer
) -> None:
    """The other half, and the one a caller actually wants.

    With the cap left alone and following switched off at the call, the 302 is returned rather
    than raised, and the hop is still not sent. This is the shape the sentence on
    `Policy.max_redirects` points callers at, so it is asserted rather than described.
    """
    first.routes["/hop0"] = (302, {"Location": f"http://first.test:{first.port}/landed"}, b"")
    first.routes["/landed"] = (200, {}, b"ok")

    with adapter.opened(policy_for(first), names()) as client:
        response = _get_without_following(adapter, client, f"http://first.test:{first.port}/hop0")

    assert response.status_code == 302  # type: ignore[attr-defined]
    assert [r.path for r in first.received] == ["/hop0"], "the hop must not have been sent"
