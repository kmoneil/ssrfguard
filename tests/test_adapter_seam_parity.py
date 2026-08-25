"""What every connection seam enforces, asserted against all three rather than against a client.

``tests/test_adapter_parity.py`` holds the guarantees that cross the three *clients*. This holds
the guarantees that cross the three *seams* underneath them, which is a different question with a
different answer: a client sees a URL and a seam sees a host and a port.

**The gap this file was written for.** ``allowed_hosts`` shipped decided in ``check_url``, which
every client calls, and the parity row asserting so drives clients. The requests seam runs the
whole URL check itself and was bound; the two httpx backends checked the port and not the host,
so a caller assembling their own ``httpcore.ConnectionPool`` -- which the class docstring invites
-- got no host narrowing and no refusal to tell them. The module docstring said the opposite.

So the rule this file encodes is: **a policy field a seam can decide, a seam decides.** The
enumeration at the bottom is what keeps that true for the next field rather than for this one.
"""

from __future__ import annotations

import dataclasses
import socket

import pytest

from ssrfguard import BlockedURLError, Policy

from .adapter_seams_under_test import LOOPBACK, SEAM_IDS, SEAMS, Seam, listener
from .stub_resolver import Resolver

#: Both extras, because the matrix drives both seams. The module also carries `adapter` in its
#: name, which is what `--ignore-glob=*adapter*.py` on the `compat` lane keys on: a marker
#: deselects a test and an ignore-glob stops the module being *imported*, and an interpreter with
#: neither client installed needs the second, because pytest imports before any marker is read.
pytestmark = [pytest.mark.httpx_adapter, pytest.mark.requests_adapter]

LISTED = "listed.test"
UNLISTED = "unlisted.test"


@pytest.fixture(params=SEAMS, ids=SEAM_IDS)
def seam(request: pytest.FixtureRequest) -> Seam:
    """One connection seam, so every test in this file runs against all three.

    Args:
        request: pytest's parameter carrier.

    Returns:
        The seam under test.
    """
    return request.param


@pytest.fixture
def server() -> socket.socket:
    """A loopback listener for the connections these tests expect to succeed.

    Yields:
        The listening socket.
    """
    sock = listener()
    yield sock
    sock.close()


def _policy(port: int, **overrides: object) -> Policy:
    """A policy that permits loopback and this test's port, and nothing else by accident.

    Args:
        port: The port the listener is on.
        **overrides: What the test is actually about.

    Returns:
        The policy.
    """
    return Policy(allowed_networks=LOOPBACK, allowed_ports=frozenset({port}), **overrides)


def _resolver() -> Resolver:
    """A resolver answering for both of this file's names, with the same address.

    The two names resolving identically is the point: any difference in outcome between them is
    the host allowlist and cannot be the address table or the network.

    Returns:
        The resolver.
    """
    return Resolver(**{LISTED: "127.0.0.1", UNLISTED: "127.0.0.1"})


def test_regression_d52_every_seam_refuses_a_host_outside_the_list(
    seam: Seam, server: socket.socket
) -> None:
    """A host the policy does not list is refused at the seam, with no client involved.

    Reds before the fix on `httpx-backend` and `httpx-async-backend`, which connected, and passes
    on `requests-connection`, which already ran the whole URL check. That asymmetry is the whole
    finding, and it is why this is parameterised rather than written against one seam.

    The refusal has to be `BlockedURLError` rather than any connection failure: a caller who
    cannot tell "I did not allow this" from "the network is down" fixes the wrong thing.
    """
    port = server.getsockname()[1]
    resolver = _resolver()

    with pytest.raises(BlockedURLError) as refusal:
        seam.reach(_policy(port, allowed_hosts=frozenset({LISTED})), resolver, UNLISTED, port)

    assert "allowed_hosts" in refusal.value.reason
    assert UNLISTED in refusal.value.reason


def test_a_listed_host_still_reaches_the_seam(seam: Seam, server: socket.socket) -> None:
    """The control, and it is not a formality: a check that refuses everything passes the row above.

    `allowed_hosts` is an allowlist, so the failure that matters as much as a wrong permit is a
    wrong deny. `CONTRIBUTING.md` says so in its own words -- a guard with false positives gets
    removed, and a removed control protects nothing.
    """
    port = server.getsockname()[1]
    seam.reach(_policy(port, allowed_hosts=frozenset({LISTED})), _resolver(), LISTED, port)


def test_a_policy_naming_no_host_narrows_nothing(seam: Seam, server: socket.socket) -> None:
    """An empty `allowed_hosts` is "no name restriction", and must stay free at the seam too.

    The default policy names no host, so this is the path almost every caller is on, and a check
    that fired on an empty set would break all of them.
    """
    port = server.getsockname()[1]
    seam.reach(_policy(port), _resolver(), UNLISTED, port)


def test_an_unlisted_host_is_refused_before_it_is_looked_up(
    seam: Seam, server: socket.socket
) -> None:
    """The refusal comes before the lookup, which is what makes it a narrowing rather than a filter.

    `tests/test_requests_adapter.py` asserts the same shape for the port, and for the same two
    reasons: a name the policy will not reach should cost no DNS query, and a lookup that happens
    anyway tells an attacker's nameserver that their URL was tried.
    """
    port = server.getsockname()[1]
    resolver = _resolver()

    with pytest.raises(BlockedURLError):
        seam.reach(_policy(port, allowed_hosts=frozenset({LISTED})), resolver, UNLISTED, port)

    assert resolver.asked == [], (
        f"{seam.name} resolved {resolver.asked} for a host it was never going to reach"
    )


def test_a_wildcard_matches_on_a_label_boundary_at_the_seam(
    seam: Seam, server: socket.socket
) -> None:
    """`evil-listed.test` must not match `*.listed.test`, at the seam as at `check_url`.

    This is `_host_is_allowed`'s own argument -- "the whole of this card is this function not
    using `endswith`" -- asserted at the layer that reaches it by a different route. A seam that
    re-derived the match rather than calling the policy is exactly how a suffix test gets
    reintroduced on one surface.
    """
    port = server.getsockname()[1]
    policy = _policy(port, allowed_hosts=frozenset({"*.listed.test"}))
    resolver = Resolver(
        **{
            "a.listed.test": "127.0.0.1",
            "evil-listed.test": "127.0.0.1",
            "listed.test": "127.0.0.1",
        }
    )

    seam.reach(policy, resolver, "a.listed.test", port)

    for refused in ("evil-listed.test", "listed.test"):
        with pytest.raises(BlockedURLError, match="allowed_hosts"):
            seam.reach(policy, resolver, refused, port)


def test_a_trailing_dot_is_the_same_name_at_the_seam(seam: Seam, server: socket.socket) -> None:
    """`listed.test.` is the absolute form of a listed name and resolves to the same place.

    httpx preserves a trailing dot into the origin and urllib3 keeps one in `_dns_host`, so this
    is a form that genuinely arrives here. Refusing it would be a wrong deny on a URL that is not
    merely legal but identical, which is the direction an allowlist fails in.
    """
    port = server.getsockname()[1]
    resolver = Resolver(**{f"{LISTED}.": "127.0.0.1", LISTED: "127.0.0.1"})
    seam.reach(_policy(port, allowed_hosts=frozenset({LISTED})), resolver, f"{LISTED}.", port)


def test_a_literal_address_is_listed_exactly_or_not_at_all(
    seam: Seam, server: socket.socket
) -> None:
    """A wildcard is a name pattern and never matches a literal, at the seam as at `check_url`.

    `_host_is_allowed` takes `literal=` for this, and a seam that did not work out whether its
    host was an address would let `*.0.1` reach `127.0.0.1`.
    """
    port = server.getsockname()[1]
    # The stub is not `getaddrinfo` and does not parse a literal, so the address has to be an
    # answer like any other name. `resolve` still passes `AI_NUMERICHOST` for it, which the stub
    # ignores; what is under test here is the allowlist, not literal handling.
    resolver = Resolver(**{"127.0.0.1": "127.0.0.1"})

    seam.reach(_policy(port, allowed_hosts=frozenset({"127.0.0.1"})), resolver, "127.0.0.1", port)

    with pytest.raises(BlockedURLError, match="allowed_hosts"):
        seam.reach(_policy(port, allowed_hosts=frozenset({"*.0.1"})), resolver, "127.0.0.1", port)


def test_every_seam_still_refuses_a_port_outside_the_list(
    seam: Seam, server: socket.socket
) -> None:
    """The field that was already enforced everywhere, held so the fix for the host did not move it.

    `_check_port` is the function the host check was added beside, and the cheapest way to break
    it is to reorder the two.
    """
    port = server.getsockname()[1]
    policy = Policy(allowed_networks=LOOPBACK, allowed_ports=frozenset({port + 1}))

    with pytest.raises(BlockedURLError, match="allowed_ports"):
        seam.reach(policy, _resolver(), LISTED, port)


# --- the enumeration, which is worth more than any row above ---------------------------------

#: Whether a connection seam can decide each `Policy` field, and what says so.
#:
#: **A seam holds a host and a port and nothing else**, so every field is either decidable there
#: or it is not, and which one has to be written down rather than left to whether anybody
#: remembered. That is the whole point of this table: `allowed_hosts` was decidable, was not
#: decided, and nothing failed for the two releases it took to notice.
#:
#: `True` means a test in this file asserts the seam enforces it. `False` carries the reason it
#: cannot be asked here, and every reason is about information a seam does not have rather than
#: about effort.
SEAM_DECIDABLE: dict[str, bool | str] = {
    "allowed_hosts": True,
    "allowed_ports": True,
    "allowed_schemes": "a backend is told a host and a port and never learns the scheme; "
    "httpcore decides whether to start TLS after connect_tcp returns",
    "allow_userinfo": "there is no authority at this layer, only a host",
    "max_url_length": "there is no URL at this layer to measure",
    "denied_networks": "decided in resolve(), against every answer, not against the host",
    "allowed_networks": "decided in resolve(), against every answer, not against the host",
    "on_partial_block": "decided in resolve(), which is the only thing holding an answer set",
    "max_connection_attempts": "decided in connect(), which is the only thing making attempts",
    "max_redirects": "a chain is the client's; a seam sees one connection and no history",
    "sensitive_headers": "there are no headers at this layer",
    "allow_proxy": "refused at construction, on the transport and the adapter, before a seam",
}


def test_every_policy_field_has_a_seam_verdict() -> None:
    """A new `Policy` field forces a decision about the seams rather than inheriting one.

    **This is the row that closes the class rather than the instance.** The three rows above
    assert `allowed_hosts` is enforced on three seams today. This asserts that the *next* field
    cannot be added without somebody saying, in this table, whether a seam can decide it, which
    is the step that was skipped when `allowed_hosts` was added: it was decidable from a host,
    the host was already the first argument at both httpx seams, and nothing anywhere had to
    notice that it was not being asked.

    Modelled on `ssrfguard.httpx._split_options`, which refuses an httpx argument it has no
    decision for rather than passing it through, and for the same reason.
    """
    declared = {field.name for field in dataclasses.fields(Policy)}
    assert set(SEAM_DECIDABLE) == declared, (
        "Policy gained or lost a field: say in SEAM_DECIDABLE whether a connection seam can "
        f"decide it. Missing: {sorted(declared - set(SEAM_DECIDABLE))}; "
        f"stale: {sorted(set(SEAM_DECIDABLE) - declared)}"
    )


#: How short a reason has to be before it is not one. A number rather than a judgement, because
#: the check is against "a seam cannot check this" being written and nothing else.
_A_REASON_WORTH_READING = 20


def test_every_undecidable_field_says_why() -> None:
    """A `False` entry with no reason is a decision nobody can review.

    `errors.py` argues that a refusal has to name the rule that refused it. The same applies to
    an exemption: "a seam cannot check this" is only useful if it says what a seam is missing.
    """
    for field, verdict in SEAM_DECIDABLE.items():
        if verdict is True:
            continue
        assert isinstance(verdict, str), (
            f"{field}'s seam verdict is neither True nor a reason, which is the one shape this "
            f"table has no meaning for"
        )
        assert len(verdict) > _A_REASON_WORTH_READING, (
            f"{field} is marked undecidable at a seam with no reason worth reading"
        )
