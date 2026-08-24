"""Every decision, and the three rules that make reporting one safe.

The record itself is small. What this file is mostly about is the three ways an observer could
make things worse than having none, because each of them is a way a logging feature turns into a
security defect:

* **It could fail a request.** A sink that throws on a *permitted* URL turns an allow into a
  deny, and the message names a logging bug rather than the request that died. That is the worst
  of the three and it has the most tests.
* **It could leak the credentials it was written to help you notice.** A record is exactly the
  place this package already warns about, "where they reach logs, hooks and retry keys".
* **It could cost something when nobody asked for it.** A default path that builds records for a
  `None` observer is a tax on every caller who wanted none.

The stage-by-stage coverage below is ordinary. The three above are the point.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from ipaddress import ip_address
from unittest import mock

import pytest

from ssrfguard import (
    Address,
    BlockedAddressError,
    BlockedURLError,
    Decision,
    Policy,
    _observer,
    _policy,
    _resolve,
    connect,
    resolve,
)
from ssrfguard import _connect as connect_module
from ssrfguard._observer import redacted, report

from .stub_resolver import Resolver

#: Permits loopback so a peer decision can be made against a socket that really connected.
LOOPBACK = Policy(allowed_networks=("127.0.0.0/8",), allowed_ports=frozenset({80, 443}))


class Sink:
    """An observer that keeps what it was handed."""

    def __init__(self) -> None:
        self.seen: list[Decision] = []

    def __call__(self, decision: Decision) -> None:
        self.seen.append(decision)

    def at(self, stage: str) -> list[Decision]:
        """Every decision recorded at one stage."""
        return [decision for decision in self.seen if decision.stage == stage]


@pytest.fixture
def listener() -> Iterator[tuple[str, int]]:
    """A TCP listener on loopback.

    Yields:
        Its address and port.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    host, port = server.getsockname()[0], int(server.getsockname()[1])
    try:
        yield str(host), port
    finally:
        server.close()


def address_for(host: str, port: int, hostname: str = "pinned.test") -> Address:
    """Build a validated-looking address without resolving anything."""
    return Address(
        family=socket.AF_INET,
        sockaddr=(host, port),
        ip=ip_address(host),
        hostname=hostname,
    )


# ---------------------------------------------------------------------------
# Rule one, and the reason this module swallows what it otherwise never would.
# ---------------------------------------------------------------------------


class Exploding:
    """An observer that raises on everything, which is the shape of a sink with a bug in it."""

    def __init__(self, exception: BaseException | None = None) -> None:
        self.exception = exception or RuntimeError("the sink is broken")
        self.calls = 0

    def __call__(self, decision: Decision) -> None:
        self.calls += 1
        raise self.exception


def test_an_observer_that_raises_does_not_fail_a_permitted_url() -> None:
    """**The most important test in this file.**

    A sink with a bug in it must not turn an allow into a deny. That failure would arrive as a
    refused request whose cause is a logging error, and it would be indistinguishable from the
    policy working.
    """
    sink = Exploding()
    target = Policy().check_url("https://example.com/a", observer=sink)
    assert target.host == "example.com"
    assert sink.calls == 1, "the observer was not called at all, so this proves nothing"


def test_an_observer_that_raises_does_not_change_a_refusal() -> None:
    """The other direction: a broken sink may not turn a deny into something else either."""
    sink = Exploding()
    with pytest.raises(BlockedURLError, match="scheme"):
        Policy().check_url("ftp://example.com/", observer=sink)
    assert sink.calls == 1


def test_an_observer_that_raises_does_not_fail_resolution() -> None:
    sink = Exploding()
    policy = Policy()
    target = policy.check_url("https://example.com/")
    resolver = Resolver(**{"example.com": "1.1.1.1"})
    addresses = resolve(target, policy=policy, resolver=resolver, observer=sink)
    assert [str(a.ip) for a in addresses] == ["1.1.1.1"]
    assert sink.calls == 1


def test_an_observer_that_raises_does_not_fail_a_connection(
    listener: tuple[str, int],
) -> None:
    sink = Exploding()
    host, port = listener
    with connect([address_for(host, port)], policy=LOOPBACK, observer=sink) as sock:
        assert sock.getpeername()[0] == host
    assert sink.calls == 1


@pytest.mark.parametrize(
    "exception",
    [RuntimeError("boom"), ValueError("boom"), TypeError("boom"), AttributeError("boom")],
    ids=lambda e: type(e).__name__,
)
def test_no_ordinary_exception_from_a_sink_escapes(exception: Exception) -> None:
    """`Exception` and not one named class, because a sink is somebody else's code."""
    report(Exploding(exception), Decision(stage="url", outcome="permitted"))


@pytest.mark.parametrize("exception", [KeyboardInterrupt(), SystemExit(1)], ids=["ctrl-c", "exit"])
def test_a_process_being_torn_down_still_travels(exception: BaseException) -> None:
    """**Not everything is swallowed, and the line is deliberate.**

    `KeyboardInterrupt` and `SystemExit` are not a sink misbehaving; they are the process going
    away. Swallowing those would make a request hang on after the interpreter was asked to stop.
    """
    with pytest.raises(type(exception)):
        report(Exploding(exception), Decision(stage="url", outcome="permitted"))


# ---------------------------------------------------------------------------
# Rule two: a record may not carry what it was written to help you notice.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://user:hunter2@example.com/a",  # pragma: allowlist secret
            "https://[redacted]@example.com/a",
        ),
        ("http://user@example.com/", "http://[redacted]@example.com/"),
        ("http://user:pw@example.com", "http://[redacted]@example.com"),  # pragma: allowlist secret
        (
            "http://user:pw@example.com?q=1",  # pragma: allowlist secret
            "http://[redacted]@example.com?q=1",
        ),  # pragma: allowlist secret
        ("http://a:b@c:d@example.com/x", "http://[redacted]@example.com/x"),
        ("https://example.com/a", "https://example.com/a"),
        # A path that carries its own `//`. Splitting on the *last* one instead of the first
        # would take the authority from the wrong side of the URL.
        (
            "http://user:pw@example.com//a",  # pragma: allowlist secret
            "http://[redacted]@example.com//a",
        ),
        ("http://example.com//a", "http://example.com//a"),
        ("https://example.com/a@b", "https://example.com/a@b"),
        ("", ""),
        ("not a url", "not a url"),
        ("http://", "http://"),
    ],
)
def test_credentials_never_reach_a_record(url: str, expected: str) -> None:
    assert redacted(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://user:hunter2@example.com/a",  # pragma: allowlist secret
        "https://user:hunter2@127.0.0.1/a",  # pragma: allowlist secret
        "gopher://user:hunter2@example.com/",  # pragma: allowlist secret
        "https://user:hunter2@" + "x" * 9000,  # pragma: allowlist secret
    ],
)
def test_no_password_survives_into_a_reported_decision(url: str) -> None:
    """**Every one of these is refused**, which is the interesting half.

    A refusal is where a URL is most likely to be logged and least likely to have been parsed,
    so redaction has to run on inputs no parser accepts.
    """
    sink = Sink()
    with pytest.raises((BlockedURLError, BlockedAddressError)):
        Policy().check_url(url, observer=sink)
    assert sink.seen, "nothing was reported, so this asserts nothing"
    assert all("hunter2" not in (d.url or "") for d in sink.seen)


def test_a_permitted_url_carrying_credentials_is_still_redacted() -> None:
    """`allow_userinfo=True` permits them into the request. It does not permit them into a log."""
    sink = Sink()
    policy = Policy(allow_userinfo=True)
    policy.check_url(
        "https://user:hunter2@example.com/a",  # pragma: allowlist secret
        observer=sink,  # pragma: allowlist secret
    )  # pragma: allowlist secret
    assert sink.seen[0].outcome == "permitted"
    assert sink.seen[0].url == "https://[redacted]@example.com/a"


# ---------------------------------------------------------------------------
# Rule three: nobody listening costs nothing.
# ---------------------------------------------------------------------------


def counting(module: object) -> mock._patch[mock.MagicMock]:
    """Patch a module's `Decision` so constructions can be counted."""
    return mock.patch.object(module, "Decision", wraps=_observer.Decision)


def test_no_record_is_built_for_a_url_when_nobody_is_listening() -> None:
    with counting(_policy) as built:
        Policy().check_url("https://example.com/a")
    assert built.call_count == 0


def test_no_record_is_built_for_a_refusal_when_nobody_is_listening() -> None:
    with counting(_policy) as built, pytest.raises(BlockedURLError):
        Policy().check_url("ftp://example.com/")
    assert built.call_count == 0


def test_no_record_is_built_while_resolving_when_nobody_is_listening() -> None:
    policy = Policy()
    target = policy.check_url("https://example.com/")
    resolver = Resolver(**{"example.com": ["1.1.1.1", "8.8.8.8"]})
    with counting(_resolve) as built:
        resolve(target, policy=policy, resolver=resolver)
    assert built.call_count == 0


def test_no_record_is_built_while_connecting_when_nobody_is_listening(
    listener: tuple[str, int],
) -> None:
    host, port = listener
    with (
        counting(connect_module) as built,
        connect([address_for(host, port)], policy=LOOPBACK) as sock,
    ):
        assert sock.getpeername()[0] == host
    assert built.call_count == 0


# ---------------------------------------------------------------------------
# What each stage reports.
# ---------------------------------------------------------------------------


def test_a_permitted_url_is_reported_with_what_it_resolved_to_be() -> None:
    sink = Sink()
    Policy().check_url("https://example.com:443/a?b=c", observer=sink)
    (decision,) = sink.at("url")
    assert (decision.outcome, decision.host, decision.port) == ("permitted", "example.com", 443)
    assert decision.url == "https://example.com:443/a?b=c"
    assert decision.reason is None, "a permit has no rule that approved it"


@pytest.mark.parametrize(
    ("url", "names"),
    [
        ("ftp://example.com/", "scheme"),
        ("https://example.com:22/", "port"),
        ("https://user:pw@example.com/", "credentials"),  # pragma: allowlist secret
        ("http://169.254.169.254/", "169.254.169.254"),
    ],
)
def test_a_refused_url_is_reported_with_the_rule_that_refused_it(url: str, names: str) -> None:
    """The record carries the same sentence the exception does, for the same reason."""
    sink = Sink()
    with pytest.raises((BlockedURLError, BlockedAddressError)) as refusal:
        Policy().check_url(url, observer=sink)
    (decision,) = sink.at("url")
    assert decision.outcome == "refused"
    assert names in (decision.reason or "")
    assert (decision.reason or "") in str(refusal.value)


def test_a_literal_address_is_carried_on_the_record() -> None:
    sink = Sink()
    Policy(allowed_networks=("1.0.0.0/8",)).check_url("http://1.1.1.1/", observer=sink)
    assert sink.at("url")[0].address == ip_address("1.1.1.1")


def test_every_address_a_name_resolves_to_is_one_decision() -> None:
    """**One record per address, not one per name.** Which of four was refused is the point."""
    sink = Sink()
    policy = Policy(on_partial_block="drop")
    target = policy.check_url("https://mixed.test/")
    resolver = Resolver(**{"mixed.test": ["1.1.1.1", "169.254.169.254", "8.8.8.8"]})
    resolve(target, policy=policy, resolver=resolver, observer=sink)

    recorded = [(str(d.address), d.outcome) for d in sink.at("address")]
    assert recorded == [
        ("1.1.1.1", "permitted"),
        ("169.254.169.254", "refused"),
        ("8.8.8.8", "permitted"),
    ]
    assert all(d.host == "mixed.test" for d in sink.at("address"))


def test_a_refused_address_names_the_block_that_refused_it() -> None:
    sink = Sink()
    policy = Policy()
    target = policy.check_url("https://internal.test/")
    resolver = Resolver(**{"internal.test": "169.254.169.254"})
    with pytest.raises(BlockedAddressError):
        resolve(target, policy=policy, resolver=resolver, observer=sink)
    (decision,) = sink.at("address")
    assert decision.outcome == "refused"
    # Longest prefix wins, so the /32 cloud-metadata row decides rather than the /16 link-local
    # one. Asserting the block that actually decided is the point of carrying the reason at all.
    assert "Cloud metadata" in (decision.reason or "")
    assert "169.254.169.254/32" in (decision.reason or "")


def test_the_peer_a_socket_reached_is_reported(listener: tuple[str, int]) -> None:
    sink = Sink()
    host, port = listener
    with connect([address_for(host, port)], policy=LOOPBACK, observer=sink) as sock:
        assert sock.getpeername()[0] == host
    (decision,) = sink.at("peer")
    assert (decision.outcome, str(decision.address), decision.port) == ("permitted", host, port)
    assert decision.host == "pinned.test", "the name is what TLS verifies; carry it"


# ---------------------------------------------------------------------------
# The record as a value.
# ---------------------------------------------------------------------------


def test_a_decision_is_frozen() -> None:
    decision = Decision(stage="url", outcome="permitted")
    with pytest.raises(AttributeError):
        decision.stage = "peer"  # type: ignore[misc]


def test_two_decisions_about_the_same_thing_are_equal() -> None:
    """A value, so a sink can deduplicate without writing a key by hand."""
    assert Decision(stage="url", outcome="permitted", host="a") == Decision(
        stage="url", outcome="permitted", host="a"
    )


def test_a_decision_defaults_to_carrying_nothing_it_was_not_told() -> None:
    decision = Decision(stage="url", outcome="permitted")
    assert (decision.reason, decision.url, decision.host, decision.port) == (None,) * 4
    assert (decision.address, decision.chain) == (None, ())


def test_reporting_to_nobody_is_not_an_error() -> None:
    report(None, Decision(stage="url", outcome="permitted"))


def test_a_peer_that_is_not_the_validated_address_is_reported_as_refused(
    listener: tuple[str, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The one decision made after a socket exists**, and the one an observer most wants.

    Nothing reachable through the public API triggers this: connecting to an address cannot land
    elsewhere. It fires for a transparent proxy, a redirecting firewall rule or a platform
    quirk, which is exactly the class of thing an operator finds out about from a log or not at
    all. A subclass rather than a patched instance, because `socket.socket` uses `__slots__`.
    """
    host, port = listener
    sink = Sink()

    class LyingSocket(socket.socket):
        def getpeername(self) -> tuple[str, int]:
            return ("203.0.113.9", port)

    monkeypatch.setattr(socket, "socket", LyingSocket)
    with pytest.raises(BlockedAddressError, match="rewrote the destination"):
        connect([address_for(host, port)], policy=LOOPBACK, timeout=5, observer=sink)

    (decision,) = sink.at("peer")
    assert decision.outcome == "refused"
    assert str(decision.address) == "203.0.113.9", "the record names where it actually landed"
    assert "rewrote the destination" in (decision.reason or "")
    # The name and the port matter as much as the address here: an operator reading this needs
    # to know *which request* landed somewhere else, and the address alone does not say.
    assert decision.host == "pinned.test"
    assert decision.port == port
