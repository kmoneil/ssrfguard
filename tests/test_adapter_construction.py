"""What the constructors promise, and where each argument they take actually goes.

**This file exists because a mutation run said so.** `SafeTransport.__init__` and
`AsyncSafeTransport.__init__` between them carried 63 surviving mutants, the two largest
clusters in the package by a wide margin, against zero in `_policy.py`. Every one of them was
the same two shapes:

* a declared default rewritten, `retries: int = 0` becoming `1`, `http2: bool = False` becoming
  `True`, and the suite noticing nothing;
* a forwarded argument deleted or replaced with `None`, `http1=http1` becoming `http1=None`, and
  the suite noticing nothing.

Neither shape breaks a request, which is exactly why nothing caught them. The transport still
connects; it just connects with httpcore's default instead of the caller's value, or offers a
protocol the caller turned off. **A silently ignored argument is the failure mode this whole
package is about**, one layer up: `tests/test_httpx_adapter.py` already asserts that `verify`
reaches the transport rather than being ignored, for the reason that an ignored `verify` is the
worst possible no-op. That test was right and it was alone. This is the rest of its argument.

**The defaults are asserted against httpx's own rather than against a copy of themselves.**
Restating `retries == 0` here would be a mirror: it would fail when somebody edited one number
in two places and pass whenever they edited it in one. The claim worth making is that a guarded
transport does not silently differ from the unguarded one it replaces, so the defaults are read
out of `httpx.HTTPTransport` and compared. That fails when this package drifts *and* when httpx
moves under it, and the second is the one nobody would otherwise see.

Three arguments are ours and have no httpx counterpart, and one is deliberately not inherited.
:data:`OURS` and :data:`REFUSED` name them, so an addition is a decision rather than a diff
nobody reads.
"""

from __future__ import annotations

import functools
import inspect
import ssl
from typing import Any

import httpcore
import httpx
import pytest

from ssrfguard import BlockedURLError, Policy, ProxyUnsupportedError
from ssrfguard.httpx import (
    _HTTPX_DEFAULT_LIMITS,
    _RESOLVER_SLOTS,
    AsyncSafeTransport,
    SafeTransport,
    _resolver_slots_for,
)

pytestmark = pytest.mark.httpx_adapter

#: Arguments this package adds. They have no counterpart on the httpx class, so the signature
#: comparison excludes them rather than reporting them as drift every run.
#:
#: **This set is the decision, and the test below is what makes adding to it deliberate.**
#: `observer` joined it when decisions gained somewhere to go; every entry here is a surface
#: this package owns and has to keep working across four constructors.
OURS = frozenset({"policy", "resolver", "resolver_slots", "observer"})

#: Taken and always refused, so it has no forwarding to assert. httpx would open one.
REFUSED = frozenset({"uds"})

#: Where the two signatures differ on purpose, and why. `None` here means "whatever httpx would
#: have done", which is a different *spelling* of the same default rather than a different
#: default, so comparing the declared values would report drift that is not there. What matters
#: is the value it resolves to, and that is asserted on the pool itself below, where the bug
#: this file found actually lived.
DELIBERATE = {"limits": "None means httpx's own default; the resolved value is asserted instead"}

#: Arguments forwarded to `httpcore.ConnectionPool`, each with a value nothing else would
#: produce. A default would be indistinguishable from the argument being dropped, which is the
#: mutant being hunted, so every value here is deliberately *not* the default.
POOL_FORWARDS: tuple[tuple[str, Any], ...] = (
    ("http1", False),
    ("http2", True),
    ("local_address", "127.0.0.1"),
    ("retries", 3),
    ("socket_options", [(6, 1, 1)]),
)

#: The three the pool takes from `limits` rather than from a same-named argument. Dropping one
#: leaves httpcore's own default in place, which is a different pool from the one configured.
LIMIT_FORWARDS = ("max_connections", "max_keepalive_connections", "keepalive_expiry")

TRANSPORTS = (SafeTransport, AsyncSafeTransport)
TRANSPORT_IDS = ("sync", "async")
POOLS = {SafeTransport: "ConnectionPool", AsyncSafeTransport: "AsyncConnectionPool"}
UNGUARDED = {SafeTransport: httpx.HTTPTransport, AsyncSafeTransport: httpx.AsyncHTTPTransport}


def defaults(callable_: Any) -> dict[str, Any]:
    """Every keyword argument a callable takes, and what it defaults to.

    Args:
        callable_: The function or class whose signature to read.

    Returns:
        Argument name to default value, skipping those with no default.
    """
    return {
        name: parameter.default
        for name, parameter in inspect.signature(callable_).parameters.items()
        if parameter.default is not inspect.Parameter.empty
    }


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> dict[str, dict[str, Any]]:
    """Record the keyword arguments the constructors below hand to the things they wrap.

    **Spying rather than reading the object back**, because the two failures being hunted look
    different from the outside and identical from a getter: an argument that was dropped and an
    argument that arrived as `None` both leave the pool holding httpcore's default. What the
    call *said* is the thing that differs, so that is what is recorded.

    Args:
        monkeypatch: pytest's patcher.

    Returns:
        A mapping filled in as each wrapped constructor is called.
    """
    seen: dict[str, dict[str, Any]] = {}

    def spy(name: str, original: Any) -> Any:
        def recorder(*arguments: Any, **keywords: Any) -> Any:
            seen[name] = keywords
            return original(*arguments, **keywords)

        return recorder

    for pool in ("ConnectionPool", "AsyncConnectionPool"):
        monkeypatch.setattr(httpcore, pool, spy(pool, getattr(httpcore, pool)))
    monkeypatch.setattr(httpx, "create_ssl_context", spy("ssl_context", httpx.create_ssl_context))
    return seen


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
def test_every_default_is_the_one_httpx_would_have_used(transport: type) -> None:
    """A guarded transport must not silently differ from the unguarded one it replaces.

    Asserted against httpx rather than against a restatement of our own numbers, so this fails
    both when this package drifts and when httpx moves underneath it. `http2=False` is the one
    worth naming: it is off because that is httpx's default, not because of any doubt about the
    pin, and this is the row that keeps those two reasons from being confused.

    Args:
        transport: The guarded class under test.
    """
    ours = defaults(transport.__init__)
    theirs = defaults(UNGUARDED[transport].__init__)
    shared = (set(ours) & set(theirs)) - set(DELIBERATE)

    assert shared, "the two signatures share nothing, so this comparison proves nothing"
    differing = {name: (ours[name], theirs[name]) for name in shared if ours[name] != theirs[name]}
    assert not differing, (
        f"{transport.__name__} defaults differ from {UNGUARDED[transport].__name__}: "
        f"{differing}. A guarded transport that configures itself differently from the "
        f"unguarded one is a surprise nobody asked for; if the difference is deliberate, say "
        f"so here"
    )


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
def test_the_signature_carries_everything_httpx_takes(transport: type) -> None:
    """An argument httpx grows and this does not is a caller who has to stop using the guard.

    Args:
        transport: The guarded class under test.
    """
    missing = set(defaults(UNGUARDED[transport].__init__)) - set(defaults(transport.__init__))

    assert missing <= REFUSED, (
        f"{transport.__name__} does not take {sorted(missing - REFUSED)}, which "
        f"{UNGUARDED[transport].__name__} does. A guarded transport that cannot be configured "
        f"the way the unguarded one can sends people back to the unguarded one"
    )


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
def test_the_arguments_we_added_are_the_ones_we_meant_to_add(transport: type) -> None:
    """The other direction, so growing the surface is a decision rather than an accident.

    Args:
        transport: The guarded class under test.
    """
    extra = set(defaults(transport.__init__)) - set(defaults(UNGUARDED[transport].__init__))

    assert extra <= OURS, (
        f"{transport.__name__} takes {sorted(extra - OURS)}, which httpx does not and OURS does "
        f"not name. Add it there with a reason, or take it out"
    )


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
@pytest.mark.parametrize(("argument", "value"), POOL_FORWARDS, ids=[n for n, _ in POOL_FORWARDS])
def test_an_argument_reaches_the_pool_that_pins(
    transport: type, argument: str, value: Any, captured: dict[str, dict[str, Any]]
) -> None:
    """Every argument the caller set arrives at the pool, carrying the value they set.

    **The pool is built twice over.** `super().__init__` builds httpx's own, and then this
    package replaces it with one holding the pinning backend. An argument forwarded to the
    first and dropped from the second reaches nothing that ends up being used, and the request
    still succeeds with httpcore's default in its place. That is the whole failure mode.

    Args:
        transport: The guarded class under test.
        argument: The keyword to set.
        value: What to set it to, chosen so no default could be mistaken for it.
        captured: The spy, from the fixture.
    """
    transport(policy=Policy(), **{argument: value})

    pool = captured[POOLS[transport]]
    assert argument in pool, (
        f"{transport.__name__} never handed {argument!r} to the pinning pool, so the pool it "
        f"pins with is configured differently from the one the caller asked for"
    )
    assert pool[argument] == value, (
        f"{transport.__name__} handed the pinning pool {argument}={pool[argument]!r} when the "
        f"caller asked for {value!r}"
    )


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
@pytest.mark.parametrize("argument", LIMIT_FORWARDS)
def test_the_pool_limits_reach_the_pool_that_pins(
    transport: type, argument: str, captured: dict[str, dict[str, Any]]
) -> None:
    """`limits` is unpacked into three pool arguments, and each is dropped independently.

    Args:
        transport: The guarded class under test.
        argument: The pool keyword the limit is unpacked into.
        captured: The spy, from the fixture.
    """
    limits = httpx.Limits(max_connections=7, max_keepalive_connections=3, keepalive_expiry=11.0)
    transport(policy=Policy(), limits=limits)

    pool = captured[POOLS[transport]]
    assert pool.get(argument) == getattr(limits, argument), (
        f"{transport.__name__} handed the pinning pool {argument}={pool.get(argument)!r} when "
        f"limits said {getattr(limits, argument)!r}. A pool bounded differently from the limits "
        f"the caller set is a second queue nobody configured"
    )


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
def test_the_pinning_backend_is_what_the_pool_gets(
    transport: type, captured: dict[str, dict[str, Any]]
) -> None:
    """The one argument whose loss would remove the guard rather than misconfigure it.

    Args:
        transport: The guarded class under test.
        captured: The spy, from the fixture.
    """
    transport(policy=Policy())

    backend = captured[POOLS[transport]].get("network_backend")
    assert backend is not None, f"{transport.__name__} built a pool with no pinning backend"
    assert type(backend).__name__.endswith("SafeBackend"), (
        f"{transport.__name__} pinned with {type(backend).__name__}, which is not ours"
    )


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
def test_all_three_tls_arguments_reach_the_context_that_is_built(
    transport: type, captured: dict[str, dict[str, Any]]
) -> None:
    """`verify`, `cert` and `trust_env` build one context, and each can be dropped alone.

    The context is built once here and handed to both the httpx transport and the pinning pool,
    so a dropped argument silently produces a *different* TLS configuration from the one asked
    for, on every connection, with no error anywhere.

    Args:
        transport: The guarded class under test.
        captured: The spy, from the fixture.
    """
    context = ssl.create_default_context()
    transport(policy=Policy(), verify=context, cert=None, trust_env=False)

    built = captured["ssl_context"]
    assert built.get("verify") is context, "verify did not reach create_ssl_context"
    assert "cert" in built, "cert did not reach create_ssl_context"
    assert built.get("trust_env") is False, "trust_env did not reach create_ssl_context"


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
def test_the_built_context_is_what_the_pinning_pool_verifies_with(
    transport: type, captured: dict[str, dict[str, Any]]
) -> None:
    """A pool verifying with something other than the context the caller configured.

    Args:
        transport: The guarded class under test.
        captured: The spy, from the fixture.
    """
    context = ssl.create_default_context()
    transport(policy=Policy(), verify=context)

    assert captured[POOLS[transport]].get("ssl_context") is context, (
        f"{transport.__name__} pins with a pool verifying against something other than the "
        f"context built from the caller's verify, cert and trust_env"
    )


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
def test_a_unix_socket_refusal_names_the_socket(transport: type) -> None:
    """Every message names the value and the rule that refused it, and this one named neither.

    A refusal that says only "unix sockets are not supported" leaves a caller with several
    configured to find out which one this was about.

    Args:
        transport: The guarded class under test.
    """
    with pytest.raises(BlockedURLError) as refusal:
        transport(policy=Policy(), uds="/run/docker.sock")

    assert "/run/docker.sock" in str(refusal.value), (
        "the refusal does not name the socket it refused"
    )


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
def test_the_transcribed_httpx_limits_are_still_httpxs_own(transport: type) -> None:
    """`_HTTPX_DEFAULT_LIMITS` is three numbers copied out of httpx, so it can go stale.

    Transcribed rather than imported, because `httpx._config.DEFAULT_LIMITS` is private and
    reading the signature at import time would put `inspect` on the import path of a package
    that measures what importing it costs. The cost of transcribing is that httpx can move
    underneath it, and this is what turns that into a failing test rather than a silent change
    in what a guarded transport does.

    Args:
        transport: The guarded class whose httpx counterpart declares the default.
    """
    theirs = defaults(UNGUARDED[transport].__init__)["limits"]

    assert theirs == _HTTPX_DEFAULT_LIMITS, (
        f"httpx now defaults {UNGUARDED[transport].__name__} to {theirs}, and ssrfguard still "
        f"transcribes {_HTTPX_DEFAULT_LIMITS}. Re-read the seam and update the constant"
    )


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
def test_regression_unbounded_pool_a_guarded_transport_is_bounded_like_an_unguarded_one(
    transport: type, captured: dict[str, dict[str, Any]]
) -> None:
    """The pinning pool was unbounded by default, where httpx's is bounded at 100 and 20.

    **`httpx.Limits()` is not httpx's default `Limits`.** Its no-argument constructor yields
    `max_connections=None, max_keepalive_connections=None`, and `limits = httpx.Limits() if
    limits is None else limits` therefore built the pinning pool with no ceiling at all. A
    caller who passed no `limits`, which is every caller who has not thought about it, got a
    guarded transport that would open connections without limit where the unguarded one it
    replaces stops at a hundred. Less bounded, from the class whose entire subject is what a
    request is allowed to reach.

    It had a second consequence, quieter than the first. `_resolver_slots_for` prefers the
    pool's own `max_connections` and falls back to `_RESOLVER_SLOTS` "for a pool that declares
    no limit". With the limit always `None`, the preferred branch never ran, and the fallback
    was load-bearing while reading as an edge case.

    Found by a test written to kill mutants rather than to find a bug, which is the argument for
    the mutation lane in one line.

    Args:
        transport: The guarded class under test.
        captured: The spy, from the fixture.
    """
    transport(policy=Policy())
    pool = captured[POOLS[transport]]
    theirs = defaults(UNGUARDED[transport].__init__)["limits"]

    assert pool["max_connections"] == theirs.max_connections == 100, (
        f"the pinning pool caps connections at {pool['max_connections']!r} where httpx caps at "
        f"{theirs.max_connections!r}; None means no cap at all"
    )
    assert pool["max_keepalive_connections"] == theirs.max_keepalive_connections == 20, (
        f"the pinning pool caps keepalive connections at "
        f"{pool['max_keepalive_connections']!r} where httpx caps at "
        f"{theirs.max_keepalive_connections!r}"
    )


def test_regression_unbounded_pool_the_resolver_takes_its_slots_from_the_pool() -> None:
    """The consequence above, asserted where it lives.

    `_resolver_slots_for` documents preferring the pool's own figure, because a resolver bound
    tighter than the pool is a second queue nobody configured. That branch was unreachable at
    the default, so this pins that the default now reaches it: 100 arrives *from the limits*
    rather than from the fallback, and a caller who sets limits gets their own number.
    """
    assert _resolver_slots_for(_HTTPX_DEFAULT_LIMITS, None) == 100
    assert _resolver_slots_for(httpx.Limits(max_connections=7), None) == 7
    assert _resolver_slots_for(httpx.Limits(max_connections=None), None) == _RESOLVER_SLOTS
    assert _resolver_slots_for(_HTTPX_DEFAULT_LIMITS, 3) == 3


#: What is forwarded to `httpx`'s own transport through `super().__init__`, with a value nothing
#: else would produce. `verify` is absent: it is forwarded as the *built* context rather than as
#: the caller's argument, and has its own row below.
SUPER_FORWARDS: tuple[tuple[str, Any], ...] = (
    ("http1", False),
    ("http2", True),
    ("trust_env", False),
    ("local_address", "127.0.0.1"),
    ("retries", 3),
    ("socket_options", [(6, 1, 1)]),
)


@pytest.fixture
def to_httpx(monkeypatch: pytest.MonkeyPatch) -> dict[type, dict[str, Any]]:
    """Record what each guarded transport hands to the httpx transport it subclasses.

    **This is the half that only matters when a proxy is configured, and that is the point.**
    Without a proxy the pool httpx builds from these arguments is thrown away and replaced by
    the pinning one, so dropping a forward here changes nothing a request can see. With
    `allow_proxy` on, this package steps back deliberately and httpx's own pool is what serves
    the request, and then every one of these is the caller's configuration or is silently not.

    Args:
        monkeypatch: pytest's patcher.

    Returns:
        A mapping from the unguarded class to the keywords it was handed.
    """
    seen: dict[type, dict[str, Any]] = {}

    def spy(unguarded: type) -> Any:
        original = unguarded.__init__

        # **Wrapped, so the signature survives the patch.** `defaults()` reads these classes for
        # what httpx would have done, and a bare recorder replaces that signature with
        # `(*args, **kwargs)`, which has no defaults to read. The fixture would then quietly
        # rewrite the answer the tests using it are comparing against.
        @functools.wraps(original)
        def recorder(self: Any, *arguments: Any, **keywords: Any) -> None:
            seen[unguarded] = keywords
            original(self, *arguments, **keywords)

        return recorder

    for unguarded in set(UNGUARDED.values()):
        monkeypatch.setattr(unguarded, "__init__", spy(unguarded))
    return seen


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
@pytest.mark.parametrize(("argument", "value"), SUPER_FORWARDS, ids=[n for n, _ in SUPER_FORWARDS])
def test_an_argument_reaches_the_httpx_transport_underneath(
    transport: type, argument: str, value: Any, to_httpx: dict[type, dict[str, Any]]
) -> None:
    """Every argument reaches httpx too, which is what the proxy path runs on.

    Args:
        transport: The guarded class under test.
        argument: The keyword to set.
        value: What to set it to, chosen so no default could be mistaken for it.
        to_httpx: The spy, from the fixture.
    """
    transport(policy=Policy(), **{argument: value})

    handed = to_httpx[UNGUARDED[transport]]
    assert argument in handed, (
        f"{transport.__name__} never handed {argument!r} to {UNGUARDED[transport].__name__}, so "
        f"a request served by httpx's own pool is configured differently from the one asked for"
    )
    assert handed[argument] == value, (
        f"{transport.__name__} handed {UNGUARDED[transport].__name__} "
        f"{argument}={handed[argument]!r} when the caller asked for {value!r}"
    )


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
def test_the_limits_and_context_reach_the_httpx_transport_underneath(
    transport: type, to_httpx: dict[type, dict[str, Any]]
) -> None:
    """The two that are not passed through under their own name.

    `limits` is handed on whole, and `verify` is handed on as the context built from the
    caller's `verify`, `cert` and `trust_env` rather than as the argument itself.

    Args:
        transport: The guarded class under test.
        to_httpx: The spy, from the fixture.
    """
    context = ssl.create_default_context()
    limits = httpx.Limits(max_connections=7, max_keepalive_connections=3, keepalive_expiry=11.0)
    transport(policy=Policy(), verify=context, limits=limits)

    handed = to_httpx[UNGUARDED[transport]]
    assert handed.get("limits") == limits, (
        f"{transport.__name__} handed httpx {handed.get('limits')!r} rather than the caller's "
        f"{limits!r}"
    )
    assert handed.get("verify") is context, (
        f"{transport.__name__} handed httpx {handed.get('verify')!r} rather than the context "
        f"built from the caller's verify, cert and trust_env"
    )


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
def test_a_client_certificate_reaches_the_context_that_is_built(
    transport: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`cert` dropped is a client certificate the caller configured and never presents.

    Stubbed rather than spied through, because a real `cert=` makes httpx read a file, and the
    claim under test is that the value was passed on rather than that OpenSSL liked it.

    Args:
        transport: The guarded class under test.
        monkeypatch: pytest's patcher.
    """
    seen: dict[str, Any] = {}

    def stub(**keywords: Any) -> ssl.SSLContext:
        seen.update(keywords)
        return ssl.create_default_context()

    monkeypatch.setattr(httpx, "create_ssl_context", stub)
    certificate = ("/etc/pki/client.pem", "/etc/pki/client.key")
    transport(policy=Policy(), cert=certificate)

    assert seen.get("cert") == certificate, (
        f"{transport.__name__} built its TLS context with cert={seen.get('cert')!r} when the "
        f"caller configured {certificate!r}; a dropped client certificate is one never presented"
    )


#: The defaults that are forwarded, so taking none of them can be observed rather than read.
EFFECTIVE_DEFAULTS = ("http1", "http2", "retries", "trust_env")


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
@pytest.mark.parametrize("argument", EFFECTIVE_DEFAULTS)
def test_taking_no_argument_forwards_the_default_httpx_would_have_used(
    transport: type, argument: str, to_httpx: dict[type, dict[str, Any]]
) -> None:
    """What a caller who passes nothing actually gets, observed rather than read.

    **A signature assertion cannot do this job, and finding out why was worth the trip.** The
    test above reads `inspect.signature`, which is right for a human reading the API and useless
    under `mutmut`: it rewrites the function into a dispatcher that picks a mutant at run time,
    so the signature the suite inspects is the dispatcher's and every rewritten default survives.
    Four of them did, in each transport, until this row existed.

    So this takes the long way round: construct with nothing, and look at what came out the far
    side. The expected value is read from httpx rather than restated, for the same reason the
    signature comparison does it, and because httpx is not the module being mutated.

    Args:
        transport: The guarded class under test.
        argument: The argument to leave unset.
        to_httpx: The spy, from the fixture.
    """
    expected = defaults(UNGUARDED[transport].__init__)[argument]
    transport(policy=Policy())

    handed = to_httpx[UNGUARDED[transport]]
    assert handed.get(argument) == expected, (
        f"{transport.__name__} defaults {argument} to {handed.get(argument)!r} and forwards "
        f"that, where {UNGUARDED[transport].__name__} defaults it to {expected!r}. A guarded "
        f"transport that configures itself differently from the unguarded one is a surprise"
    )


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
def test_a_unix_socket_refusal_names_the_rule_as_well_as_the_socket(transport: type) -> None:
    """Both halves, because dropping either leaves a refusal somebody has to guess at.

    The value alone says which socket and not why; the rule alone says why and not which. This
    package's stance on that is in `SECURITY.md` and in every other refusal it raises, and the
    async transport was the one where nothing checked.

    Args:
        transport: The guarded class under test.
    """
    with pytest.raises(BlockedURLError) as refusal:
        transport(policy=Policy(), uds="/run/docker.sock")

    assert "unix domain socket" in str(refusal.value), (
        "the refusal does not say what rule refused it, only which socket"
    )
    assert "no address for this policy to check" in str(refusal.value), (
        "the refusal states the rule without the reason behind it"
    )


@pytest.mark.parametrize("transport", TRANSPORTS, ids=TRANSPORT_IDS)
def test_a_proxy_refusal_names_the_proxy(transport: type) -> None:
    """A caller with several proxies configured should not have to find out which one this was.

    Args:
        transport: The guarded class under test.
    """
    with pytest.raises(ProxyUnsupportedError) as refusal:
        transport(policy=Policy(allow_proxy=False), proxy="http://proxy.internal:3128")

    assert "proxy.internal:3128" in str(refusal.value), (
        f"the refusal does not name the proxy it refused: {refusal.value}"
    )
    assert refusal.value.proxy, "the refusal carries no proxy at all"
    assert "None" not in refusal.value.proxy, (
        f"the refusal carries {refusal.value.proxy!r} as the proxy it refused"
    )
