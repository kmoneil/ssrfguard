"""The exception hierarchy as a public surface.

All five are now raised by something. Two of them -- `ProxyUnsupportedError` and
`TooManyRedirectsError` -- were defined and tested here before the layers that raise them
existed, because the hierarchy is what callers write `except` clauses against, and a class that
arrives in a later release is a class every existing `except SSRFGuardError` already covers only
if it was in the tree from the start. The assertions below stayed the same when the adapters
landed, which is the point of having written them early.

An untested exception is one whose message nobody has read. These assert the whole message,
because the message *is* the feature: a refusal a user cannot act on gets configured around.
"""

from __future__ import annotations

import pytest

import ssrfguard
from ssrfguard import (
    BlockedAddressError,
    BlockedURLError,
    ProxyUnsupportedError,
    SSRFGuardError,
    TooManyRedirectsError,
)


@pytest.mark.parametrize(
    "error",
    [BlockedAddressError, BlockedURLError, ProxyUnsupportedError, TooManyRedirectsError],
)
def test_every_refusal_is_catchable_as_one_thing(error: type[SSRFGuardError]) -> None:
    """`except SSRFGuardError` has to catch everything this package refuses, and only that."""
    assert issubclass(error, SSRFGuardError)
    assert issubclass(error, Exception)
    assert not issubclass(error, (OSError, ValueError, TypeError)), (
        "a refusal that is also an OSError would be swallowed by a caller's network handling"
    )


def test_blocked_address_names_the_address_and_the_rule() -> None:
    error = BlockedAddressError("127.0.0.1", "127.0.0.0/8 is Loopback (RFC1122)")
    assert error.address == "127.0.0.1"
    assert error.reason == "127.0.0.0/8 is Loopback (RFC1122)"
    assert str(error) == "127.0.0.1 is not permitted: 127.0.0.0/8 is Loopback (RFC1122)"


def test_blocked_url_quotes_the_url_so_whitespace_is_visible() -> None:
    """A URL refused for a control character has to show it, or the message reads as nonsense."""
    error = BlockedURLError("http://a\nb/", "contains a control character")
    assert str(error) == "'http://a\\nb/' is not permitted: contains a control character"


def test_proxy_unsupported_explains_the_mechanism_and_names_the_escape_hatch() -> None:
    """Refusing without saying how to proceed is how a control gets removed instead of adjusted."""
    error = ProxyUnsupportedError("http://proxy.internal:3128")
    assert error.proxy == "http://proxy.internal:3128"
    message = str(error)
    assert "http://proxy.internal:3128" in message
    assert "resolves the target itself" in message
    assert "allow_proxy=True" in message


def test_too_many_redirects_shows_the_chain_that_was_walked() -> None:
    """The limit alone is not actionable; the hops are what tell a user what happened."""
    chain = ("http://a.example/", "http://b.example/", "http://c.example/")
    error = TooManyRedirectsError(2, chain)
    assert error.limit == 2
    assert error.chain == chain
    assert str(error) == (
        "redirect chain exceeded max_redirects=2: "
        "http://a.example/ -> http://b.example/ -> http://c.example/"
    )


def test_the_public_error_surface_is_exactly_what_is_exported() -> None:
    """A new exception is a new thing callers must handle, so adding one fails here first."""
    exported = {
        name
        for name in ssrfguard.__all__
        if isinstance(getattr(ssrfguard, name), type)
        and issubclass(getattr(ssrfguard, name), BaseException)
    }
    assert exported == {
        "SSRFGuardError",
        "BlockedAddressError",
        "BlockedURLError",
        "ProxyUnsupportedError",
        "TooManyRedirectsError",
    }
