"""`Target` must be awkward to misuse, and this file is what keeps it awkward.

D-2 exists because every SSRF advisory of 2026 describes a validator that handed back something
an HTTP client would accept. The defence is a return type that cannot be used that way -- which
is a property of the *shape* of the class, so it decays the moment somebody adds a convenience
method. These tests are the fence around that.
"""

from __future__ import annotations

import pickle

import pytest

from ssrfguard import Policy, Target

POLICY = Policy()


def test_str_renders_a_debug_form_that_is_not_a_url() -> None:
    target = POLICY.check_url("https://example.com/a/b?c=d#e")
    rendered = str(target)
    assert rendered == "<Target https host=example.com port=443>"
    assert "://" not in rendered, "a renderable URL is the thing this type exists not to be"


def test_a_target_carries_no_path_query_or_fragment() -> None:
    """A Target is an origin, not a request. Dropping these is deliberate, not an oversight."""
    target = POLICY.check_url("https://example.com/secret/path?token=abc#frag")
    for attribute in vars(target).values():
        assert "secret" not in str(attribute)
        assert "token" not in str(attribute)
        assert "frag" not in str(attribute)


@pytest.mark.parametrize(
    "attribute",
    ["geturl", "url", "href", "__fspath__", "to_url", "as_url", "unsplit", "full_url"],
)
def test_a_target_offers_no_way_to_become_a_url(attribute: str) -> None:
    """Named individually so that adding any one of them fails by name rather than in review."""
    target = POLICY.check_url("https://example.com/")
    assert not hasattr(target, attribute), (
        f"Target grew {attribute!r}; that is the affordance this type exists to withhold, and "
        f"the next line of code after it is the vulnerability D-2 is about"
    )


def test_the_public_surface_is_exactly_what_was_intended() -> None:
    """A new public attribute is a new way to misuse this, so it fails here first."""
    target = POLICY.check_url("https://example.com/")
    public = {name for name in dir(target) if not name.startswith("_")}
    assert public == {"scheme", "host", "port", "host_as_written", "address", "is_literal_address"}


def test_a_target_is_immutable() -> None:
    """A validated origin that can be edited afterwards was never validated."""
    target = POLICY.check_url("https://example.com/")
    with pytest.raises(AttributeError):
        target.host = "127.0.0.1"  # type: ignore[misc]


def test_a_target_compares_and_hashes_by_value() -> None:
    """Useful, and safe: equality cannot be used to smuggle a different origin past anything."""
    first = POLICY.check_url("https://example.com/one")
    second = POLICY.check_url("https://example.com/two")
    assert first == second, "the path is not part of the origin"
    assert len({first, second}) == 1
    # ...and the port is part of it, so two origins that differ only there are not equal.
    assert first != POLICY.check_url("https://example.com:80/")


def test_a_target_survives_a_round_trip_unchanged() -> None:
    """Callers will put these in queues and caches; a Target must not decay in transit."""
    target = POLICY.check_url("http://8.8.8.8/")
    restored = pickle.loads(pickle.dumps(target))  # noqa: S301  # our own value, not user input
    assert restored == target
    assert restored.address == target.address


def test_a_literal_address_target_says_it_needs_no_resolution() -> None:
    literal = POLICY.check_url("http://8.8.8.8/")
    assert literal.is_literal_address
    assert literal.address is not None
    named = POLICY.check_url("http://example.com/")
    assert not named.is_literal_address
    assert named.address is None


def test_constructing_a_target_by_hand_is_possible_and_bypasses_nothing() -> None:
    """The type is public, so it can be built directly -- and doing so grants no permission.

    A Target is a record of a decision, not the decision itself. Nothing downstream trusts one
    it did not see made: resolution re-checks every address it gets back, which is why hand-
    building one cannot be an escalation.
    """
    forged = Target(scheme="http", host="127.0.0.1", port=80, host_as_written="127.0.0.1")
    assert str(forged) == "<Target http host=127.0.0.1 port=80>"
    assert not POLICY.permits_address("127.0.0.1"), (
        "the policy still refuses the address, which is the check that actually holds"
    )
