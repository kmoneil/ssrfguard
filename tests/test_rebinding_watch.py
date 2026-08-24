"""A name that resolved somewhere else, and the four ways this could be worse than nothing.

`on_partial_block` refuses a name that resolves to both permitted and denied addresses within one
lookup, because that is the signature of a rebinding attempt rather than of a misconfiguration.
Across two lookups the signal is identical and nothing remembered the first answer to notice it.

The tests that matter here are not the ones where it fires. They are:

* **the honest cases**, where a detector that fired would be switched off, and a detector that is
  switched off is worse than none because somebody believes it is running;
* **the bound**, because the keys are hostnames an attacker chooses;
* **the cache it must never become**, because reusing a remembered answer would be a stale pin;
* **the composition**, because a wrapped observer must not gain the power to fail a request that
  an unwrapped one deliberately does not have.
"""

from __future__ import annotations

import contextlib
import time

import pytest

from ssrfguard import BlockedAddressError, Decision, Policy, RebindingWatch, resolve
from ssrfguard._observer import report

from .stub_resolver import Resolver

#: Permitted, and standing in for wherever a name honestly points.
PUBLIC = "1.1.1.1"
ELSEWHERE = "8.8.8.8"

#: Denied by the shipped table, and where a rebind goes.
METADATA = "169.254.169.254"


def watched() -> tuple[RebindingWatch, list[Decision]]:
    """A watch over a list, so a test can read what came out of it."""
    seen: list[Decision] = []
    return RebindingWatch(seen.append), seen


def look_up(watch: RebindingWatch, host: str, *answers: str) -> None:
    """Resolve `host` to `answers` under the default policy, swallowing a refusal."""
    policy = Policy()
    target = policy.check_url(f"https://{host}/")
    resolver = Resolver(**{host: list(answers)})
    with contextlib.suppress(BlockedAddressError):
        resolve(target, policy=policy, resolver=resolver, observer=watch)


def enriched(seen: list[Decision]) -> list[Decision]:
    """Every decision that came out carrying something in `also_seen`."""
    return [decision for decision in seen if decision.also_seen]


# ---------------------------------------------------------------------------
# What it is for.
# ---------------------------------------------------------------------------


def test_a_name_that_moved_between_lookups_says_where_it_was() -> None:
    """The signal `on_partial_block` catches within one lookup, caught across two."""
    watch, seen = watched()
    look_up(watch, "moves.test", PUBLIC)
    look_up(watch, "moves.test", METADATA)

    (finding,) = enriched(seen)
    assert (finding.stage, finding.outcome) == ("address", "refused")
    assert str(finding.address) == METADATA
    assert finding.also_seen == (PUBLIC,)
    assert "Cloud metadata" in (finding.reason or "")


def test_a_name_that_resolves_both_ways_at_once_says_so_too() -> None:
    """Within one lookup this duplicates a signal the refusal already carries, and it is the
    same fact rather than a different one, so it is reported rather than special-cased away."""
    watch, seen = watched()
    look_up(watch, "both.test", PUBLIC, METADATA)

    (finding,) = enriched(seen)
    assert finding.also_seen == (PUBLIC,)


def test_every_address_a_name_reached_is_carried_not_just_the_last() -> None:
    watch, seen = watched()
    look_up(watch, "many.test", PUBLIC, ELSEWHERE)
    look_up(watch, "many.test", METADATA)

    (finding,) = enriched(seen)
    assert finding.also_seen == (PUBLIC, ELSEWHERE)


# ---------------------------------------------------------------------------
# The honest cases. **A detector that fires on normal operation gets switched off.**
# ---------------------------------------------------------------------------


def test_a_round_robin_name_produces_nothing() -> None:
    """Answers rotating among permitted addresses is what a load balancer does all day."""
    watch, seen = watched()
    for answers in ((PUBLIC, ELSEWHERE), (ELSEWHERE, PUBLIC), (PUBLIC,), (ELSEWHERE,)):
        look_up(watch, "rotating.test", *answers)
    assert enriched(seen) == []


def test_a_failover_to_a_different_permitted_address_produces_nothing() -> None:
    """DNS-based failover moves a name deliberately, and moving is not the signal."""
    watch, seen = watched()
    look_up(watch, "failover.test", PUBLIC)
    look_up(watch, "failover.test", ELSEWHERE)
    assert enriched(seen) == []


def test_a_name_seen_only_once_produces_nothing() -> None:
    watch, seen = watched()
    look_up(watch, "once.test", PUBLIC)
    assert enriched(seen) == []


def test_a_refused_name_with_nothing_on_file_produces_nothing() -> None:
    """The first time a name is seen and refused, there is nothing to compare it to."""
    watch, seen = watched()
    look_up(watch, "denied.test", METADATA)
    assert [d.outcome for d in seen] == ["refused"]
    assert enriched(seen) == []


def test_one_name_moving_says_nothing_about_another() -> None:
    watch, seen = watched()
    look_up(watch, "a.test", PUBLIC)
    look_up(watch, "b.test", METADATA)
    assert enriched(seen) == []


def test_a_sighting_older_than_the_window_is_not_compared() -> None:
    """**The window is what keeps a long-lived client from comparing across a deployment.**

    A name that pointed somewhere else an hour ago is a re-provisioning, not a rebind.
    """
    seen: list[Decision] = []
    watch = RebindingWatch(seen.append, window=0.05)
    look_up(watch, "slow.test", PUBLIC)
    _sleep_past(0.05)
    look_up(watch, "slow.test", METADATA)
    assert enriched(seen) == []


def _sleep_past(window: float) -> None:
    """Wait until a window of this length has certainly closed.

    Three times the window rather than a hair over it: this decides how long a *passing* test
    takes and never whether it passes, so it can be generous without measuring the runner.
    """
    time.sleep(window * 3)


# ---------------------------------------------------------------------------
# The bound. The keys are hostnames an attacker chooses.
# ---------------------------------------------------------------------------


def test_the_number_of_remembered_hosts_is_capped() -> None:
    """**An unbounded map keyed on attacker input is a memory-exhaustion path**, which
    `SECURITY.md` puts squarely in scope. Oldest out first."""
    seen: list[Decision] = []
    watch = RebindingWatch(seen.append, capacity=4)
    for number in range(50):
        look_up(watch, f"host{number}.test", PUBLIC)
    assert len(watch._seen) == 4  # noqa: SLF001


def test_the_host_evicted_first_is_the_one_seen_longest_ago() -> None:
    seen: list[Decision] = []
    watch = RebindingWatch(seen.append, capacity=2)
    look_up(watch, "first.test", PUBLIC)
    look_up(watch, "second.test", PUBLIC)
    look_up(watch, "third.test", PUBLIC)

    look_up(watch, "first.test", METADATA)
    assert enriched(seen) == [], "the oldest host should have been forgotten"
    look_up(watch, "third.test", METADATA)
    assert len(enriched(seen)) == 1, "the newest host should still be on file"


@pytest.mark.parametrize(
    ("kwargs", "why"),
    [({"window": 0}, "must be positive"), ({"capacity": 0}, "must be at least 1")],
)
def test_a_bound_that_cannot_mean_anything_is_refused(kwargs: dict, why: str) -> None:
    with pytest.raises(ValueError, match=why):
        RebindingWatch(lambda _decision: None, **kwargs)


# ---------------------------------------------------------------------------
# The cache it must never become.
# ---------------------------------------------------------------------------


def test_what_it_remembers_is_never_handed_back_to_a_lookup() -> None:
    """**Storing an answer to compare it is not storing it to reuse it.**

    Reusing a remembered address would be a stale pin: a name that legitimately moved keeps
    reaching an address it no longer owns, which is the mirror image of the bug this package
    exists to prevent. So a second lookup returns the *new* answer, watch or no watch.
    """
    watch, _seen = watched()
    look_up(watch, "moved.test", PUBLIC)

    policy = Policy()
    target = policy.check_url("https://moved.test/")
    resolver = Resolver(**{"moved.test": ELSEWHERE})
    addresses = resolve(target, policy=policy, resolver=resolver, observer=watch)

    assert [str(a.ip) for a in addresses] == [ELSEWHERE], "a remembered answer was reused"


# ---------------------------------------------------------------------------
# The composition. Wrapping must not grant a power the wrapped thing does not have.
# ---------------------------------------------------------------------------


def test_a_wrapped_observer_that_raises_still_cannot_fail_a_request() -> None:
    """An observer that raises cannot fail a request, and wrapping one does not change that.

    `report` is still what calls the outermost observer, and it swallows whatever comes back. A
    watch that made a broken sink fatal would be a detector that breaks the thing it watches,
    which is the one way this feature could be worse than not having it.
    """

    def explode(_decision: Decision) -> None:
        raise RuntimeError("the sink is broken")

    watch = RebindingWatch(explode)
    report(watch, Decision(stage="address", outcome="permitted", host="a.test"))

    policy = Policy()
    target = policy.check_url("https://ok.test/")
    resolver = Resolver(**{"ok.test": PUBLIC})
    addresses = resolve(target, policy=policy, resolver=resolver, observer=watch)
    assert [str(a.ip) for a in addresses] == [PUBLIC]


@pytest.mark.parametrize("stage", ["url", "peer", "redirect"])
def test_a_decision_about_anything_else_passes_straight_through(stage: str) -> None:
    watch, seen = watched()
    original = Decision(stage=stage, outcome="refused", host="a.test", reason="because")  # type: ignore[arg-type]
    watch(original)
    assert seen == [original]


def test_an_address_decision_with_no_host_passes_straight_through() -> None:
    """Nothing to key on, so nothing to do."""
    watch, seen = watched()
    original = Decision(stage="address", outcome="refused", address=None)
    watch(original)
    assert seen == [original]


# ---------------------------------------------------------------------------
# The defaults, and the degenerate configuration that is still a configuration.
# ---------------------------------------------------------------------------


def test_the_documented_defaults_are_the_defaults() -> None:
    """`docs/observing.md` names both numbers, so a test holds the two together."""
    watch = RebindingWatch(lambda _decision: None)
    assert (watch.window, watch.capacity) == (60.0, 512)


def test_remembering_exactly_one_host_is_allowed() -> None:
    """One is a bound, not an error. The refusal is for a capacity that remembers nothing."""
    seen: list[Decision] = []
    watch = RebindingWatch(seen.append, capacity=1)
    look_up(watch, "only.test", PUBLIC)
    look_up(watch, "only.test", METADATA)
    assert [decision.also_seen for decision in enriched(seen)] == [(PUBLIC,)]


def test_a_second_host_pushes_the_first_out_at_a_capacity_of_one() -> None:
    seen: list[Decision] = []
    watch = RebindingWatch(seen.append, capacity=1)
    look_up(watch, "first.test", PUBLIC)
    look_up(watch, "second.test", PUBLIC)
    look_up(watch, "first.test", METADATA)
    assert enriched(seen) == []


# ---------------------------------------------------------------------------
# What it declines to look at.
# ---------------------------------------------------------------------------


def test_a_url_decision_never_reaches_the_map_even_carrying_a_host() -> None:
    """**Both halves of the guard are load-bearing.**

    A `url` decision carries a host and no address. Letting one into the map would file the
    string `None` against that host, and the next refusal for it would report having also seen
    somewhere called `None`. Stage and host are both checked, and this is the test that says the
    stage half is doing something.
    """
    watch, seen = watched()
    watch(Decision(stage="url", outcome="permitted", host="sneaky.test", port=443))
    look_up(watch, "sneaky.test", METADATA)

    assert enriched(seen) == [], "a decision with no address was remembered"
    assert all("None" not in str(decision.also_seen) for decision in seen)
