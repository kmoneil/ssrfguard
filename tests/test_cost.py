"""What one URL is allowed to cost, asserted rather than commented.

Ten lanes gate ten things and none of them was about cost, in a package whose source states
measured costs in three places and whose central refusal, ``max_url_length``, exists for no other
reason. This file is the missing half.

**None of the three assertions here is a stopwatch, and that is deliberate.** A threshold in
microseconds is a threshold about the runner, and a suite that runs on shared CI cannot carry
one. Two of these compare a measurement to another measurement taken in the same run on the same
thread, which cancels the runner, and the third has no clock in it at all.

The reason the third kind exists at all is worth writing down, because the obvious alternative
was tried first and failed. When ``max_url_length`` was added, the property it needed was argued
from the regex rather than measured: every repetition in ``_HOSTNAME`` must consume a literal
dot, so there is no backtracking, so ``check_url`` is linear. That argument is sound and
``check_url`` is linear. The ceiling still missed by three orders of magnitude, because *linear
in what* was never pinned down: the scan is linear in characters of URL and the ``idna`` codec is
linear in characters of host, at two hundred and fifty times the price. A regex argument cannot
reach that, and neither can a stopwatch. A ratio can.

Every threshold here now sits at what the code should do rather than at what it happened to do
when the gate was written, and each says in place what it is protecting. Two of them arrived as
ratchets above the tree and were lowered as the work behind them landed, which is the same stance
``scripts/lanes.py`` takes on the coverage floor: a floor is a ratchet, not a dare.
"""

from __future__ import annotations

import contextlib
from unittest import mock

import pytest

import cost_corpus
from ssrfguard import Policy, SSRFGuardError, _policy

#: How many times ``check_url`` may parse its host as an address.
#:
#: **One, and for a name it is zero.** It was two: ``_check_host`` parsed the host, used the
#: answer as a boolean and threw it away, and ``check_url`` parsed the same string again to get
#: the value back. On a name each of those raised three exceptions to arrive at ``None``, which
#: was 40% of the whole check. ``_check_host`` now returns what it parsed, and a one-character
#: test runs in front of the parse, so an ordinary hostname never reaches ``ip_address`` at all.
#:
#: The regression this bounds is somebody adding a call back for convenience, which is exactly
#: how the second one arrived: it reads as free.
#:
#: A count rather than a duration, so this gates without a clock and cannot flake.
_MAX_HOST_PARSES = 1

#: How much more the ``idna`` path may cost than the ASCII one, at the same URL length.
#:
#: **The two hosts either side of this ratio take identical branches through ``check_url`` apart
#: from one**: which arm of ``_normalise`` runs. Everything else, the length check, the
#: control-character scan, ``urlsplit``, the hostname regex, the port, is the same work on the
#: same number of characters, so it divides out and what is left is the constant this package
#: has to bound. That is why the denominator is an 8 KiB ASCII URL rather than an ordinary
#: request-shaped one, and the choice is load-bearing rather than tidy: measured against an
#: ordinary URL, making ``check_url`` faster in general would *raise* this number without
#: anything getting slower, and a gate that fires on an improvement is a gate somebody deletes.
#:
#: Measured at 9.1 to 11.3 across the five supported interpreters. It was 251 before a host
#: longer than DNS can carry was refused before normalisation rather than after.
#:
#: **100 rather than 30, because 30 was the guess and 35.1 was the measurement.** The reasoning
#: behind 30 was right and its number was not: this does run on more than one architecture, and
#: a shared runner reached 35.1x on the first CI run this repository ever had, on a tree nothing
#: was wrong with. A ratchet that fires on somebody else's CPU is a ratchet that gets deleted,
#: and this one had 2.8x of headroom over a machine it had never been measured on.
#:
#: 100 sits between the two numbers that matter rather than close to either: two and a half times
#: below the 251 the defect actually produced, and three times above the worst clean measurement
#: anything has reported. The regression it guards is not gradual. The ceiling is either applied
#: before normalisation or after it, so the ratio is either about ten or about two hundred and
#: fifty, and nothing in between is a state this code can be in.
#:
#: Raising it costs less than it looks, because the specific defect that produced 251x is now
#: also asserted without a clock, by counting what reaches the codec rather than timing it. That
#: assertion cannot flake and cannot be argued with; this one stays for what a count cannot see,
#: which is the codec itself getting slower.
_MAX_IDNA_MULTIPLE = 100

#: How much more an 8 KiB URL may cost than a 1 KiB one: eight times the input, so at most this
#: many times the work if the scan is linear, and about sixty-four times if it is quadratic.
#:
#: 16 sits between the two with a factor of three either side, so it distinguishes the thing worth
#: distinguishing and tolerates a great deal of noise doing it. Measured at 5.0 to 5.9 across the
#: five supported interpreters.
#:
#: It read 3.9 to 4.5 before the host parse was taken out of ``check_url``, and rose without
#: anything getting slower, which is worth understanding before reading a future move as a
#: regression. Both URLs here pay the same fixed cost and the 1 KiB one pays proportionally more
#: of it, so removing fixed cost from both moves the ratio *towards* the 8 that linear scanning
#: implies. A number approaching 8 from below is this measurement getting cleaner. Only a number
#: heading for 64 is a defect.
_MAX_LENGTH_SCALING = 16


@pytest.fixture(scope="module")
def policy() -> Policy:
    """The defaults, which are what a caller who has not thought about this gets."""
    return Policy()


def test_check_url_parses_the_host_as_an_address_at_most_once(policy: Policy) -> None:
    """A count, so this gates on every runner and flakes on none.

    Asserted for a name and for both address families, because they take different branches and
    only one of them should reach the parser at all.
    """
    for url in (cost_corpus.TYPICAL[0], cost_corpus.V4_LITERALS[0], cost_corpus.V6_LITERALS[0]):
        with mock.patch.object(_policy, "ip_address", wraps=_policy.ip_address) as parses:
            policy.check_url(url)
        assert parses.call_count <= _MAX_HOST_PARSES, (
            f"check_url parsed the host of {url!r} {parses.call_count} times; "
            f"at most {_MAX_HOST_PARSES} is the current ratchet"
        )


def test_check_url_is_linear_in_the_length_of_the_url(policy: Policy) -> None:
    """The claim ``max_url_length`` rests on, measured rather than argued from the regex.

    Every URL here takes identical branches and differs only in how many characters each scan
    walks, so the ratio between them is about complexity and not about two code paths. Both
    halves are timed on this thread's CPU clock in the same run, so a slow or busy runner
    slows both and cancels.
    """
    small = cost_corpus.cost_ns(policy.check_url, cost_corpus.scaled_to(1024))
    large = cost_corpus.cost_ns(policy.check_url, cost_corpus.scaled_to(8192))
    scaling = large / small
    assert scaling < _MAX_LENGTH_SCALING, (
        f"an 8 KiB URL cost {scaling:.1f}x a 1 KiB one for 8x the input; linear is at most 8 "
        f"and quadratic is about 64, so this reads as superlinear scanning"
    )


def test_a_non_ascii_host_is_not_a_different_order_of_cost(policy: Policy) -> None:
    """What a length ceiling cannot say, and what the host ceiling is for.

    ``max_url_length`` bounds how many characters ``check_url`` reads and says nothing about what
    a character costs, and the two arms of ``_normalise`` differ by two orders of magnitude per
    character. **This is the only assertion here that could have caught that gap.**

    Two corpora, and both are needed, which is the thing to understand before editing either.
    :data:`~cost_corpus.WORST_ACCEPTED` is the most expensive host a default policy *permits*, so
    it catches the codec itself getting slower. It cannot catch the host ceiling being removed,
    because it is 253 characters either way and 253 characters cost the same either way.
    :data:`~cost_corpus.HOSTILE` is built past every ceiling and so it can: refused, it is
    microseconds, and permitted it is milliseconds. **Its cost counts whether or not it is
    refused**, because a refusal that takes fifteen milliseconds is exactly as good an attack as
    an acceptance that does.

    The denominator is an ASCII URL of the same length, so every scan and check either side of
    ``_normalise`` divides out and what is left is the constant being bounded.
    """
    # Every one of these takes the default number of batches. The numerators used to take
    # three, which is fewer chances for `cost_ns` to catch a clean one, and a minimum estimated
    # from three samples on a busy runner is the noisiest half of a ratio built to cancel noise.
    ascii_host = cost_corpus.cost_ns(policy.check_url, cost_corpus.scaled_to(8192))
    permitted = cost_corpus.cost_ns(policy.check_url, cost_corpus.WORST_ACCEPTED)
    hostile = cost_corpus.cost_ns(policy.check_url, cost_corpus.HOSTILE, allow_refusal=True)
    multiple = max(permitted, hostile) / ascii_host
    assert multiple < _MAX_IDNA_MULTIPLE, (
        f"the most work one URL can make check_url do cost {multiple:.1f}x an ASCII URL of the "
        f"same length (permitted {permitted / ascii_host:.1f}x, hostile "
        f"{hostile / ascii_host:.1f}x); the ratchet is {_MAX_IDNA_MULTIPLE}x. Something is "
        f"running the idna codec over more host than DNS can carry"
    )


def test_the_idna_codec_never_sees_more_host_than_dns_can_carry(policy: Policy) -> None:
    """The 251x defect, counted rather than timed.

    The ratio above is what catches the codec itself getting slower, and nothing countable can
    do that job. This is the other half of the same guard, and it is the half that matters most,
    because the regression that actually happened was not the codec changing. It was the host
    ceiling sitting *after* normalisation instead of before it, and where a ceiling sits is a
    fact about how many characters `_normalise` is handed. A fact needs no clock, no runner and
    no tolerance, so this gates where a ratio can only ratchet.

    Both directions, because either alone is half an assertion. A permitted host reaches the
    codec and is bounded by what DNS can carry; a host built past every ceiling never reaches it
    at all.
    """
    # Both privates are the subject here rather than a shortcut into one: the assertion is about
    # where a ceiling sits relative to a function, and neither of them is public.
    longest = _policy._LONGEST_HOSTNAME  # noqa: SLF001
    real = _policy._normalise  # noqa: SLF001

    with mock.patch.object(_policy, "_normalise", wraps=real) as normalise:
        for url in cost_corpus.WORST_ACCEPTED:
            policy.check_url(url)
        permitted = [len(call.args[1]) for call in normalise.call_args_list]

        normalise.reset_mock()
        for url in cost_corpus.HOSTILE:
            with contextlib.suppress(SSRFGuardError):
                policy.check_url(url)
        hostile = [len(call.args[1]) for call in normalise.call_args_list]

    assert permitted, (
        "no permitted host reached the idna codec, so the bound below is vacuous and this test "
        "would pass with the ceiling deleted"
    )
    assert max(permitted) <= longest, (
        f"the idna codec was handed {max(permitted)} characters of host, and DNS carries at most "
        f"{longest}. Something normalises before it checks the length"
    )
    assert hostile == [], (
        f"a host built past every ceiling reached the idna codec, at lengths "
        f"{sorted(set(hostile))}. That is the 251x defect exactly: the ceiling is being applied "
        f"after normalisation rather than before it"
    )
