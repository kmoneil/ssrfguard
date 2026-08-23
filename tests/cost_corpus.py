"""The workload the cost gates and the cost report both measure, defined once.

Two definitions of "what a representative URL looks like" is how the gate and the report come to
disagree about whether anything got slower, which is the same argument ``scripts/lanes.py`` makes
about pytest flags. `tests/test_cost.py` asserts against these corpora and
``scripts/cost_report.py`` prints timings for them, and neither carries a URL of its own.

**Generated rather than committed as data**, so the corpora are reproducible from the rule that
built them, cost nothing in the repository, and cannot rot into a fixture nobody re-reads. Every
one is deterministic: no clock, no randomness, no network.

Two measurement traps are handled here rather than left to each caller, because both were found
the hard way and both silently produce a number that is wrong rather than a run that fails.

**``urlsplit`` is ``@lru_cache(typed=True)`` on the interpreters this package supports.** Timing
one URL in a loop therefore measures a cache hit and understates ``check_url`` by about a fifth.
:func:`cost_ns` clears that cache before every batch, which is also the honest workload: a
fetcher of untrusted URLs sees each one once.

**The clock is the calling thread's CPU time, not wall clock**, and that choice is what makes a
timing assertion able to gate at all. Measured on a twelve-core machine with sixteen threads of
background load against an idle one, the wall-clock ratio between the most expensive URL a
default policy accepts and an ordinary one moved from 2 100 to 10 900, because a fourteen-
millisecond call absorbs far more descheduling than a seven-microsecond one and the ratio does
not cancel it. The same ratio measured on ``time.thread_time_ns`` moved from 2 138 to 2 160.
A shared CI runner is the loaded case.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from contextlib import suppress
from urllib.parse import clear_cache

from ssrfguard import SSRFGuardError

__all__ = [
    "HOSTILE",
    "IDN_TYPICAL",
    "TYPICAL",
    "V4_LITERALS",
    "V6_LITERALS",
    "WORST_ACCEPTED",
    "cost_ns",
    "scaled_to",
]

#: How many distinct URLs a batch draws from. Large enough that per-call overhead is averaged
#: out and small enough that a batch is a few milliseconds, so a gate costs nothing noticeable.
_CORPUS_SIZE = 256

#: Distinct hostnames, which is what a webhook deliverer or a link-preview service actually
#: sees. **This is the corpus the steady-state number is quoted against**, because a name is the
#: input the whole package exists for: an address literal needs no second resolution and cannot
#: be moved between the check and the connect.
TYPICAL: tuple[str, ...] = tuple(
    f"https://api{i}.example{i % 7}.com/v1/resource/{i}?token=abc{i}&page={i % 5}"
    for i in range(_CORPUS_SIZE)
)

#: Literal IPv4 hosts. A different path: no hostname regex, but the address table is consulted
#: during ``check_url`` rather than at the socket, so this is the one shape where classification
#: lands on the per-request path.
V4_LITERALS: tuple[str, ...] = tuple(
    f"https://93.184.{i // 256}.{i % 256}/health" for i in range(_CORPUS_SIZE)
)

#: Literal IPv6 hosts, which cost more than v4 for the same reason: a longer parse and a
#: longer table scan.
V6_LITERALS: tuple[str, ...] = tuple(
    f"https://[2606:2800:220:1:248:1893:25c8:{i:04x}]/health" for i in range(_CORPUS_SIZE)
)

#: An ordinary internationalised name. Here because the ``idna`` codec is the most expensive
#: thing ``check_url`` can be made to do and a legitimate caller reaches it: this is the price
#: of supporting IDN at all, separate from the adversarial case below.
IDN_TYPICAL: tuple[str, ...] = tuple(
    f"https://münchen{i}.example.com/x" for i in range(_CORPUS_SIZE)
)

#: The two ceilings this corpus is built against, restated rather than imported: a corpus that
#: reads the limits from the code it measures would follow them wherever they went and stop being
#: a fixed workload. If either of these moves, this file is meant to fail and be re-derived.
_LONGEST_HOSTNAME = 253
_LONGEST_URL = 8192

#: How the most expensive host of a given length is arranged, which is **not** the arrangement
#: it looks like it should be. Measured across label lengths from 1 to 63 at a fixed 253-character
#: host: one-character labels cost 608 microseconds and 57-character labels cost 428, because the
#: ``idna`` codec pays a fixed cost per label and the most labels wins. Sixty-three-character
#: labels are cheaper still, at 170, and for a reason worth knowing before anyone "fixes" this
#: constant: they are *refused*, because the codec's 63-byte limit is on the encoded label and a
#: non-ASCII character does not survive punycode as one byte, so the walk stops at the first one.
_WORST_LABEL_LENGTH = 1

#: The host that costs the most a default policy will pay: as long as DNS can carry, every
#: character of it non-ASCII, and cut into as many labels as that allows.
_WORST_HOST_LABELS = (_LONGEST_HOSTNAME + 1) // (_WORST_LABEL_LENGTH + 1)

#: **The most expensive URL a default policy accepts**, which is a moving target by construction:
#: it is defined by what the policy refuses, so tightening a ceiling changes what belongs here.
#:
#: It was once a host of 389 short non-ASCII labels, because ``max_url_length`` counted characters
#: of URL while the cost sat in characters of host, and 14.9 milliseconds of one worker fitted
#: comfortably inside an 8 KiB URL. Capping the host at what DNS can carry ended that, and this
#: is what is left: the same trick at the largest size still permitted.
#:
#: The path is padded to the URL ceiling so both scans are also at their maximum, and one label
#: per entry carries a different non-ASCII character so no two are the same name while every one
#: keeps the arrangement above.
WORST_ACCEPTED: tuple[str, ...] = tuple(
    "https://"
    + ".".join("ü" if label == i else "é" for label in range(_WORST_HOST_LABELS))
    + "/"
    + "a" * (_LONGEST_URL - _LONGEST_HOSTNAME - 16)
    for i in range(16)
)


def cost_ns(
    work: Callable[[str], object],
    urls: Iterable[str],
    *,
    repeat: int = 5,
    allow_refusal: bool = False,
) -> float:
    """Measure one call of ``work`` over ``urls``, in nanoseconds of this thread's CPU time.

    Args:
        work: What to measure. Called once per URL.
        urls: The batch. Timed as a whole and divided, so per-call clock overhead does not
            dominate a microsecond-scale measurement.
        repeat: How many batches to run.
        allow_refusal: Whether a :class:`~ssrfguard.SSRFGuardError` is part of the measurement
            rather than the end of it. **False by default and that default is the useful one**:
            for every corpus that asks what permitted traffic costs, an entry that stops being
            accepted is a change in the workload rather than a timing result, and swallowing it
            would quietly report a number for something else. :data:`HOSTILE` is the exception
            and the reason this flag exists: it asks how much work one URL can cause, and the
            answer counts the same whether the guard ends up saying yes or no.

    Returns:
        The **minimum** per-call cost across the batches. Minimum rather than mean or median
        because every source of error here is additive: an interrupted batch is slower than a
        clean one and nothing makes a batch faster than the work in it.
    """
    batch = tuple(urls)
    measured = _ignoring_refusal(work) if allow_refusal else work
    per_call = []
    for _ in range(repeat):
        clear_cache()
        started = time.thread_time_ns()
        for url in batch:
            measured(url)
        per_call.append((time.thread_time_ns() - started) / len(batch))
    return min(per_call)


def _ignoring_refusal(work: Callable[[str], object]) -> Callable[[str], object]:
    """Wrap ``work`` so a refusal is part of the measurement rather than the end of it.

    Wrapped once here rather than branched on inside the timing loop, so the loop being timed is
    the same shape in both modes and the flag does not appear in the number.

    Args:
        work: What to measure.

    Returns:
        The same call, with this package's own refusals swallowed.
    """

    def measured(url: str) -> None:
        # `contextlib.suppress` costs a measured 155 nanoseconds per call over a bare `try`,
        # which sounds disqualifying inside a timing loop and is not: the only corpus that asks
        # for this is :data:`HOSTILE`, whose calls run to hundreds of microseconds, so it is
        # 0.03% of what is being measured. Checked rather than assumed, because the argument for
        # the faster form would have been an unmeasured optimization in a file about measuring.
        with suppress(SSRFGuardError):
            work(url)

    return measured


def scaled_to(length: int, *, count: int = 32) -> tuple[str, ...]:
    """Build URLs of a given length that differ only in how much string there is to scan.

    The host is a fixed ordinary name and the padding goes in the path, so every one of these
    takes the same branches through ``check_url`` and the only thing that varies is the number
    of characters each scan walks. That is what makes a pair of these a measurement of
    *complexity* rather than of two different code paths.

    Args:
        length: How long each URL should be.
        count: How many to build.

    Returns:
        URLs of exactly ``length`` characters.

    Raises:
        ValueError: If ``length`` leaves no room for the padding, which would silently produce
            a corpus that does not scale and a linearity result that means nothing.
    """
    prefix = "https://api.example.com/"
    padding = length - len(prefix) - 4
    if padding < 1:
        raise ValueError(f"length {length} is too short to carry a scaled path")
    return tuple(f"{prefix}{'a' * padding}{i:04d}" for i in range(count))


#: **A URL built to make ``check_url`` do as much work as possible, whether or not it survives.**
#:
#: This is the corpus that carries the security property, and it is a different question from
#: :data:`WORST_ACCEPTED`. That one asks what the most expensive *permitted* URL costs, which is
#: a fact about the steady state. This one asks what the most expensive URL costs, full stop,
#: because a refusal that takes fifteen milliseconds is exactly as good an attack as an
#: acceptance that does. Whether the guard ends up saying yes or no is not the attacker's
#: concern and must not be this corpus's either.
#:
#: Pinning it to the current limits would defeat it. A corpus fixed at 253 characters of host
#: cannot notice the host ceiling being removed, because 253 characters cost the same either way,
#: and a gate that cannot see the regression it is named after is decoration. So this is
#: deliberately built **past** every ceiling: a host far longer than DNS can carry, cut into as
#: many non-ASCII labels as fit, inside a URL just under the length limit. With the ceilings in
#: place it is refused in microseconds. With either of them gone it costs milliseconds, and that
#: difference is the assertion.
HOSTILE: tuple[str, ...] = tuple(
    "https://" + ".".join(["é" * 20] * 380) + f".{i:02d}.com/" + "a" * (_LONGEST_URL - 8000)
    for i in range(4)
)
