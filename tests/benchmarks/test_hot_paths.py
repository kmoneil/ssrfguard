"""What the per-request and per-connection paths cost, compared against this machine's own past.

``tests/test_cost.py`` gates on ratios and counts because a duration is a fact about the runner,
and this file does not change that. It answers the question a ratio cannot: **did this change make
the ordinary call slower**, measured where a duration does mean something, which is against a
baseline saved on the same machine. That baseline lives in ``.benchmarks/``, which is ignored by
git because a number from one laptop says nothing about another.

**Not collected by default, and not a lane.** ``benchmarks`` is in ``norecursedirs``, so a plain
``pytest`` never reaches it, and the ``compat`` rows, which install neither plugin, never try to
import it. It is not a lane because every lane runs in CI, and CI has no saved baseline to compare
against: a CI job could only print absolute timings from a shared runner, which is what the
``cost`` lane already reports, and with the reason it does not gate. Run it explicitly::

    pytest tests/benchmarks --benchmark-save=baseline         # once, on the tree to compare to
    pytest tests/benchmarks --benchmark-compare --benchmark-compare-fail=mean:10%
    pytest tests/benchmarks --memray --benchmark-disable        # the allocation ceilings

**Ten percent on the mean is a threshold this can hold**, measured rather than hoped: on the
machine this was written on, three runs of unchanged code against their own baseline drifted at
most 5% on any benchmark, and a slowdown injected into ``check_url`` failed the compare at 88%. A
machine that drifts more than that against itself needs a quieter run, not a wider threshold.

**Measured again on 2026-10-09, with less headroom:** three runs against a fresh baseline drifted
up to 7.5%. The baseline saved before that one was worse: taken while the machine was busy, it
came out 10 to 14% slow on the two fastest benchmarks, so every later run looked faster than it
and a regression that size would have passed. The compare only fails on the slow side, which is
why a slow baseline is the dangerous one. Compare against a new baseline once before trusting it.

**The workload is ``tests/cost_corpus.py``, not a second definition of it**, so this and the
``cost`` lane cannot disagree about what a representative URL is. The same two traps are handled
the same way: the clock is this thread's CPU time, because wall clock absorbs every descheduling
on a loaded machine, and ``urlsplit``'s cache is cleared before every batch, because a fetcher of
untrusted URLs sees each one once.

What is measured, and what is not:

* ``Policy.check_url``, once per request and on every corpus shape the cost lane reports.
* ``resolve``, once per connection, with a stand-in that answers instantly, so what is timed is
  the validation of four answers rather than a nameserver.
* ``Policy.check_address``, the address-table lookup ``resolve`` makes for every answer.
* **Not ``connect``.** Its cost is a socket and a kernel, and a benchmark of it would time the
  operating system.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Callable
from contextlib import suppress
from urllib.parse import clear_cache

import pytest

import cost_corpus
from ssrfguard import Policy, SSRFGuardError, resolve

pytestmark = pytest.mark.benchmark(timer=time.thread_time)

#: The corpora `check_url` is timed on, by the name the cost lane prints them under.
CORPORA = {
    "typical": cost_corpus.TYPICAL,
    "ipv4-literal": cost_corpus.V4_LITERALS,
    "ipv6-literal": cost_corpus.V6_LITERALS,
    "idn": cost_corpus.IDN_TYPICAL,
    "worst-accepted": cost_corpus.WORST_ACCEPTED,
}

#: What a CDN-fronted name typically answers: two of each family, all public.
_ANSWERS: list[tuple] = [
    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 443)),
    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.15", 443)),
    (
        socket.AF_INET6,
        socket.SOCK_STREAM,
        6,
        "",
        ("2606:2800:21f:cb07:6820:80da:af6b:8b2c", 443, 0, 0),
    ),
    (
        socket.AF_INET6,
        socket.SOCK_STREAM,
        6,
        "",
        ("2606:2800:21f:cb07:6820:80da:af6b:8b2d", 443, 0, 0),
    ),
]


def _answer(*_query: object) -> list[tuple]:
    """Answer every lookup with `_ANSWERS`, and record nothing.

    **Not `tests/stub_resolver.py`**, which appends every name it is asked to a list. That is the
    point of it in the adapter suites and a leak here, where it would be called a few million
    times and the list would be part of what got timed.

    Returns:
        The same four rows every time.
    """
    return _ANSWERS


def _batch(work: Callable[[str], object], urls: tuple[str, ...]) -> Callable[[], None]:
    """One pass over a corpus, from a cold `urlsplit` cache, as a single timed call.

    Args:
        work: What to call on each entry.
        urls: The corpus.

    Returns:
        A function taking no arguments, which is the shape `benchmark` times.
    """

    def run() -> None:
        clear_cache()
        for url in urls:
            work(url)

    return run


@pytest.mark.parametrize("corpus", CORPORA.values(), ids=CORPORA.keys())
def test_check_url(benchmark, corpus: tuple[str, ...]) -> None:
    benchmark(_batch(Policy().check_url, corpus))


def test_check_url_refusing_a_hostile_url(benchmark) -> None:
    """The URL built past every ceiling, which is refused, and which must be refused cheaply."""
    check = Policy().check_url

    def refused(url: str) -> None:
        with suppress(SSRFGuardError):
            check(url)

    benchmark(_batch(refused, cost_corpus.HOSTILE))


def test_resolve_validates_every_answer(benchmark) -> None:
    policy = Policy()
    target = policy.check_url("https://api.example.com/v1/resource")
    benchmark(resolve, target, policy=policy, resolver=_answer)


@pytest.mark.parametrize(
    "literals", [cost_corpus.V4_LITERALS, cost_corpus.V6_LITERALS], ids=["ipv4", "ipv6"]
)
def test_check_address(benchmark, literals: tuple[str, ...]) -> None:
    policy = Policy()
    # The hosts out of the corpus's own URLs, so the addresses are the cost lane's addresses.
    addresses = [policy.check_url(url).host for url in literals]

    def run() -> None:
        for address in addresses:
            policy.check_address(address)

    benchmark(run)


#: **Twice what was measured, and allocation is not timing**: the same interpreter allocates the
#: same bytes for the same input on every run, so headroom here is for a different patch release
#: of the standard library rather than for noise. Measured on 3.13 as the high watermark with
#: ``urlsplit``'s cache cleared before every URL, so the figure is what one URL costs. Without
#: the clear it is what the cache retains, which grows with the corpus and is not this package's.
_WORST_ACCEPTED_CEILING = "128 KB"  # measured 53 KiB
_HOSTILE_CEILING = "256 KB"  # measured 109 KiB, nearly all of it copies of an 8 KiB netloc


@pytest.fixture
def idna_loaded() -> None:
    """Pay the ``idna`` codec's one-time import outside the measurement.

    The first IDN call in a process imports ``stringprep`` and compiles it, which measured
    142 KiB, nearly three times what the worst accepted URL itself costs. Which test pays it
    depends on selection order, so leaving it in would make the ceiling a fact about ``-k``.
    pytest-memray tracks the test body and not its fixtures, which is what makes this work.
    """
    Policy().check_url("https://münchen.example.com/")


@pytest.mark.usefixtures("idna_loaded")
@pytest.mark.limit_memory(_WORST_ACCEPTED_CEILING)
def test_the_worst_accepted_url_allocates_a_bounded_amount() -> None:
    """The most expensive URL a default policy accepts, held to an allocation ceiling."""
    check = Policy().check_url
    for url in cost_corpus.WORST_ACCEPTED:
        clear_cache()
        check(url)


@pytest.mark.limit_memory(_HOSTILE_CEILING)
def test_a_hostile_url_allocates_a_bounded_amount() -> None:
    """The URL built past every ceiling, refused without allocating its way there first."""
    check = Policy().check_url
    for url in cost_corpus.HOSTILE:
        clear_cache()
        with suppress(SSRFGuardError):
            check(url)
