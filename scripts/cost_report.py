"""What this package costs a caller, printed rather than asserted.

**This lane reports and does not gate**, for one reason: a threshold in microseconds is a
threshold about the runner, and this one runs on shared hardware. The numbers that *do* gate are
in ``tests/test_cost.py`` and none of them is an absolute duration; they
compare one measurement against another taken on the same thread in the same run, or they count
calls and hold no clock at all.

What this adds is the other half. A ratio catches a regression and cannot answer the question a
reader evaluating this package actually has, which is what it costs them. So this prints the
absolute numbers with the environment that produced them, and it is the command the README should
point at rather than quoting a figure that is wrong on somebody else's machine the moment they
read it.

The corpora come from ``tests/cost_corpus.py`` rather than from here, deliberately: two
definitions of "a representative URL" is how the gate and the report come to disagree about
whether anything got slower, which is the argument ``scripts/lanes.py`` makes about pytest flags
one layer up.
"""

from __future__ import annotations

import platform
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The corpora live with the tests because they are the workload definition and the gates are
# their first consumer. Adding the directory rather than duplicating the URLs is the same trade
# `tests/test_lanes.py` makes in the other direction when it imports this package's lane registry.
sys.path.insert(0, str(REPO_ROOT / "tests"))

import cost_corpus  # noqa: E402
from ssrfguard import Policy  # noqa: E402

#: How many times the import measurement is taken. A process start is noisy and additive, so the
#: minimum is the estimate and a handful of samples is enough to find it.
_IMPORT_SAMPLES = 7


def _describe_environment() -> None:
    """Print what would have to match for these numbers to be reproduced.

    A benchmark result without its environment cannot be reproduced and cannot be contested,
    which makes it an anecdote with a unit attached.
    """
    print("environment")
    print(f"  python      {platform.python_version()} ({platform.python_implementation()})")
    print(f"  platform    {platform.system()} {platform.release()} {platform.machine()}")
    resolution = time.get_clock_info("thread_time").resolution
    print(f"  clock       time.thread_time_ns, resolution {resolution * 1e9:.0f} ns")
    print()


def _import_cost_ms() -> float:
    """Measure what ``import ssrfguard`` adds to starting an interpreter.

    Measured as a difference against an empty start rather than absolutely, because most of a
    Python process's start-up is not ours and reporting it as though it were would overstate
    this by a factor of two.

    Returns:
        Milliseconds the import adds, the minimum across samples.
    """

    def _run(code: str) -> float:
        started = time.perf_counter()
        subprocess.run([sys.executable, "-c", code], check=True)  # noqa: S603
        return (time.perf_counter() - started) * 1000

    bare = min(_run("pass") for _ in range(_IMPORT_SAMPLES))
    loaded = min(_run("import ssrfguard") for _ in range(_IMPORT_SAMPLES))
    return loaded - bare


def _report_corpora(policy: Policy) -> dict[str, float]:
    """Time every corpus and print a row for each.

    Args:
        policy: The policy to measure, which for a report is always the defaults: what a caller
            who has not configured anything gets is the number worth publishing.

    Returns:
        Nanoseconds per call, keyed by corpus name, for the ratios below.
    """
    corpora = (
        ("hostname (the common case)", cost_corpus.TYPICAL, 5),
        ("IPv4 literal", cost_corpus.V4_LITERALS, 5),
        ("IPv6 literal", cost_corpus.V6_LITERALS, 5),
        ("internationalised name", cost_corpus.IDN_TYPICAL, 5),
        ("worst URL a default policy accepts", cost_corpus.WORST_ACCEPTED, 3),
    )
    print("Policy.check_url, per call, this thread's CPU time")
    measured = {}
    for label, urls, repeat in corpora:
        nanoseconds = cost_corpus.cost_ns(policy.check_url, urls, repeat=repeat)
        measured[label] = nanoseconds
        print(f"  {label:38s} {nanoseconds / 1000:12.2f} us")
    print()
    return measured


def _report_ratios(measured: dict[str, float], policy: Policy) -> None:
    """Print what the gates assert, and the one number they deliberately do not.

    Args:
        measured: Per-corpus costs from :func:`_report_corpora`.
        policy: The policy to measure the length scaling against.
    """
    typical = measured["hostname (the common case)"]
    worst = measured["worst URL a default policy accepts"]
    small = cost_corpus.cost_ns(policy.check_url, cost_corpus.scaled_to(1024))
    large = cost_corpus.cost_ns(policy.check_url, cost_corpus.scaled_to(8192))
    hostile = cost_corpus.cost_ns(
        policy.check_url, cost_corpus.HOSTILE, repeat=3, allow_refusal=True
    )
    print("what tests/test_cost.py gates on")
    print(f"  permitted non-ASCII host / ASCII, same length  {worst / large:8.1f}x")
    print(f"  host built past every ceiling / ASCII          {hostile / large:8.1f}x")
    print(f"  8 KiB URL / 1 KiB URL, 8x the input            {large / small:8.1f}x")
    print()
    # Amplification is the number a reader asks for and the wrong thing to gate on: making
    # `check_url` faster in general raises it without anything getting slower, so a gate here
    # would fire on an improvement. Reported, not asserted.
    print("reported, not gated")
    print(f"  worst accepted URL / ordinary one              {worst / typical:8.0f}x")
    print()


def main() -> int:
    """Print the report.

    Returns:
        0, always. This lane reports; see the module docstring.
    """
    policy = Policy()
    _describe_environment()
    measured = _report_corpora(policy)
    _report_ratios(measured, policy)
    print(f"import ssrfguard, over an empty interpreter   {_import_cost_ms():8.1f} ms")
    print()
    print("This lane reports and does not gate. The gates are in tests/test_cost.py and none of")
    print("them is an absolute duration; see that file for why.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
