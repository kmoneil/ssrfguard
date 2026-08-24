"""The mutation gate's comparison, checked without running a mutation.

`scripts/check_mutants.py` is what turned the `mutation` lane from a number nobody diffed into
something that fails. Its two halves have very different costs: reading a completed run takes a
completed run, and comparing what it found against the register is pure. Only the second half
decides whether the lane goes red, so it is the half tested here, at the cost of a millisecond
rather than a minute.

**The one-directional rule is the thing to fence.** A survivor outside the register has to fail,
because it is behaviour the suite stopped noticing. A registered survivor that got killed must
*not* fail, because two runs of an unchanged tree disagreed by one mutant and a lane that goes
red when a mutant dies is a lane that punishes progress and gets deleted for flaking. Those two
directions are easy to write down and easy to get backwards, and nothing else in the repository
would catch it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_mutants  # noqa: E402

#: Reads the repository rather than the library. `mutmut` copies `src`, `tests` and two
#: files into `mutants/` and runs the suite from there, where the rest of the tree does
#: not exist, so this cannot run: it imports `check_mutants` from `scripts/`. It could not
#: kill a mutant in `src/ssrfguard` either way.
pytestmark = pytest.mark.repository

#: A register shaped like the real one, small enough to reason about.
REGISTER = {
    "src/ssrfguard/_connect.py::_open": [
        "sock = socket.socket(family, SOCK_STREAM)  ->  sock = socket.socket(family, )",
    ],
    "src/ssrfguard/httpx.py::SafeTransport.__init__": [
        "retries: int = 0  ->  retries: int = 1",
        "verify: bool = True  ->  verify: bool = False",
    ],
}


def test_a_run_matching_the_register_is_clean() -> None:
    """The ordinary case, and the one that must not cost anybody anything."""
    assert check_mutants.unregistered(REGISTER, REGISTER) == {}


def test_a_survivor_the_register_does_not_hold_is_reported() -> None:
    """The whole point. New untested behaviour has to reach somebody."""
    found = {
        **REGISTER,
        "src/ssrfguard/_policy.py::check_url": ["if port in allowed  ->  if port not in allowed"],
    }
    fresh = check_mutants.unregistered(found, REGISTER)
    assert fresh == {
        "src/ssrfguard/_policy.py::check_url": ["if port in allowed  ->  if port not in allowed"]
    }


def test_a_new_survivor_in_an_already_registered_function_is_reported() -> None:
    """A per-function count would miss this, which is why the register holds changes.

    The function is known and already carries survivors, so anything keyed on "how many does
    this function have" would have to see the count rise. It does not have to: a change that
    kills one default and stops pinning another leaves the count where it was.
    """
    found = dict(REGISTER)
    found["src/ssrfguard/httpx.py::SafeTransport.__init__"] = [
        "retries: int = 0  ->  retries: int = 1",
        "timeout: float = 5.0  ->  timeout: float = 6.0",
    ]
    fresh = check_mutants.unregistered(found, REGISTER)
    assert fresh == {
        "src/ssrfguard/httpx.py::SafeTransport.__init__": [
            "timeout: float = 5.0  ->  timeout: float = 6.0"
        ]
    }


def test_a_registered_survivor_that_was_killed_does_not_fail_the_lane() -> None:
    """Progress must never turn a gate red.

    This is the direction that gets written backwards, and getting it backwards would make the
    lane fail on the run that first killed something. It would also flake on its own, because
    one mutant in this tree survives some runs and not others.
    """
    found = {key: list(changes) for key, changes in REGISTER.items()}
    found["src/ssrfguard/httpx.py::SafeTransport.__init__"] = [
        "retries: int = 0  ->  retries: int = 1"
    ]

    assert check_mutants.unregistered(found, REGISTER) == {}
    assert check_mutants.killed_since(found, REGISTER) == 1


def test_a_whole_function_that_vanished_is_reported_and_does_not_fail() -> None:
    """Deleting the code is one way to kill every mutant in it, and it is a legitimate one."""
    found = {"src/ssrfguard/_connect.py::_open": REGISTER["src/ssrfguard/_connect.py::_open"]}

    assert check_mutants.unregistered(found, REGISTER) == {}
    assert check_mutants.killed_since(found, REGISTER) == 2


def test_a_function_absent_from_the_register_contributes_all_of_its_survivors() -> None:
    """New code arriving with nothing behind it is the case this exists for.

    A register that treated an unknown function as "nothing recorded, so nothing to compare"
    would pass a whole new module with no tests, which is the opposite of the point.
    """
    found = {"src/ssrfguard/_new.py::whatever": ["a  ->  b", "c  ->  d"]}
    assert check_mutants.unregistered(found, {}) == found


def test_the_committed_register_is_readable_and_says_when_it_was_taken() -> None:
    """A baseline with no date is a baseline nobody can tell is stale."""
    document = json.loads(check_mutants.REGISTER.read_text(encoding="utf-8"))
    assert document["taken"], "the register carries the date it was taken"
    assert document["surviving_mutants"] >= document["distinct_changes"], (
        "more than one mutant can render to the same change, never fewer"
    )
    assert document["survivors"], "an empty register would make the gate vacuous"
    assert check_mutants.load_register() == document["survivors"]


def test_the_change_rendering_distinguishes_a_rewrite_from_a_deletion() -> None:
    """`-> ` with nothing after it is a diff a reader has to count spaces to understand."""
    render = check_mutants._change  # noqa: SLF001  # the rendering is the thing under test
    rewrite = render("--- a.py\n+++ a.py\n@@ -1 +1 @@\n-    x = 1\n+    x = 2\n")
    deletion = render("--- a.py\n+++ a.py\n@@ -1 +0 @@\n-    x = 1\n")

    assert rewrite == f"x = 1{check_mutants.BECOMES}x = 2"
    assert deletion == f"x = 1{check_mutants.BECOMES}{check_mutants.DELETED}"
