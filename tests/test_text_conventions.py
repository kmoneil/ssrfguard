"""What characters committed text may contain.

`src/ssrfguard/` was already written this way and nothing enforced it: nine shipped modules, one
hundred and fifty-one ASCII `--`, and not a single em dash. The convention was visible in the
source and invisible to every gate, which is the same shape as a docstring that states an
invariant nothing checks, and this repository has already been bitten by one of those.

The rule now runs the whole tree rather than just the shipped package, so the prose a contributor
writes and the prose that ships use one form of punctuation instead of two.

**This file spells the character it forbids as an escape**, which is not a cute trick: written
literally it would be a committed file containing an em dash, so the test would fail against
itself and the only fix would be to exempt it, and an exempt guard is a guard with a hole in
the shape of the thing it guards. `src/ssrfguard/__init__.py` writes its circled-digit doctest
the same way and for the same reason.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

#: Reads the repository rather than the library. `mutmut` copies `src`, `tests` and two
#: files into `mutants/` and runs the suite from there, where the rest of the tree does
#: not exist, so this cannot run: it reads every committed file. It could not kill a
#: mutant in `src/ssrfguard` either way.
pytestmark = pytest.mark.repository

REPO_ROOT = Path(__file__).resolve().parent.parent

#: U+2014 EM DASH, spelled as an escape. Written literally, this line would make the file an
#: instance of what it forbids. See the module docstring.
EM_DASH = "\u2014"


def _tracked() -> list[str]:
    """Every file git is tracking.

    Asked of git rather than walked, so the answer is what a clone actually carries: an
    untracked scratch file is nobody's business and a gitignored one is not shipped.

    Returns:
        Repository-relative paths.
    """
    listed = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in listed.stdout.splitlines() if line]


def test_no_committed_file_contains_an_em_dash() -> None:
    """One form of punctuation, not two.

    `--` is the form the shipped package already uses everywhere, so this is the rest of the
    tree adopting it rather than a new convention being invented for the occasion.
    """
    offenders: list[str] = []
    for name in _tracked():
        try:
            text = (REPO_ROOT / name).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # not text; nothing to say about its punctuation
        for number, line in enumerate(text.splitlines(), 1):
            if EM_DASH in line:
                offenders.append(f"{name}:{number}: {line.strip()}")

    assert not offenders, (
        "committed files contain an em dash; this project writes that punctuation as '--', "
        "which is the form src/ssrfguard already uses throughout:\n" + "\n".join(offenders)
    )


def test_the_guard_can_actually_fail() -> None:
    """A check that has never caught anything is indistinguishable from one that cannot.

    The assertion above is a `not in` over files that currently all pass, so nothing about a
    green run says the search works. This runs the same search over a string that does contain
    the character.
    """
    assert chr(0x2014) == EM_DASH
    assert EM_DASH in f"a{EM_DASH}b"
    assert EM_DASH not in "a -- b"


def test_the_shipped_package_stays_ascii() -> None:
    """The wider rule the dash convention is a consequence of.

    A user reads this package's docstrings in a terminal, a traceback, a REPL and `help()`, and
    ASCII is the only encoding all four agree on. `src/ssrfguard/__init__.py` writes its
    circled-digit example as `\\u2460\\u2461\\u2466` rather than as literal characters, which is
    what says this was a decision rather than an accident.

    One docstring in `_policy.py` writes the same characters literally, so the rule is asserted
    here for every module *except* that one, named rather than silently excluded. A known
    exception is a decision; an unexplained gap in a loop is a bug waiting to be copied.
    """
    known_exception = "src/ssrfguard/_policy.py"
    offenders: list[str] = []
    for name in _tracked():
        if not name.startswith("src/") or not name.endswith(".py") or name == known_exception:
            continue
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            if not line.isascii():
                offenders.append(f"{name}:{number}: {line.strip()}")

    assert not offenders, (
        "the shipped package is ASCII; write the character as an escape, the way "
        "src/ssrfguard/__init__.py writes its circled-digit doctest:\n" + "\n".join(offenders)
    )


def test_the_one_known_exception_is_still_the_only_one() -> None:
    """So the exemption above cannot quietly grow.

    If `_policy.py` is ever made ASCII, this test fails and tells whoever did it to delete the
    exemption rather than leave a carve-out for a file that no longer needs one.

    **This pins the line's content and not its number.** It used to assert `== [541]`, which is
    a position, and a position is not what the exemption is about: inserting anything anywhere
    above that docstring reds this test while the property it guards is untouched. The two
    things worth catching are a *second* non-ASCII line appearing and the last one going away,
    and neither of those is a line number.
    """
    text = (REPO_ROOT / "src" / "ssrfguard" / "_policy.py").read_text(encoding="utf-8")
    non_ascii = [line.strip() for line in text.splitlines() if not line.isascii()]

    assert len(non_ascii) == 1, (
        f"_policy.py has {len(non_ascii)} non-ASCII lines rather than the one known exception: "
        f"{non_ascii}. If the file is now ASCII, delete the exemption in "
        f"test_the_shipped_package_stays_ascii; if it grew, write the character as an escape."
    )
    assert "into ``127.0.0.1``" in non_ascii[0], (
        f"the known non-ASCII line is no longer the circled-digit docstring: {non_ascii[0]}. "
        f"A different line carrying non-ASCII is a new exemption rather than the old one."
    )
