"""No committed file may point a reader at something they cannot open.

A reader who clones this repository is told where to go and has to be able to get there. A
citation to an ignored path — a planning document, a scratch directory, a report — looks
authoritative and leads nowhere, which is the same defect class as a stale reference and worse
in a public repository, where *every* reader is in that position.

**The fix is to inline the reason, not to relocate the document.** "because `is_global` returns
True for NAT64 addresses" is both reachable and more useful than "see the design doc, section
five".

What this deliberately does not forbid is a path a reader can *create*: `.venv/bin/ruff` exists
after `uv sync`, and an ignored directory named in a tool's exclude list is configuration rather
than a citation. The distinction is whether the path is being offered as something to read.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Directories `.gitignore` excludes that a reader could be sent to as reading material.
# `.venv` and the tool caches are deliberately absent: those are created by `uv sync`, so a
# reference to one is an instruction rather than a dead end.
UNREACHABLE = ("_plans", "_tmp", "_reports", "_reviews")

# Where a reference would be offered as reading. Configuration files name ignored directories
# for a living — ruff's `extend-exclude`, pytest's `norecursedirs` — and those are exempt by
# being outside this set rather than by a per-line waiver, so a new exemption has to be a
# deliberate change to this tuple.
PROSE = (".md", ".py", ".yml", ".yaml")

EXEMPT = frozenset({"tests/test_no_gitignored_references.py", ".gitignore"})


def _tracked_files() -> list[str]:
    done = subprocess.run(  # resolved by git itself, list argv, no shell
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:  # pragma: no cover - only outside a git checkout
        pytest.skip("not a git repository, so there is no tracked set to check")
    return [line for line in done.stdout.splitlines() if line]


@pytest.fixture(scope="module")
def tracked() -> list[str]:
    return _tracked_files()


def test_no_committed_file_cites_an_ignored_path(tracked: list[str]) -> None:
    pattern = re.compile(r"(?<![\w/.-])(" + "|".join(re.escape(d) for d in UNREACHABLE) + r")/")
    offenders: list[str] = []
    for name in tracked:
        if name in EXEMPT or not name.endswith(PROSE):
            continue
        for number, line in enumerate(
            (REPO_ROOT / name).read_text(encoding="utf-8").splitlines(), 1
        ):
            if pattern.search(line):
                offenders.append(f"{name}:{number}: {line.strip()}")
    assert not offenders, (
        "committed files cite ignored paths a reader cannot open; inline the reason instead:\n"
        + "\n".join(offenders)
    )


def test_no_committed_file_cites_the_uncommitted_design_document(tracked: list[str]) -> None:
    """Section citations are references too, and this one points at a file that is not shipped."""
    pattern = re.compile(r"\bDESIGN\b")
    offenders: list[str] = []
    for name in tracked:
        if name in EXEMPT or not name.endswith(PROSE):
            continue
        for number, line in enumerate(
            (REPO_ROOT / name).read_text(encoding="utf-8").splitlines(), 1
        ):
            if pattern.search(line):
                offenders.append(f"{name}:{number}: {line.strip()}")
    assert not offenders, (
        "committed files cite a design document that is not committed; state the reason "
        "in place:\n" + "\n".join(offenders)
    )


def test_the_ignored_directories_really_are_ignored() -> None:
    """If one of these stopped being ignored, the rule above would be guarding nothing."""
    for directory in UNREACHABLE:
        done = subprocess.run(  # resolved by git itself, list argv, no shell
            ["git", "check-ignore", "-q", f"{directory}/x"],
            cwd=REPO_ROOT,
            check=False,
        )
        if done.returncode == 128:  # pragma: no cover - only outside a git checkout
            pytest.skip("not a git repository")
        assert done.returncode == 0, (
            f"{directory}/ is no longer gitignored; either restore it or drop it from "
            "UNREACHABLE, because this test is otherwise asserting nothing about it"
        )


if sys.platform == "win32":  # pragma: no cover - the gates lane is POSIX-only
    pytest.skip("git plumbing paths differ on Windows", allow_module_level=True)
