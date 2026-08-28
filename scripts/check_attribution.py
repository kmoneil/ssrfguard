"""Refuse tool-attribution trailers and session links in commit messages and PR bodies.

This repository's history carried a `Claude-Session:` trailer on all 74 commits and a matching
link at the foot of all 18 pull request bodies, and removing them cost a full history rewrite,
three repointed release tags and a force-push through a protected branch. The setting that
generates them is off now; this is the part that does not depend on a setting staying off.

**Four things could put one back, and a setting stops only the first.** The generator can be
re-enabled by an edit nobody reads; a session already running carries its old instructions and
can write the trailer by hand; a machine that is not this one has its own configuration; and a
cloud session has neither this checkout's hooks nor this machine's settings. The last two are
why this runs in CI rather than only in a hook: CI is the only place that sees a commit no
matter where it was authored.

What counts as an offence is deliberately narrow, because a check that fires on prose is a check
people learn to skip. Every rule below is anchored on a machine-generated *form*: a trailer at
the start of a line, a session URL, the ``noreply@`` address the tool signs with. Writing
``Claude-Session:`` inside a sentence, as this paragraph's neighbours do, is not an offence and
must not become one, or the commit that introduced this file could not have described itself.

Usage::

    python scripts/check_attribution.py --history          # every commit reachable from HEAD
    python scripts/check_attribution.py --history --range origin/main..HEAD
    python scripts/check_attribution.py FILE [FILE ...]    # a commit message, a PR body

Exits 1 on the first offence found, after printing every one of them: a run that stopped at the
first would send somebody round the loop once per trailer.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The NUL-delimited format `_commit_messages` parses. A commit message can contain blank lines,
#: colons and anything else a delimiter might have been, so the delimiter is the one byte git
#: guarantees a message cannot hold.
_LOG_FORMAT = "%H%x00%B%x00"


@dataclass(frozen=True)
class Rule:
    """One forbidden form.

    Attributes:
        name: What a reader should call this when it fires.
        pattern: Matched against the whole text, multiline.
        why: Why this specific form is machine-generated rather than something a person wrote.
    """

    name: str
    pattern: re.Pattern[str]
    why: str


RULES: tuple[Rule, ...] = (
    Rule(
        name="Claude-Session trailer",
        # Anchored at the start of a line, which is what makes the prose in this module's own
        # docstring legal. A trailer is a line; a mention is not.
        pattern=re.compile(r"^[ \t]*Claude-Session[ \t]*:", re.MULTILINE | re.IGNORECASE),
        why="the trailer the tool appends when attribution.sessionUrl is left on",
    ),
    Rule(
        name="claude.ai session link",
        # Unanchored on purpose: this one has no legitimate form anywhere in a commit message or
        # a PR body. It is a link into one person's private session, and it means nothing to
        # anybody else reading the history.
        pattern=re.compile(r"claude\.ai/code/session", re.IGNORECASE),
        why="a link to a private session, which no reader of this history can open",
    ),
    Rule(
        name="tool co-author trailer",
        # Keyed on the address rather than on the name. `Co-authored-by: Claude` would also
        # match a human being called Claude, and refusing somebody's name is a bug, not a gate.
        pattern=re.compile(
            r"^[ \t]*Co-authored-by:[^\n]*noreply@anthropic\.com", re.MULTILINE | re.IGNORECASE
        ),
        why="the co-author trailer attribution.commit suppresses",
    ),
    Rule(
        name="generated-with line",
        # The footer carries `claude.ai/code` without `/session`, so the link rule above does
        # not see it. Two rules rather than one loose one.
        pattern=re.compile(r"generated with \[?claude code", re.IGNORECASE),
        why="the generated-with footer attribution.commit and attribution.pr suppress",
    ),
)


def offences(text: str) -> list[Rule]:
    """Every rule that matches the given text.

    Args:
        text: A commit message, a PR body, or any other text to check.

    Returns:
        The matching rules, in the order they are declared. Empty if the text is clean.
    """
    return [rule for rule in RULES if rule.pattern.search(text)]


def _git() -> str:
    """Locate git.

    Returns:
        An absolute path to the git executable.

    Raises:
        SystemExit: If git is not installed.
    """
    found = shutil.which("git")
    if found is None:
        raise SystemExit("check_attribution: git is not installed")
    return found


def _commit_messages(rev_range: str) -> list[tuple[str, str]]:
    """Read every commit message in a revision range.

    Args:
        rev_range: Anything ``git log`` accepts, such as ``HEAD`` or ``origin/main..HEAD``.

    Returns:
        ``(short sha, message)`` pairs, newest first.

    Raises:
        SystemExit: If git cannot walk the range, which usually means a shallow clone.
    """
    result = subprocess.run(  # noqa: S603  # resolved absolute path, list argv, no shell
        [_git(), "log", f"--format={_LOG_FORMAT}", rev_range],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"check_attribution: git log {rev_range} failed: {result.stderr.strip()}\n"
            "If this is CI, the checkout needs fetch-depth: 0; a shallow clone has no history "
            "to scan and would pass while proving nothing."
        )
    fields = result.stdout.split("\0")
    # git writes a newline after each record, so every sha field but the first arrives with one
    # attached, and the element after the final delimiter is that last newline alone. Strip the
    # sha and pair the rest up; a field that is empty once stripped is that trailing remnant.
    pairs: list[tuple[str, str]] = []
    for index in range(0, len(fields) - 1, 2):
        sha = fields[index].strip()
        if sha:
            pairs.append((sha[:8], fields[index + 1]))
    return pairs


def _report(source: str, text: str) -> int:
    """Print every offence in one piece of text.

    Args:
        source: How to name this text in the output.
        text: The text to check.

    Returns:
        The number of offences found.
    """
    found = offences(text)
    for rule in found:
        print(f"  {source}: {rule.name} ({rule.why})")
    return len(found)


def main() -> int:
    """Entry point.

    Returns:
        Process exit status: 1 if anything was found, 0 otherwise.
    """
    parser = argparse.ArgumentParser(description=__doc__, add_help=True)
    parser.add_argument(
        "paths", nargs="*", type=Path, help="text files to scan (a commit message, a PR body)"
    )
    parser.add_argument(
        "--history", action="store_true", help="also scan commit messages in --range"
    )
    parser.add_argument(
        "--range", default="HEAD", help="revision range for --history (default: HEAD)"
    )
    args = parser.parse_args()

    if not args.history and not args.paths:
        parser.error("nothing to check: pass --history, one or more files, or both")

    total = 0
    if args.history:
        for sha, message in _commit_messages(args.range):
            total += _report(f"commit {sha}", message)
    for path in args.paths:
        # A missing PR body is written as an empty file by the caller rather than skipped, so
        # an unreadable path here is a wiring mistake and should be loud.
        total += _report(str(path), path.read_text(encoding="utf-8"))

    if total:
        print(
            f"\nerror: {total} tool-attribution offence(s).\n"
            "\n"
            "No commit message or PR body carries a session link or a tool attribution trailer.\n"
            "Turn the generator off with, in ~/.claude/settings.json:\n"
            '    "attribution": {"commit": "", "pr": "", "sessionUrl": false}\n'
            "All three keys: defining neither commit nor pr leaves the deprecated\n"
            "includeCoAuthoredBy in charge, and an empty string is not the same as unset.\n"
            "\n"
            "To fix a message already written, amend or rebase it out. To fix a PR body,\n"
            "edit it: gh pr edit <n> --body-file <file>.",
            file=sys.stderr,
        )
        return 1

    scanned = "history" if args.history else ""
    scanned = ", ".join(filter(None, [scanned, *(str(p) for p in args.paths)]))
    print(f"check_attribution: clean ({scanned})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
