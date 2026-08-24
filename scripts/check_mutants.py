"""Surviving mutants, compared against the register of the ones already known about.

**The lane this serves reported a number nobody could act on, and before that it reported
nothing at all**, because `mutmut run` exited on the first module it collected and the lane
swallowed it. With the run working, the remaining problem is the one `scripts/lanes.py` names:
`mutmut run` exits 0 whether or not mutants survive, so a machine has nothing to compare a run
against and the count goes past a human once a week.

This is that comparison.

**A survivor is identified by what it changed, never by its name.** mutmut names a mutant
`xǁSafeTransportǁ__init____mutmut_5`, where the trailing number is a position in a list that
shifts the moment anyone edits the function. A register keyed on that would go red on an
unrelated edit and quiet on a real one. The changed source line does not move, so the key here
is the function plus the diff: `retries: int = 0  ->  retries: int = 1`.

**The comparison is one-directional, and that is forced by measurement rather than taste.** Two
runs of an unchanged tree disagreed by one mutant, 216 survivors and then 217, so a gate on set
equality or on an exact count would flake on a rerun that changed nothing. So:

- a survivor **not** in the register fails, because it is untested behaviour that was not there
  when the register was taken, and that is the whole point of the gate;
- a registered survivor that no longer survives is reported and nothing else, so progress never
  turns the lane red and the nondeterministic one cannot flake it.

**The register is debt, not a target.** It records what the suite does not currently notice,
with the date it was taken, and the count is printed on every run so it stays visible rather
than being blessed by living in a file. Lowering it as survivors are killed is the same stance
`scripts/lanes.py` takes on the coverage floor: a floor is a ratchet, not a dare.

Run `--write` to regenerate the register after a deliberate change, and read the diff before
committing it: every line added is a thing the suite stopped noticing.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTER = REPO_ROOT / "scripts" / "mutation_register.json"


def _tool(name: str) -> str:
    """Resolve a tool to an absolute path, preferring the project virtualenv.

    A partial executable path is resolved against ``PATH``, which is attacker-influenced in
    exactly the environments a security tool runs in. Same resolution order as
    ``scripts/lanes.py`` and ``scripts/audit_deps.py``.

    Args:
        name: Executable name.

    Returns:
        An absolute path.

    Raises:
        SystemExit: If the tool cannot be found.
    """
    beside = Path(sys.executable).parent / name
    if beside.exists():
        return str(beside)
    candidate = REPO_ROOT / ".venv" / "bin" / name
    if candidate.exists():
        return str(candidate)
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"tool not found: {name!r} (is the development environment synced?)")
    return found


#: What a mutant that deletes a line rather than rewriting one reads as. Forty-four of the
#: first register's entries are this shape, and `-> ` with nothing after it is a diff a reader
#: would have to count spaces to understand.
DELETED = "(line removed)"

#: Separator between the removed source and what replaced it. Wide on purpose: these strings
#: are read in a JSON file next to code that itself contains `->`.
BECOMES = "  ->  "


def survivors() -> tuple[dict[str, list[str]], int]:
    """Read the surviving mutants out of the last `mutmut run`, keyed by what they changed.

    Imported here rather than at module scope so that `--check` against a register can be
    unit-tested, and so that a missing `mutants/` tree reports itself as a missing run rather
    than as an import error.

    **The two numbers differ and both are reported.** Several mutants in one function can render
    to the same changed line, and two that a reader cannot tell apart are one entry as far as a
    register is concerned. Collapsing them silently would make the register look smaller than
    the debt, so the raw count travels alongside.

    Returns:
        Function key to its sorted, deduplicated survivor changes, and the raw number of
        surviving mutants behind them. The function key is the source path and the qualified
        name, as in ``ssrfguard/httpx.py::SafeTransport.__init__``.

    Raises:
        SystemExit: If no completed run is there to read.
    """
    try:
        from mutmut.__main__ import (  # noqa: PLC0415  # optional tooling, not a lane dependency
            Config,
            SourceFileMutationData,
            get_diff_for_mutant,
            orig_function_and_class_names_from_key,
            status_by_exit_code,
            walk_mutatable_files,
        )
    except ImportError as missing:  # pragma: no cover - the mutation lane installs it
        raise SystemExit(f"mutmut is not installed: {missing}") from missing

    if not (REPO_ROOT / "mutants").is_dir():
        raise SystemExit("no mutants/ tree; run `mutmut run` before checking it")

    Config.ensure_loaded()
    found: dict[str, list[str]] = {}
    for path in walk_mutatable_files():
        data = SourceFileMutationData(path=path)
        data.load()
        for name, exit_code in data.exit_code_by_key.items():
            if status_by_exit_code[exit_code] != "survived":
                continue
            function, class_name = orig_function_and_class_names_from_key(name)
            qualified = f"{class_name}.{function}" if class_name else function
            key = f"{Path(path).as_posix()}::{qualified}"
            found.setdefault(key, []).append(_change(get_diff_for_mutant(name, path=path)))
    raw = sum(len(changes) for changes in found.values())
    return {key: sorted(set(changes)) for key, changes in sorted(found.items())}, raw


def _change(diff: str) -> str:
    """Render one mutant's unified diff as the single line that identifies it.

    Args:
        diff: What `get_diff_for_mutant` produced.

    Returns:
        The removed source and what replaced it, joined by :data:`BECOMES`.
    """
    lines = diff.splitlines()
    removed = [line[1:].strip() for line in lines if line.startswith("-") and line[1:2] != "-"]
    added = [line[1:].strip() for line in lines if line.startswith("+") and line[1:2] != "+"]
    return " ; ".join(removed) + BECOMES + (" ; ".join(added) or DELETED)


def unregistered(
    found: dict[str, list[str]], register: dict[str, list[str]]
) -> dict[str, list[str]]:
    """Survivors that the register does not already account for.

    The pure half of this script, so the comparison can be tested without a mutation run. A
    function absent from the register contributes every one of its survivors, which is what
    makes a newly added function with no tests behind it fail rather than pass quietly.

    Args:
        found: What the last run produced, from :func:`survivors`.
        register: What was recorded, from :func:`load_register`.

    Returns:
        The same shape, holding only what is new. Empty when nothing is.
    """
    fresh: dict[str, list[str]] = {}
    for key, changes in found.items():
        known = set(register.get(key, ()))
        new = [change for change in changes if change not in known]
        if new:
            fresh[key] = new
    return fresh


def killed_since(found: dict[str, list[str]], register: dict[str, list[str]]) -> int:
    """How many registered survivors no longer survive.

    Reported rather than gated, for the reason the module docstring gives: a run that kills a
    mutant must not turn a lane red, and one mutant here is nondeterministic.

    Args:
        found: What the last run produced.
        register: What was recorded.

    Returns:
        The count of registered changes that did not survive this time.
    """
    live = {(key, change) for key, changes in found.items() for change in changes}
    return sum(
        1 for key, changes in register.items() for change in changes if (key, change) not in live
    )


def load_register() -> dict[str, list[str]]:
    """Read the committed register.

    Returns:
        Function key to its recorded survivor changes, empty if there is no register yet.
    """
    if not REGISTER.exists():
        return {}
    return dict(json.loads(REGISTER.read_text(encoding="utf-8"))["survivors"])


def write_register(found: dict[str, list[str]], raw: int, taken: str) -> None:
    """Replace the register with what the last run produced.

    Args:
        found: What the last run produced.
        raw: The number of surviving mutants behind those changes.
        taken: The date to stamp it with, so a reader knows how old the debt is.
    """
    document = {
        "_note": [
            "Surviving mutants this suite does not currently notice, and the date that was true.",
            "Generated by scripts/check_mutants.py --write. Do not hand-edit: regenerate it, and",
            "read the diff, because every line added is something the suite stopped noticing.",
            "Keyed on what each mutant changed rather than on its name, because mutmut names",
            "carry a position that shifts whenever the function around them is edited.",
            "Several mutants can render to the same changed line, so surviving_mutants is the",
            "raw count and distinct_changes is what a register can tell apart.",
            "This is debt with a date on it, not a target. See the script's own docstring.",
        ],
        "taken": taken,
        "surviving_mutants": raw,
        "distinct_changes": sum(len(changes) for changes in found.values()),
        "functions": len(found),
        "survivors": found,
    }
    REGISTER.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def main() -> int:
    """Compare the last run against the register, or replace the register with it.

    Returns:
        The process exit code: 1 if any survivor is not accounted for.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", metavar="DATE", help="replace the register, stamped with DATE")
    parser.add_argument("--run", action="store_true", help="run the mutants first, then check")
    arguments = parser.parse_args()

    if arguments.run:
        # The lane is one argument vector, so the sequencing lives here rather than in
        # `scripts/lanes.py`. `mutmut run` writes its own progress to this process's stdout.
        completed = subprocess.run(  # noqa: S603  # resolved absolute path, list argv, no shell
            [_tool("mutmut"), "run"], cwd=REPO_ROOT, check=False
        )
        if completed.returncode != 0:
            print(f"mutmut run exited {completed.returncode}", file=sys.stderr)
            return completed.returncode

    found, raw = survivors()
    total = sum(len(changes) for changes in found.values())

    if arguments.write:
        write_register(found, raw, arguments.write)
        print(f"register written: {raw} surviving mutants, {total} distinct changes, ", end="")
        print(f"{len(found)} functions")
        return 0

    register = load_register()
    if not register:
        print("no register to compare against; run --write to take one", file=sys.stderr)
        return 1

    fresh = unregistered(found, register)
    killed = killed_since(found, register)
    print(f"{raw} surviving mutants, {total} distinct changes across {len(found)} ", end="")
    print(f"functions; the register holds {sum(len(c) for c in register.values())}, ", end="")
    print(f"of which {killed} no longer survive")

    if not fresh:
        return 0

    print("\nsurvivors the register does not account for:", file=sys.stderr)
    for key, changes in fresh.items():
        print(f"  {key}", file=sys.stderr)
        for change in changes:
            print(f"      {change}", file=sys.stderr)
    print(
        f"\n{sum(len(c) for c in fresh.values())} new survivor(s). Either the suite lost an "
        f"assertion, or new code arrived without one. If the mutant is genuinely equivalent, "
        f"regenerate the register with --write and say so in the commit.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
