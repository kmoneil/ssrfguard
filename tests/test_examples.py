"""Every example runs, and every example is listed where a reader is told to look.

`examples/README.md` claims that each file there "runs with no arguments, no network and no
fixtures", and that every one is executed by the suite. Both halves of that are only true if
something checks, and an example that quietly stopped working would be worse than no example at
all: it is a documented, copied, apparently-blessed snippet that does not do what it says.

**They run as subprocesses rather than by import**, for three reasons. It is the way a reader
runs them, so it is the thing worth asserting. It proves each file works from a cold interpreter
with nothing else imported, which is what `if __name__ == "__main__"` promises. And it keeps
their lines out of the coverage measurement, which is a property of `src/` and would be
flattered by nine files of printing.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "examples"

#: Examples are numbered so a reader has a reading order; the glob keeps that order.
SCRIPTS = sorted(EXAMPLES.glob("[0-9][0-9]_*.py"))

#: How long one example may take. Generous on purpose: these bind loopback sockets and one of
#: them sleeps for 250 milliseconds to make a point about the event loop. A timeout here should
#: mean "hung", not "slow CI".
TIMEOUT_SECONDS = 120


def test_there_are_examples_to_run() -> None:
    """A glob that matched nothing would make every test below vacuously pass."""
    assert SCRIPTS, f"no numbered examples found in {EXAMPLES}"


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.stem)
def test_example_runs_with_no_arguments(script: Path) -> None:
    """Run one example exactly as its docstring tells a reader to run it.

    Args:
        script: The example to run.
    """
    done = subprocess.run(  # our own file, list argv, no shell
        [sys.executable, script.name],
        cwd=EXAMPLES,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
    )
    assert done.returncode == 0, (
        f"{script.name} exited {done.returncode}. Examples are documentation that runs, so a "
        f"failure here is a documentation bug.\n\nstdout:\n{done.stdout}\n\nstderr:\n"
        f"{done.stderr}"
    )
    assert done.stdout.strip(), f"{script.name} printed nothing, so it demonstrates nothing"


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.stem)
def test_example_is_listed_in_the_examples_readme(script: Path) -> None:
    """An example nobody is pointed at is an example nobody reads.

    Args:
        script: The example that must appear in the index.
    """
    index = (EXAMPLES / "README.md").read_text(encoding="utf-8")
    assert script.name in index, (
        f"{script.name} is not linked from examples/README.md; add a row for it so the table "
        f"stays the complete list rather than a sample of one"
    )


def test_the_examples_readme_links_nothing_that_is_gone() -> None:
    """The other direction, so a deleted example leaves no dead link behind.

    Every link target in the index is resolved against the directory the index sits in, which
    is what a reader's browser does with it.
    """
    index = (EXAMPLES / "README.md").read_text(encoding="utf-8")
    targets = re.findall(r"\]\(([^)#]+)\)", index)
    dead = sorted({target for target in targets if not (EXAMPLES / target).resolve().exists()})
    assert not dead, f"examples/README.md links files that do not exist: {dead}"


@pytest.mark.parametrize("script", [*SCRIPTS, EXAMPLES / "_support.py"], ids=lambda p: p.stem)
def test_example_explains_itself_before_it_runs(script: Path) -> None:
    """Each file opens with a docstring, because the prose is half of what an example is.

    Args:
        script: The file to check.
    """
    text = script.read_text(encoding="utf-8")
    assert text.startswith('"""'), (
        f"{script.name} does not open with a module docstring. An example is documentation "
        f"that happens to run; without the prose it is only the second half"
    )
