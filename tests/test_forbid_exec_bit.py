"""The executable-bit hook, run under the bash a contributor's Mac actually has.

`scripts/forbid_exec_bit.sh` is a pre-commit hook and nothing else calls it, so the only place it
ran was the `gates` lane, on Ubuntu, under bash 5. That is how it came to need bash 4 while every
Mac ships 3.2 as `/bin/bash`: CI could not see the difference, and a contributor on a stock Mac got
`mapfile: command not found` on every commit, which is the hook people learn to skip.

These read the repository rather than the library, which is what the `repository` marker is for.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.repository

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOK = REPO_ROOT / "scripts" / "forbid_exec_bit.sh"

#: The system's bash rather than whichever one is first on the path. The hook's entry is
#: `bash scripts/forbid_exec_bit.sh`, so it gets the path's bash, and on a Mac without Homebrew
#: that is this one, at 3.2. GitHub's macOS runners put Homebrew's 5.x first, which is why
#: running the path's bash here would pass on every machine CI has and catch nothing.
STOCK_BASH = "/bin/bash"


def _scratch_environment() -> dict[str, str]:
    """This process's environment without the variables that would aim git somewhere else.

    A hook exports `GIT_DIR` and `GIT_INDEX_FILE` to its children, and the pre-push hook runs
    this suite, so an inherited variable would point both the setup and the hook at the real
    repository's index instead of the scratch one.

    Returns:
        The environment to run git and the hook in.
    """
    return {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}


def _git(*args: str, cwd: Path) -> None:
    """Run git against the scratch repository and nothing else.

    Args:
        *args: The git subcommand and its arguments.
        cwd: The scratch repository.
    """
    subprocess.run(
        ["git", *args], cwd=cwd, env=_scratch_environment(), check=True, capture_output=True
    )


def _index(tmp_path: Path, *executable: str) -> Path:
    """A repository whose index holds one ordinary file and the given files marked executable.

    Args:
        tmp_path: Where to make it.
        *executable: Names to record with mode 100755.

    Returns:
        The repository's root.
    """
    _git("init", "-q", ".", cwd=tmp_path)
    for name in ("ordinary.py", *executable):
        (tmp_path / name).write_text("", encoding="utf-8")
    _git("add", ".", cwd=tmp_path)
    for name in executable:
        _git("update-index", "--chmod=+x", name, cwd=tmp_path)
    return tmp_path


def _run_hook(repository: Path) -> subprocess.CompletedProcess[str]:
    """Run the hook the way pre-commit does, from the repository's root.

    Args:
        repository: The repository to check.

    Returns:
        The finished process.
    """
    return subprocess.run(
        [STOCK_BASH, str(HOOK)],
        cwd=repository,
        env=_scratch_environment(),
        capture_output=True,
        text=True,
        check=False,
    )


def test_regression_exec_bit_bash3_the_hook_passes_a_clean_index_under_stock_bash(
    tmp_path: Path,
) -> None:
    """The hook read its file list with `mapfile`, which bash 3.2 does not have.

    So on a stock Mac it failed before it had looked at anything, on every commit, whether or not
    a file was executable. The fix is a `while read` loop, which every bash has.
    """
    result = _run_hook(_index(tmp_path))

    assert result.returncode == 0, result.stderr


def test_it_names_the_file_marked_executable(tmp_path: Path) -> None:
    """The other half: a hook that passes a clean index has to be able to fail a dirty one."""
    result = _run_hook(_index(tmp_path, "stray.sh"))

    assert result.returncode == 1, result.stderr
    assert "  stray.sh\n" in result.stderr
    assert "ordinary.py" not in result.stderr
