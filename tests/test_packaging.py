"""What the distribution claims about itself, checked rather than trusted."""

from __future__ import annotations

import doctest
import re
import sys
from pathlib import Path

import pytest

import ssrfguard

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import lanes  # noqa: E402

# `tomllib` arrived in 3.11 and this package's floor is 3.10. The alternative is `tomli`, which
# would be a dependency, and a dependency acquired to test that there are no dependencies is
# not a trade this repository gets to make. These are assertions about repository *metadata*,
# not about the library, so the one `compat` row below 3.11 skips them and every other row runs
# them. `fast` runs on 3.13, so nothing here is ever unchecked.
tomllib = pytest.importorskip(
    "tomllib",
    reason="repository-metadata assertions need tomllib (3.11+); the library itself does not",
)


@pytest.fixture(scope="module")
def pyproject() -> dict:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_version_is_single_sourced(pyproject: dict) -> None:
    assert pyproject["project"]["dynamic"] == ["version"]
    assert pyproject["tool"]["hatch"]["version"]["path"] == "src/ssrfguard/__init__.py"
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:[.\-]?\w+)?", ssrfguard.__version__)


def test_dependencies_are_empty(pyproject: dict) -> None:
    """The claim on the front of the README, at its source."""
    assert pyproject["project"]["dependencies"] == []


def test_build_group_agrees_with_build_system(pyproject: dict) -> None:
    """A `build` group that has drifted produces a build that quietly re-resolves."""
    required = pyproject["build-system"]["requires"]
    group = pyproject["dependency-groups"]["build"]
    assert {r.split(">=")[0].strip() for r in required} == {g.split(">=")[0].strip() for g in group}


def test_license_text_ships_alongside_the_identifier(pyproject: dict) -> None:
    """Apache-2.0 section 4(a) wants the file; a compliance scan looks for it, not the SPDX id."""
    assert pyproject["project"]["license"] == "Apache-2.0"
    assert pyproject["project"]["license-files"] == ["LICENSE"]
    text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.lstrip().startswith("Apache License")
    assert "Version 2.0, January 2004" in text


def test_classifiers_name_every_supported_interpreter(pyproject: dict) -> None:
    """The matrix and the classifiers are two claims about the same set."""
    classified = {
        c.rsplit(" :: ", 1)[-1]
        for c in pyproject["project"]["classifiers"]
        if c.startswith("Programming Language :: Python :: ") and c[-1].isdigit() and "." in c
    }
    assert classified == set(lanes.SUPPORTED_PYTHONS)


def test_requires_python_matches_the_floor(pyproject: dict) -> None:
    assert pyproject["project"]["requires-python"] == f">={lanes.SUPPORTED_PYTHONS[0]}"


def test_ruff_targets_the_floor_not_the_dev_interpreter(pyproject: dict) -> None:
    """`target-version` is the only gate that can stop above-the-floor *syntax* reaching src/."""
    floor = lanes.SUPPORTED_PYTHONS[0].replace(".", "")
    assert pyproject["tool"]["ruff"]["target-version"] == f"py{floor}"


def test_both_type_checkers_target_the_floor(pyproject: dict) -> None:
    """Both must check the floor, and one of them can only do so because of where the floor is.

    mypy refuses `python_version = "3.9"`, and warns and carries on rather than failing, so at
    a lower floor this setting would be silently ignored and the gate would check nothing while
    appearing to. That it can be asserted equal to the floor here is a property of the floor
    being 3.10, and it is one of the reasons the floor is 3.10. If the floor ever moves down,
    this test fails rather than the gate quietly going dark.
    """
    floor = lanes.SUPPORTED_PYTHONS[0]
    assert pyproject["tool"]["mypy"]["python_version"] == floor
    assert pyproject["tool"]["ty"]["environment"]["python-version"] == floor


def test_py_typed_ships() -> None:
    assert (REPO_ROOT / "src" / "ssrfguard" / "py.typed").exists()


def test_changelog_has_a_section_for_this_version() -> None:
    """Either a heading for the packaged version, or `Unreleased` before the first tag."""
    text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(rf"^## {re.escape(ssrfguard.__version__)}( |$)", text, re.MULTILINE) or (
        re.search(r"^## Unreleased( |$)", text, re.MULTILINE)
    )


def test_security_policy_exists() -> None:
    """Required for this package, not merely expected: it is what a reporter looks for first."""
    text = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "@" in text, "SECURITY.md carries no disclosure address"


def test_the_package_docstring_example_is_true() -> None:
    """The front page of the package is code, so it is run rather than read.

    Nothing else runs it: no lane passes `--doctest-modules`, and the example sat wrong for
    several releases' worth of commits because of that: it claimed the `<Target ...>` debug
    form where a dataclass's generated `repr` was what actually came back. An example a reader
    copies is documentation with a test-shaped hole in it unless something executes it.

    `testmod` covers this module's own docstring and nothing else: the names re-exported here
    belong to `ssrfguard._policy` and friends, so their `__module__` does not match and doctest
    skips them. That keeps this free of the optional adapters, which is what lets it run on the
    compatibility rows where neither client is installed.
    """
    results = doctest.testmod(
        ssrfguard,
        optionflags=doctest.ELLIPSIS | doctest.IGNORE_EXCEPTION_DETAIL,
        verbose=False,
    )
    assert results.attempted > 0, "the docstring stopped carrying an example, so this checks none"
    assert results.failed == 0, f"{results.failed} of {results.attempted} docstring examples fail"
