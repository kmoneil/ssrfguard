"""The lane registry is the single source, and this asserts CI agrees with it.

Two spellings of "how this project runs its tests" is how a lane ends up with one set of flags
locally and another in CI. `scripts/lanes.py` is the source; this file is what stops
`.github/workflows/ci.yml` from quietly disagreeing with it.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

#: Reads the repository rather than the library. `mutmut` copies `src`, `tests` and two
#: files into `mutants/` and runs the suite from there, where the rest of the tree does
#: not exist, so this cannot run: it imports `lanes` from `scripts/`. It could not kill a
#: mutant in `src/ssrfguard` either way.
pytestmark = pytest.mark.repository

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import lanes  # noqa: E402

CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
RELEASE = REPO_ROOT / ".github" / "workflows" / "release.yml"
RULESET = REPO_ROOT / ".github" / "rulesets" / "main.json"


@pytest.fixture(scope="module")
def ci_text() -> str:
    return CI.read_text(encoding="utf-8")


def test_every_lane_is_invoked_by_ci(ci_text: str) -> None:
    for lane in lanes.LANES:
        assert f"scripts/lanes.py {lane.name}" in ci_text, (
            f"lane {lane.name!r} exists but ci.yml never runs it"
        )


def test_every_lane_has_a_job(ci_text: str) -> None:
    for lane in lanes.LANES:
        assert re.search(rf"^  {re.escape(lane.name)}:$", ci_text, re.MULTILINE), (
            f"lane {lane.name!r} has no job of its own in ci.yml"
        )


def test_ci_runs_no_lane_the_registry_does_not_know(ci_text: str) -> None:
    invoked = set(re.findall(r"scripts/lanes\.py ([a-z-]+)", ci_text))
    assert invoked <= set(lanes.BY_NAME), (
        f"ci.yml runs lanes the registry does not define: {invoked - set(lanes.BY_NAME)}"
    )


def test_compat_matrix_matches_the_registry(ci_text: str) -> None:
    """The interpreter list decides what the address-table assertions cover; it must not drift."""
    block = re.search(r"^  compat:$.*?^  \w", ci_text, re.MULTILINE | re.DOTALL)
    assert block is not None, "ci.yml has no compat job"
    declared = re.findall(r'"(\d+\.\d+)"', block.group(0))
    assert tuple(declared) == lanes.COMPAT_PYTHONS, (
        f"ci.yml compat matrix {declared} disagrees with lanes.COMPAT_PYTHONS "
        f"{list(lanes.COMPAT_PYTHONS)}"
    )


def test_every_gating_lane_is_a_required_status_check() -> None:
    """A gate nothing requires is a gate a merge can ignore."""
    ruleset = json.loads(RULESET.read_text(encoding="utf-8"))
    contexts = {
        check["context"]
        for rule in ruleset["rules"]
        if rule["type"] == "required_status_checks"
        for check in rule["parameters"]["required_status_checks"]
    }
    for lane in lanes.LANES:
        if not lane.gates:
            continue
        # A matrixed job appears once per row, named `job (value)`.
        matched = any(c == lane.name or c.startswith(f"{lane.name} (") for c in contexts)
        assert matched, f"gating lane {lane.name!r} is not a required status check"


def test_no_lane_reports_without_saying_why() -> None:
    for lane in lanes.LANES:
        if lane.gates:
            continue
        assert lane.reports_only.strip(), (
            f"lane {lane.name!r} does not gate and gives no reason; "
            "a lane that could gate and does not is a gap wearing a policy's clothes"
        )


def test_third_party_actions_are_pinned_to_a_sha() -> None:
    """A floating tag is a mutable reference to somebody else's code.

    release.yml runs with permission to publish, so this is not a style rule.
    """
    for workflow in (CI, RELEASE):
        for line in workflow.read_text(encoding="utf-8").splitlines():
            match = re.search(r"uses:\s*(\S+)", line)
            if match is None or match.group(1).startswith("./"):
                continue
            reference = match.group(1)
            _, _, version = reference.partition("@")
            assert re.fullmatch(r"[0-9a-f]{40}", version), (
                f"{workflow.name}: {reference} is not pinned to a commit SHA"
            )
            assert "#" in line, f"{workflow.name}: {reference} has no trailing tag comment"


def test_release_keeps_the_decisions_that_are_written_out() -> None:
    """Defaults a documented decision rests on are restated so an edit cannot silently drop one."""
    text = RELEASE.read_text(encoding="utf-8")
    assert "attestations: true" in text, (
        "SECURITY.md tells readers provenance is a signed PEP 740 attestation; "
        "that is only true while one is produced"
    )
    assert "digest-mismatch: error" in text
    assert "--no-build-isolation" in text, (
        "without it the build backend is resolved fresh from PyPI, unpinned and unhashed"
    )
    # Comments stripped first, and not as a tidy-up: the header *explains* why there is no
    # long-lived token, so a naive substring search finds the string it is looking for inside
    # the paragraph arguing against it and fails a correct file. What must not appear is a
    # token reference in something the runner executes.
    executable = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "PYPI_API_TOKEN" not in executable, (
        "trusted publishing means there is no long-lived token"
    )
    assert "secrets." not in executable, (
        "release.yml reads a repository secret; trusted publishing needs none"
    )
