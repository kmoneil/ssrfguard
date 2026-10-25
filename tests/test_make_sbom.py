"""The release SBOM describes the wheel, and the check on it can say no.

The SBOM attached to 0.4.0 listed 73 components for a package that installs one, because both
workflows pointed ``cyclonedx-py`` at the environment they were running in, and the only check
on the result was that it listed something. These pin the two halves of the fix: the check
refuses that document, and neither workflow generates an SBOM except through
``scripts/make_sbom.py``.

Generating one for real needs ``cyclonedx-bom`` from PyPI, so that half is the rehearsal step
in ``ci.yml``'s ``audit`` job rather than a test here. These read the repository rather than the
library, which is what the ``repository`` marker is for.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.repository

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import make_sbom  # noqa: E402

WORKFLOWS = REPO_ROOT / ".github" / "workflows"

#: A sample of the 73 components in the `ssrfguard.cdx.json` attached to the v0.4.0 release:
#: the package itself, the two that carry advisories, and enough of the toolchain to show what
#: the rest was.
SHIPPED_IN_0_4_0 = [
    ("ssrfguard", "0.4.0"),
    ("certifi", "2026.7.22"),
    ("filelock", "3.32.3"),
    ("hatchling", "1.32.0"),
    ("mypy", "2.3.1"),
    ("pytest", "9.1.1"),
    ("requests", "2.34.2"),
]


def bom(*components: tuple[str, str]) -> dict[str, object]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [{"name": name, "version": version} for name, version in components],
    }


def executable(workflow: Path) -> str:
    """A workflow without its comments, which explain the old command by quoting it."""
    lines = workflow.read_text(encoding="utf-8").splitlines()
    return "\n".join(line for line in lines if not line.lstrip().startswith("#"))


def test_the_wheel_alone_passes() -> None:
    assert make_sbom.problems(bom(("ssrfguard", "0.4.1")), "0.4.1") == []


def test_regression_sbom_build_env_the_document_0_4_0_shipped_is_refused() -> None:
    found = make_sbom.problems(bom(*SHIPPED_IN_0_4_0), "0.4.0")
    assert len(found) == 1, found
    assert "components the wheel does not install" in found[0]
    for name, version in SHIPPED_IN_0_4_0[1:]:
        assert f"{name}=={version}" in found[0]
    assert "ssrfguard==0.4.0" not in found[0], "the package itself is not the problem"


@pytest.mark.parametrize("workflow", ["release.yml", "ci.yml"])
def test_regression_sbom_build_env_every_workflow_generates_it_through_the_script(
    workflow: str,
) -> None:
    text = executable(WORKFLOWS / workflow)
    assert "scripts/make_sbom.py" in text, f"{workflow} does not generate the SBOM from the wheel"
    assert "cyclonedx-py" not in text, (
        f"{workflow} runs cyclonedx-py itself; a second copy is how both came to describe "
        "the environment they ran in"
    )


def test_the_wrong_version_is_refused() -> None:
    found = make_sbom.problems(bom(("ssrfguard", "0.4.0")), "0.4.1")
    assert "ssrfguard==0.4.1 is not among the components" in found
    assert "components the wheel does not install: ssrfguard==0.4.0" in found


def test_an_sbom_that_lists_nothing_is_refused() -> None:
    assert make_sbom.problems(bom(), "0.4.1") == ["ssrfguard==0.4.1 is not among the components"]


def test_a_component_that_is_not_a_mapping_is_named_rather_than_skipped() -> None:
    document = bom(("ssrfguard", "0.4.1"))
    document["components"] = [{"name": "ssrfguard", "version": "0.4.1"}, "certifi"]
    assert make_sbom.problems(document, "0.4.1") == [
        "components the wheel does not install: 'certifi'"
    ]


def test_a_document_that_is_not_cyclonedx_is_refused() -> None:
    assert make_sbom.problems({"spdxVersion": "SPDX-2.3"}, "0.4.1") == [
        "not a CycloneDX document: bomFormat is None",
        "the document has no components list",
    ]


def test_the_version_comes_off_the_wheel_filename() -> None:
    assert make_sbom.wheel_version(Path("dist/ssrfguard-0.4.1-py3-none-any.whl")) == "0.4.1"


@pytest.mark.parametrize(
    "name", ["ssrfguard-0.4.1.tar.gz", "certifi-2026.10.23-py3-none-any.whl", "ssrfguard.whl"]
)
def test_anything_but_an_ssrfguard_wheel_is_refused(name: str) -> None:
    with pytest.raises(make_sbom.NotProducedError, match="is not a ssrfguard wheel"):
        make_sbom.wheel_version(Path(name))


def test_a_missing_wheel_is_not_checked_rather_than_passed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status = make_sbom.main([str(tmp_path / "ssrfguard-0.4.1-py3-none-any.whl"), str(tmp_path)])
    assert status == 2
    assert "no SBOM was produced" in capsys.readouterr().err
