"""Write the release SBOM from the wheel alone, and refuse one that describes anything more.

**0.4.0 shipped an SBOM of the machine that built it.** ``release.yml`` pointed ``cyclonedx-py
environment`` at the interpreter ``uv run`` resolves, which is the build job's project
environment, and ``uv sync --group build`` fills that with the ``dev`` group as well, because
``dev`` is a default group. The document SECURITY.md calls nearly empty listed 73 components,
and 72 of them are not in the wheel: pytest, mypy, hatchling, and certifi 2026.7.22 and
filelock 3.32.3, which now carry a critical and a high advisory. The rehearsal in ``ci.yml``
generated the same document the same way and asked only whether ``components`` was non-empty,
which 73 is.

So this does what the workflow comment always said it did: installs the built wheel, and only
the wheel, into a fresh environment, and describes that. ``uv venv`` seeds nothing, not even
pip, so the wheel is the only distribution there. It installs *with* dependencies rather than
``--no-deps``, because the question is what ``pip install ssrfguard`` puts on a machine.

**Then it reads the answer**, because the failure above was a document nobody read. The SBOM
must list ``ssrfguard`` at the wheel's version and nothing else. A runtime dependency would make
that false, and it should fail here as well as in ``zero-deps``: ``[project.dependencies]`` is
``[]`` by decision, and the SBOM is how a reader checks that without taking our word for it.

Usage::

    python scripts/make_sbom.py dist/ssrfguard-0.4.1-py3-none-any.whl dist/ssrfguard.cdx.json

Exit status is 0 for an SBOM naming the wheel alone, 1 for one that names anything else, and 2
for "no SBOM could be produced", which is a distinct answer and must not be read as a pass.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DISTRIBUTION = "ssrfguard"


class NotProducedError(Exception):
    """Raised when no SBOM could be produced, which is distinct from a wrong one.

    Everything that raises this maps to exit status 2 rather than 0 or 1.
    """


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a command, capturing output.

    Args:
        argv: Argument vector, whose first element is already an absolute path.

    Returns:
        The completed process.
    """
    return subprocess.run(  # noqa: S603  # resolved absolute path, list argv, no shell
        argv, capture_output=True, text=True, check=False
    )


def _uv() -> str:
    """Resolve ``uv`` to an absolute path.

    Returns:
        An absolute path to ``uv``.

    Raises:
        NotProducedError: If ``uv`` is not installed anywhere this can see it.
    """
    found = shutil.which("uv")
    if found is None:
        raise NotProducedError("uv not found; it builds the environment the SBOM describes")
    return found


def wheel_version(wheel: Path) -> str:
    """Read the version off a wheel's filename.

    The filename is part of the wheel format (``name-version[-build]-python-abi-platform.whl``),
    so nothing has to be unpacked to know which version the SBOM is meant to describe.

    Args:
        wheel: Path to the wheel.

    Returns:
        The version the filename carries.

    Raises:
        NotProducedError: If the path is not an ssrfguard wheel.
    """
    parts = wheel.stem.split("-")
    if wheel.suffix != ".whl" or len(parts) not in {5, 6} or parts[0] != DISTRIBUTION:
        raise NotProducedError(f"{wheel.name} is not a {DISTRIBUTION} wheel")
    return parts[1]


def problems(bom: dict[str, object], version: str) -> list[str]:
    """List everything that makes ``bom`` something other than this wheel's SBOM.

    Args:
        bom: A parsed CycloneDX document.
        version: The version of the wheel it is meant to describe.

    Returns:
        One line per problem, empty when the document names ``ssrfguard`` at ``version`` and
        nothing else.
    """
    found: list[str] = []
    if bom.get("bomFormat") != "CycloneDX":
        found.append(f"not a CycloneDX document: bomFormat is {bom.get('bomFormat')!r}")
    components = bom.get("components")
    if not isinstance(components, list):
        return [*found, "the document has no components list"]
    # A component that is not a mapping is listed rather than skipped: dropping it here is how
    # a validator ends up approving something it never looked at.
    listed = sorted(
        f"{c.get('name')}=={c.get('version')}" if isinstance(c, dict) else repr(c)
        for c in components
    )
    want = f"{DISTRIBUTION}=={version}"
    if want not in listed:
        found.append(f"{want} is not among the components")
    extra = [entry for entry in listed if entry != want]
    if extra:
        found.append(f"components the wheel does not install: {', '.join(extra)}")
    return found


def generate(wheel: Path, output: Path, work: Path) -> None:
    """Install ``wheel`` alone into a fresh environment and write that environment's SBOM.

    Args:
        wheel: Path to the built wheel.
        output: Where the CycloneDX JSON goes.
        work: A scratch directory for the environment.

    Raises:
        NotProducedError: If any step could not complete.
    """
    uv = _uv()
    venv = work / "venv"
    made = _run([uv, "venv", "--quiet", str(venv)])
    if made.returncode != 0:
        raise NotProducedError(f"could not create the clean environment:\n{made.stderr}")

    python = venv / "bin" / "python"
    installed = _run([uv, "pip", "install", "--quiet", "--python", str(python), str(wheel)])
    if installed.returncode != 0:
        raise NotProducedError(f"could not install the wheel:\n{installed.stderr}")

    described = _run(
        [
            uv,
            "tool",
            "run",
            "--from",
            "cyclonedx-bom",
            "cyclonedx-py",
            "environment",
            "--output-format",
            "json",
            "--output-file",
            str(output),
            str(python),
        ]
    )
    if described.returncode != 0:
        raise NotProducedError(f"cyclonedx-py failed:\n{described.stderr}")


def produce(wheel: Path, output: Path) -> tuple[str, dict[str, object]]:
    """Write the SBOM for ``wheel`` to ``output`` and read it back.

    Args:
        wheel: Path to the built wheel.
        output: Where the CycloneDX JSON goes.

    Returns:
        The wheel's version and the parsed document.

    Raises:
        NotProducedError: If there is no wheel, no SBOM, or nothing readable in it.
    """
    if not wheel.is_file():
        raise NotProducedError(f"{wheel} does not exist")
    version = wheel_version(wheel)
    with tempfile.TemporaryDirectory() as tmp:
        generate(wheel, output, Path(tmp))
    try:
        bom = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise NotProducedError(f"could not read {output.name} back: {exc}") from exc
    if not isinstance(bom, dict):
        raise NotProducedError(f"{output.name} is a JSON {type(bom).__name__}, not a document")
    return version, bom


def main(argv: list[str] | None = None) -> int:
    """Generate the SBOM for one wheel and check that it describes that wheel alone.

    Args:
        argv: Arguments, or ``None`` for ``sys.argv``.

    Returns:
        0 the wheel alone, 1 anything more, 2 no SBOM produced.
    """
    parser = argparse.ArgumentParser(
        description="Write the release SBOM from the wheel alone, and refuse one that says more."
    )
    parser.add_argument("wheel", type=Path, help="the built wheel the release uploads")
    parser.add_argument("output", type=Path, help="where to write the CycloneDX JSON")
    args = parser.parse_args(argv)
    wheel: Path = args.wheel.resolve()
    output: Path = args.output.resolve()

    try:
        version, bom = produce(wheel, output)
    except (NotProducedError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        print("no SBOM was produced", file=sys.stderr)
        return 2

    found = problems(bom, version)
    if found:
        for line in found:
            print(line, file=sys.stderr)
        print(f"{output.name} describes more than {wheel.name}; refusing it", file=sys.stderr)
        return 1
    print(f"{output.name}: {DISTRIBUTION}=={version} and nothing else")
    return 0


if __name__ == "__main__":
    sys.exit(main())
