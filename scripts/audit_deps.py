"""Known advisories against what this project installs, in two scopes with two verdicts.

**The shipped scope is empty, and printing that empty set every release is most of this
lane's value.** ``[project.dependencies]`` is ``[]`` and stays ``[]``; ``zero-deps`` proves the
built artifact agrees. What this adds is the standing check that nothing a *user* installs has
a published advisory — which, for a package with no runtime dependencies, is the claim on the
README verified rather than asserted. A release note can cite a run of this instead of citing
an intention.

The development scope is a different question with a different answer. A vulnerable pytest is
not a vulnerability in ssrfguard, and gating on it would make an advisory in somebody's test
runner able to block a security fix. It reports.

**A failure to reach the advisory service is a third outcome, not a pass.** pip-audit exits
non-zero with empty stdout when it cannot reach PyPI; this script routes on that and exits 2,
so a lane that could not check says so rather than reporting a clean tree.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The two scopes. `--no-deps` is wrong for both: the question is what gets installed, which
# includes the transitive closure, and for the shipped scope that closure is empty by
# construction.
SHIPPED = ["uv", "export", "--no-dev", "--no-emit-project", "--format", "requirements.txt"]
DEVELOPMENT = ["uv", "export", "--no-emit-project", "--format", "requirements.txt"]


def _tool(name: str) -> str:
    """Resolve a tool to an absolute path, preferring the project virtualenv.

    A partial executable path is resolved against ``PATH``, which is attacker-influenced in
    exactly the environments a security tool runs in. Same resolution order as
    ``scripts/lanes.py``.

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
        raise SystemExit(f"tool not found: {name!r} (is the audit group synced?)")
    return found


def _requirements(argv: list[str]) -> str | None:
    """Export one scope as a requirements file.

    Args:
        argv: The ``uv export`` invocation.

    Returns:
        The requirements text, or ``None`` if the export failed.
    """
    resolved = [_tool(argv[0]), *argv[1:]]
    done = subprocess.run(  # noqa: S603  # resolved absolute path, list argv, no shell
        resolved, capture_output=True, text=True, check=False
    )
    if done.returncode != 0:
        print(done.stderr, file=sys.stderr)
        return None
    return done.stdout


def _audit(requirements: str) -> tuple[list[dict[str, object]], bool]:
    """Audit one requirements set.

    Args:
        requirements: Requirements-file text.

    Returns:
        A pair of (findings, reachable). ``reachable`` is ``False`` when the advisory service
        could not be consulted, which is distinct from "no findings".
    """
    done = subprocess.run(  # noqa: S603  # resolved absolute path, list argv, no shell
        [_tool("pip-audit"), "--format", "json", "--requirement", "/dev/stdin"],
        input=requirements,
        capture_output=True,
        text=True,
        check=False,
    )
    if not done.stdout.strip():
        print(done.stderr, file=sys.stderr)
        return [], False
    report = json.loads(done.stdout)
    findings = [
        dependency for dependency in report.get("dependencies", []) if dependency.get("vulns")
    ]
    return findings, True


def _describe(scope: str, findings: list[dict[str, object]]) -> None:
    """Print one scope's findings.

    Args:
        scope: Human-readable scope name.
        findings: Dependencies carrying at least one advisory.
    """
    if not findings:
        print(f"{scope}: no known advisories")
        return
    print(f"{scope}: {len(findings)} package(s) with advisories")
    for dependency in findings:
        vulns = dependency.get("vulns", [])
        ids = ", ".join(str(v.get("id")) for v in vulns)  # type: ignore[union-attr]
        print(f"  {dependency.get('name')} {dependency.get('version')}: {ids}")


def main() -> int:
    """Audit both scopes.

    Returns:
        0 clean, 1 a shipped-scope finding, 2 the service could not be reached.
    """
    shipped = _requirements(SHIPPED)
    development = _requirements(DEVELOPMENT)
    if shipped is None or development is None:
        print("could not export a scope; nothing was checked", file=sys.stderr)
        return 2

    shipped_findings, reachable = _audit(shipped)
    if not reachable:
        print("could not reach the advisory service; nothing was checked", file=sys.stderr)
        return 2
    _describe("shipped surface (gates)", shipped_findings)

    development_findings, reachable = _audit(development)
    if reachable:
        _describe("development environment (reports)", development_findings)
    else:
        print("development scope: could not reach the advisory service", file=sys.stderr)

    return 1 if shipped_findings else 0


if __name__ == "__main__":
    sys.exit(main())
