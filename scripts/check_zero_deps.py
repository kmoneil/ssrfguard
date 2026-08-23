"""Prove the empty dependency tree against a built artifact, not against intent.

``tests/test_zero_deps.py`` reads the installed distribution's ``Requires-Dist`` and asserts
every entry carries an ``extra ==`` marker. That is the right check and it runs everywhere, and
it **cannot catch the failure that actually matters**: a development checkout has httpx and
requests installed, so an adapter that imports its client at module scope, instead of lazily
inside the function body, passes every test in the suite while breaking the promise on the
front of the README for anyone who installs the bare package.

Only an interpreter that does not have those clients can see that. This script builds the
wheel, installs it alone into a fresh environment, and asks three questions there:

1. **Is the environment actually clean?** If httpx or requests is importable, everything below
   is vacuous. This is checked first and fails loudly, because a vacuous pass is worse than a
   failure. It is a green lane asserting nothing.
2. **Does the built METADATA declare an unconditional requirement?** Read off the artifact a
   user would download rather than off ``pyproject.toml``, because the build backend is what
   decides what lands there.
3. **Does importing the package pull in a third-party module?** Measured as the difference
   between ``sys.modules`` before and after the import, filtered to modules whose file lives in
   ``site-packages`` and is not ours.

Exit status is 0 for a clean result, 1 for a violation, and 2 for "this could not be checked",
which is a distinct answer and must not be read as a pass.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Run inside the clean environment. Kept as a string rather than a file in `scripts/` so it
# cannot accidentally be collected by the outer suite or import anything from this repository.
PROBE = r"""
import json, sys, sysconfig

result = {"clients_present": [], "leaked": [], "requires": [], "import_error": None}

# **Metadata first, and before importing anything.** A package that declared a hard dependency
# has it installed, so the clean-environment check below would fire and call the run "vacuous"
# and diagnose a violation as broken infrastructure. Reading METADATA needs no import, so the
# violation is named before anything can mask it.
import importlib.metadata as md
result["requires"] = list(md.requires("ssrfguard") or [])

for client in ("httpx", "requests", "urllib3", "httpcore"):
    try:
        __import__(client)
    except ImportError:
        pass
    else:
        result["clients_present"].append(client)

before = set(sys.modules)
try:
    import ssrfguard  # noqa: F401
except ImportError as exc:
    # **This is a finding, not a crash.** An adapter importing its client at module scope
    # fails exactly here and nowhere else, which is the whole reason this lane exists. Letting
    # the traceback escape would report the one defect we are looking for as "the probe did
    # not run".
    result["import_error"] = str(exc)
    print("SSRFGUARD_PROBE " + json.dumps(result))
    raise SystemExit(0)
after = set(sys.modules)

purelib = sysconfig.get_paths()["purelib"]
for name in sorted(after - before):
    module = sys.modules.get(name)
    origin = getattr(getattr(module, "__spec__", None), "origin", None)
    if not origin or not origin.startswith(purelib):
        continue
    if name == "ssrfguard" or name.startswith("ssrfguard."):
        continue
    result["leaked"].append(name)

print("SSRFGUARD_PROBE " + json.dumps(result))
"""


def _run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    """Run a command, capturing output.

    Args:
        argv: Argument vector, whose first element is already an absolute path.
        **kwargs: Passed through to ``subprocess.run``.

    Returns:
        The completed process.
    """
    return subprocess.run(  # noqa: S603  # resolved absolute path, list argv, no shell
        argv, capture_output=True, text=True, check=False, **kwargs
    )


def _uv() -> str:
    """Resolve ``uv`` to an absolute path.

    Returns:
        An absolute path to ``uv``.

    Raises:
        SystemExit: If ``uv`` is not installed anywhere this can see it.
    """
    found = shutil.which("uv")
    if found is None:
        raise SystemExit("uv not found; this lane builds and installs with it")
    return found


class NotCheckedError(Exception):
    """Raised when the lane could not run, which is distinct from a finding.

    A lane that could not check must not report a pass. Everything that raises this maps to
    exit status 2 rather than 0 or 1.
    """


def _probe_clean_environment(work: Path) -> dict[str, object]:
    """Build the wheel, install it alone, and probe the resulting environment.

    Args:
        work: A scratch directory to build and install into.

    Returns:
        The probe's result mapping.

    Raises:
        NotCheckedError: If any step could not complete, so the caller reports "not checked".
    """
    uv = _uv()
    dist = work / "dist"
    venv = work / "venv"

    build = _run([uv, "build", "--out-dir", str(dist)], cwd=REPO_ROOT)
    if build.returncode != 0:
        raise NotCheckedError(f"could not build the distribution:\n{build.stderr}")

    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        raise NotCheckedError(f"expected exactly one wheel, found {len(wheels)}")

    made = _run([uv, "venv", str(venv)])
    if made.returncode != 0:
        raise NotCheckedError(f"could not create the clean environment:\n{made.stderr}")

    python = venv / "bin" / "python"
    installed = _run([uv, "pip", "install", "--python", str(python), str(wheels[0])])
    if installed.returncode != 0:
        raise NotCheckedError(f"could not install the wheel:\n{installed.stderr}")

    probed = _run([str(python), "-c", PROBE])
    marker = "SSRFGUARD_PROBE "
    line = next((ln for ln in probed.stdout.splitlines() if ln.startswith(marker)), None)
    if line is None:
        raise NotCheckedError(f"the probe produced no result:\n{probed.stdout}\n{probed.stderr}")

    result: dict[str, object] = json.loads(line[len(marker) :])
    return result


def _report(result: dict[str, object]) -> bool:
    """Print the verdict for a probe result.

    Args:
        result: The probe's result mapping.

    Returns:
        ``True`` if anything violated the zero-dependency rule.
    """
    failed = False
    requires = [str(r) for r in result["requires"]]  # type: ignore[union-attr]

    hard = [req for req in requires if "extra ==" not in req]
    if hard:
        print(f"the built distribution declares runtime dependencies: {hard}", file=sys.stderr)
        failed = True
    else:
        print(f"METADATA: no unconditional Requires-Dist ({len(requires)} behind extras)")

    import_error = result["import_error"]
    if import_error:
        print(f"importing ssrfguard failed in a clean interpreter: {import_error}", file=sys.stderr)
        print(
            "an adapter is importing its client at module scope; "
            "move the import inside the function or class body",
            file=sys.stderr,
        )
        return True

    leaked = [str(name) for name in result["leaked"]]  # type: ignore[union-attr]
    if leaked:
        print(
            f"importing ssrfguard loaded third-party modules: {', '.join(leaked)}", file=sys.stderr
        )
        print(
            "an adapter is importing its client eagerly; move the import inside the body",
            file=sys.stderr,
        )
        failed = True
    else:
        print("import ssrfguard: no third-party module loaded")

    return failed


def _contamination(result: dict[str, object]) -> str | None:
    """Decide whether a client in the environment makes the run vacuous.

    A client is only contamination when *we* did not put it there. If the package declared a
    hard dependency, the client's presence is the violation rather than an obstacle to seeing
    one, and `_report` names it that way.

    Args:
        result: The probe's result mapping.

    Returns:
        A message naming the unexplained clients, or ``None`` if there are none.
    """
    present = [str(name) for name in result["clients_present"]]  # type: ignore[union-attr]
    if not present:
        return None
    requires = [str(r) for r in result["requires"]]  # type: ignore[union-attr]
    if [req for req in requires if "extra ==" not in req]:
        return None  # the package pulled them in; that is the finding, not a blind spot
    return ", ".join(present)


def main() -> int:
    """Build, install into a clean environment, and probe it.

    Returns:
        0 clean, 1 violation, 2 could not be checked.
    """
    try:
        with tempfile.TemporaryDirectory() as tmp:
            result = _probe_clean_environment(Path(tmp))
    except NotCheckedError as exc:
        print(str(exc), file=sys.stderr)
        print("nothing was checked", file=sys.stderr)
        return 2

    unexplained = _contamination(result)
    if unexplained is not None:
        print(f"the 'clean' environment already has {unexplained}", file=sys.stderr)
        print(
            "nothing this package did explains that, so every check below would be", file=sys.stderr
        )
        print("vacuous; refusing to report a pass", file=sys.stderr)
        return 2

    return 1 if _report(result) else 0


if __name__ == "__main__":
    sys.exit(main())
