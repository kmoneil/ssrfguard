"""Every lane this repository has, named in one place.

A lane is one named way of running this project's proofs: what it checks, what it needs to be
able to run, and **whether it gates**. That last field is the one worth writing down. A lane
list that called every lane a gate would be lying about `mutation`, which cannot fail a build
because ``mutmut run`` exits 0 whether or not mutants survive.

Two spellings of "how this project runs its tests" is how a lane ends up with one set of flags
locally and another in CI. ``.github/workflows/ci.yml`` invokes every lane through this file
and never spells out a pytest command, and ``tests/test_lanes.py`` asserts that every lane
named here appears there.

Usage::

    python scripts/lanes.py                # print the table
    python scripts/lanes.py <lane>         # run one lane
    python scripts/lanes.py --list         # lane names, one per line

The gating set is mirrored into ``.github/rulesets/main.json`` as required status checks. That
file is the one thing here a test cannot fully verify, because a ruleset lives in repository
settings once applied and ``git`` stops being the authority on it.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Every interpreter this package claims. Has to agree with `[project] classifiers` in
# pyproject.toml, which `tests/test_packaging.py` asserts.
#
# **This set is load-bearing rather than routine.** Most libraries matrix on Python to catch
# syntax and API drift. This one matrices because the answer it computes *differs by
# interpreter*: the standard library's idea of which addresses are private moved in
# CVE-2024-4032, and `ipaddress.ip_address("64:ff9b::7f00:1").is_global` still returns True on
# every version, and that is a NAT64 address a gateway will translate to 127.0.0.1. This package
# therefore ships its own address table, and the assertions that pin it against the standard
# library's only mean something when they run on more than one interpreter.
SUPPORTED_PYTHONS: tuple[str, ...] = ("3.10", "3.11", "3.12", "3.13", "3.14")

# The interpreter the lock is resolved for, and the one `fast` runs. See `[tool.uv]
# environments` in pyproject.toml.
DEV_PYTHON = "3.13"

# What `compat` actually matrices: everything except the development interpreter, which `fast`
# already covers with the extras installed. Running it twice would buy a duplicate row and a
# slower merge. `tests/test_lanes.py` asserts this equals the matrix in ci.yml, so the two
# cannot drift.
COMPAT_PYTHONS: tuple[str, ...] = tuple(p for p in SUPPORTED_PYTHONS if p != DEV_PYTHON)


@dataclass(frozen=True)
class Lane:
    """One named way of running this project's proofs.

    Attributes:
        name: How the lane is invoked and how CI names the job.
        checks: What a passing run proves.
        needs: What has to be present for the lane to run at all.
        command: Argument vector, relative to the repository root.
        reports_only: Why this lane reports instead of gating, or ``""`` if it gates. A
            non-empty string here is a claim that has to survive review: a lane that could
            gate and does not is a gap wearing a policy's clothes.
    """

    name: str
    checks: str
    needs: str
    command: tuple[str, ...]
    reports_only: str = ""
    matrix: tuple[str, ...] = field(default_factory=tuple)

    @property
    def gates(self) -> bool:
        """Whether a failure here should stop the change."""
        return not self.reports_only


LANES: tuple[Lane, ...] = (
    Lane(
        name="gates",
        checks=(
            "ruff, mypy --strict over src, ty, complexipy, the deprecation check, "
            "the uv.lock check, the exec-bit check and the secrets scan"
        ),
        needs=(
            "uv sync. POSIX only, because the local pre-commit hooks name .venv/bin/* by "
            "path, "
            "which does not exist on Windows, and nothing they check is platform-dependent"
        ),
        command=("pre-commit", "run", "--all-files", "--hook-stage", "pre-commit"),
    ),
    Lane(
        name="zero-deps",
        checks=(
            "the claim on the front of the README: a built wheel declares no unconditional "
            "runtime requirement, and importing the package in an interpreter where neither "
            "httpx nor requests is installed loads no third-party module"
        ),
        needs=(
            "uv, and an interpreter with nothing else in it. **The isolation is the lane.** "
            "tests/test_zero_deps.py reads METADATA and can run anywhere, but it cannot catch "
            "an adapter that imports its client eagerly, because a dev checkout has both "
            "clients installed. Only a clean interpreter can see that, so this cannot be a "
            "flag on `fast`"
        ),
        command=("python", "scripts/check_zero_deps.py"),
    ),
    Lane(
        name="fast",
        checks=(
            "the unit suite on the development interpreter, with both adapter extras present, "
            "and the coverage floor: **branch** coverage at 99%, because an untested branch in "
            "an address table is an address nobody has ever asked about, and statement coverage "
            "cannot see one"
        ),
        needs=(
            "uv sync --frozen --all-extras. This is the pre-push hook's lane, and the only one "
            "that measures coverage: it is a property of the codebase rather than of an "
            "interpreter, so measuring it once here beats five differing numbers across `compat`"
        ),
        # **`--cov-branch` is the flag this lane's own rationale was always describing.** Without
        # it the floor measured statements, and statement coverage cannot see a branch: both
        # lines of an `if` execute, only one edge between them ever does. Measured: the suite
        # sat at 100% statements and 99% branches, and one of the two gaps was
        # `AsyncClient(transport=...)`, a documented path on a shipped client surface that no
        # test had ever constructed.
        #
        # 99 rather than 100 on purpose: a floor is a ratchet, not a dare. Pinning it at 100
        # turns the next legitimate `# pragma: no cover` into a red build for a reason nobody
        # will read, and this codebase is already above the line so the ratchet costs nothing.
        command=(
            "pytest",
            "-m",
            "not egress",
            "--cov=ssrfguard",
            "--cov-branch",
            "--cov-report=term-missing:skip-covered",
            "--cov-fail-under=99",
        ),
    ),
    Lane(
        name="compat",
        checks=(
            "the unit suite on every supported interpreter, which is where the assertions "
            "pinning our address table against the standard library's mean something"
        ),
        needs=(
            "one environment per interpreter, resolved for that interpreter rather than from "
            "uv.lock. **Deliberately unlocked**: the lock is resolved for "
            f"python_version >= '{DEV_PYTHON}' so the toolchain is not dragged back to the "
            "floor, which is a promise about src/ rather than about ruff"
        ),
        # The marker deselects the adapter rows and `--ignore-glob` stops them being *imported*,
        # which is a different problem with the same cause: these environments deliberately
        # have neither client installed, and pytest imports every test module before any marker
        # decides what runs. Without the glob the lane dies at collection. It is a glob rather
        # than a list so that adding an adapter suite does not mean editing this line: any
        # test module with `adapter` in its name is one that needs an extra installed.
        command=(
            "pytest",
            "-m",
            "not egress and not httpx_adapter and not requests_adapter",
            "--ignore-glob=*adapter*.py",
        ),
        matrix=COMPAT_PYTHONS,
    ),
    Lane(
        name="rebind",
        checks=(
            "the central claim: a resolver that changes its answer between validation and "
            "connect does not move the connection"
        ),
        needs=(
            "the ability to bind a UDP socket on loopback. No network and no privileges, but "
            "a locked-down container can refuse the bind, and this lane fails rather than "
            "skips when it does. See the note on `egress`, which is the same failure"
        ),
        command=("pytest", "-m", "rebind", "--no-header"),
    ),
    Lane(
        name="adapters",
        checks=(
            "httpx and requests against one shared matrix, so the two seams cannot drift "
            "apart, including the assertion neither may ever fail: the TLS server_hostname "
            "is the hostname, never the pinned IP, because passing an IP there silently "
            "disables certificate hostname verification"
        ),
        needs="uv sync --frozen --all-extras",
        command=("pytest", "-m", "httpx_adapter or requests_adapter"),
    ),
    Lane(
        name="egress",
        checks=(
            "the seams against a real server: TLS completes over a pinned socket with SNI "
            "carrying the hostname, and a redirect chain re-enters the transport per hop. "
            "Also the address table's freshness: the registry is regenerated from IANA and "
            "compared to the committed table as values, so a registry that moved is a failing "
            "test rather than a table nobody re-read"
        ),
        needs=(
            "outbound network. **This lane fails rather than skips when it cannot run.** "
            "A suite whose egress rows skip reports green having proven nothing, and the "
            "skipped rows are precisely the ones under test, so ci.yml runs a reachability "
            "probe as a separate step before this one for exactly that reason"
        ),
        command=("pytest", "-m", "egress"),
    ),
    Lane(
        name="audit",
        checks=(
            "known advisories against the versions uv.lock pins, in two scopes: what a user "
            "installs gates, what a developer installs reports"
        ),
        needs=(
            "uv sync --group audit, and a reachable advisory service. A run that cannot reach "
            "it exits 2, which is neither a pass nor a finding, rather than reporting a "
            "clean tree. "
            "**The shipped scope is empty and that is the point**: this lane prints the empty "
            "set every release, which is the claim on the README verified rather than asserted"
        ),
        command=("python", "scripts/audit_deps.py"),
    ),
    Lane(
        name="leaks",
        checks="the unit suite again with the socket and file-descriptor leak check armed",
        needs=(
            "uv sync --frozen --all-extras. A separate job rather than a flag on `fast`, "
            "because a library that opens sockets for a living should not have the gating "
            "lane pay for the check on every run"
        ),
        command=("pytest", "-m", "not egress", "-p", "ssrfguard_leakcheck"),
    ),
    Lane(
        name="cost",
        checks=(
            "what one URL costs: the per-call price of `check_url` on every corpus shape, the "
            "two ratios `tests/test_cost.py` gates on, and what importing the package adds to "
            "starting an interpreter"
        ),
        needs=(
            "uv sync --frozen. No extras and no network: this measures the policy layer, which "
            "is pure and has no client in it"
        ),
        reports_only=(
            "**a threshold in microseconds is a threshold about the runner**, and this one runs "
            "on shared hardware, so a number here could only ever be advisory. What gates "
            "instead is in `tests/test_cost.py`, on the `fast` lane, and none of it is an "
            "absolute duration: "
            "two assertions compare a measurement to another taken on the same thread in the "
            "same run, which cancels the runner, and the third counts calls and holds no clock "
            "at all. This lane prints the numbers a reader evaluating the package wants and a "
            "ratio cannot give them"
        ),
        command=("python", "scripts/cost_report.py"),
    ),
    Lane(
        name="mutation",
        checks="whether the suite would notice if the policy logic were subtly wrong",
        needs="uv sync --frozen --all-extras",
        reports_only=(
            "`mutmut run` exits 0 whether or not mutants survive, and no register of "
            "known-equivalent survivors is committed, so there is nothing for a machine to "
            "diff a run against. `mutmut results` is printed so a human can do the diff until "
            "there is"
        ),
        command=("mutmut", "run"),
    ),
)

BY_NAME = {lane.name: lane for lane in LANES}


def _resolve(tool: str) -> str:
    """Find a lane's tool, preferring the interpreter this script is running under.

    The order matters and is not the obvious one. **The running interpreter's own ``bin``
    directory comes first**, because that is what makes the `compat` lane work: it builds one
    environment per interpreter and invokes this script with that environment's ``python``, so
    "the pytest next to me" is the only spelling that picks the right one. Looking in
    ``.venv/`` first would run the development interpreter's pytest against the matrix row's
    code and report a pass for an interpreter that was never exercised.

    Args:
        tool: Executable name as written in a lane's command.

    Returns:
        An absolute path to the executable.

    Raises:
        SystemExit: If the tool is not installed anywhere this can see it.
    """
    if tool == "python":
        return sys.executable
    beside = Path(sys.executable).parent / tool
    if beside.exists():
        return str(beside)
    candidate = REPO_ROOT / ".venv" / "bin" / tool
    if candidate.exists():
        return str(candidate)
    found = shutil.which(tool)
    if found is None:
        raise SystemExit(f"lane tool not found: {tool!r} (is the environment synced?)")
    return found


def run(lane: Lane) -> int:
    """Run one lane and return its exit status.

    Args:
        lane: The lane to run.

    Returns:
        The process exit status, or 0 for a reporting lane that failed.
    """
    argv = (_resolve(lane.command[0]), *lane.command[1:])
    print(f"==> {lane.name}: {' '.join(lane.command)}")
    status = subprocess.run(argv, cwd=REPO_ROOT, check=False).returncode  # noqa: S603  # resolved executable, list argv, no shell
    if status != 0 and not lane.gates:
        print(f"==> {lane.name} failed with {status}; reports only, so not failing the build")
        print(f"    reason: {lane.reports_only}")
        return 0
    return status


def table() -> str:
    """Render every lane as a table.

    Returns:
        The rendered table.
    """
    width = max(len(lane.name) for lane in LANES)
    lines = [f"{'lane'.ljust(width)}  gates  checks", f"{'-' * width}  -----  ------"]
    for lane in LANES:
        marker = "yes  " if lane.gates else " no  "
        suffix = f" [{'/'.join(lane.matrix)}]" if lane.matrix else ""
        lines.append(f"{lane.name.ljust(width)}  {marker}  {lane.checks}{suffix}")
    return "\n".join(lines)


def main() -> int:
    """Entry point.

    Returns:
        Process exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__, add_help=True)
    parser.add_argument("lane", nargs="?", help="lane to run; omit to print the table")
    parser.add_argument("--list", action="store_true", help="print lane names, one per line")
    args = parser.parse_args()

    if args.list:
        print("\n".join(lane.name for lane in LANES))
        return 0
    if args.lane is None:
        print(table())
        return 0
    if args.lane not in BY_NAME:
        known = ", ".join(BY_NAME)
        raise SystemExit(f"unknown lane {args.lane!r}; known lanes are: {known}")
    return run(BY_NAME[args.lane])


if __name__ == "__main__":
    sys.exit(main())
