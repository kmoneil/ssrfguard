"""The dependency rule is a test, not a policy.

Intent decays. A build that fails when someone adds an import does not. This ships in the
package's own suite so the constraint is visible to a contributor before review rather than
after.

**This file is necessary and not sufficient**, and the boundary is worth knowing. It reads
declared metadata, which catches somebody adding an entry to ``[project.dependencies]``. It
cannot catch an adapter that imports httpx at module scope instead of lazily inside the
function body, because this suite runs in an environment where httpx is installed and the
eager import simply succeeds. That failure is only visible from an interpreter without the
clients — see ``scripts/check_zero_deps.py`` and the ``zero-deps`` lane.
"""

from __future__ import annotations

import importlib.metadata as md

import pytest

DISTRIBUTION = "ssrfguard"


def test_no_unconditional_runtime_dependencies() -> None:
    try:
        requires = md.requires(DISTRIBUTION) or []
    except md.PackageNotFoundError:  # pragma: no cover - only when run from a bare checkout
        pytest.skip(f"{DISTRIBUTION} is not installed; install it to check its metadata")

    # Extras carry an `extra == "..."` marker; anything without one is installed for every
    # user, everywhere.
    hard = [requirement for requirement in requires if "extra ==" not in requirement]
    assert hard == [], f"package grew runtime dependencies: {hard}"


def test_adapters_are_declared_as_extras() -> None:
    """The clients we integrate with must be reachable, and only behind an extra."""
    try:
        requires = md.requires(DISTRIBUTION) or []
    except md.PackageNotFoundError:  # pragma: no cover
        pytest.skip(f"{DISTRIBUTION} is not installed; install it to check its metadata")

    behind_extras = [r for r in requires if "extra ==" in r]
    names = " ".join(behind_extras)
    for client in ("httpx", "requests"):
        assert client in names, (
            f"{client} is not declared behind an extra; the adapter cannot be installed"
        )
