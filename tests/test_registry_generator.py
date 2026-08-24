"""The generator that writes the address table, and the boundary it sits on.

`src/ssrfguard/_registry.py` is the one committed artifact whose whole job is to be trusted, and
it is produced by a script that fetches a CSV over the network and writes Python. That is a
code-execution boundary: whatever comes back from IANA ends up in a module `import ssrfguard`
executes. Three properties keep it closed, and none of them was asserted before this file.

**Nothing here reaches the network except the last test**, which is marked `egress`. The rest
drive the generator against a fixed CSV, because the properties they check are about the
generator rather than about what IANA is serving today.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from ssrfguard._registry import TABLE

#: Reads the repository rather than the library. `mutmut` copies `src`, `tests` and two
#: files into `mutants/` and runs the suite from there, where the rest of the tree does
#: not exist, so this cannot run: it imports `refresh_registry` from `scripts/`. It could not kill a
#: mutant in `src/ssrfguard` either way.
pytestmark = pytest.mark.repository

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import refresh_registry  # noqa: E402

COMMITTED = REPO_ROOT / "src" / "ssrfguard" / "_registry.py"

#: Enough of IANA's shape to drive the generator without a network: the columns it reads, one
#: ordinary row, and one row whose reachability column is blank.
FIXED_CSV = (
    "Address Block,Name,RFC,Allocation Date,Termination Date,Source,Destination,Forwardable,"
    "Globally Reachable,Reserved-by-Protocol\r\n"
    "10.0.0.0/8,Private-Use,[RFC1918],1996-02,N/A,True,True,True,False,False\r\n"
    "192.0.0.0/24,IETF Protocol Assignments,[RFC6890],2010-01,N/A,False,False,False,,False\r\n"
)


def _load(path: Path, name: str) -> Any:
    """Import a generated module from a path, so its contents can be compared as values.

    Args:
        path: The file to import.
        name: A module name to register it under.

    Returns:
        The imported module.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before execution: a dataclass defined in the module looks itself up in
    # `sys.modules` to resolve its own annotations, and a module that is not there yet
    # fails with an AttributeError that names none of this.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[name]
    return module


def test_a_quote_in_a_registry_field_cannot_close_the_literal() -> None:
    """The field nobody thought of as input.

    Three of the four values `_emit` interpolates come from a CSV fetched over the network, and
    they are being written into Python source. `name` happened to be defended, with its quotes
    stripped upstream, and `cidr` was not, so a quote in IANA's *Address Block* column closed
    the string and the rest of the cell became code that `import ssrfguard` would run.
    """
    hostile = '10.0.0.0/8"), __import__("os").system("id"), _b("10.0.0.0/8'
    emitted = refresh_registry._emit([(hostile, "Private-Use", "RFC1918", "DENIED", "")])

    calls = _calls_in(emitted)
    assert len(calls) == 1
    assert [_literal(argument) for argument in calls[0].args[:3]] == [
        hostile,
        "Private-Use",
        "RFC1918",
    ]


@pytest.mark.parametrize("field", ["cidr", "name", "rfc"])
def test_every_interpolated_field_is_repr_quoted(field: str) -> None:
    """Not just the one that was found. A defence applied to the field somebody remembered is
    the same defence missing from the next one."""
    values = {"cidr": "10.0.0.0/8", "name": "N", "rfc": "R"}
    values[field] = 'x"), evil(), _b("y'
    emitted = refresh_registry._emit(
        [(values["cidr"], values["name"], values["rfc"], "DENIED", "")]
    )

    calls = _calls_in(emitted)
    assert len(calls) == 1
    assert [_literal(argument) for argument in calls[0].args[:3]] == [
        values["cidr"],
        values["name"],
        values["rfc"],
    ]


def _calls_in(emitted: str) -> list[ast.Call]:
    """Parse emitted source and return every call in it.

    Asked of the parser rather than of `str.count`, because a hostile value *contains* the text
    of a call and counting substrings cannot tell that from being one. The property under test is
    "this source is one call", which is a question about the tree.

    Args:
        emitted: A fragment of generated source, as `_emit` returns it.

    Returns:
        Every `Call` node in it.
    """
    tree = ast.parse(f"[\n{emitted}\n]")
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def _literal(node: ast.expr) -> object:
    """Read a node that must be a literal, failing loudly if it is not.

    Args:
        node: The argument node.

    Returns:
        Its value.
    """
    return ast.literal_eval(node)


def test_an_address_block_that_is_not_a_network_stops_the_generator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The likelier failure, and the one with no attacker in it.

    IANA changing a footnote format produces a cell this generator does not understand. Skipping
    the row would silently drop a block from a table that decides what gets refused, so it stops
    instead and names the row.
    """
    broken = FIXED_CSV.replace("10.0.0.0/8", "10.0.0.0/8 [note]")
    monkeypatch.setattr(refresh_registry, "urllib", _fake_urllib(broken))

    with pytest.raises(SystemExit, match="address block this generator cannot parse"):
        refresh_registry._rows(4)


def _fake_urllib(payload: str) -> Any:
    """Stand in for `urllib.request.urlopen`, serving a fixed CSV.

    Args:
        payload: What the fetch should return.

    Returns:
        An object exposing the one attribute path the generator uses.
    """

    class _Response(io.BytesIO):
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_: object) -> None:
            self.close()

    class _Request:
        @staticmethod
        def urlopen(_url: str, timeout: float = 0) -> _Response:
            return _Response(payload.encode())

    class _Urllib:
        request = _Request

    return _Urllib


def test_the_generator_still_produces_the_file_that_is_committed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`_registry.py` says **Generated. Do not edit by hand**, and that has to stay true.

    It was not: the committed file had been hand-repaired after generation, so running the
    documented workflow produced a module that failed this repository's own ruff gate: a
    `typing.Union` left over from the abandoned 3.9 floor, and an `__all__` in the wrong order.
    Nothing caught it, because the generator deliberately does not run in CI.

    This compares the *header*, everything the template owns and therefore everything above the
    table, against the committed file, with the snapshot date normalised because it is the one
    line that is supposed to differ. No network: what the template emits does not depend on what
    IANA is serving.
    """
    monkeypatch.setattr(refresh_registry, "urllib", _fake_urllib(FIXED_CSV))
    generated = tmp_path / "_registry.py"
    monkeypatch.setattr(refresh_registry, "TARGET", generated)

    assert refresh_registry.main() == 0

    marker = "TABLE: tuple[Block, ...] = ("
    undated = re.compile(r'REGISTRY_SNAPSHOT = "\d{4}-\d{2}-\d{2}"')
    fresh = undated.sub("SNAPSHOT", generated.read_text().split(marker)[0])
    committed = undated.sub("SNAPSHOT", COMMITTED.read_text().split(marker)[0])

    assert fresh == committed


def test_the_generated_module_imports_and_the_fixed_rows_survive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A generator whose output does not import is a generator nobody can run."""
    monkeypatch.setattr(refresh_registry, "urllib", _fake_urllib(FIXED_CSV))
    generated = tmp_path / "_registry.py"
    monkeypatch.setattr(refresh_registry, "TARGET", generated)
    refresh_registry.main()

    module = _load(generated, "generated_registry_fixture")
    by_cidr = {str(block.network): block for block in module.TABLE}

    assert by_cidr["10.0.0.0/8"].reach is module.Reach.DENIED
    assert by_cidr["10.0.0.0/8"].name == "Private-Use"
    # A blank `Globally Reachable` column refuses rather than assumes.
    assert by_cidr["192.0.0.0/24"].reach is module.Reach.DENIED
    assert "Registry asserts nothing" in by_cidr["192.0.0.0/24"].note
    # The additions and the metadata names travel with every regeneration.
    assert "::/96" in by_cidr
    assert "169.254.169.254/32" in by_cidr


@pytest.mark.egress
def test_the_committed_table_still_matches_what_iana_serves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The freshness check, and the only test here that reaches the network.

    Compared as *values* rather than as text, so formatting cannot make this fail and a real
    registry change cannot hide behind whitespace. A difference here is not a bug. It is IANA
    having moved, which is a change to what this package refuses and is reviewed as one.
    """
    generated = tmp_path / "_registry.py"
    monkeypatch.setattr(refresh_registry, "TARGET", generated)

    assert refresh_registry.main() == 0

    fresh = _load(generated, "iana_registry_now")
    live = {(str(b.network), b.name, b.rfc, b.reach.value) for b in fresh.TABLE}
    committed = {(str(b.network), b.name, b.rfc, b.reach.value) for b in TABLE}

    assert live == committed, (
        "the committed address table disagrees with IANA as served right now; run "
        "`python scripts/refresh_registry.py` and review the diff as a change to what this "
        "package refuses"
    )
