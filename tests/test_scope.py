"""The boundary this package promises, held to.

`SECURITY.md` says it in one sentence: **this guards the connection, and the fetch around it is
not ours.** Everything from the URL inwards to the socket landing on a validated address is in;
what a permitted host sends back is out.

That was a decision rather than an accident, and the alternative was live for a while: "we safely
fetch an untrusted URL" is a promise this package could plausibly have made, and the audience it
names, a webhook fetcher or a URL-preview service, would have welcomed it. It was rejected
because it has no edge. Everything a fetch touches becomes in scope, and the first casualty is
the claim on the front of the README that is worth making.

**A boundary nothing checks is a boundary that moves one convenient argument at a time**, and
each argument is individually reasonable: a byte ceiling is three lines, a decompression ratio is
two more, a scanner is a nice-to-have. So the boundary is asserted here in the shape the erosion
would take.

These read the repository rather than the library, which is what the `repository` marker is for.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import ssrfguard
from ssrfguard import Policy

pytestmark = pytest.mark.repository

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Words that would only appear in an argument about a *response*. Deliberately about the body
#: rather than about sizes in general: `max_url_length` and `max_connection_attempts` are ceilings
#: on what this package itself spends, which is squarely ours, and neither reads on this list.
RESPONSE_VOCABULARY = (
    "response",
    "body",
    "content_length",
    "decompress",
    "max_bytes",
    "read_limit",
    "download",
)


def named_arguments(target: object) -> set[str]:
    """Every parameter name a callable takes."""
    return set(inspect.signature(target).parameters)  # type: ignore[arg-type]


def test_the_policy_decides_nothing_about_a_response() -> None:
    """**The shape the erosion would take.**

    A `Policy` field about response size would be the first step, and it would arrive with a
    reasonable argument attached: a caller who reached for this package is exactly the caller who
    will not remember `stream=True`. The answer is that bounding a body is the client's job and
    this package does not sit in that path, which `SECURITY.md` states and this holds.
    """
    fields = set(Policy.__dataclass_fields__)
    offenders = [f for f in fields if any(word in f.lower() for word in RESPONSE_VOCABULARY)]
    assert not offenders, (
        f"Policy grew {offenders}, which is about what a permitted host sends back rather than "
        f"about what may be reached. That is the other promise; see SECURITY.md."
    )


@pytest.mark.parametrize(
    "surface",
    ["ssrfguard.httpx:Client", "ssrfguard.httpx:AsyncClient", "ssrfguard.requests:Session"],
)
def test_no_client_takes_an_argument_about_a_response(surface: str) -> None:
    """The same boundary at the surface a caller actually touches.

    Args:
        surface: A `module:name` pair naming one guarded client.
    """
    module_name, _, attribute = surface.partition(":")
    module = pytest.importorskip(module_name)
    client = getattr(module, attribute)
    offenders = [
        argument
        for argument in named_arguments(client.__init__)
        if any(word in argument.lower() for word in RESPONSE_VOCABULARY)
    ]
    assert not offenders, f"{surface} grew {offenders}, which is about the fetch, not the guard"


def test_the_public_surface_names_nothing_about_a_response() -> None:
    offenders = [
        name
        for name in ssrfguard.__all__
        if any(word in name.lower() for word in RESPONSE_VOCABULARY)
    ]
    assert not offenders, f"ssrfguard exports {offenders}, which is the other promise"


def test_the_package_ships_no_command() -> None:
    """**The second shape the erosion would take**, and it is not a smaller one.

    A detector for the bug this package prevents is a genuinely good idea and a genuinely
    different product: it has its own false positives, its own AST drift, and a support burden
    from people who do not use the library at all. Worse, a scanner that finds nothing has said
    something, and what it said is false, which is the class of claim this project removes rather
    than adds.
    """
    # **`tomllib` arrived in 3.11 and this package's floor is 3.10**, and the alternative is a
    # dependency acquired to test that there are no dependencies. `tests/test_packaging.py`
    # skips its whole module for this; only this one assertion needs it, so only this one skips
    # and the other fences still run on the floor. `fast` runs on 3.13, so it is never unchecked.
    tomllib = pytest.importorskip(
        "tomllib", reason="reading repository metadata needs tomllib (3.11+); the library does not"
    )
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = pyproject.get("project", {}).get("scripts", {})
    assert not scripts, (
        f"pyproject declares console scripts {sorted(scripts)}. A command is a second product; "
        f"see the promise in SECURITY.md."
    )


def test_the_promise_is_still_written_down() -> None:
    """A test that guards a sentence has to fail when the sentence goes.

    The prose is the decision. Deleting it while leaving these checks in place would leave a
    fence around nothing, and the next person to argue for a response ceiling would find no
    reason on file, only a test that says no.
    """
    security = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "## What this package promises" in security
    assert "It guards the connection." in security
    assert "we safely fetch an untrusted URL" in security, (
        "the rejected alternative is named on purpose; a boundary reads as arbitrary without the "
        "thing it was chosen over"
    )
