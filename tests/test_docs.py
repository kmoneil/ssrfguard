"""The documentation's checkable claims, checked.

Prose rots differently from code: it fails silently, it fails for readers rather than for
maintainers, and nothing about a green suite says otherwise. Three kinds of rot are worth a test
because all three are mechanical.

**A link that no longer resolves.** A reader who clones this repository is told where to go and
has to be able to get there, and `tests/test_no_gitignored_references.py` already makes the same
argument about paths a reader cannot open. This file extends it to the links that *can* be
followed, including the ones with an anchor, since a section that was renamed leaves a link that
still looks right.

**A number that was typed rather than derived.** `docs/address-table.md` says the shipped table
has 60 rows, 13 of them permitted and 5 translated. Every one of those is read out of the table
here, so refreshing the registry either updates the prose or fails the build.

**A guide nobody is pointed at.** A page that exists and is linked from nowhere is a page nobody
reads, and the index it is missing from reads as complete.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ssrfguard import DEFAULT_DENIED, REGISTRY_SNAPSHOT, Reach

#: Reads the repository rather than the library. `mutmut` copies `src`, `tests` and two
#: files into `mutants/` and runs the suite from there, where the rest of the tree does
#: not exist, so this cannot run: it reads `docs/` and the root markdown. It could not kill a
#: mutant in `src/ssrfguard` either way.
pytestmark = pytest.mark.repository

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = REPO_ROOT / "docs"

#: Every markdown file a clone carries, which is the set a reader can follow links through.
MARKDOWN = sorted(
    path
    for path in REPO_ROOT.rglob("*.md")
    # Ignored directories hold planning notes and tool caches; a reader never sees them, and
    # `.venv` in particular carries thousands of vendored READMEs.
    if not any(part.startswith((".", "_")) for part in path.relative_to(REPO_ROOT).parts)
)

#: `[text](target)` in markdown. The fragment is captured separately so an anchor can be checked
#: against the headings of the file it points into.
LINK = re.compile(r"\[[^\]]*\]\(([^)\s#]*)(?:#([^)\s]+))?\)")

#: An ATX heading, which is the only kind this repository writes.
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*$", re.MULTILINE)


def slug(heading: str) -> str:
    """Turn a heading into the anchor GitHub would generate for it.

    Args:
        heading: The heading text, without its leading hashes.

    Returns:
        The anchor, lowercased, with punctuation dropped and spaces hyphenated.
    """
    # Backticks and emphasis are markdown formatting rather than text, so GitHub drops
    # them. Underscores it keeps, which is why they are not in this class.
    text = re.sub(r"[`*]", "", heading).strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"[\s]+", "-", text)


def anchors_in(path: Path) -> set[str]:
    """Every anchor a reader could jump to in one file.

    Args:
        path: The markdown file.

    Returns:
        The slugs of its headings.
    """
    return {slug(found) for found in HEADING.findall(path.read_text(encoding="utf-8"))}


def test_there_is_documentation_to_check() -> None:
    """A glob that matched nothing would make every test below vacuously pass."""
    assert len(MARKDOWN) >= 10, f"expected the docs tree, found {[str(p) for p in MARKDOWN]}"
    assert DOCS.is_dir(), "docs/ is gone; this file is asserting nothing"


@pytest.mark.parametrize("source", MARKDOWN, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_every_relative_link_resolves(source: Path) -> None:
    """No committed document points a reader at a file that is not there.

    Args:
        source: The markdown file whose links are checked.
    """
    broken: list[str] = []
    for target, _fragment in LINK.findall(source.read_text(encoding="utf-8")):
        if not target:
            continue  # a bare `#anchor` into this same page; the anchor test owns it
        if target.startswith(("http://", "https://", "mailto:")):
            continue  # somebody else's server, and not this suite's business
        if not (source.parent / target).resolve().exists():
            broken.append(target)
    assert not broken, (
        f"{source.relative_to(REPO_ROOT)} links files that do not exist: {sorted(set(broken))}"
    )


@pytest.mark.parametrize("source", MARKDOWN, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_every_anchor_resolves(source: Path) -> None:
    """A section that was renamed leaves a link that still looks right.

    Args:
        source: The markdown file whose anchors are checked.
    """
    broken: list[str] = []
    for target, fragment in LINK.findall(source.read_text(encoding="utf-8")):
        if not fragment or target.startswith(("http://", "https://", "mailto:")):
            continue
        destination = (source.parent / target).resolve() if target else source
        if not destination.exists() or destination.suffix != ".md":
            continue  # a missing file is the other test's finding, not this one's
        if fragment not in anchors_in(destination):
            broken.append(f"{target}#{fragment}")
    assert not broken, (
        f"{source.relative_to(REPO_ROOT)} links anchors that no heading produces: "
        f"{sorted(set(broken))}. Headings were renamed, or the anchor was guessed."
    )


@pytest.mark.parametrize("guide", sorted(DOCS.glob("*.md")), ids=lambda p: p.stem)
def test_every_guide_is_reachable_from_both_indexes(guide: Path) -> None:
    """A guide linked from nowhere is a guide nobody reads.

    Args:
        guide: The page that must appear in the tables of contents.
    """
    if guide.name == "README.md":
        return  # the index does not index itself
    index = (DOCS / "README.md").read_text(encoding="utf-8")
    front = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert guide.name in index, f"docs/{guide.name} is missing from docs/README.md"
    assert f"docs/{guide.name}" in front, f"docs/{guide.name} is missing from the README table"


def test_the_documented_table_size_is_the_table_size() -> None:
    """`docs/address-table.md` quotes counts; they are read out of the table here."""
    text = (DOCS / "address-table.md").read_text(encoding="utf-8")
    counts = {
        "60 rows": len(DEFAULT_DENIED.blocks),
        "Thirteen permitted rows": sum(
            1 for block in DEFAULT_DENIED.blocks if block.reach is Reach.PERMITTED
        ),
        "Five translated blocks": sum(
            1 for block in DEFAULT_DENIED.blocks if block.reach is Reach.TRANSLATED
        ),
        "Five cloud metadata endpoints": sum(
            1 for block in DEFAULT_DENIED.blocks if "metadata" in block.name.lower()
        ),
    }
    expected = {
        "60 rows": 60,
        "Thirteen permitted rows": 13,
        "Five translated blocks": 5,
        "Five cloud metadata endpoints": 5,
    }
    for phrase, actual in counts.items():
        assert phrase in text, (
            f"docs/address-table.md no longer says {phrase!r}; if the table changed, update the "
            f"prose and this test together"
        )
        assert actual == expected[phrase], (
            f"the table now has {actual} where docs/address-table.md says {phrase!r}. Refresh "
            f"the registry and the prose in the same commit."
        )


def test_the_documented_registry_snapshot_is_the_shipped_one() -> None:
    """A stale date in the prose is the same defect as a stale table, and quieter."""
    text = (DOCS / "address-table.md").read_text(encoding="utf-8")
    assert REGISTRY_SNAPSHOT in text, (
        f"docs/address-table.md does not mention the shipped registry snapshot "
        f"{REGISTRY_SNAPSHOT}; refresh_registry.py bumped it and the prose did not follow"
    )


def test_the_readme_and_the_docs_agree_on_what_it_costs() -> None:
    """One set of figures, quoted twice, so the two cannot drift.

    The README carries the table because a reader deciding whether to install should not have to
    click; `docs/cost.md` carries it because that is where the caveats are. Two copies is how one
    of them goes stale, so every row of the README's is required to appear in the guide's.
    """
    front = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    guide = (DOCS / "cost.md").read_text(encoding="utf-8")
    rows = re.findall(r"^\| (`check_url`[^|]*|`import ssrfguard`[^|]*)\|([^|]*)\|$", front, re.M)
    assert len(rows) == 5, f"the README cost table changed shape; found {rows}"
    for measured, price in rows:
        line = f"| {measured}|{price}|"
        assert line in guide, (
            f"the README quotes {line.strip()!r} and docs/cost.md does not. The figures live in "
            f"both places on purpose; change them in both."
        )


def test_the_link_search_can_actually_fail() -> None:
    """A check that has never caught anything is indistinguishable from one that cannot.

    Every assertion above is a `not in` or a `==` over documents that currently all pass, so
    nothing about a green run says the searching works. This runs the same two pieces of
    machinery over inputs that are known to be wrong.
    """
    found = LINK.findall("see [a](docs/policy.md#the-fields) and [b](#status) and [c](x.md)")
    assert found == [("docs/policy.md", "the-fields"), ("", "status"), ("x.md", "")]

    assert slug("The attempt cap") == "the-attempt-cap"
    assert slug("Reach: three answers, not two") == "reach-three-answers-not-two"
    assert slug("`allowed_networks` and TLS") == "allowed_networks-and-tls"
    assert slug("What it costs") != "what-it-cost"


#: A path into the test suite, as the documentation writes one.
CITED_PATH = re.compile(r"`((?:tests|scripts|examples)/[\w/.]+?\.(?:py|json))")

#: A test function named in prose. Backticked, because that is how this repository writes one,
#: and long enough that a sentence about "test coverage" is not mistaken for a citation.
CITED_TEST = re.compile(r"`(?:[\w/.]+\.py::)?(test_[a-z0-9_]{12,})`")


@pytest.mark.parametrize("source", MARKDOWN, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_every_file_the_docs_cite_is_there(source: Path) -> None:
    """Documentation that points at a file which was renamed is documentation that lies.

    Args:
        source: The markdown file to read.
    """
    cited = sorted(set(CITED_PATH.findall(source.read_text(encoding="utf-8"))))
    missing = [path for path in cited if not (REPO_ROOT / path).exists()]

    assert not missing, f"{source.name} cites files that do not exist: {missing}"


@pytest.mark.parametrize("source", MARKDOWN, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_every_test_the_docs_cite_is_there(source: Path) -> None:
    """**A prevention claim naming a test that no longer exists is worse than no claim.**

    `architecture.md` names sixteen tests and `threat-model.md` names more, each as the evidence
    for a property this package promises. A reader is being told to go and look. Renaming a test
    is ordinary, quiet, and turns every one of those into a dead reference, and nothing else here
    would notice.

    Args:
        source: The markdown file to read.
    """
    cited = sorted(set(CITED_TEST.findall(source.read_text(encoding="utf-8"))))
    defined = {
        name
        for path in (REPO_ROOT / "tests").glob("*.py")
        for name in re.findall(r"^def (test_\w+)", path.read_text(encoding="utf-8"), re.MULTILINE)
    }
    missing = [name for name in cited if name not in defined]

    assert not missing, (
        f"{source.name} cites tests that are not defined in tests/: {missing}. Either the test "
        f"was renamed and the claim is now unevidenced, or the name in the prose is wrong"
    )


def test_the_citation_search_can_actually_fail() -> None:
    """A check that has never caught anything is indistinguishable from one that cannot.

    Both patterns above are permissive on purpose, so the interesting question is not whether
    they match too much but whether they match at all. A regex that quietly stopped matching
    would let every citation in the tree rot while reporting green.
    """
    assert CITED_PATH.findall("see `tests/test_rebinding.py` for it") == ["tests/test_rebinding.py"]
    assert CITED_TEST.findall("`test_a_pooled_second_request_asks_nothing`") == [
        "test_a_pooled_second_request_asks_nothing"
    ]
    assert CITED_TEST.findall("`tests/x.py::test_a_pooled_second_request_asks_nothing`") == [
        "test_a_pooled_second_request_asks_nothing"
    ]

    architecture = (DOCS / "architecture.md").read_text(encoding="utf-8")
    assert len(set(CITED_TEST.findall(architecture))) >= 5, (
        "the guide that exists to name its evidence cites almost nothing, so either it changed "
        "shape or this pattern stopped matching"
    )
