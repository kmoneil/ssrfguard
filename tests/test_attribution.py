"""The attribution gate, held to.

This repository's history carried a `Claude-Session:` trailer on all 74 commits and a matching
link at the foot of all 18 pull request bodies. Removing them cost a full history rewrite, three
repointed release tags and a force-push through a protected branch, so the gate that stops it
recurring is worth more than the setting that stops it being generated: settings are one file on
one machine, and neither the rewrite nor the cost of it was caused by a machine anybody could
reach at the time.

**A gate that has never failed is indistinguishable from one that cannot**, so every rule below
is checked by making it fire, and the legal-prose corpus is checked by making it not. That second
half is the one that decides whether this file survives contact: a check that fires on a sentence
about the check is a check somebody disables, and the commit that introduced this file had to be
able to describe itself.

These read the repository rather than the library, which is what the `repository` marker is for.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.repository

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_attribution  # noqa: E402
import lanes  # noqa: E402

PRE_COMMIT = REPO_ROOT / ".pre-commit-config.yaml"

BY_NAME = {rule.name: rule for rule in check_attribution.RULES}

#: One text per rule that the rule must reject. Keyed by rule name, and
#: `test_every_rule_has_a_sample` asserts the two sets match exactly, so a rule added without
#: proof that it fires is a failing test rather than a line nobody exercised.
SAMPLES: dict[str, str] = {
    "Claude-Session trailer": (
        "Subject line\n\nA body.\n\nClaude-Session: https://example.invalid/s/abc\n"
    ),
    "claude.ai session link": "A pull request body.\n\nhttps://claude.ai/code/session_0123abc\n",
    "tool co-author trailer": ("Subject line\n\nCo-authored-by: Claude <noreply@anthropic.com>\n"),
    "generated-with line": (
        "Subject line\n\nGenerated with [Claude Code](https://claude.ai/code)\n"
    ),
}

#: Text that mentions the forbidden forms and must stay legal. Every entry is something a person
#: would reasonably write *about* this gate, and the first two are close paraphrases of sentences
#: in `scripts/check_attribution.py` and in the commit that added it.
LEGAL_PROSE: tuple[str, ...] = (
    "Refuse a Claude-Session: trailer in any commit message",
    "The PR bodies carried a claude.ai link at the foot, and the commits carried a trailer",
    "A mention mid-sentence, like Claude-Session: written here, is not a trailer",
    "Co-authored-by: A Human Being <person@example.com>",
    "The generated-with footer and the co-author trailer are both suppressed by settings",
    "See docs on attribution.sessionUrl, attribution.commit and attribution.pr",
)


def test_every_rule_has_a_sample() -> None:
    """A rule with nothing proving it fires is a rule that may not."""
    assert set(SAMPLES) == set(BY_NAME), (
        "every rule in check_attribution.RULES needs a sample here that it must reject"
    )


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_each_rule_fires_on_its_own_form(name: str) -> None:
    """Each rule rejects the form it names, and the checker surfaces it."""
    assert BY_NAME[name] in check_attribution.offences(SAMPLES[name])


@pytest.mark.parametrize("text", LEGAL_PROSE)
def test_prose_about_the_gate_is_not_an_offence(text: str) -> None:
    """Writing about the forbidden forms must stay legal, or nobody can document them."""
    assert check_attribution.offences(text) == []


def test_the_checkers_own_source_is_legal() -> None:
    """The module names every form it forbids; it must not be unable to describe itself."""
    source = (REPO_ROOT / "scripts" / "check_attribution.py").read_text(encoding="utf-8")
    assert check_attribution.offences(source) == []


def test_the_history_this_checkout_can_see_is_clean() -> None:
    """No commit reachable from HEAD carries one.

    **This asserts what the checkout in front of it holds, which in CI is one commit.** The
    `fast` lane runs on the default shallow checkout, so the full-history claim belongs to the
    `attribution` lane, which checks out with `fetch-depth: 0` for exactly this reason. Here it
    is still the gate that catches a bad message on a developer's machine, where the clone is
    whole.
    """
    for sha, message in check_attribution._commit_messages("HEAD"):  # noqa: SLF001
        assert check_attribution.offences(message) == [], f"commit {sha} carries an attribution"


def test_the_lane_exists_and_gates() -> None:
    """A reporting-only lane here would be a gap wearing a policy's clothes."""
    lane = lanes.BY_NAME["attribution"]
    assert lane.gates
    assert "check_attribution.py" in " ".join(lane.command)


def test_the_commit_msg_hook_is_configured_and_installed_by_default() -> None:
    """Configured is not installed.

    pre-commit writes one file per hook type into `.git/hooks/`, and only the types named in
    `default_install_hook_types` are written. A `commit-msg` hook in a repository that never
    installs that type is configured, reads as configured, and never runs.
    """
    text = PRE_COMMIT.read_text(encoding="utf-8")
    installed = re.search(r"^default_install_hook_types:\s*\[(.*)\]", text, re.MULTILINE)
    assert installed is not None, "pre-commit config declares no default_install_hook_types"
    assert "commit-msg" in installed.group(1), (
        "the no-attribution hook is a commit-msg hook, so that type has to be installed by "
        "default or the hook never runs"
    )
    assert "check_attribution.py" in text, "the commit-msg hook is gone from the pre-commit config"


def test_regression_session_link_a_trailer_and_a_body_link_are_both_refused() -> None:
    """The two exact forms this repository actually shipped, in the shape it shipped them.

    Reconstructed from the history as it stood before the rewrite: a trailer at the foot of the
    commit message, and a bare link as the last line of the PR body. Both were live on `main`
    and on all 18 pull requests, and nothing in the repository objected to either.

    **The session identifier is a placeholder, and deliberately so.** The real ones pointed at
    private sessions, and committing one here to prove they are unwelcome would leave the thing
    itself in the tree for good. What the rule matches is the shape, which is what is preserved.
    """
    commit_message = (
        "Check the host at the seam that only checked the port\n"
        "\n"
        "`SafeBackend` and `AsyncSafeBackend` checked the port and every resolved address.\n"
        "\n"
        "Claude-Session: https://claude.ai/code/session_PLACEHOLDER\n"
    )
    pull_request_body = (
        "**Fail-first, verified twice:** 8 reds before the fix.\n"
        "\n"
        "https://claude.ai/code/session_PLACEHOLDER\n"
    )
    assert check_attribution.offences(commit_message) != []
    assert check_attribution.offences(pull_request_body) != []
