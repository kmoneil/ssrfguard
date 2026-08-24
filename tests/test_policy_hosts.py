"""`allowed_hosts`, and the one line that would turn it into a way in.

Domain allowlisting is the strongest SSRF control there is, and it is one string comparison away
from being the weakest. `"evil-github.com".endswith("github.com")` is `True`. So the balance of
this file is a corpus of hosts that *nearly* match a listed entry, because a matcher that gets
those right is the whole of the feature and everything else here is bookkeeping.

**This is the opposite direction from the one this package refuses.** Denying by name is defeated
by a trailing dot, a case change, an IDN homograph or a `CNAME`, which is why the address table
denies addresses and never names. Allowlisting inverts every term: an attacker has to *match* the
string rather than evade it, evasion means refusal, and matching buys only the right to be looked
up and then checked against the address table like anything else. There is no permit to spoof
into, which is why this is safe and a denylist by name would not be.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ssrfguard import BlockedURLError, Decision, Policy
from ssrfguard._policy import _host_is_allowed

#: The list under test throughout: one exact entry and one wildcard.
LISTED = frozenset({"api.stripe.com", "*.githubusercontent.com"})

POLICY = Policy(allowed_hosts=LISTED)


def permitted_by(policy: Policy, url: str) -> bool:
    """Whether a policy allows this URL."""
    try:
        policy.check_url(url)
    except BlockedURLError:
        return False
    return True


def permitted(url: str) -> bool:
    """Whether the policy under test allows this URL."""
    return permitted_by(POLICY, url)


# ---------------------------------------------------------------------------
# The trap. Every row here is a host somebody would expect a careless matcher to let through.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "evil-githubusercontent.com",
        "evilgithubusercontent.com",
        "notapi.stripe.com",
        "api.stripe.com.evil.tld",
        "githubusercontent.com.evil.tld",
        "api-stripe.com",
        "xapi.stripe.com",
        "api.stripe.co",
        "api.stripe.comm",
        "stripe.com",
        "com",
        "githubusercontent.com",
    ],
)
def test_a_host_that_merely_resembles_a_listed_one_is_refused(host: str) -> None:
    """**The reason this card is marked SEC.**

    `endswith` says yes to the first two, and a matcher that trims a prefix instead says yes to
    others. Every row is refused because matching happens on label boundaries and a bare entry
    is exact.
    """
    assert not permitted(f"https://{host}/")


def test_the_suffix_trap_is_a_real_trap_and_not_a_hypothetical() -> None:
    """The bug this file exists to prevent, written out so nobody has to take it on faith."""
    assert "evil-githubusercontent.com".endswith("githubusercontent.com")
    assert not permitted("https://evil-githubusercontent.com/")


# ---------------------------------------------------------------------------
# What a listed entry does mean.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "api.stripe.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "a.b.c.githubusercontent.com",
    ],
)
def test_a_listed_host_is_permitted(host: str) -> None:
    assert permitted(f"https://{host}/some/path?q=1")


def test_a_bare_entry_is_exact_and_does_not_carry_its_subdomains() -> None:
    """A caller who wants both writes both. Guessing which they meant is how a widening ships."""
    assert permitted("https://api.stripe.com/")
    assert not permitted("https://x.api.stripe.com/")


def test_a_wildcard_entry_does_not_carry_its_own_base() -> None:
    """`*.example.com` is about subdomains. The bare name is a different entry."""
    assert permitted("https://raw.githubusercontent.com/")
    assert not permitted("https://githubusercontent.com/")


def test_both_forms_together_permit_both() -> None:
    policy = Policy(allowed_hosts=frozenset({"example.test", "*.example.test"}))
    assert policy.check_url("https://example.test/").host == "example.test"
    assert policy.check_url("https://a.example.test/").host == "a.example.test"


# ---------------------------------------------------------------------------
# The spellings of one name. Each of these defeats a *denylist*, which is why this package has
# none; against an allowlist each has to be folded or it is a wrong deny.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://api.stripe.com./",
        "https://API.STRIPE.COM/",
        "https://Api.Stripe.Com./",
    ],
)
def test_another_spelling_of_a_listed_name_is_still_that_name(url: str) -> None:
    """**The absolute form is the one that would have slipped.**

    `_HOSTNAME` deliberately permits a trailing dot and `_normalise` keeps it, so a matcher that
    did not fold it would refuse `https://api.stripe.com./`, which is not merely legal but
    resolves to exactly the same place.
    """
    assert permitted(url)


@pytest.mark.parametrize("entry", ["api.stripe.com.", "API.STRIPE.COM", " api.stripe.com "])
def test_another_spelling_of_a_listed_entry_lists_the_same_name(entry: str) -> None:
    """Folding happens on both sides, or the two halves cannot be compared."""
    policy = Policy(allowed_hosts=frozenset({entry}))
    assert policy.check_url("https://api.stripe.com/").host == "api.stripe.com"


def test_an_entry_may_be_written_in_the_script_a_caller_reads() -> None:
    """Entries go through the same codec a host does, so punycode is not the price of using this."""
    policy = Policy(allowed_hosts=frozenset({"пример.рф"}))
    assert policy.check_url("https://пример.рф/").host == ("xn--e1afmkfd.xn--p1ai")
    assert policy.check_url("https://xn--e1afmkfd.xn--p1ai/").host == "xn--e1afmkfd.xn--p1ai"


def test_a_homograph_of_a_listed_name_is_a_different_name() -> None:
    """A Cyrillic small a (U+0430) is not a Latin one, and normalises to a different A-label.

    Written as an escape rather than as the character, which is the convention
    `src/ssrfguard/__init__.py` set for its circled-digit example: a homograph is unreadable in
    source by definition, so spelling it out is what says the test means it.

    This is the direction an allowlist fails in. The same substitution defeats a *denylist*,
    which is why this package has none.
    """
    assert not permitted("https://\u0430pi.stripe.com/")


# ---------------------------------------------------------------------------
# Literal addresses, which are not host patterns.
# ---------------------------------------------------------------------------


def test_a_literal_address_is_refused_when_a_host_list_is_set() -> None:
    """Otherwise the list reads as a restriction and is not one."""
    assert not permitted("https://93.184.216.34/")
    assert not permitted("https://[2606:4700::1111]/")


def test_a_literal_address_is_permitted_by_being_listed_exactly() -> None:
    policy = Policy(allowed_hosts=frozenset({"1.1.1.1"}), allowed_ports=frozenset({443}))
    assert policy.check_url("https://1.1.1.1/").host == "1.1.1.1"
    assert policy.check_url("https://1.1.1.1/").is_literal_address


def test_a_wildcard_never_reaches_an_address() -> None:
    """**An entry is about names.** A caller who wrote `*.0.1` wrote something about hostnames,
    and letting it decide about `127.0.0.1` would answer a question they did not ask."""
    policy = Policy(allowed_hosts=frozenset({"*.0.1"}), allowed_networks=("127.0.0.0/8",))
    with pytest.raises(BlockedURLError, match="allowed_hosts"):
        policy.check_url("http://127.0.0.1/")


# ---------------------------------------------------------------------------
# Construction. A pattern nobody can read is a pattern nobody can review.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entry", "why"),
    [
        ("", "names no host"),
        ("   ", "names no host"),
        (".", "names no host"),
        ("*", "would permit every host"),
        ("*.", "would permit every host"),
        ("ap*.stripe.com", "only meaningful as the whole of the leftmost label"),
        ("*api.stripe.com", "only meaningful as the whole of the leftmost label"),
        ("api.*.stripe.com", "only meaningful as the whole of the leftmost label"),
        ("api.stripe.*", "only meaningful as the whole of the leftmost label"),
    ],
)
def test_a_pattern_that_cannot_mean_anything_is_refused_at_construction(
    entry: str, why: str
) -> None:
    with pytest.raises(ValueError, match=why):
        Policy(allowed_hosts=frozenset({entry}))


def test_a_bare_wildcard_says_what_to_do_instead() -> None:
    """`allowed_hosts={"*"}` and `allowed_hosts=set()` mean the same thing, and one of them is
    a sentence somebody wrote on purpose. Refusing it names the other."""
    with pytest.raises(ValueError, match="leave allowed_hosts empty instead"):
        Policy(allowed_hosts=frozenset({"*"}))


# ---------------------------------------------------------------------------
# The default, and the refusal.
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(host=st.from_regex(r"\A[a-z][a-z0-9-]{0,20}(\.[a-z][a-z0-9-]{0,20}){0,3}\Z", fullmatch=True))
def test_an_empty_host_list_decides_nothing(host: str) -> None:
    """**No existing policy's behaviour moves.** The default is empty and empty means no name
    restriction, so whatever `Policy()` did with a URL it still does."""
    url = f"https://{host}/"
    plain, listed = Policy(), Policy(allowed_hosts=frozenset())
    try:
        expected = plain.check_url(url).host
    except BlockedURLError:
        with pytest.raises(BlockedURLError):
            listed.check_url(url)
        return
    assert listed.check_url(url).host == expected


def test_a_refusal_names_the_host_and_the_field() -> None:
    with pytest.raises(BlockedURLError) as refusal:
        POLICY.check_url("https://evil.test/")
    assert "evil.test" in refusal.value.reason
    assert "allowed_hosts" in refusal.value.reason


def test_a_refusal_points_at_the_entry_that_was_nearly_matched() -> None:
    """The first mistake a caller makes is listing `example.com` and fetching `api.example.com`.
    The refusal is correct and baffling without saying which entry was close."""
    with pytest.raises(BlockedURLError) as refusal:
        POLICY.check_url("https://x.api.stripe.com/")
    assert "the nearest entry is 'api.stripe.com'" in refusal.value.reason


def test_a_refusal_with_nothing_near_it_does_not_invent_a_hint() -> None:
    with pytest.raises(BlockedURLError) as refusal:
        POLICY.check_url("https://unrelated.test/")
    assert "nearest entry" not in refusal.value.reason


def test_the_refusal_reaches_an_observer_like_any_other() -> None:
    seen: list[Decision] = []
    with pytest.raises(BlockedURLError):
        POLICY.check_url("https://evil.test/", observer=seen.append)
    (decision,) = seen
    assert (decision.stage, decision.outcome) == ("url", "refused")
    assert "allowed_hosts" in (decision.reason or "")


# ---------------------------------------------------------------------------
# The invariant, over inputs nobody chose.
# ---------------------------------------------------------------------------


@settings(max_examples=300, deadline=None)
@given(host=st.from_regex(r"\A[a-z][a-z0-9-]{0,12}(\.[a-z][a-z0-9-]{0,12}){0,3}\Z", fullmatch=True))
def test_a_permitted_host_is_always_a_listed_name_or_below_a_listed_wildcard(host: str) -> None:
    """**The property the corpus above is a sample of.**

    Whatever the matcher does, a permitted host is either exactly a listed entry or a proper
    subdomain of a wildcard entry's base. Anything else permitted is a bypass, whether or not
    anybody thought to write it down as a row.
    """
    if not permitted(f"https://{host}/"):
        return
    name = host.rstrip(".")
    assert name == "api.stripe.com" or (
        name.endswith(".githubusercontent.com") and len(name) > len(".githubusercontent.com")
    ), f"{name!r} was permitted and is neither a listed name nor below a listed wildcard"


# ---------------------------------------------------------------------------
# The matcher's own contract, at the boundaries a URL cannot currently reach.
# ---------------------------------------------------------------------------


def test_a_wildcard_needs_something_in_front_of_the_dot() -> None:
    """**A pattern's base is not a subdomain of itself**, asserted on the function rather than
    through a URL, because `_HOSTNAME` refuses a leading dot and so no URL can pose the question.

    A matcher is a matcher. The guard is what keeps `*.example.test` from matching the literal
    string `.example.test`, and it should hold for whoever calls this next rather than only for
    the caller it has today.
    """
    listed = frozenset({"*.example.test"})
    assert not _host_is_allowed(".example.test", listed, literal=False)
    assert _host_is_allowed("a.example.test", listed, literal=False)


def test_the_matcher_is_told_whether_it_is_looking_at_an_address() -> None:
    """No default, because every caller knows and a default is a path nothing takes."""
    listed = frozenset({"*.0.1"})
    assert not _host_is_allowed("127.0.0.1", listed, literal=True)
    assert _host_is_allowed("127.0.0.1", listed, literal=False), (
        "as a name, that host is below the wildcard; the literal flag is what excludes it"
    )


# ---------------------------------------------------------------------------
# Entries in a script the caller reads.
# ---------------------------------------------------------------------------


def test_a_wildcard_entry_may_also_be_written_in_unicode() -> None:
    """The wildcard is stripped before the codec sees the rest.

    **Not because the codec would refuse it**, which is what this docstring used to claim and is
    measurably untrue: `"*.\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444"
    .encode("idna")` succeeds and passes the `*` through. It is held back because `*` is not a
    hostname character and the codec's tolerance of it is incidental rather than promised.
    """
    policy = Policy(allowed_hosts=frozenset({"*.пример.рф"}))
    assert policy.check_url("https://a.пример.рф/").host == ("a.xn--e1afmkfd.xn--p1ai")
    assert not permitted_by(policy, "https://пример.рф/")


def test_regression_config_error_a_bad_entry_is_a_value_error_not_a_url_refusal() -> None:
    """**A constructor raises `ValueError`.** This one raised `BlockedURLError`, whose message
    reads "'...' is not permitted", naming a URL that does not exist for a caller who was
    configuring a policy rather than fetching anything.

    `_normalise` is shared with `check_url`, where a URL refusal is exactly right, so the wrong
    answer here came from reusing it without translating the failure at the boundary.
    """
    unusable = "пример" * 20 + ".рф"
    with pytest.raises(ValueError, match="allowed_hosts contains") as refusal:
        Policy(allowed_hosts=frozenset({unusable}))
    assert not isinstance(refusal.value, BlockedURLError)
    assert "is not a usable name" in str(refusal.value)


# ---------------------------------------------------------------------------
# The hint, on the spellings a host actually arrives in.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["x.api.stripe.com", "x.api.stripe.com."])
def test_the_nearest_entry_is_found_whichever_form_the_host_takes(host: str) -> None:
    """The absolute form reaches the hint too, and a hint that only works on one spelling of a
    name is a hint that vanishes exactly when somebody is confused about spellings."""
    with pytest.raises(BlockedURLError) as refusal:
        POLICY.check_url(f"https://{host}/")
    assert "the nearest entry is 'api.stripe.com'" in refusal.value.reason


def test_the_base_of_a_wildcard_entry_is_told_which_entry_it_nearly_matched() -> None:
    """**The second mistake anybody makes**, after listing a bare name and fetching a subdomain.

    Listing `*.githubusercontent.com` and then fetching `githubusercontent.com` is refused
    correctly, because a wildcard is about subdomains. Without the hint the refusal reads as the
    entry simply not working.
    """
    with pytest.raises(BlockedURLError) as refusal:
        POLICY.check_url("https://githubusercontent.com/")
    assert "the nearest entry is '*.githubusercontent.com'" in refusal.value.reason


def test_only_the_trailing_dot_is_stripped_from_an_entry_and_not_the_letters_near_it() -> None:
    """An entry is folded, not trimmed. A label may end in any letter, including the ones a
    careless strip set would take with it."""
    policy = Policy(allowed_hosts=frozenset({"example.testX."}))
    assert policy.check_url("https://example.testX/").host == "example.testx"
    assert not permitted_by(policy, "https://example.test/")
