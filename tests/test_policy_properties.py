"""Properties of the policy layer, generated rather than enumerated.

The corpus in `test_policy_urls.py` covers what somebody thought of. These assert things that
must hold for every URL, including the ones nobody would think to write down.
"""

from __future__ import annotations

import ipaddress
import string

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from ssrfguard import BlockedAddressError, BlockedURLError, Policy
from ssrfguard._policy import _NUMERIC_SHAPED
from ssrfguard._registry import TABLE, Reach

POLICY = Policy()

Refusal = BlockedURLError | BlockedAddressError


def refusal_for(url: str, policy: Policy = POLICY) -> Refusal | None:
    """Check a URL and return the refusal, if there was one.

    Hypothesis properties are about *either* outcome, so `pytest.raises` does not fit: it
    asserts that a call raises, and here raising is one of two correct answers. Capturing the
    exception and asserting outside the handler keeps the assertions where a reader can see
    which branch they belong to.

    Args:
        url: The URL to check.
        policy: The policy to check it against.

    Returns:
        The refusal, or ``None`` if the URL was permitted.
    """
    try:
        policy.check_url(url)
    except (BlockedURLError, BlockedAddressError) as refused:
        return refused
    return None


labels = st.text(alphabet=string.ascii_lowercase + string.digits, min_size=1, max_size=20)
# The final label starts with a letter. Not decoration: a host made only of digits and dots is
# refused as an encoded address, which Hypothesis found immediately by generating `http://0/` --
# and it was right to, because `getaddrinfo("0")` returns 0.0.0.0. That behaviour is asserted in
# `test_policy_urls.py`; here it would only mean the generator produces addresses rather than
# the hostnames these properties are about.
tlds = st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=8)
hostnames = st.tuples(st.lists(labels, min_size=0, max_size=3), tlds).map(
    lambda parts: ".".join([*parts[0], parts[1]])
)
schemes = st.sampled_from(["http", "https", "ftp", "file", "gopher", "jar", "data", "ws"])
ports = st.integers(min_value=0, max_value=70000)
v4 = st.integers(min_value=0, max_value=2**32 - 1).map(ipaddress.IPv4Address)
v6 = st.integers(min_value=0, max_value=2**128 - 1).map(ipaddress.IPv6Address)


@settings(max_examples=400)
@given(st.one_of(v4, v6))
def test_a_denied_address_is_never_reachable_as_a_url(address: object) -> None:
    """The property the whole layer rests on: no URL spelling launders a denied address.

    Whatever the policy says about the bare address, it must say the same about the URL that
    names it. Otherwise the URL parser is a bypass around the address table.
    """
    literal = f"[{address}]" if isinstance(address, ipaddress.IPv6Address) else str(address)
    url = f"http://{literal}/"
    permitted_bare = POLICY.permits_address(address)
    try:
        POLICY.check_url(url)
    except (BlockedURLError, BlockedAddressError):
        return  # refused as a URL; refusing more than the bare address is always safe
    assert permitted_bare, f"{url} was permitted while the bare address {address} was not"


@settings(max_examples=300)
@given(hostnames, schemes, ports)
def test_check_url_either_returns_a_target_or_explains_itself(
    host: str, scheme: str, port: int
) -> None:
    """There is no third outcome, and no refusal without a reason."""
    url = f"{scheme}://{host}:{port}/"
    refused = refusal_for(url)
    if refused is not None:
        assert refused.reason
        if isinstance(refused, BlockedURLError):
            assert refused.url == url
        return
    target = POLICY.check_url(url)
    assert target.scheme in POLICY.allowed_schemes
    assert target.port in POLICY.allowed_ports


@settings(max_examples=300)
@given(hostnames, ports)
def test_a_permitted_port_is_exactly_the_configured_set(host: str, port: int) -> None:
    """Nothing outside `allowed_ports` gets through, and everything inside it does."""
    assume(1 <= port <= 65535)
    policy = Policy(allowed_ports=frozenset({port}))
    assert policy.check_url(f"http://{host}:{port}/").port == port
    other = port + 1 if port < 65535 else 1
    refused = refusal_for(f"http://{host}:{other}/", policy)
    assert refused is not None, f"port {other} passed a policy allowing only {port}"
    assert "allowed_ports" in refused.reason


@settings(max_examples=300)
@given(hostnames)
def test_a_url_with_a_control_character_anywhere_is_refused(host: str) -> None:
    """urlsplit strips these silently, so what was checked would not be what was parsed."""
    for character in ("\n", "\r", "\t", "\x00", " "):
        url = f"http://{host}{character}/"
        refused = refusal_for(url)
        assert refused is not None, f"{url!r} was permitted"
        assert "control character" in refused.reason or "well-formed" in refused.reason


@settings(max_examples=200)
@given(st.sampled_from([b for b in TABLE if b.reach is Reach.DENIED]))
def test_allowing_a_denied_block_permits_it_and_nothing_else(block: object) -> None:
    """`allowed_networks` must be exactly as wide as it says, in both directions."""
    network = block.network  # type: ignore[attr-defined]
    assume(network.num_addresses >= 2)
    inside = ipaddress.ip_address(int(network.network_address) + 1)
    policy = Policy(allowed_networks=(network,))
    assert policy.permits_address(inside), "an explicitly allowed network must be reachable"
    # ...and nothing outside it. Loopback is the check, unless the block under test contains it.
    loopback = ipaddress.ip_address("::1" if network.version == 6 else "127.0.0.1")
    if loopback not in network:
        assert not policy.permits_address(loopback), (
            f"allowing {network} also permitted {loopback}, which it does not contain"
        )


@settings(max_examples=300)
@given(hostnames)
def test_normalisation_is_idempotent(host: str) -> None:
    """Checking a normalised host again must not change it, or two checks could disagree."""
    first = POLICY.check_url(f"http://{host}/")
    second = POLICY.check_url(f"http://{first.host}/")
    assert first.host == second.host


@settings(max_examples=300)
@given(hostnames)
def test_case_never_changes_the_verdict(host: str) -> None:
    """A guard that answers differently for HOST and host is a guard with a bypass."""
    lower = POLICY.check_url(f"http://{host}/")
    upper = POLICY.check_url(f"HTTP://{host.upper()}/")
    assert lower == upper


@settings(max_examples=2000)
@given(st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), max_size=48))
def test_the_shortcut_around_the_address_parser_never_lets_an_address_through(text: str) -> None:
    """`_check_host` skips the address parser on a cheap test, and this is why that is safe.

    Handing every host to `ipaddress.ip_address` to find out whether it is one costs three
    raised exceptions on the ordinary answer, which is "no", and that was the most expensive
    thing in `check_url`. So a one-character test runs first: an address literal either holds a
    colon or is nothing but digits and dots.

    **A wrong answer here is a wrong permit, not a wrong deny**, which is why this is generated
    rather than argued. A literal address mistaken for a name skips `check_address` entirely and
    reaches the resolver as though it were a hostname. The argument is that `IPv4Address` accepts
    only digits and dots and `IPv6Address` requires a colon, so there is no third shape, and this
    is what says the argument holds for strings nobody would think to write down.
    """
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return
    assert ":" in text or _NUMERIC_SHAPED.match(text) is not None, (
        f"{text!r} parses as an address and the shortcut in _check_host would have treated it "
        f"as a name, which skips check_address entirely"
    )


@settings(max_examples=400)
@given(st.one_of(st.ip_addresses(v=4), st.ip_addresses(v=6)))
def test_the_shortcut_admits_every_address_the_parser_accepts(address: object) -> None:
    """The same property from the other side, over addresses rather than over text.

    Random printable text almost never happens to be an address, so the property above spends
    most of its examples on the uninteresting branch. This one generates only addresses, in both
    the compressed and the exploded spelling, so the interesting branch is every example.

    Each spelling is fed back through the parser before it is asserted on, because a rendering
    is not automatically an input: ``format(IPv6Address("::a"), "x")`` is 32 bare hex digits,
    which nothing accepts, and asserting on it tests the fixture rather than the code.
    """
    for form in {address.compressed, address.exploded}:
        try:
            ipaddress.ip_address(form)
        except ValueError:
            continue
        assert ":" in form or _NUMERIC_SHAPED.match(form) is not None, (
            f"{form!r} is an address the shortcut would have skipped"
        )
