"""What `check_url` decides, over a corpus of URLs written to get past it.

Every refusal here was measured against `urllib.parse.urlsplit`'s actual behaviour rather than
its documented one -- several of the entries exist because the two differ.
"""

from __future__ import annotations

import pytest

from ssrfguard import BlockedURLError, Policy

POLICY = Policy()

# (url, refused, why it is in this corpus)
PERMITTED: tuple[tuple[str, str], ...] = (
    ("http://example.com/", "the ordinary case"),
    ("https://example.com/", "the other ordinary case"),
    ("https://example.com:443/path?query=1#frag", "explicit default port, path, query, fragment"),
    ("http://example.com:80/", "explicit default port"),
    ("HTTP://EXAMPLE.COM/", "scheme and host case are normalised, not refused"),
    ("http://example.com./", "a trailing dot is a fully-qualified name, not an error"),
    ("http://xn--mnchen-3ya.de/", "an A-label arrives already encoded"),
    ("http://münchen.de/", "a U-label is encoded rather than refused"),
    ("http://8.8.8.8/", "a literal public address"),
    ("http://[2606:4700:4700::1111]/", "a literal public IPv6 address"),
    ("http://a.b.c.d.example.com/", "deep subdomains"),
    ("http://x/", "a single-label host is legal; the resolver decides if it exists"),
)

REFUSED: tuple[tuple[str, str], ...] = (
    # -- scheme --
    ("file:///etc/passwd", "file: is absent from the allow set by construction"),
    ("gopher://example.com/", "gopher: likewise"),
    ("ftp://example.com/", "ftp: likewise"),
    ("//example.com/", "no scheme at all"),
    ("/just/a/path", "relative URL names no origin"),
    ("example.com", "bare host is not a URL"),
    # -- authority --
    ("http://evil.com@127.0.0.1/", "the disguise: text before '@' is not the host"),
    ("http://user:pass@example.com/", "credentials leak into logs and redirect chains"),
    ("http://", "no host"),
    ("http:///path", "no host, path only"),
    ("http://[::1", "unterminated IPv6 literal; urlsplit raises"),
    ("http://a b.com/", "space in host"),
    ("http://exa_mple.com/", "underscore is not a hostname character"),
    ("http://-example.com/", "a label may not start with a hyphen"),
    ("http://%65xample.com/", "percent-encoding the resolver will not decode"),
    ("http://[fe80::1%25lo]/", "an IPv6 zone identifier is link-local scope"),
    # -- control characters urlsplit strips silently --
    ("http://exa\nmple.com/", "newline; urlsplit removes it, so checked != parsed"),
    ("http://example.com\t/", "tab, same"),
    ("http://example.com\r/", "carriage return, same"),
    ("http://exam ple.com/", "space, same class"),
    # -- ports --
    ("http://example.com:8080/", "8080 is not in the default allow set"),
    ("http://example.com:22/", "ssh"),
    ("http://example.com:0/", "port 0 is not a port"),
    ("http://example.com:99999/", "out of range; urlsplit's .port raises"),
    ("http://example.com:-1/", "negative"),
    ("http://example.com:abc/", "not a number"),
    # -- literal addresses the table denies --
    ("http://127.0.0.1/", "loopback"),
    ("http://169.254.169.254/", "cloud metadata"),
    ("http://[::1]/", "IPv6 loopback"),
    ("http://10.0.0.1/", "RFC1918"),
    ("http://[64:ff9b::7f00:1]/", "NAT64 carrying loopback"),
    ("http://0.0.0.0/", "unspecified, which reaches localhost"),
    # -- encoded addresses, which are not valid literals and not hostnames either --
    ("http://0177.0.0.1/", "octal"),
    ("http://2130706433/", "integer"),
    ("http://127.1/", "short form"),
    ("http://1.2.3.4.5/", "digits and dots, not an address"),
    ("http://0/", "a bare zero; getaddrinfo returns 0.0.0.0 for it. Found by Hypothesis"),
    ("http://1/", "same shape, and 0.0.0.1 is inside 0.0.0.0/8"),
    # -- Unicode that normalises to an address --
    ("http://①②⑦.0.0.1/", "circled digits normalise to 127.0.0.1"),
    ("http://127。0。0。1/", "ideographic full stop is a label separator"),
)


# **The boundary of this layer, written down as a corpus.**
#
# These reach an internal address and `check_url` permits every one of them, because deciding
# where a *name* points requires resolving it and nothing here resolves anything. They are not
# gaps -- they are the reason `check_url` returns a `Target` instead of a URL, and the reason
# its docstring says "necessary and not sufficient" in the first paragraph.
#
# If one of these ever starts being refused here, that is a string-matching fast path and it
# should be removed: a blocklist of names is a bypass with extra steps.
NOT_CAUGHT_HERE: tuple[tuple[str, str], ...] = (
    ("http://0x7f.0.0.1/", "hex-encoded 127.0.0.1; 'x' and 'f' make it a legal hostname shape"),
    ("http://ⓁⓄⒸⒶⓁⒽⓄⓈⓉ/", "circled letters normalise to 'localhost', which is a name"),
    ("http://localhost/", "the name itself; refusing it by string would be the wrong mechanism"),
    ("http://metadata.google.internal/", "a metadata endpoint reached by name"),
    ("http://rebind.example/", "a name whose answer changes between two lookups"),
    ("http://example.com/", "and the ordinary case, which is indistinguishable from the above"),
)


@pytest.mark.parametrize(("url", "why"), NOT_CAUGHT_HERE, ids=[repr(u) for u, _ in NOT_CAUGHT_HERE])
def test_the_policy_layer_does_not_pretend_to_resolve(url: str, why: str) -> None:
    """`check_url` permits these, and that is correct rather than a gap.

    Each reaches somewhere a fetcher should not go, and each is caught by resolution instead --
    which is exactly why a `Target` is not something an HTTP client will accept. A user who
    calls only this method has the shape of every advisory in this package's README.
    """
    target = POLICY.check_url(url)
    assert not target.is_literal_address, (
        f"{url!r} normalised to a literal address, so it belongs in REFUSED rather than here"
    )


@pytest.mark.parametrize(("url", "why"), PERMITTED, ids=[u for u, _ in PERMITTED])
def test_permitted(url: str, why: str) -> None:
    target = POLICY.check_url(url)
    assert target.scheme in {"http", "https"}
    assert target.port in {80, 443}


@pytest.mark.parametrize(("url", "why"), REFUSED, ids=[repr(u) for u, _ in REFUSED])
def test_refused(url: str, why: str) -> None:
    with pytest.raises(BlockedURLError) as caught:
        POLICY.check_url(url)
    assert caught.value.url == url
    assert caught.value.reason, f"{url!r} ({why}) was refused with no reason"


def test_a_refusal_names_the_field_that_refused_it() -> None:
    """A user has to be able to fix this from the message, not from the source."""
    with pytest.raises(BlockedURLError) as caught:
        POLICY.check_url("http://example.com:8080/")
    assert caught.value.reason == "port 8080 is not in allowed_ports (80, 443)"

    with pytest.raises(BlockedURLError) as caught:
        POLICY.check_url("ftp://example.com/")
    assert caught.value.reason == "scheme 'ftp' is not in allowed_schemes (http, https)"


def test_a_control_character_refusal_says_why_it_matters() -> None:
    """The reason is a parser differential, not tidiness, and the message has to say so."""
    with pytest.raises(BlockedURLError) as caught:
        POLICY.check_url("http://exa\nmple.com/")
    assert "urlsplit strips silently" in caught.value.reason
    assert "offset 10" in caught.value.reason


def test_unicode_normalisation_matches_what_the_resolver_would_do() -> None:
    """The host is encoded with the same codec `socket.getaddrinfo` uses, so they cannot differ."""
    with pytest.raises(BlockedURLError) as caught:
        POLICY.check_url("http://①②⑦.0.0.1/")
    assert caught.value.reason == "127.0.0.0/8 is Loopback (RFC1122)"


def test_a_u_label_host_is_encoded_and_both_forms_are_kept() -> None:
    target = POLICY.check_url("http://münchen.de/")
    assert target.host == "xn--mnchen-3ya.de", "the resolver and TLS both need the A-label"
    assert target.host_as_written == "münchen.de", "the message needs what the caller typed"


def test_check_url_refuses_a_non_string() -> None:
    """A type error is a programming mistake, not a policy decision, so it is not a refusal."""
    with pytest.raises(TypeError, match="check_url expects a string, got bytes"):
        POLICY.check_url(b"http://example.com/")  # type: ignore[arg-type]


def test_widening_the_policy_actually_widens_it() -> None:
    """Every default here is meant to be adjustable; a refusal nobody can lift is a bug."""
    wide = Policy(allowed_ports=frozenset({8080}), allowed_schemes=frozenset({"http"}))
    assert wide.check_url("http://example.com:8080/").port == 8080
    with pytest.raises(BlockedURLError):
        wide.check_url("https://example.com/")


def test_allow_userinfo_permits_credentials_when_asked() -> None:
    permissive = Policy(allow_userinfo=True)
    assert permissive.check_url("http://user:pass@example.com/").host == "example.com"
    # ...and the disguise still fails, because the host really is the loopback address
    with pytest.raises(BlockedURLError):
        permissive.check_url("http://evil.com@127.0.0.1/")


def test_allowed_networks_beats_the_denied_table() -> None:
    """An internal-services fetcher has to be able to reach its internal services."""
    internal = Policy(allowed_networks=("10.0.0.0/8",))
    assert internal.check_url("http://10.1.2.3/").address is not None
    with pytest.raises(BlockedURLError):
        internal.check_url("http://127.0.0.1/"), "allowing one network allows only that one"
