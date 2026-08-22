"""Resolution against the real resolver.

Everything else in this layer is driven by a fake, which is right -- a fake is the only way to
arrange a name that resolves both ways. What a fake cannot show is that the *real* getaddrinfo
call is shaped correctly: the flags, the argument order, the socket type, and the fact that a
literal address takes a path that cannot perform a lookup at all.

Marked `egress`, so a developer without a network sees a clean suite and CI runs these behind a
reachability probe that fails rather than skips.
"""

from __future__ import annotations

import socket

import pytest

from ssrfguard import BlockedAddressError, Policy, resolve

pytestmark = pytest.mark.egress

POLICY = Policy()


def test_a_public_name_resolves_and_every_answer_is_public() -> None:
    resolved = resolve(POLICY.check_url("https://example.com/"), policy=POLICY)
    assert resolved
    for address in resolved:
        assert address.port == 443
        assert address.hostname == "example.com"
        assert POLICY.permits_address(address.ip)


def test_the_sockaddr_is_what_the_socket_layer_wants() -> None:
    """Proved by connecting with it, which is the only proof that counts."""
    resolved = resolve(POLICY.check_url("https://example.com/"), policy=POLICY)
    first = resolved[0]
    with socket.socket(first.family, socket.SOCK_STREAM) as sock:
        sock.settimeout(15)
        sock.connect(first.sockaddr)
        assert sock.getpeername()[0] == str(first.ip)


def test_localhost_is_refused_by_the_real_resolver() -> None:
    """The end-to-end shape: a name nobody would blocklist, refused on what it resolves to."""
    with pytest.raises(BlockedAddressError) as caught:
        resolve(POLICY.check_url("http://localhost/"), policy=POLICY)
    assert "127.0.0.1" in caught.value.reason or "::1" in caught.value.reason


def test_a_literal_address_cannot_reach_dns_even_with_the_real_resolver() -> None:
    """AI_NUMERICHOST makes the no-lookup claim structural rather than a promise."""
    resolved = resolve(POLICY.check_url("http://8.8.8.8/"), policy=POLICY)
    assert [str(a.ip) for a in resolved] == ["8.8.8.8"]


def test_a_name_that_does_not_exist_raises_gaierror_not_a_refusal() -> None:
    target = POLICY.check_url("http://this-name-does-not-exist.invalid/")
    with pytest.raises(socket.gaierror):
        resolve(target, policy=POLICY)
