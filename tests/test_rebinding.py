"""The claim on the front of this package, demonstrated against a nameserver that lies.

Every other test here drives resolution with a Python callable. That is right for deciding what
the policy decides, and it is structurally incapable of proving the one thing this package
exists for: that nothing looks a name up twice. A stand-in cannot change its mind between two
calls. An attacker's nameserver does exactly that for a living.

So these run against a real DNS server on a real UDP socket, whose answers live in a dict a test
edits mid-flight. Each one resolves a name, moves the record, and then does the thing that would
be vulnerable, and asserts the connection went where the *first* answer pointed.

**The loopback policy is the harness, not a loophole.** These need an address that is both
permitted and reachable from a test process, and the shipped table denies loopback for good
reason. `PINNED_OK` allows `127.0.0.0/8` explicitly, which is the documented escape hatch doing
its job; every flip target is something that policy still refuses, or a second loopback address,
so nothing here is proved by the allowance itself.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator

import pytest

from ssrfguard import BlockedAddressError, Policy, connect, resolve

from .rebind_dns import FlippingDNS, Zone, resolver_using

pytestmark = pytest.mark.rebind

#: Permits loopback so a test can connect to itself. Everything else is still refused, and the
#: address every flip below moves *to* is refused by this policy.
PINNED_OK_NETWORKS = ("127.0.0.0/8",)

#: Where the flips point. Denied by the policy above, so a connection reaching it is the failure
#: this whole file exists to detect.
METADATA = "169.254.169.254"


@pytest.fixture
def dns() -> Iterator[FlippingDNS]:
    """A nameserver whose answers a test can change.

    Yields:
        The running server.
    """
    server = FlippingDNS()
    server.start()
    try:
        yield server
    finally:
        server.stop()


class Listener:
    """A TCP listener that records the addresses it accepted on.

    **A second loopback address is not free everywhere.** Linux routes the whole of
    `127.0.0.0/8`, so `127.0.0.2` binds without anything being configured. macOS assigns only
    `127.0.0.1` to `lo0`, and the tests below need two distinguishable permitted addresses in
    order to say which one the connection landed on. So the bind is where this file meets the
    platform, and it says what to do rather than reporting `Errno 49` from inside a fixture.
    """

    def __init__(self, host: str) -> None:
        self.host = host
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((host, 0))
        except OSError as unassigned:  # pragma: no cover - only where the address is not there
            self._sock.close()
            hint = f"sudo ifconfig lo0 alias {host} up"
            raise OSError(
                f"cannot bind {host}: {unassigned}. Only 127.0.0.1 is assigned to loopback on "
                f"this platform, and these tests need a second permitted address to move a "
                f"record to. Add it with: {hint}"
            ) from unassigned
        self._sock.listen(8)
        self._sock.settimeout(0.05)
        self.port = int(self._sock.getsockname()[1])
        self.accepted: list[str] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:  # pragma: no cover - only on a socket closed mid-accept
                return
            self.accepted.append(self.host)
            client.close()

    def wait_for_accept(self, timeout: float = 2.0) -> bool:
        """Wait until this listener has accepted something.

        The accept loop polls, so `accepted` is not populated the instant `connect` returns.
        Asserting on it without waiting is a race that fails about as often as the scheduler
        feels like it, which is the worst possible property for a security test, because the
        response to an intermittent failure is to delete it.

        Args:
            timeout: Seconds to wait.

        Returns:
            Whether anything was accepted.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.accepted:
                return True
            time.sleep(0.01)
        return False

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()


@pytest.fixture
def listener() -> Iterator[Listener]:
    """A listener on 127.0.0.1.

    Yields:
        The listener.
    """
    server = Listener("127.0.0.1")
    try:
        yield server
    finally:
        server.close()


def policy_for(port: int, *, networks: tuple[str, ...] = PINNED_OK_NETWORKS) -> Policy:
    """Build a policy that permits this test's port and loopback.

    Args:
        port: The ephemeral port the listener got.
        networks: Networks to permit.

    Returns:
        The policy.
    """
    return Policy(allowed_ports=frozenset({port}), allowed_networks=networks)


# ---------------------------------------------------------------------------------------------
# The headline
# ---------------------------------------------------------------------------------------------


def test_the_connection_lands_on_the_validated_address_after_the_record_moves(
    dns: FlippingDNS, listener: Listener
) -> None:
    """Resolve, move the record to the metadata endpoint, connect. It must not follow.

    This is the test the package exists to pass. A guard that validates a name and then hands
    the name to an HTTP client fails it, which is the shape of CVE-2026-55391, CVE-2026-27826,
    CVE-2026-62240 and every other advisory in the README.
    """
    policy = policy_for(listener.port)
    dns.set("rebind.test", a=["127.0.0.1"])
    resolver = resolver_using(dns)

    target = policy.check_url(f"http://rebind.test:{listener.port}/")
    addresses = resolve(target, policy=policy, resolver=resolver)
    assert [str(a.ip) for a in addresses] == ["127.0.0.1"]

    queries_before = dns.query_count
    dns.set("rebind.test", a=[METADATA])  # the attacker moves the record, right here

    with connect(addresses, policy=policy, timeout=5) as sock:
        assert sock.getpeername()[0] == "127.0.0.1", "the connection followed the moved record"

    assert dns.query_count == queries_before, (
        f"the name was looked up again after validation: {dns.queries[queries_before:]}"
    )


def test_pinning_is_not_merely_preferring_a_public_address(dns: FlippingDNS) -> None:
    """The record moves to a *permitted* address, and the connection still must not follow.

    A guard that re-resolved and then re-validated would pass every test above: the new answer
    is permitted, so nothing would be refused and nothing would look wrong. It would also have
    connected somewhere the caller never approved. This is the test that separates *pinning*
    from *checking again*.
    """
    first = Listener("127.0.0.1")
    second = Listener("127.0.0.2")
    try:
        # Two listeners cannot share an ephemeral port by luck, so give the policy both.
        policy = Policy(
            allowed_ports=frozenset({first.port, second.port}),
            allowed_networks=PINNED_OK_NETWORKS,
        )
        dns.set("pinned.test", a=["127.0.0.1"])
        resolver = resolver_using(dns)

        target = policy.check_url(f"http://pinned.test:{first.port}/")
        addresses = resolve(target, policy=policy, resolver=resolver)

        dns.set("pinned.test", a=["127.0.0.2"])  # still permitted, and still not where we go

        with connect(addresses, policy=policy, timeout=5) as sock:
            assert sock.getpeername()[0] == "127.0.0.1"
        assert first.wait_for_accept(), "the pinned listener saw the connection"
        assert not second.accepted, "the moved-to listener must have seen nothing"
    finally:
        first.close()
        second.close()


def test_the_vulnerable_pattern_reaches_the_metadata_endpoint(
    dns: FlippingDNS, listener: Listener
) -> None:
    """What a guard that validates and then re-resolves actually does, spelled out.

    Not a test of this package, but a test of the *bug*, written against the same fixture so the
    difference between the two is one line of code and not an argument. If this ever stops
    reaching the metadata address, the fixture has stopped being able to demonstrate rebinding
    and the test above has stopped meaning anything.
    """
    policy = policy_for(listener.port)
    dns.set("rebind.test", a=["127.0.0.1"])
    resolver = resolver_using(dns)

    # Step one, as every advisory describes it: resolve, check, discard the address.
    target = policy.check_url(f"http://rebind.test:{listener.port}/")
    validated = resolve(target, policy=policy, resolver=resolver)
    assert [str(a.ip) for a in validated] == ["127.0.0.1"]

    dns.set("rebind.test", a=[METADATA])

    # Step two: hand the *name* back to something that resolves it again. That is the whole bug.
    reresolved = resolver("rebind.test", listener.port)  # type: ignore[operator]
    landed = [str(row[4][0]) for row in reresolved]
    assert landed == [METADATA], (
        "the fixture can no longer demonstrate a rebind, so the pinning tests prove nothing"
    )
    assert not policy.permits_address(METADATA), "and this is where the guard would have gone"


# ---------------------------------------------------------------------------------------------
# The rest of the matrix
# ---------------------------------------------------------------------------------------------


def test_a_flip_before_resolution_is_caught_by_resolution(
    dns: FlippingDNS, listener: Listener
) -> None:
    """Moving the record between the URL check and the lookup changes nothing: we validate what
    we resolved, not what we expected to resolve."""
    policy = policy_for(listener.port)
    dns.set("early.test", a=["127.0.0.1"])
    resolver = resolver_using(dns)

    target = policy.check_url(f"http://early.test:{listener.port}/")
    dns.set("early.test", a=[METADATA])

    with pytest.raises(BlockedAddressError) as caught:
        resolve(target, policy=policy, resolver=resolver)
    assert METADATA in caught.value.reason


def test_a_flip_that_adds_a_denied_answer_refuses_the_whole_name(
    dns: FlippingDNS, listener: Listener
) -> None:
    """The partial-block rule against a real nameserver rather than a fake one."""
    policy = policy_for(listener.port)
    resolver = resolver_using(dns)
    dns.set("partial.test", a=["127.0.0.1", METADATA])

    target = policy.check_url(f"http://partial.test:{listener.port}/")
    with pytest.raises(BlockedAddressError) as caught:
        resolve(target, policy=policy, resolver=resolver)
    assert "signature of a DNS rebinding attempt" in caught.value.reason


def test_each_resolution_validates_its_own_answer(dns: FlippingDNS, listener: Listener) -> None:
    """Two lookups of the same name give two answers, and each is judged on its own merits."""
    policy = policy_for(listener.port)
    resolver = resolver_using(dns)
    target = policy.check_url(f"http://twice.test:{listener.port}/")

    dns.set("twice.test", a=["127.0.0.1"])
    assert [str(a.ip) for a in resolve(target, policy=policy, resolver=resolver)] == ["127.0.0.1"]

    dns.set("twice.test", a=[METADATA])
    with pytest.raises(BlockedAddressError):
        resolve(target, policy=policy, resolver=resolver)


def test_connecting_asks_the_nameserver_nothing(dns: FlippingDNS, listener: Listener) -> None:
    """Counted rather than reasoned about: connect issues no query, ever."""
    policy = policy_for(listener.port)
    dns.set("count.test", a=["127.0.0.1"])
    resolver = resolver_using(dns)

    target = policy.check_url(f"http://count.test:{listener.port}/")
    addresses = resolve(target, policy=policy, resolver=resolver)
    after_resolution = dns.query_count

    for _ in range(3):
        with connect(addresses, policy=policy, timeout=5):
            pass

    assert dns.query_count == after_resolution, (
        "connect asked the nameserver something; the address it was given is the only input it "
        "is entitled to"
    )


def test_an_ipv6_answer_is_pinned_too(dns: FlippingDNS) -> None:
    """The AAAA path, which the IPv4 tests above never exercise."""
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        server.bind(("::1", 0))
    except OSError:  # pragma: no cover - a host with no IPv6 loopback
        server.close()
        pytest.skip("this host has no IPv6 loopback")
    server.listen(4)
    try:
        port = int(server.getsockname()[1])
        policy = Policy(allowed_ports=frozenset({port}), allowed_networks=("::1/128",))
        dns.set("v6.test", aaaa=["::1"])
        resolver = resolver_using(dns)

        target = policy.check_url(f"http://v6.test:{port}/")
        addresses = resolve(target, policy=policy, resolver=resolver)
        assert [str(a.ip) for a in addresses] == ["::1"]

        before = dns.query_count
        dns.set("v6.test", aaaa=["fd00:ec2::254"])  # the IPv6 metadata endpoint

        with connect(addresses, policy=policy, timeout=5) as sock:
            assert sock.getpeername()[0] == "::1"
        assert dns.query_count == before
    finally:
        server.close()


def test_resolution_asks_exactly_once_per_record_type(dns: FlippingDNS, listener: Listener) -> None:
    """One `resolve` is one lookup, counted rather than reasoned about.

    This is the check that catches a *second* lookup hidden inside resolution: the version
    that re-validates what it gets back and therefore refuses nothing wrongly, looks correct in
    review, and still connects to an address the caller never approved. Editing the record
    between calls cannot see it, because both of its lookups happen on the same side of the edit.
    """
    policy = policy_for(listener.port)
    dns.set("once.test", a=["127.0.0.1"])
    resolver = resolver_using(dns)

    target = policy.check_url(f"http://once.test:{listener.port}/")
    resolve(target, policy=policy, resolver=resolver)

    assert dns.queries == [("once.test", 28), ("once.test", 1)], (
        f"resolution asked {len(dns.queries)} questions for one name: {dns.queries}"
    )


def test_a_nameserver_that_flips_on_every_query_cannot_move_the_connection(
    dns: FlippingDNS,
) -> None:
    """The strongest form: the record changes between one query and the next, unprompted.

    A real rebinding nameserver does not wait to be asked politely. It answers differently
    every time, so any implementation that looks up more than once gets an address nobody
    approved.

    **The second answer is deliberately a permitted one.** An implementation that re-resolved
    and then re-validated would refuse a metadata address and quietly fall back to the good one,
    passing a test whose flip target is denied, and measured, that is exactly what happened. Only
    a flip to somewhere *allowed* separates pinning from checking again, because there the
    second lookup produces a perfectly acceptable address that the caller still never approved.
    """
    pinned = Listener("127.0.0.1")
    moved = Listener("127.0.0.2")
    try:
        policy = Policy(
            allowed_ports=frozenset({pinned.port, moved.port}),
            allowed_networks=PINNED_OK_NETWORKS,
        )
        dns.set_sequence(
            "flip.test",
            [
                Zone(a=["127.0.0.1"]),  # what validation sees
                Zone(a=["127.0.0.2"]),  # what a second look sees, and it is allowed
                Zone(a=[METADATA]),  # and what a third would see, once trust is established
            ],
        )
        resolver = resolver_using(dns)

        target = policy.check_url(f"http://flip.test:{pinned.port}/")
        addresses = resolve(target, policy=policy, resolver=resolver)
        assert [str(a.ip) for a in addresses] == ["127.0.0.1"], (
            "resolution returned something other than its first answer, so it looked twice"
        )

        with connect(addresses, policy=policy, timeout=5) as sock:
            assert sock.getpeername()[0] == "127.0.0.1"
        assert pinned.wait_for_accept(), "the validated address saw the connection"
        assert not moved.accepted, "the address the record moved to must have seen nothing"
    finally:
        pinned.close()
        moved.close()
