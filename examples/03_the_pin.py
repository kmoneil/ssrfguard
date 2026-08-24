"""The claim on the front of the package, run rather than argued.

Run it:

    python examples/03_the_pin.py

Every SSRF guard in Python validates a hostname and then hands the URL to an HTTP client that
resolves DNS a *second* time. The attacker moves the record in between: the guard approves
93.184.216.34 and the socket lands on 169.254.169.254. The guard was not wrong. The next line of
code was the vulnerability.

This example runs a nameserver that lies. It answers with a permitted address the first time and
with the cloud metadata endpoint every time after, which is a DNS rebinding attack written in
five lines. Three things are then shown, in order:

1.  **Within one request, the address validated is the address connected to.** One lookup, and
    `connect` has no name to re-resolve, because it is handed addresses rather than a hostname.
2.  **Every new connection is validated again.** The pin is not a one-off blessing that a later
    connection inherits. When the record moves, the next connection is refused.
3.  **A pooled connection is not re-resolved, because it was never re-opened.** The lookup count
    is how you can tell the difference.

The last of those is the part a reader should hold onto: this package's guarantee is
per-connection, and a connection's lifetime is how long it holds.

**A stand-in resolver cannot prove point 1 on its own** and this example does not pretend
otherwise: it cannot change its mind between two calls that a single `resolve` brackets, because
there is only one call to change it between. That is exactly why the package's own suite proves
this against a real nameserver on a real UDP socket, in `tests/test_rebinding.py`. What this
file demonstrates is the shape of the mechanism and the lookup count that gives it away.
"""

from __future__ import annotations

from _support import ScriptedResolver, heading, loopback_server

from ssrfguard import Policy, connect, resolve
from ssrfguard.errors import SSRFGuardError
from ssrfguard.httpx import Client

#: The address a hostile nameserver moves the record to. Nothing about this example depends on
#: it being the metadata endpoint rather than 10.0.0.1; it is the one every advisory names.
METADATA = "169.254.169.254"


def by_hand(port: int) -> None:
    """Walk the three steps a client takes, so the seam is visible rather than internal.

    Args:
        port: The loopback port to aim at.
    """
    heading("1. Validated, then connected, with the record moving in between")
    policy = Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={port})
    dns = ScriptedResolver("127.0.0.1", METADATA)

    target = policy.check_url(f"http://inside.example:{port}/status")
    print(f"  check_url  -> {target}")
    print("               a Target, not a URL: no path, no query, and no way to hand it to a")
    print("               client by accident. The only thing that consumes it is resolution.")

    addresses = resolve(target, policy=policy, resolver=dns)
    print(f"  resolve    -> {[str(a) for a in addresses]}   (lookups: {dns.calls})")

    # This is the moment the attack happens. The nameserver has already changed its answer, and
    # the next thing anybody asks it will be told the metadata endpoint. Nothing below asks it.
    print(f"  ... the nameserver now answers {METADATA} for that name ...")

    sock = connect(addresses, policy=policy, timeout=5)
    try:
        print(f"  connect    -> peer {sock.getpeername()[0]}   (lookups: {dns.calls})")
    finally:
        sock.close()

    print("               connect took addresses, not a name. There was nothing to re-resolve,")
    print("               so the moved record moved nothing.")


def through_the_client(port: int) -> None:
    """Show the same thing through an ordinary httpx client, which is how you would use it.

    Args:
        port: The loopback port to aim at.
    """
    heading("2. The same seam, inside a client, over three requests")
    policy = Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={port})
    dns = ScriptedResolver("127.0.0.1", METADATA)

    with Client(policy=policy, resolver=dns) as client:
        response = client.get(f"http://inside.example:{port}/first")
        print(f"  request 1: {response.status_code} {response.text!r}   (lookups: {dns.calls})")

        # Keep-alive: this request reuses the open connection, so no name is looked up at all.
        response = client.get(f"http://inside.example:{port}/second")
        print(f"  request 2: {response.status_code} {response.text!r}   (lookups: {dns.calls})")
        print("             the pool reused the connection, so nothing was resolved")

    # A second client has an empty pool, so its first request must open a connection, which
    # means resolving the name again. A connection that expired, or a pool that filled and
    # evicted, reaches the same place; a fresh client is just the version of it that fits in an
    # example. Note that the resolver is the same object, so the nameserver has not been reset:
    # it has simply moved on, the way a hostile one does.
    with Client(policy=policy, resolver=dns) as client:
        try:
            client.get(f"http://inside.example:{port}/third")
        except SSRFGuardError as refused:
            print(f"  request 3: {type(refused).__name__}: {refused}")
            print(f"             (lookups: {dns.calls}) a new connection revalidates, and this")
            print("             one was refused before a packet left the process")


def what_a_plain_client_would_do(port: int) -> None:
    """Name the failure this prevents, without staging a fake version of it.

    Args:
        port: The loopback port, named so the contrast is about the same request.
    """
    heading("3. What the unguarded shape looks like, for contrast")
    print("  The pattern every 2026 advisory describes is three lines long:")
    print()
    print("      address = socket.gethostbyname(urlparse(url).hostname)   # lookup 1")
    print("      if is_private(address): raise Forbidden                  # validated ...")
    print("      return httpx.get(url)                                    # ... and discarded")
    print()
    print("  The third line resolves the name again. Whatever the second line approved is not")
    print("  what the third line connects to, and the gap between them is the vulnerability.")
    print(f"  Here, that gap is where {METADATA} arrives.")
    print()
    print("  Named in: datamodel-code-generator (CVE-2026-55391), mcp-atlassian")
    print("  (CVE-2026-27826), crewAI (CVE-2026-62240), mlflow, AutoGPT, Craft CMS,")
    print("  pydantic-ai. Same bug, seven times, in one year.")


def main() -> None:
    """Run the three parts against one loopback server."""
    with loopback_server() as server:
        by_hand(server.port)
        through_the_client(server.port)
        what_a_plain_client_would_do(server.port)


if __name__ == "__main__":
    main()
