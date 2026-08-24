"""Redirects: the hop that is checked, the chain that is capped, the header that is dropped.

Run it:

    python examples/07_redirects.py

A redirect is the interesting half of SSRF, because it is where a URL a caller approved becomes
a URL nobody approved. Three things happen here, and each is a separate decision:

1.  **Every hop gets a full policy evaluation.** A `302` to the metadata endpoint is refused at
    the hop, not at the origin, and the refusal names the redirect target rather than the URL
    the caller typed.
2.  **The chain is capped by this package**, not by the HTTP client. The client's own limit
    exists to stop loops, is an order of magnitude larger, and can be changed without touching
    the policy, which makes it not a security control.
3.  **Credentials are dropped when a hop crosses origin.** The default set is the three headers
    whose *definition* is credentials. `x-api-key` is a naming convention rather than a
    specification, so you name it rather than this package guessing.
"""

from __future__ import annotations

from _support import heading, loopback_server

from ssrfguard import Policy
from ssrfguard.errors import SSRFGuardError
from ssrfguard.httpx import Client

#: A redirect table: five hops, plus one that leaves for the metadata endpoint.
CHAIN = {
    "/hop/0": "/hop/1",
    "/hop/1": "/hop/2",
    "/hop/2": "/hop/3",
    "/hop/3": "/hop/4",
    "/hop/4": "/hop/5",
    "/hop/5": "/hop/6",
    "/hop/6": "/done",
    "/escape": "http://169.254.169.254/latest/meta-data/",
}


def a_hop_that_leaves(port: int) -> None:
    """Refuse a redirect whose target the policy denies.

    Args:
        port: The loopback port to aim at.
    """
    heading("1. A redirect to somewhere the policy refuses")
    policy = Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={port, 80})
    with Client(policy=policy) as client:
        try:
            client.get(f"http://127.0.0.1:{port}/escape", follow_redirects=True)
        except SSRFGuardError as refused:
            print(f"  {type(refused).__name__}: {refused}")
    print("  the caller asked for /escape, which is permitted. The hop is what was refused,")
    print("  and the message names the hop rather than the URL that was typed.")


def the_chain_cap(port: int) -> None:
    """Show the policy's own redirect limit, including what zero means.

    Args:
        port: The loopback port to aim at.
    """
    heading("2. The chain cap belongs to the policy")
    base = Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={port, 80})

    with Client(policy=base) as client:
        try:
            client.get(f"http://127.0.0.1:{port}/hop/0", follow_redirects=True)
        except SSRFGuardError as refused:
            print(f"  default (max_redirects=5): {type(refused).__name__}")
            print(f"    {refused}")

    # Two hops is enough for /hop/0 -> /hop/1 -> /hop/2, and no further.
    with Client(
        policy=Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={port, 80}, max_redirects=2)
    ) as client:
        try:
            client.get(f"http://127.0.0.1:{port}/hop/0", follow_redirects=True)
        except SSRFGuardError as refused:
            print(f"  max_redirects=2: {refused}")

    # Zero is the one that surprises people, so it is shown rather than footnoted.
    zero = Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={port, 80}, max_redirects=0)
    with Client(policy=zero) as client:
        try:
            client.get(f"http://127.0.0.1:{port}/hop/0", follow_redirects=False)
        except SSRFGuardError as refused:
            print(f"  max_redirects=0, follow_redirects=False: {refused}")
    print("    0 means 'a redirect is refused', not 'redirects are not followed'. Both clients")
    print("    build the next request in order to expose it, and the cap fires on the build.")
    print("    To receive a 302 without following it, leave max_redirects alone and switch")
    print("    following off at the call.")


def credentials_across_an_origin(port_a: int, port_b: int) -> None:
    """Show which headers survive a hop that crosses origin.

    Args:
        port_a: The origin the caller asks for.
        port_b: The origin it is redirected to, which is a different origin.
    """
    heading("3. Credentials do not follow a hop to another origin")
    policy = Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={port_a, port_b})
    sent = {
        "authorization": "Bearer sk-live-do-not-log-me",
        "cookie": "session=abc123",
        "x-api-key": "also-a-secret-but-not-by-specification",
        "accept": "application/json",
    }
    with Client(policy=policy) as client:
        client.get(f"http://127.0.0.1:{port_a}/cross", headers=sent, follow_redirects=True)

    print(f"  sent to the first origin      : {sorted(sent)}")
    print("  redirected to a different port on 127.0.0.1, which is a different origin, which")
    print("  is what the rule turns on")
    print()
    print("  default sensitive_headers = {authorization, proxy-authorization, cookie}")
    print("  so x-api-key crossed. To drop it too, name it:")
    print()
    print("      Policy(sensitive_headers={'authorization', 'cookie', 'x-api-key'})")
    print()
    print("  this package does not guess which of your headers are secrets, because a header")
    print("  whose secrecy is a naming convention is yours to declare and not ours to infer.")


def main() -> None:
    """Run every section, using two servers for the cross-origin half."""
    with loopback_server(redirects=CHAIN) as first, loopback_server() as second:
        a_hop_that_leaves(first.port)
        the_chain_cap(first.port)

        with loopback_server(
            redirects={"/cross": f"http://127.0.0.1:{second.port}/landed"}
        ) as third:
            credentials_across_an_origin(third.port, second.port)
            seen = zip(second.requests, second.headers, strict=True)
            landed = [headers for path, headers in seen if path == "/landed"]
            if landed:
                interesting = {"authorization", "cookie", "x-api-key", "accept"}
                arrived = sorted(k for k in landed[0] if k in interesting)
                print(f"  arrived at the second origin  : {arrived}")
                print("  authorization and cookie were dropped by the crossing; the rest were not")


if __name__ == "__main__":
    main()
