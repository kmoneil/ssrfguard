"""The whole library in twelve lines: build a policy, build a client, fetch a URL.

Run it:

    python examples/01_first_request.py

`ssrfguard.httpx.Client` is an ordinary `httpx.Client`. Everything you already know about httpx
still applies: verbs, headers, timeouts, streaming, pooling, `follow_redirects`. The one
difference is where it connects, and that difference is not something you have to remember to
use. There is no `check_this_first()` to forget.
"""

from __future__ import annotations

from _support import heading, loopback_server

from ssrfguard import Policy
from ssrfguard.errors import SSRFGuardError
from ssrfguard.httpx import Client


def main() -> None:
    """Fetch a permitted URL, then watch the same client refuse a hostile one."""
    with loopback_server() as server:
        # The default policy denies loopback, which is the right default and the wrong one for
        # an example with no network. Allowing 127.0.0.0/8 is the whole of the difference
        # between this policy and `Policy()`, and it is the kind of decision the
        # `allowed_networks` field exists to make explicit.
        policy = Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={server.port})

        heading("A request that is allowed")
        with Client(policy=policy) as client:
            response = client.get(f"{server.origin}/hello")
            print(f"GET {server.origin}/hello -> {response.status_code} {response.text!r}")

        heading("The same client, against the addresses it exists to refuse")
        # Back to the shipped defaults. Nothing about these URLs needs configuring away: a
        # default policy already refuses all four. The encoded forms of the same addresses,
        # such as 0177.0.0.1 and 2130706433, are in 02_what_a_refusal_says.py, checked with
        # `policy.check_url` directly, because httpx refuses some of them before we see them.
        with Client(policy=Policy()) as client:
            for url in (
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:8080/admin",
                "http://[::1]/",
                "http://10.0.0.5/internal",
            ):
                try:
                    client.get(url)
                except SSRFGuardError as refused:
                    print(f"{type(refused).__name__}: {refused}")

        heading("What a refusal is, as a type")
        # Every refusal this package makes descends from SSRFGuardError, and nothing else does.
        # A connection that failed because the host was down stays an httpx error, because an
        # outage is not a policy decision and dressing it as one sends people hunting for a
        # security problem they do not have.
        print("catch ssrfguard.SSRFGuardError to catch every refusal, and nothing else")


if __name__ == "__main__":
    main()
