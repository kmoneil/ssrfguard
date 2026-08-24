"""The `requests` surface: a Session, an adapter, and the one way to defeat it.

Run it:

    python examples/06_requests_session.py

`ssrfguard.requests.Session` is a `requests.Session` with a guarded adapter mounted on both
`http://` and `https://`. Everything a session does goes through that seam: the verb helpers,
`Session.request`, redirects, retries and pooled connections.

The failure worth knowing about is silent, so it is demonstrated here rather than described:
**an adapter is only mounted against the prefixes it was mounted against.** A session that
mounts the guard on `https://` and leaves `http://` with the stock adapter is guarded on one
scheme, and a redirect is how it will find out. `Session` mounts both, which is the reason to
use it instead of assembling one yourself.
"""

from __future__ import annotations

import requests
from _support import ScriptedResolver, heading, loopback_server

from ssrfguard import Policy
from ssrfguard.errors import SSRFGuardError
from ssrfguard.requests import SafeAdapter, Session


def ordinary_use(port: int) -> None:
    """Use it the way you already use requests.

    Args:
        port: The loopback port to aim at.
    """
    heading("An ordinary session")
    policy = Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={port})
    with Session(policy=policy) as session:
        response = session.get(f"http://127.0.0.1:{port}/things", timeout=5)
        print(f"  GET  -> {response.status_code} {response.text!r}")

        # Session-level configuration works as it always did: headers, auth, hooks, params.
        session.headers["user-agent"] = "example/1.0"
        response = session.get(f"http://127.0.0.1:{port}/things", timeout=5)
        print(f"  GET with session headers -> {response.status_code}")

        # And the policy is on the session, so a caller can read what it is bound by.
        print(f"  session.policy.max_redirects = {session.policy.max_redirects}")


def refusals() -> None:
    """The same refusals as the httpx surface, since they are the same policy."""
    heading("Refusals")
    with Session(policy=Policy()) as session:
        for url in ("http://169.254.169.254/latest/", "http://127.0.0.1/", "http://[::1]/"):
            try:
                session.get(url, timeout=5)
            except SSRFGuardError as refused:
                print(f"  {type(refused).__name__}: {refused}")

    # A name whose answer is denied is refused when it is resolved, not when it is parsed.
    with Session(policy=Policy(), resolver=ScriptedResolver("169.254.169.254")) as session:
        try:
            session.get("http://metadata.google.internal/", timeout=5)
        except SSRFGuardError as refused:
            print(f"  {type(refused).__name__}: {refused}")


def mounting_it_yourself(port: int) -> None:
    """Show the adapter alone, and the hole that leaving a prefix unmounted opens.

    Args:
        port: The loopback port to aim at.
    """
    heading("Mounting the adapter yourself, and the scheme it is easy to forget")
    # 80 and 443 are here so `get_adapter` has a URL it can check; see the note below.
    policy = Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={port, 80, 443})

    # A hand-built session, guarded on https:// only. This is the mistake.
    half_guarded = requests.Session()
    half_guarded.mount("https://", SafeAdapter(policy=policy))
    print("  requests.Session() with SafeAdapter on https:// only:")
    print(
        f"    http://  adapter -> {type(half_guarded.get_adapter('http://example.com/')).__name__}"
    )
    print(
        f"    https:// adapter -> {type(half_guarded.get_adapter('https://example.com/')).__name__}"
    )
    print("    the http:// prefix still has the stock adapter, so it is not guarded at all")
    half_guarded.close()

    # What Session does instead.
    with Session(policy=policy) as guarded:
        print("  ssrfguard.requests.Session():")
        print(
            f"    http://  adapter -> {type(guarded.get_adapter('http://example.com/')).__name__}"
        )
        print(
            f"    https:// adapter -> {type(guarded.get_adapter('https://example.com/')).__name__}"
        )

    print()
    print("  `Session.get_adapter` runs the policy check on the whole URL before it picks an")
    print("  adapter, which is why the URLs above have to be ones this policy permits. That")
    print("  is deliberate: requests calls get_adapter on every hop of a redirect chain, so")
    print("  it is the one place a check catches a hop no matter who is following it.")
    print()
    print("  mounting an adapter of your own over either prefix removes the guard from it.")
    print("  There is no way to prevent that and no attempt to; it is said out loud because")
    print("  the failure is silent.")


def main() -> None:
    """Run every section against one loopback server."""
    with loopback_server() as server:
        ordinary_use(server.port)
        refusals()
        mounting_it_yourself(server.port)


if __name__ == "__main__":
    main()
