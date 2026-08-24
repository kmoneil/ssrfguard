"""Using the pieces directly, for a protocol this package ships no client for.

Run it:

    python examples/08_building_blocks.py

The three clients are assembled from three functions, and the functions are public. If you need
to reach a Redis, a Postgres, an SMTP server or anything else at a URL a stranger supplied, this
is the shape:

    target    = policy.check_url(url)                 # no I/O at all
    addresses = resolve(target, policy=policy)        # exactly one lookup, every answer checked
    sock      = connect(addresses, policy=policy)     # connects to an address, never to a name

The signature is the argument. `connect` takes a sequence of `Address`, and an `Address` carries
a socket address rather than a hostname, so there is nothing in scope for it to re-resolve. That
is a property of the types rather than a promise in a docstring.

**The one thing you must get right yourself is TLS.** If you wrap the socket, the certificate has
to be verified against `address.hostname`, which is the name, and never against the address you
connected to. Passing an IP as `server_hostname` silently disables hostname verification and
trades an SSRF hole for a worse one. The last section shows the correct call.
"""

from __future__ import annotations

import socket
import ssl

from _support import ScriptedResolver, heading, loopback_server

from ssrfguard import Address, Policy, connect, resolve
from ssrfguard.errors import SSRFGuardError


def the_three_steps(port: int) -> None:
    """Walk check_url, resolve and connect, printing what each hands to the next.

    Args:
        port: The loopback port to aim at.
    """
    heading("The three steps, and what each one returns")
    policy = Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={port})
    dns = ScriptedResolver("127.0.0.1")

    target = policy.check_url(f"http://cache.internal:{port}/ignored/path?and=query")
    print(f"  check_url -> {target}")
    print(f"      .scheme          {target.scheme}")
    print(f"      .host            {target.host!r}          (an A-label: TLS verifies this)")
    print(f"      .port            {target.port}")
    print(f"      .host_as_written {target.host_as_written!r}   (only for quoting in a refusal)")
    print(f"      .is_literal_address {target.is_literal_address}")
    print("      the path and query are gone on purpose: this is an origin to connect to,")
    print("      not a request to make, and a value a client would accept is the shape every")
    print("      advisory in this package's README describes.")

    addresses = resolve(target, policy=policy, resolver=dns)
    print(f"  resolve   -> {len(addresses)} validated answer(s), after {dns.calls} lookup")
    for address in addresses:
        print(f"      {address}")
        print(f"          .ip       {address.ip}       (what the policy was asked about)")
        print(f"          .family   {address.family.name}")
        print(f"          .sockaddr {address.sockaddr}   (unmodified, so a v6 scope id survives)")
        print(f"          .hostname {address.hostname!r}  (what TLS must verify against)")

    sock = connect(addresses, policy=policy, timeout=5)
    try:
        print(f"  connect   -> socket to {sock.getpeername()}, {dns.calls} lookup in total")
        sock.sendall(b"GET / HTTP/1.0\r\nHost: cache.internal\r\n\r\n")
        first_line = sock.recv(64).split(b"\r\n", 1)[0]
        print(f"      spoke to it: {first_line!r}")
    finally:
        sock.close()


def what_the_pieces_refuse() -> None:
    """Show each function refusing what it is responsible for."""
    heading("Each piece refuses what it can see, and nothing it cannot")
    policy = Policy()

    try:
        policy.check_url("http://169.254.169.254/")
    except SSRFGuardError as refused:
        print(f"  check_url, literal address: {refused}")

    print("  check_url, a name:          permitted, because this layer resolves nothing")

    try:
        resolve(
            policy.check_url("http://metadata.google.internal/"),
            policy=policy,
            resolver=ScriptedResolver("169.254.169.254"),
        )
    except SSRFGuardError as refused:
        print(f"  resolve:                    {refused}")

    # connect re-checks every address it is handed, so there is no path through this package to
    # a socket that skipped the check. An optional security check is one somebody forgets.
    fabricated = (
        Address(
            family=socket.AF_INET,
            sockaddr=("169.254.169.254", 80),
            ip=__import__("ipaddress").ip_address("169.254.169.254"),
            hostname="metadata.google.internal",
        ),
    )
    try:
        connect(fabricated, policy=policy, timeout=1)
    except SSRFGuardError as refused:
        print(f"  connect, hand-built input:  {refused}")
    print("      that input never came from resolve, so it happening means the caller went")
    print("      around it, and that is exactly when a loud failure beats a quiet fallback.")


def tls_the_right_way(port: int) -> None:
    """Print the correct wrap call, with the reason the wrong one is worse than no guard.

    Args:
        port: The loopback port, named so the snippet is concrete.
    """
    heading("Wrapping it in TLS")
    print("  Connect to the address; verify the certificate against the name:")
    print()
    print("      context = ssl.create_default_context()")
    print("      addresses = resolve(target, policy=policy)")
    print("      raw = connect(addresses, policy=policy, timeout=10)")
    print("      tls = context.wrap_socket(raw, server_hostname=addresses[0].hostname)")
    print()
    print("  `server_hostname=addresses[0].hostname` is the whole of it. It is a name, so SNI")
    print("  is sent and the certificate is checked against it, while the socket underneath is")
    print("  already connected to a validated address.")
    print()
    print("  Passing the address instead is the failure this project most wants not to ship:")
    print("  RFC 6066 forbids an IP literal in server_name, so Python sends no SNI at all, and")
    print("  hostname verification has nothing to check. You would have traded an SSRF hole")
    print("  for an unauthenticated TLS connection, which is worse.")
    print()
    print(f"  (ssl.create_default_context() here would want a certificate for 127.0.0.1:{port},")
    print("  so the snippet is printed rather than run. The package's own suite runs the real")
    print("  thing against a loopback TLS server and reads the SNI off the wire.)")
    assert ssl.create_default_context().check_hostname is True


def main() -> None:
    """Run every section against one loopback server."""
    with loopback_server() as server:
        the_three_steps(server.port)
        what_the_pieces_refuse()
        tls_the_right_way(server.port)


if __name__ == "__main__":
    main()
