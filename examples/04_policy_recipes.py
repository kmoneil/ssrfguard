"""Six policies for six jobs, and what each one changes about what gets through.

Run it:

    python examples/04_policy_recipes.py

`Policy` is a frozen dataclass of twelve fields, every one of them a deny-by-default narrowing.
The defaults are what a webhook fetcher or a URL-preview service should want. Widening any of
them is a decision, and this file is the decisions worth knowing how to make.

Each recipe below is run against the same set of URLs, so the table shows the *difference* a
field makes rather than describing it.
"""

from __future__ import annotations

from _support import heading

from ssrfguard import Policy
from ssrfguard.errors import SSRFGuardError

#: How much of a refusal to print in the comparison table. The whole sentence is in
#: 02_what_a_refusal_says.py; here the point is which field decided, which is the front of it.
REASON_WIDTH = 70

#: The same probe set for every recipe, so the columns are comparable.
PROBES: tuple[str, ...] = (
    "https://api.example.com/v1/things",
    "http://api.example.com:8080/v1/things",
    "https://10.4.0.7/internal",
    "http://169.254.169.254/latest/meta-data/",
    # An example that shows credentials in an authority being refused has to contain
    # some. The marker travels with the line rather than with a line number in a
    # baseline file, which is the convention tests/test_adapter_parity.py already uses.
    "https://user:token@api.example.com/",  # pragma: allowlist secret
    "ws://api.example.com/socket",
)


def show(name: str, policy: Policy, why: str) -> None:
    """Run the probe set against one policy and print the verdicts.

    Args:
        name: The recipe's name.
        policy: The policy to exercise.
        why: One line on when to reach for it.
    """
    heading(name)
    print(f"  {why}")
    for url in PROBES:
        try:
            policy.check_url(url)
        except SSRFGuardError as refused:
            # Just the rule, not the whole sentence: this table is about which field decided.
            reason = str(refused).split(": ", 1)[-1]
            if len(reason) > REASON_WIDTH:
                reason = reason[: REASON_WIDTH - 1] + "..."
            print(f"    refused  {url:46}  {reason}")
        else:
            print(f"    allowed  {url}")


def main() -> None:
    """Print every recipe."""
    show(
        "The default: a webhook fetcher, a URL preview, an avatar importer",
        Policy(),
        "Anything reaching a URL a stranger typed. Change nothing until something breaks.",
    )

    show(
        "An internal-services fetcher",
        Policy(allowed_networks=["10.4.0.0/16"]),
        "allowed_networks beats the denied table, so this reaches one private range and no other.",
    )

    show(
        "A service that talks to a non-standard port",
        Policy(allowed_ports={80, 443, 8080}),
        "allowed_ports is a set, not a range. Add the port you need, not the block it is in.",
    )

    show(
        "A client that must carry credentials in the URL",
        Policy(allow_userinfo=True),
        "Off by default: they leak into logs and redirect chains, and 'trusted@evil' is old.",
    )

    show(
        "A websocket client",
        Policy(allowed_schemes={"http", "https", "ws", "wss"}),
        "ws and wss default to ports 80 and 443, so allowed_ports usually needs nothing.",
    )

    show(
        "Address filtering off, and said out loud",
        Policy(allowed_networks=["0.0.0.0/0", "::/0"]),
        "For a test harness. Scheme, port, userinfo and encoding checks all still run.",
    )

    heading("Fields that decide behaviour rather than admission")
    # These five do not change which URLs are accepted, so they do not show up in the table
    # above. They change what happens after one is.
    print("  on_partial_block        a name resolving to permitted AND denied addresses:")
    print("                          'reject' refuses the whole name (the default, because that")
    print("                          pattern is a rebinding signature); 'drop' keeps the good ones")
    print("  max_redirects           counted by this package, not by the client (default 5).")
    print("                          0 means a single redirect is refused, not 'do not follow'")
    print("  max_connection_attempts how many validated addresses to try (default 4). timeout is")
    print("                          per attempt, so this is what bounds a 200-answer name")
    print("  sensitive_headers       dropped when a redirect crosses origin. Default is the three")
    print("                          whose definition is credentials; add your own x-api-key")
    print("  allow_proxy             off, because a proxy resolves the target itself and pinning")
    print("                          cannot reach it. On means enforcement moved to the proxy")

    heading("A policy that cannot mean anything is refused at construction")
    # A typo in a configuration file should surface on start-up, not as a permit nobody noticed
    # or as a refusal on the first request of the week.
    for description, build in (
        ("empty allowed_ports", lambda: Policy(allowed_ports=frozenset())),
        ("negative max_redirects", lambda: Policy(max_redirects=-1)),
        ("on_partial_block='maybe'", lambda: Policy(on_partial_block="maybe")),  # type: ignore[arg-type]
        ("allowing a NAT64 prefix", lambda: Policy(allowed_networks=["64:ff9b::/96"])),
    ):
        try:
            build()
        except ValueError as refused:
            print(f"  {description:26} ValueError: {str(refused)[:96]}")


if __name__ == "__main__":
    main()
