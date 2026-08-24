"""The address table: what it denies, how it decodes a wrapper, and how to replace it.

Run it:

    python examples/09_address_table.py

`DEFAULT_DENIED` is generated from the IANA special-purpose address registries, refreshed by a
script and reviewed as a change to what this package refuses. It is not a hand-written list of
"private ranges", and the difference shows up in three places this example walks through.

**Longest prefix wins**, the way a routing table works, so a specific row can permit something
inside a denied one.

**A wrapper is decoded rather than answered about.** `::ffff:169.254.169.254` is not "an IPv6
address that is probably fine"; it is the metadata endpoint with four extra colons. The table
decodes it and asks the question again about what came out, and the verdict carries the chain it
walked.

**A handful of blocks are marked reachable on purpose.** IANA marks some special-purpose blocks
globally reachable, such as public anycast services, AS112 and AMT. Refusing those would be a
denial with no security benefit behind it, and a guard with false positives gets removed.
"""

from __future__ import annotations

from _support import heading

from ssrfguard import DEFAULT_DENIED, REGISTRY_SNAPSHOT, AddressTable, Block, Policy, Reach


def what_is_in_it() -> None:
    """Summarise the shipped table."""
    heading("The shipped table")
    print(f"  {DEFAULT_DENIED!r}")
    print(f"  generated from the IANA registries fetched {REGISTRY_SNAPSHOT}")
    counts = dict.fromkeys(Reach, 0)
    for block in DEFAULT_DENIED.blocks:
        counts[block.reach] += 1
    for reach, count in counts.items():
        print(f"    {reach.value:11} {count:3} rows")
    print()
    print("  A row is a network, IANA's name for it, the RFC that defines it, and what this")
    print("  table says about it. The name and the RFC are not decoration: they are what the")
    print("  refusal message quotes, and a refusal a user cannot act on gets configured around.")


def verdicts() -> None:
    """Classify a spread of addresses and print what the table said and why."""
    heading("Classifying addresses")
    probes = (
        ("93.184.216.34", "an ordinary public address"),
        ("8.8.8.8", "a public resolver"),
        ("127.0.0.1", "loopback"),
        ("10.1.2.3", "RFC 1918"),
        ("169.254.169.254", "the endpoint every advisory names"),
        ("100.64.1.1", "carrier-grade NAT, which people forget"),
        ("198.18.0.1", "benchmarking, which routes nowhere useful"),
        ("::1", "loopback again"),
        ("fd00::1", "unique-local"),
        ("fe80::1", "link-local"),
        ("2001:4860:4860::8888", "a public v6 resolver"),
        ("192.0.0.9", "PCP anycast: denied block, permitted row"),
    )
    for text, note in probes:
        verdict = DEFAULT_DENIED.classify(text)
        mark = "DENY " if verdict.blocked else "allow"
        print(f"  {mark} {text:22} {note}")
        if verdict.blocked:
            print(f"        {verdict.reason}")


def decoding() -> None:
    """Show the wrappers, which is the part a hand-written list gets wrong."""
    heading("Wrappers are decoded, and the chain is in the verdict")
    wrapped = (
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b::7f00:1",
        "2002:7f00:1::",
    )
    for text in wrapped:
        verdict = DEFAULT_DENIED.classify(text)
        print(f"  {'DENY ' if verdict.blocked else 'allow'} {text}")
        for block, inner in verdict.chain:
            print(f"        decoded through {block.name} {block.network} -> {inner}")
        if verdict.blocked:
            print(f"        {verdict.reason}")
    print()
    print("  A string comparison against '169.254.' catches none of these. A parsed address")
    print("  and a table that decodes catches all of them, which is why the check is")
    print("  structural rather than a pattern.")


def longest_prefix() -> None:
    """Demonstrate the routing-table rule with a row that permits inside a denial."""
    heading("Longest prefix wins, so a specific row can permit inside a denied one")
    for text in ("192.0.0.1", "192.0.0.9", "192.0.0.10", "192.0.0.171"):
        verdict = DEFAULT_DENIED.classify(text)
        match = DEFAULT_DENIED.match(__import__("ipaddress").ip_address(text))
        deciding = f"{match.network} ({match.name}, {match.reach.value})" if match else "no row"
        print(f"  {'DENY ' if verdict.blocked else 'allow'} {text:14} decided by {deciding}")
    print()
    print("  192.0.0.0/24 is denied as IETF Protocol Assignments. Three /32s inside it are")
    print("  anycast services IANA marks globally reachable, and they are permitted, because")
    print("  refusing a public anycast address protects nothing and breaks something.")


def customising() -> None:
    """Build tables of your own, from the shipped one and from scratch."""
    heading("Building a table of your own")

    # Adding a row: your own network you never want reached, on top of the shipped rows.
    extra = Block(
        network=__import__("ipaddress").ip_network("192.30.252.0/22"),
        name="Our own build fleet",
        rfc="internal policy",
        reach=Reach.DENIED,
    )
    with_extra = AddressTable(blocks=(*DEFAULT_DENIED.blocks, extra))
    print(f"  extended: {with_extra!r}")
    print(f"    192.30.252.7 -> {with_extra.classify('192.30.252.7').reason}")

    # An empty table denies nothing. Every other check in the policy still runs, which is why
    # this is a coherent thing to want for a test harness rather than a way to switch the
    # package off.
    permissive = AddressTable(blocks=())
    print(f"  empty:    {permissive!r}")
    print(f"    127.0.0.1 blocked? {permissive.classify('127.0.0.1').blocked}")

    policy = Policy(denied_networks=permissive)
    print("    Policy(denied_networks=<empty>).check_url('http://127.0.0.1/') ->")
    print(f"      {policy.check_url('http://127.0.0.1/')}")
    print()
    print("  Prefer this to a wide allowed_networks entry when the intent is 'no address")
    print("  filtering'. The refusal for allowing a NAT64 prefix says so in as many words:")
    print("  to turn address filtering off, pass a table that says so.")

    heading("Why allowed_networks cannot be handed a translation prefix")
    # allowed_networks is consulted before the table gets to decode, so an entry inside a
    # wrapper permits everything embedded in it. Refused at construction rather than at the
    # address that needed it, so a typo surfaces on start-up.
    try:
        Policy(allowed_networks=["64:ff9b::/96"])
    except ValueError as refused:
        for line in str(refused).split(". "):
            print(f"  {line.strip()}")


def main() -> None:
    """Print every section."""
    what_is_in_it()
    verdicts()
    decoding()
    longest_prefix()
    customising()


if __name__ == "__main__":
    main()
