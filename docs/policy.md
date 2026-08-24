# Configuring a policy

`Policy` is a frozen dataclass of twelve fields. Every one is a deny-by-default narrowing, and
the defaults are what a service fetching a URL a stranger supplied should want.

```python
from ssrfguard import Policy

policy = Policy()                                   # the defaults, and usually the answer
policy = Policy(allowed_networks=["10.4.0.0/16"])   # one deliberate widening
```

It is frozen, so a policy cannot be mutated after a client is built with it. To vary one field,
build a second policy; `dataclasses.replace` works.

Every refusal names the field that refused, so when something breaks you can usually go straight
to the row below rather than reading the whole page.

## The fields

| Field                     | Default                                              | What it decides                                                                   |
| ------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------- |
| `allowed_schemes`         | `{"http", "https"}`                                  | Which schemes a URL may use                                                       |
| `denied_networks`         | `DEFAULT_DENIED`                                     | The address table. See [The address table](address-table.md)                      |
| `allowed_networks`        | `()`                                                 | Networks permitted even when the table denies them. **Explicit allow beats deny** |
| `allowed_ports`           | `{80, 443}`                                          | Which ports a URL may name                                                        |
| `allowed_hosts`           | `frozenset()`                                        | Which hosts a URL may name. Empty means no name restriction                       |
| `allow_userinfo`          | `False`                                              | Whether credentials may ride in the authority                                     |
| `on_partial_block`        | `"reject"`                                           | What to do when a name resolves both ways                                         |
| `max_redirects`           | `5`                                                  | How many hops a chain may take                                                    |
| `max_connection_attempts` | `4`                                                  | How many validated addresses to try                                               |
| `sensitive_headers`       | `{"authorization", "proxy-authorization", "cookie"}` | Dropped when a redirect crosses origin                                            |
| `allow_proxy`             | `False`                                              | Whether to proceed when a proxy is configured                                     |
| `max_url_length`          | `8192`                                               | How long a URL may be before it is refused unread                                 |

[`examples/04_policy_recipes.py`](../examples/04_policy_recipes.py) runs six of these against one
probe set, so you can see the difference a field makes rather than read a description of it.

## Reaching your own internal services

This is the common one. `allowed_networks` beats the denied table, so it is how an
internal-services fetcher reaches the internal services it is meant to:

```python
Policy(allowed_networks=["10.4.0.0/16"])
```

That permits one private range. `10.5.0.0/16`, `127.0.0.1` and the metadata endpoint stay
refused, which is the point of naming a range rather than switching the table off.

Two consequences of _beats_ are worth knowing before you write an entry, because neither is
visible from the field name.

**An entry inside a translation prefix is refused at construction.** `64:ff9b::/96` reads as
"let NAT64 through" and would mean "let anything through": it covers `64:ff9b::7f00:1` and
`64:ff9b::a9fe:a9fe`, which are loopback and the metadata endpoint behind a NAT64 gateway, and
the allowlist is consulted before the table gets a chance to decode them.

```python
>>> Policy(allowed_networks=["64:ff9b::/96"])
ValueError: allowed_networks contains 64:ff9b::/96, which overlaps 64:ff9b::/96
(IPv4-IPv6 Translation, RFC6052), a prefix that carries an IPv4 destination inside it. ...
To reach specific internal hosts, allow the embedded IPv4 range instead; to turn address
filtering off, pass a denied_networks table that says so ...
```

An entry that merely _contains_ a translation prefix, such as `::/0`, is honoured: at that
breadth the caller asked for everything and is entitled to get it.

**An entry does not carry across address families.** `10.0.0.0/8` does not permit
`::ffff:10.0.0.1`, because the check compares versions and the mapped form is version 6. That
direction over-denies, so it stands; if you want the mapped form, say so.

## Reaching only what you meant to

`allowed_networks` widens what a policy may reach. `allowed_hosts` narrows it, and is the
strongest control here: a fetcher that is only ever meant to talk to two APIs can say so.

```python
Policy(allowed_hosts={"api.stripe.com", "*.githubusercontent.com"})
```

Empty by default, and empty means no name restriction, so adding the field is the only thing
that changes anything.

| Entry | Matches | Does not match |
| --- | --- | --- |
| `api.stripe.com` | `api.stripe.com`, and the absolute form `api.stripe.com.` | `x.api.stripe.com`, `notapi.stripe.com` |
| `*.githubusercontent.com` | `raw.githubusercontent.com`, `a.b.githubusercontent.com` | `githubusercontent.com`, `evil-githubusercontent.com` |

**A bare entry is exact and does not carry its subdomains.** A caller who wants both writes both.
Guessing which was meant is how a widening ships by accident.

**`*` is only meaningful as the whole of the leftmost label**, and anything else is refused at
construction rather than quietly ignored:

```python
Policy(allowed_hosts={"api.*.stripe.com"})   # ValueError
Policy(allowed_hosts={"*"})                  # ValueError: leave allowed_hosts empty instead
```

**A literal address is not a host pattern.** With `allowed_hosts` set, `https://93.184.216.34/`
is refused unless that address is listed verbatim, and a wildcard never matches one. Otherwise
the list would read as a restriction and not be one.

### Why an allowlist by name is safe where a denylist by name would not be

This package denies *addresses* and never names, on purpose: a name denial is a string match, and
`metadata.google.internal.` with a trailing dot, `METADATA.GOOGLE.INTERNAL`, an IDN homograph or
a `CNAME` that resolves there without carrying the name all defeat the string while none of them
defeats the address check. See [the address table](address-table.md).

**Allowlisting inverts every term of that.** An attacker has to *match* the string rather than
evade it; evasion means refusal; and matching buys only the right to be resolved and then checked
against the address table like any other host. There is no permit to spoof into. The spellings
that defeat a denylist are folded here rather than exploited: case, the absolute form, and IDN
are all normalised on both the entry and the host, so `API.STRIPE.COM.` matches
`api.stripe.com` and an entry may be written in the script you read rather than in punycode.

**Matching is on label boundaries and never a suffix test.** `"evil-github.com".endswith(
"github.com")` is `True`, which is the single line that would turn this feature into a way in.
`tests/test_policy_hosts.py` carries a corpus of hosts that nearly match a listed entry, and a
property test asserting that anything permitted is either exactly a listed name or a proper
subdomain of a listed wildcard.

**A refusal names the entry it nearly matched**, because the first mistake anybody makes is
listing `example.com` and then fetching `api.example.com`:

```
BlockedURLError: 'https://x.api.stripe.com/' is not permitted: host 'x.api.stripe.com' is not in
allowed_hosts, which lists ['*.githubusercontent.com', 'api.stripe.com']; the nearest entry is
'api.stripe.com'
```

## Turning address filtering off

If what you actually want is "no address filtering", say that with an empty table rather than a
wide `allowed_networks` entry:

```python
from ssrfguard import AddressTable, Policy

Policy(denied_networks=AddressTable(blocks=()))
```

Every other check still runs: scheme, port, credentials, control characters, encoded hosts,
length. This is a reasonable thing to want for a test harness pointed at loopback. It is not a
reasonable thing to want in production, and it is spelled out here so that it reads as the
decision it is.

## When a name resolves both ways

`on_partial_block` decides what happens when one name answers with both permitted and denied
addresses.

```python
Policy(on_partial_block="reject")   # default: refuse the whole name
Policy(on_partial_block="drop")     # keep only the permitted answers
```

`"reject"` is the default because **that pattern is the signature of a rebinding attempt rather
than of a misconfiguration.** A name that answers `93.184.216.34` and `169.254.169.254` in the
same response is not a mistake somebody made.

The refusal says so, and names the escape hatch:

```
both.example is not permitted: resolves to both permitted and denied addresses;
permitted: 93.184.216.34; denied: 169.254.169.254 (169.254.169.254/32 is Cloud metadata ...).
A name that resolves both ways is the signature of a DNS rebinding attempt rather than of a
misconfiguration, so on_partial_block='reject' refuses the whole name. Set
on_partial_block='drop' to use only the permitted answers, which is safe only if you know
this name
```

`"drop"` is safe only if you know the name. A dual-stack host in your own infrastructure whose
IPv6 answer is unique-local is the legitimate case.

## Redirects

`max_redirects` is counted **by this package rather than by the HTTP client.** The client's own
limit exists to stop loops, is an order of magnitude larger, and can be changed without touching
the policy, which is what makes it not a security control.

`0` means **a redirect is refused**, not "redirects are not followed", and the difference shows
at the boundary: a single `302` raises `TooManyRedirectsError` even when following is switched
off at the client, because both clients build the next request in order to expose it and the cap
fires on the build.

- To **receive** a redirect without following it: leave `max_redirects` alone, pass
  `follow_redirects=False` at the call.
- To **refuse** one: `max_redirects=0`.

Every hop gets a full policy evaluation, so a `302` to the metadata endpoint is refused at the
hop and the message names the hop rather than the URL you asked for.

## Credentials on a redirect

`sensitive_headers` are dropped when a hop crosses to another origin. The default is the three
whose _definition_ is credentials. A header like `x-api-key` is a naming convention rather than
a specification, so you name it:

```python
Policy(sensitive_headers={"authorization", "proxy-authorization", "cookie", "x-api-key"})
```

An upgrade from `http` to `https` on the same host is not a crossing, which is what both clients
already do for `Authorization` and is not worth differing from.
[`examples/07_redirects.py`](../examples/07_redirects.py) measures which headers actually arrive
at the second origin.

## The attempt cap

`max_connection_attempts` bounds how many of a name's validated addresses are tried before
giving up. It exists because **`timeout` is per attempt and the answer count is not yours to
choose.**

A name whose authoritative server returns two hundred addresses, every one permitted and every
one silently dropping packets, costs two hundred times the timeout you asked for: one request,
one held worker, no log line that reads as an attack. Four keeps the dual-stack failover that is
the reason for trying more than one at all, and bounds the cost at four times what was asked
for.

## Proxies

`allow_proxy` is off, and the refusal explains itself:

```
a proxy is configured (http://proxy.internal:3128) and it resolves the target itself, so the
validated address cannot be pinned; set allow_proxy=True to accept that enforcement has moved
to the proxy
```

When a client connects through a proxy, the proxy performs the DNS lookup and opens the socket.
Pinning happens in your process and the proxy is not in it. Refusing is the honest answer:
silently passing the request through would leave you believing in a control that is no longer
running, which is worse than having no control at all.

This fires for `HTTP_PROXY` and `HTTPS_PROXY` in the environment as well as for an explicit
`proxy=` or `proxies=`. If your deployment genuinely routes through a proxy that does its own
egress filtering, `allow_proxy=True` says that out loud.

## URL length

`max_url_length` is checked first, before anything that scans the string. **It is a ceiling, not
a ReDoS fix.** `check_url` is strictly linear on both paths, and the hostname pattern cannot
backtrack because every repetition in it must consume a literal dot. What it did not have was a
bound.

8192 because that is where nginx, Apache and IIS converge for a request line, which is a number
you can recognise rather than one this package invented.

It is one of two ceilings and it is not the one that bounds the cost. The host is capped
separately at the 253 characters DNS can carry, before normalisation, and that one is not
configurable because a longer name cannot resolve on any resolver. [What it costs](cost.md) has
the measurements.

## A policy that cannot mean anything is refused at construction

A typo in a configuration file should surface on start-up, not as a permit nobody noticed or as
a refusal on the first request of the week.

```python
Policy(allowed_ports=frozenset())      # ValueError: allowed_ports is empty, so no URL can ever
                                       # be permitted
Policy(allowed_schemes=frozenset())    # ValueError: allowed_schemes is empty, ...
Policy(max_redirects=-1)               # ValueError: max_redirects must not be negative
Policy(max_connection_attempts=0)      # ValueError: ... a policy that permits no attempt can
                                       # never connect to anything
Policy(on_partial_block="maybe")       # ValueError: must be 'reject' or 'drop'
Policy(allowed_networks=["nonsense"])  # ValueError, from ip_network
```

Schemes and header names are lowercased for you; `allowed_networks` accepts CIDR strings or
already-parsed `ip_network` objects.

## Checking a URL without making a request

Both halves of the policy layer are public, and neither performs any I/O:

```python
policy.check_url(url)          # -> Target, or raises
policy.check_address(address)  # -> None, or raises
policy.permits_address(ip)     # -> bool, for when a refusal is an expected outcome
```

`check_url` is the whole URL question: scheme, port, credentials, control characters, encoded
hosts, length, and, when the host is a literal address, the address itself. It never resolves
anything, so a hostname always survives it. See
[Using the pieces directly](building-blocks.md) for what to do with the result.
