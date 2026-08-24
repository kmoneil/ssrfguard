# Using the pieces directly

The three clients are assembled from three public functions. If you need to reach a Redis, a
Postgres, an SMTP server, a gRPC endpoint or anything else at a URL a stranger supplied, this is
the shape:

```python
from ssrfguard import Policy, connect, resolve

policy    = Policy(allowed_schemes={"redis"}, allowed_ports={6379})
target    = policy.check_url(url)                  # no I/O at all
addresses = resolve(target, policy=policy)         # exactly one lookup, every answer checked
sock      = connect(addresses, policy=policy, timeout=10)
```

**The signature is the argument.** `connect` takes a sequence of `Address`, and an `Address`
carries a socket address rather than a hostname, so there is nothing in scope for it to
re-resolve. That is a property of the types rather than a promise in a docstring.

[`examples/08_building_blocks.py`](../examples/08_building_blocks.py) runs all of this against a
loopback server and prints what each step hands to the next.

## Step 1: `policy.check_url(url) -> Target`

Everything decidable about a URL without touching the network: the scheme, the port, whether
credentials are riding in the authority, whether the host is well-formed, its length, whether it
contains a control character, and, when the host is a literal address rather than a name, whether
that address is permitted.

```python
>>> Policy().check_url("https://example.com/a/b?c=d")
<Target https host=example.com port=443>
```

A `Target` carries five things and no more:

| Attribute         |                                                                                                                                                    |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scheme`          | Lowercased, guaranteed to be in the policy's allowed set                                                                                           |
| `host`            | As the resolver will see it, an **A-label**, so an internationalised name arrives already punycoded. This is also the name TLS must verify against |
| `port`            | Explicit, or defaulted from the scheme                                                                                                             |
| `host_as_written` | The host exactly as supplied, before normalisation. Kept only so a refusal can quote what was typed. **Never use it to connect**                   |
| `address`         | The parsed address when the host was a literal one, otherwise `None`. `is_literal_address` is the predicate                                        |

The path, the query and the fragment are dropped on purpose. `__str__` and `__repr__` both render
a debug form rather than a URL, there is no `geturl`, no `__fspath__` and no `url` attribute, and
there will not be. Handing back a value an HTTP client would accept is the exact shape of every
advisory this package exists to answer.

## Step 2: `resolve(target, *, policy, resolver=None) -> tuple[Address, ...]`

Performs **one** lookup. The addresses returned are the addresses that were checked, and
`connect` uses them directly. There is no second resolution anywhere in this package, which is
the whole of its argument.

```python
>>> addresses = resolve(target, policy=policy)
>>> addresses
(Address(family=AF_INET, sockaddr=('93.184.216.34', 443), ip=..., hostname='example.com'),)
```

An `Address` carries:

| Attribute  |                                                                                                                                                                                                                 |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `family`   | `AF_INET` or `AF_INET6`                                                                                                                                                                                         |
| `sockaddr` | The tuple `getaddrinfo` produced, **unmodified**: two elements for IPv4, four for IPv6, where the third is the flow label and the fourth is the scope identifier. Passing anything else to `connect` loses them |
| `ip`       | The parsed address, which is what the policy was asked about                                                                                                                                                    |
| `hostname` | The name this answer came from, as an A-label. **This is what TLS must verify against**, and it is the reason an `Address` is not just an address                                                               |
| `port`     | A property reading the port out of the sockaddr                                                                                                                                                                 |

Returns every permitted answer, in the resolver's own order, and never an empty tuple. Raises
`BlockedAddressError` if no answer is permitted, or if the name resolves both ways while
`on_partial_block` is `"reject"`. A name that does not resolve raises `socket.gaierror`, **not
wrapped**, because a name that does not exist is not a policy decision.

A target carrying a literal address is not resolved at all. It is re-validated, because a
function that returns validated addresses must validate everything it returns, and the caller
should not have to know which path their target took.

### The timeout that does not exist

`socket.getaddrinfo` has no timeout and `socket.setdefaulttimeout` does not apply to it, so a
hostile authoritative server can stall this call for as long as it likes. On the synchronous path
that is a known denial-of-service surface, documented in `SECURITY.md` as out of scope, and it is
yours to supervise: a stalled call holds up the caller that made it and nobody else.

If you are on an event loop, do not call `resolve` on it. Run it in a worker thread with a bound
on how many can be in flight, which is what `ssrfguard.httpx.AsyncClient` does with
`resolver_slots`.

## Step 3: `connect(addresses, *, policy, ...) -> socket.socket`

Connects to the first reachable address among those validated, up to the attempt cap.

```python
sock = connect(
    addresses,
    policy=policy,           # required, not optional
    timeout=10,              # seconds PER ATTEMPT, not for the sequence
    source_address=None,     # local address to bind
    socket_options=None,     # setsockopt arguments applied to every attempt
)
```

`policy` is **required**, so that there is no path through this package to a socket that skipped
the check. An optional security check is a security check somebody forgets. Every address is
re-checked here, even though `resolve` already checked them, and a refusal at this point means
the caller assembled the sequence some other way.

`timeout` is per attempt, so the whole call is bounded by
`timeout * policy.max_connection_attempts`. That is the reason the cap exists; see
[the attempt cap](policy.md#the-attempt-cap).

The returned socket's peer has been confirmed to be the address that was validated.

## Wrapping it in TLS

If you wrap the socket, the certificate has to be verified against `address.hostname`, and never
against the address you connected to:

```python
import ssl

context   = ssl.create_default_context()
addresses = resolve(target, policy=policy)
raw       = connect(addresses, policy=policy, timeout=10)
tls       = context.wrap_socket(raw, server_hostname=addresses[0].hostname)
```

`server_hostname=addresses[0].hostname` is the whole of it. It is a name, so SNI is sent and the
certificate is checked against it, while the socket underneath is already connected to a
validated address.

**Passing the address instead is the failure this project most wants not to ship.** RFC 6066 does
not permit an IP literal in the `server_name` extension, so Python sends no SNI at all and
hostname verification has nothing to check. You would have traded an SSRF hole for an
unauthenticated TLS connection, which is worse than the hole.

If you connected to `addresses[n]` rather than `addresses[0]`, use that one's `hostname`. They
are all the same name for a single `resolve`, which is why the snippet above is safe as written.

## A worked example: a Redis URL from a user

```python
from ssrfguard import Policy, SSRFGuardError, connect, resolve

REDIS = Policy(
    allowed_schemes={"redis", "rediss"},
    allowed_ports={6379},
    allowed_networks=["10.20.0.0/16"],   # our cache subnet, and nothing else
)

def open_redis(url: str) -> socket.socket:
    """Open a socket to a user-supplied Redis URL, or refuse it."""
    target = REDIS.check_url(url)
    addresses = resolve(target, policy=REDIS)
    return connect(addresses, policy=REDIS, timeout=5)
```

`redis://127.0.0.1:6379/`, `redis://169.254.169.254:6379/`, `http://cache.internal:6379/` and
`redis://cache.internal:22/` are all refused, each naming the field that refused it. A name
inside `10.20.0.0/16` is permitted, resolved once, and connected to.

## What you are responsible for

Using the pieces directly means the seam is yours, so three things that a client does for you
become yours to do:

1. **TLS**, as above. This is the one that matters.
2. **Re-validating on a new connection.** The guarantee is per-connection. If you pool the
   socket, that pool's lifetime is how long the validation holds, and the next connection has to
   go back through `resolve`.
3. **Redirects, if your protocol has them.** `max_redirects` and `sensitive_headers` are policy
   fields that nothing enforces unless something enforces them; the clients do it, and a hand-
   rolled loop does not.

If your protocol is HTTP, use a client instead. That is what they are for.
