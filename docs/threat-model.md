# Threat model

**This is not an audit, and it does not claim to be one.** ssrfguard has had no independent
security review. What follows is the thing an audit would start from: what an attacker controls,
what each control does about it, the evidence you can run yourself, and, at the end and in
detail, what is still not defended.

The last section is the point. A threat model that lists only what a package stops is marketing
with a table in it.

Written against **0.1.0**. `SECURITY.md` carries the reporting process and the scope of what we
will treat as a vulnerability; this carries the reasoning behind it.

## The asset

A server-side fetcher is a request the attacker did not have to be authorised to make. It runs
inside the trust boundary, so what it can reach is the network the application can reach:

- **Cloud instance metadata.** `169.254.169.254` and its IPv6 and vendor-specific variants, which
  return credentials to anything that asks from the right network position.
- **Internal services with no authentication**, because they were only ever reachable from
  inside: admin panels, message queues, databases, Kubernetes and Docker APIs, `localhost`
  debug endpoints.
- **The loopback interface of the process itself**, which is frequently the most privileged
  network position in the system.

The attacker does not need a response body. A request that arrives is often enough, and a timing
difference is a port scan.

## What the attacker controls

Everything in this list is assumed fully attacker-controlled. The model is not "some of this
might be hostile"; it is that all of it is.

| Surface | What that means in practice |
| --- | --- |
| **The URL** | Scheme, credentials in the authority, host in any encoding, port, path, length |
| **The authoritative nameserver for their own domain** | Every answer, its TTL, and **whether the answer changes between two lookups** |
| **The redirect chain** | Any number of hops, to any origin, with any `Location` |
| **The TLS certificate their own host presents** | Including a valid one for a name they own |
| **Timing** | How long their server takes to answer, or whether it answers at all |

What the attacker does **not** control: the policy, the address table, the client library, and
the code that calls this package. Those are trusted inputs. A caller who passes
`allowed_networks=("0.0.0.0/0",)` has made an authorisation decision, and this package will
honour it.

## Trust boundaries

There are four, and three of them are crossed more than once per request.

1. **Untrusted text becomes a decision.** `Policy.check_url()` takes a string and returns a
   `Target`. Everything decidable without the network is decided here: scheme, port, credentials,
   host shape, length. The return type is an origin and not a URL, deliberately: it has no path,
   no query and no `geturl`, so a checked URL cannot be reassembled and handed onward as though
   the check travelled with it.
2. **A name becomes addresses.** `resolve()` performs **exactly one** lookup and validates every
   answer. This is the boundary the entire package exists for, and the one every other guard in
   the category crosses twice.
3. **Addresses become a socket.** `connect()` re-checks every address it was given, connects to
   the `sockaddr` the resolver produced, and then asks the socket where it actually landed.
4. **A response becomes a new request.** Every redirect hop re-enters boundary 1, counted by the
   policy rather than by the client.

## Capabilities, and what each meets

Organised by what the attacker does rather than by what we prevent, because that is the order
they arrive in.

| The attacker … | What meets it | Evidence you can run |
| --- | --- | --- |
| Points a name at `169.254.169.254` | The address table refuses the address after resolution, naming the block and its RFC | `tests/test_registry.py`, `tests/test_address_table.py` |
| Writes the address so string matching misses it: `0177.0.0.1`, `2130706433`, `127.1`, `0x7f.0.0.1`, circled digits, a trailing dot, `localhost。` | Nothing here matches strings. Digits-and-dots that is not an address is refused by shape; everything else is decoded by the resolver and refused as an address | `tests/test_encodings.py`, thirteen forms, each refused at both layers |
| Wraps the address in a translation prefix: NAT64, 6to4, Teredo, IPv4-mapped | The payload is unwrapped and re-checked, and the refusal names every hop walked to reach it | `tests/test_address_table.py`, `64:ff9b::7f00:1` refused as loopback |
| **Moves the DNS record between the validation call and the connect call** | One lookup. The connection is made to the address that was validated, never to the name | `tests/test_rebinding.py`, against a real nameserver on a real UDP socket that changes its answers mid-request |
| Moves the record to another **permitted** address, so re-validation would not notice | Same control. This is what separates pinning from checking twice, and the fixture proves the difference | `test_pinning_is_not_merely_preferring_a_public_address` |
| Answers differently on **every** query | Same control, and the fixture answers from a sequence rather than a pair to prove it | `test_a_nameserver_that_flips_on_every_query_cannot_move_the_connection` |
| Returns one public and one private address for the same name | The whole name is refused. A partial answer is not a partial permission | `test_a_name_resolving_both_ways_is_refused_whole` |
| Redirects to an internal host after the first hop passes | Every hop is checked as a new URL, and the count is the policy's rather than the client's | `tests/test_adapter_redirects.py`, all three surfaces |
| Redirects cross-origin to collect the `Authorization` header | Sensitive headers are dropped when the origin changes | `test_a_cross_origin_hop_drops_the_policys_sensitive_headers` |
| Hopes the pin loosened certificate checking | TLS carries the **hostname** as `server_hostname`, never the pinned address. Passing an address there silently disables hostname verification, so this is the assertion that may never fail | `test_the_handshake_carries_the_hostname_and_never_the_address`, read off the wire from a server-side SNI callback |
| Hopes a pooled second request skips the check | A pooled request resolves nothing and is still checked per request | `test_a_pooled_second_request_asks_nothing` |
| Hopes something between the process and the network rewrites the destination | After connecting, the socket is asked where it landed, and a mismatch is refused | `_verify_peer`, `tests/test_connect.py` |
| Supplies a `file://`, `gopher://` or `ftp://` URL, or a Unix socket | Refused by scheme, and a Unix socket is refused outright because it has no address to check | `tests/test_policy_urls.py`, `tests/test_adapter_construction.py` |
| Supplies credentials in the authority | Refused. An authority carrying a username and password is a credential-leak shape rather than a fetch | `tests/test_policy_urls.py` |
| Makes the guard expensive: an 8 KiB URL of non-ASCII labels | A host longer than DNS can carry is refused **before** normalisation, and a ratio gate holds the idna path within a bounded multiple of the ASCII one | `tests/test_cost.py`, two clock-free assertions and one ratio |
| Opens many connections at once | The pinning pool is bounded exactly as httpx's own is, 100 connections and 20 keepalive | `test_regression_unbounded_pool_a_guarded_transport_is_bounded_like_an_unguarded_one` |

## What the defaults refuse

A `Policy()` with nothing configured, which is what a caller who has not thought about it gets:

| Field | Default | Meaning |
| --- | --- | --- |
| `allowed_schemes` | `http`, `https` | Everything else refused |
| `allowed_ports` | `80`, `443` | A port scan needs ports |
| `allow_proxy` | `False` | See the residual risk below |
| `max_redirects` | `5` | Counted by the policy |
| `max_url_length` | `8192` | Bounds what any scan reads |
| `max_connection_attempts` | `4` | Bounds a name answering with two hundred addresses that all drop packets |
| denied networks | **60 rows**, transcribed from the IANA IPv4 and IPv6 special-purpose registries, snapshot `2026-08-22`, plus four blocks the registries do not carry | Longest prefix wins |

## Residual risk

**The honest section.** Everything here is either not defended, defended less than it looks, or
true only on some platforms. None of it is a secret; most of it is stated somewhere else in this
repository, and the value of this list is that it is in one place.

### Not defended, by design

- **No independent audit.** Nobody outside this project has reviewed the code. The evidence below
  is reproducible, which is not the same thing as reviewed.
- **This is not an egress control.** It guards requests made through its own clients. Anything
  else in the process, a subprocess, a C extension, another HTTP library, reaches the network
  untouched. A control at the network layer is a different tool and this does not replace it.
- **Application logic that builds the URL.** If a program interpolates attacker input into a
  path and produces a URL that was never meant to exist, this package will faithfully guard the
  URL it was given.
- **A host you allowed, behaving badly within its own rights.** Adding a network to
  `allowed_networks` is an authorisation decision, and it is honoured.
- **No application-layer inspection.** Once a permitted host is reached, what travels over that
  connection is not examined.

### Defended less than it looks

- **`allow_proxy=True` steps back deliberately, and it is a real blind spot.** A proxy resolves
  the target itself and opens the socket to it, so nothing this package does can reach that
  decision. With the flag on, the guard checks the *proxy* and not the target. It is off by
  default, and turning it on is a decision to trust the proxy instead. Saying so beats leaving a
  caller believing in a control that stopped running.
- **DNS resolution time is unbounded with the default resolver.** `socket.getaddrinfo` takes no
  timeout, so a hostile authoritative server can hold a request for as long as the resolver's own
  configuration allows. **`ssrfguard.resolvers.UdpResolver` bounds it** and is one constructor
  argument away; it is not the default because the platform's resolver knows `/etc/hosts`,
  `nsswitch.conf` and search domains, and this one does not. See
  [Resolvers](resolvers.md).
- **The asynchronous path bounds the blast radius rather than the stall.** Resolution runs in a
  worker thread so a slow lookup cannot freeze the event loop, but a thread blocked in
  `getaddrinfo` cannot be cancelled. Held lookups accumulate until the client's `resolver_slots`
  are gone, and past that a new *name* waits. Connections already open are unaffected. A held
  lookup blocking a request over an already-open connection would be a finding.

  **With `UdpResolver` the hold is bounded rather than removed.** The thread is released at its
  deadline instead of at the platform's discretion, so the accumulation has a ceiling. It still
  cannot be cancelled, because the client offloads a synchronous call rather than awaiting an
  asynchronous one; that is a change to the client and is not made.
- **The address table is a transcription with a date on it.** IANA moves; the `egress` lane
  re-fetches the registries and compares them to the committed table as values, so a registry
  that moved is a failing test. Between runs, the table is as fresh as its snapshot.

### Platform-dependent

- **`0177.0.0.1` is refused twice on Linux and once on macOS.** glibc reads the leading zero as
  octal, so the form decodes to `127.0.0.1` and the address table refuses it. macOS strips the
  zero and reads decimal, reaching `177.0.0.1`, a public address with nothing wrong with it and
  nothing for the table to refuse. **The shape rule still refuses it before anything is looked
  up, on every platform**, so this is one defence rather than two rather than none.
  `PLATFORM_DECODES` in `tests/test_encodings.py` records the difference as data and asserts
  whichever direction the platform actually goes.

### Where the tests would not notice

The suite is held against a **mutation register**: `mutmut` rewrites the source in 969 ways and
the suite must notice. As of `2026-08-24`, **140 mutants survive across 29 functions**, and the
register records exactly which change each one made. A survivor is a place where the code could
be subtly wrong and no test would fail.

The concentration matters more than the number. `_policy.py`, which decides everything about a
URL, has **zero**. The clusters are in adapter plumbing: `requests._pinned_socket` at 25,
`Session.resolve_redirects` at 13, and `_registry._b` at 12, the last of which is table
construction where many mutants are likely equivalent. `scripts/mutation_register.json` is the
list; `python scripts/lanes.py mutation` regenerates and gates on it.

Coverage is 100% of lines and branches and that is **not** the same claim. The unbounded-pool
defect fixed in 0.1.0 sat at full branch coverage on a line every test executed; it took asking
whether the suite would notice the value being wrong.

## Reproducing all of it

Nothing above asks to be taken on trust. From a clone:

```console
uv sync --frozen --all-extras
python scripts/lanes.py                  # every lane, what it checks, whether it gates
python scripts/lanes.py rebind           # the central claim, against a real nameserver
python scripts/lanes.py egress           # the seams against a real server, and IANA freshness
python scripts/lanes.py mutation         # the survivors, against the committed register
python scripts/lanes.py cost             # what one URL costs
```

Ten of the eleven lanes gate; `cost` reports and says why. `examples/03_the_pin.py` scripts a
nameserver that answers honestly once and then moves the record to the metadata endpoint, and
prints the lookup count that gives the seam away.

## What an audit would add that this cannot

This document is written by the people who wrote the code, which is its central weakness. An
independent review would bring the things a self-assessment structurally cannot:

- **Attacks nobody here thought of.** Every table above is bounded by one team's imagination.
  The tests prove the listed properties hold; they say nothing about properties nobody listed.
- **Adversarial review of the seams**, particularly the two integration points with httpx and
  requests, where the assumption "this is where the socket comes from" is load-bearing and is
  ours rather than theirs.
- **Judgement on the residual risks above**, several of which are trade-offs we made and graded
  ourselves.

The position today is the one the nearest competitor states about itself, and stating it
honestly is the minimum. Getting it reviewed is the actual answer, and it is worth doing once
the API stops moving.

---

Reporting: [`SECURITY.md`](../SECURITY.md). Why the design is shaped this way:
[Why this exists](architecture.md). What is in the table and why:
[The address table](address-table.md).
