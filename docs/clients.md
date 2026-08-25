# The clients

Three surfaces, one guarantee:

```python
from ssrfguard.httpx import Client, AsyncClient    # needs ssrfguard[httpx]
from ssrfguard.requests import Session             # needs ssrfguard[requests]
```

Each is an ordinary client of its library. `Client` subclasses `httpx.Client`, `AsyncClient`
subclasses `httpx.AsyncClient`, `Session` subclasses `requests.Session`. Everything you already
know still works: verbs, headers, auth, timeouts, streaming, hooks, `follow_redirects`, pooling.

**The pinning lives at the connection seam**, which is why that matters. Redirects, retries and
pool refills all go through the same code path whether or not anyone remembered they would.

## Why these are clients and not just transports

You can build the transport yourself, and `SafeTransport`, `AsyncSafeTransport`, `SafeBackend`
and `SafeAdapter` are all public. For httpx you should not, and the reason is measured rather
than stylistic.

`httpx.Client(transport=SafeTransport(...))` does neutralise `HTTP_PROXY`, because httpx computes
`allow_env_proxies = trust_env and transport is None`. But an explicit `proxy=` or `mounts=`
builds a **separate** transport that `_transport_for_url` prefers, and the request never reaches
the guarded one. A class that owns its own construction is the only place that can be refused,
so `ssrfguard.httpx.Client` refuses it.

The same class closes a quieter trap. `verify`, `cert`, `http1`, `http2` and `limits` configure
the transport httpx _would have built_, so passing them to a client that was given a transport
does nothing, silently. For `verify` that means believing you configured certificate
verification when you did not. `Client` routes each of them to whichever object actually
configures it.

For `requests` the situation is reversed: requests hands the adapter the merged proxy mapping,
so a bare `SafeAdapter` can refuse a proxy on its own. `Session` still exists because of the
mounting problem below.

### What a backend decides on its own

If you do assemble a pool around `SafeBackend` or `AsyncSafeBackend`, it is worth knowing exactly
what you are and are not getting, because a backend is handed a host and a port and never sees a
URL.

| Decided at the backend | Only decided by a client or transport |
| ---------------------- | ------------------------------------- |
| `allowed_ports`        | `allowed_schemes`: httpcore decides whether to start TLS *after* `connect_tcp` returns |
| `allowed_hosts`        | `allow_userinfo`: there is no authority at this layer, only a host |
| `denied_networks` and `allowed_networks`, against every resolved address | `max_url_length`: there is no URL to measure |
| `on_partial_block` and `max_connection_attempts` | `max_redirects` and `sensitive_headers`: a chain belongs to the client |

The right-hand column is what `Client`, `AsyncClient` and `Session` add by checking the whole URL
once per request. The split is not a matter of effort; it is what a backend is told.
`tests/test_adapter_seam_parity.py` holds it as a table over `Policy`'s own fields, so a new field fails a
test until it is placed on one side or the other.

## The failure that is silent

An adapter is only mounted against the prefixes it was mounted against.

```python
session = requests.Session()
session.mount("https://", SafeAdapter(policy=policy))   # guarded on one scheme
```

That session is unguarded on `http://`, and a redirect is how it will find out.
`ssrfguard.requests.Session` mounts both, replacing the two stock adapters rather than sitting
alongside them. Mounting an adapter of your own over either prefix removes the guard from that
prefix; there is no way to prevent that and no attempt to, and it is written down here because
the failure produces no error.

[`examples/06_requests_session.py`](../examples/06_requests_session.py) shows both sessions side
by side.

## Constructor arguments

Everything the underlying client accepts, plus:

| Argument                                                        | Surfaces      | Meaning                                                                                          |
| --------------------------------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------ |
| `policy`                                                        | all three     | What this client is willing to reach. Required, unless you pass a transport that already has one |
| `resolver`                                                      | all three     | A stand-in for `socket.getaddrinfo`. See below                                                   |
| `transport`                                                     | httpx         | An already-built `SafeTransport` / `AsyncSafeTransport`                                          |
| `resolver_slots`                                                | `AsyncClient` | How many name lookups may be in flight at once                                                   |
| `local_address`, `retries`, `socket_options`                    | httpx         | The transport's own options, routed there for you                                                |
| `pool_connections`, `pool_maxsize`, `max_retries`, `pool_block` | requests      | The adapter's own options                                                                        |

An option that neither httpx nor this package knows is **refused rather than dropped**, because
httpx growing a new way to route a request is a decision for this class rather than something to
inherit silently.

## Handing in a resolver

`resolver=` is a supported argument on every surface, not a test hook:

```python
Client(policy=policy, resolver=my_resolver)
```

**Every address a resolver returns is validated before it is used**, so a resolver that lies
about where a name points buys nothing. That is what makes it a reasonable thing to accept from a
caller: use it for tests, for a fixture, or when you have a resolver you trust more than the
system one.

The one thing carried through unchecked is the _port_ in the answer. `socket.getaddrinfo` echoes
the port it was handed, so the two can only disagree for a stand-in you installed yourself, which
makes it your trust to place rather than a boundary this package defends.

## TLS

The certificate is verified against the **hostname**, always, while the socket underneath is
connected to a validated address. That is the whole trick, and it is the assertion this project
most wants never to fail.

Passing an IP literal as `server_hostname` would silently disable hostname verification, because
RFC 6066 does not allow an address in the `server_name` extension, so Python sends no SNI and
there is nothing to check against. You would have traded an SSRF hole for an unauthenticated TLS
connection. Both seams are shaped so that no line in them _could_ do it, and the suite reads the
SNI off the wire from a loopback TLS server rather than trusting the client to report it.

Nothing about pinning loosens certificate checking. A certificate issued to another name is
refused; an untrusted authority is refused. `verify=` works as it does in httpx.

## The async client

`AsyncClient` refuses the same things for the same reasons, with one extra argument whose reason
is worth more than the argument.

`socket.getaddrinfo` blocks, has no timeout, and `socket.setdefaulttimeout` does not apply to it.
A hostile authoritative nameserver can stall a lookup for as long as it likes. On the synchronous
path that holds up the caller who made it and nobody else. **On an event loop it would freeze
every unrelated task in the process**, which is how a security library becomes an outage and
then gets removed. So the async client resolves in a worker thread.

That moves the bound rather than removing it, and the honest version is the number. A thread
blocked in `getaddrinfo` cannot be cancelled, so held lookups accumulate until the client's
resolver slots are gone, and past that point a **new** name waits. Connections already in the
pool are unaffected, which is what keeps this a limit rather than an outage.

```python
AsyncClient(policy=policy)                      # slots = limits.max_connections
AsyncClient(policy=policy, resolver_slots=4)    # or say it yourself
```

The pool is the client's own rather than anyio's process-wide default, so a stall here cannot
starve unrelated thread work elsewhere on the loop.
[`examples/05_async_client.py`](../examples/05_async_client.py) measures a 250 ms blocking lookup
and counts how many times an unrelated task was scheduled while it was stuck.

## What is checked, and when

| Moment               | Checked                                                                                                                |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Client construction  | Proxy configuration                                                                                                    |
| Every request        | The URL: scheme, port, credentials, control characters, encoded host, length, and a literal address if the host is one |
| Every **connection** | One DNS lookup, every answer validated, and the socket opened to one of the answers that was validated                 |
| Every redirect hop   | The full URL check again, the chain length, and the sensitive headers if the origin changed                            |
| Every pooled reuse   | Nothing, because nothing was re-opened and nothing was re-resolved                                                     |

That last row is the shape of the guarantee: **it is per-connection, and a connection's lifetime
is how long it holds.** A connection validated when it was opened is not re-validated on reuse,
because there is nothing new to validate. When the pool opens the next one, it starts over.

## The three asymmetries

Genuine differences between the surfaces, each with a test pinning it so it cannot drift into
being an accident.

**1. Only httpx can be asked for a unix socket.** httpx takes `uds=` and httpcore's backend
interface has `connect_unix_socket`, so there is something to refuse, and it is refused. urllib3
routes by scheme and has no unix entry at all, so requests has nothing to refuse rather than
something it fails to.

**2. Only the requests adapter can refuse a proxy on its own.** requests hands the adapter the
merged proxy mapping. httpx builds a second transport for an explicit `proxy=` and prefers it, so
the guarded transport is never asked. That is the whole reason `ssrfguard.httpx.Client` exists as
a client.

**3. `socket_options` land before connect on `Client` and after connect on `AsyncClient`**, and
this one is silent. The synchronous backend sets options on a socket it created and has not
connected; the asynchronous one sets them on the socket anyio hands back, already connected. So
`SO_SNDBUF` window scaling, `TCP_FASTOPEN`, `SO_BINDTODEVICE` and `IP_TOS` on the SYN work on
`Client` and do nothing at all on `AsyncClient`, with no error and no warning.

It is not fixable without owning socket creation, which means writing the stream, which means
writing the `server_hostname` line this seam exists in order not to have. So it is pinned rather
than papered over: if anyio ever grows a pre-connect hook, the test fails and says so.

## What is not covered

**A proxy.** Refused by default; see [Configuring a policy](policy.md#proxies).

**An adapter you mounted over ours.** Named above, because the failure is silent.

**Anything that is not this client.** A `subprocess` call to `curl`, a library that opens its own
socket, or a second HTTP client in the same process are all outside the seam. This is a library,
not egress control; see [Why this exists](architecture.md#what-this-is-not).

**Application-layer traffic to a permitted host.** Once a connection to a host the policy allows
is open, what travels over it is not inspected.

**DNS resolution time.** Bounded on the async path by `resolver_slots`, and not bounded at all on
the synchronous one, which is the caller's to supervise.
