# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Repository scaffolding: packaging, lane registry, CI and release workflows, branch ruleset,
  pre-commit gates, security policy.
- **The address table.** `ssrfguard.DEFAULT_DENIED` classifies an IP address, transcribed from
  the IANA IPv4 and IPv6 special-purpose registries and versioned with the snapshot date, plus
  four blocks those registries do not carry: IPv4-compatible IPv6, IPv4 and IPv6 multicast, and
  deprecated site-local. A registry-only table was measured to permit every one of them.
- **Translation-prefix decoding.** An address inside NAT64, 6to4, Teredo, IPv4-mapped or
  IPv4-compatible space is unwrapped and its payload re-checked, so `64:ff9b::7f00:1` is refused
  as loopback and `64:ff9b::808:808` is permitted as 8.8.8.8. Teredo decodes both the server and
  the bit-inverted client address.
- `AddressTable` for callers who need a different answer, which refuses duplicate networks at
  construction rather than silently shadowing one of them. **It is frozen**, because
  `DEFAULT_DENIED` is a module-level singleton and the default for every `Policy`, so a plain
  class meant one assignment anywhere in a process changed what every policy in it refused,
  retroactively. The quieter half is the reason it matters: `blocks` is the attribute with the
  public-looking name and every lookup reads the index derived from it, so a write to one left
  the table reporting a rule it did not enforce. Its `repr` is a count and a registry date rather
  than the generated one, which is eleven kilobytes of blocks *inside* every policy repr that
  reaches a log line. `Target.__repr__` exists for the same reason, and was found the same way.
- `SSRFGuardError` and `BlockedAddressError`, whose messages name the block, its RFC and any
  translation hop walked to reach it.
- **The policy layer.** `Policy.check_url()` decides everything about a URL that can be decided
  without the network, meaning scheme, port, credentials in the authority and host shape. It
  returns a `Target`, which is an origin rather than a URL: no path, no query, no `geturl`, and a
  `__str__` that renders `<Target https host=example.com port=443>`. A policy check is necessary and
  not sufficient, and the return type is what keeps that true.
- `Target.__repr__` renders that same debug form. A frozen dataclass generates a `repr` that
  spells every field out, and `repr`, not `str`, is what reaches a log line, a traceback and
  any container a target is printed inside, so the careful rendering was the one form nobody
  ever saw. The package docstring's own example claimed otherwise, which is how it was found:
  no lane ran doctests, so the front-page example had never been executed. One now does.
- Host normalisation through the `idna` codec, the same transformation `socket.getaddrinfo`
  applies internally, so `http://①②⑦.0.0.1/` is refused as loopback before any lookup happens.
- URLs containing a control character are refused rather than normalised, because `urlsplit`
  strips tab, newline and carriage return silently, so the URL that was checked would not be
  the URL that was parsed.
- `Policy.check_address()` and `permits_address()`, where `allowed_networks` beats the denied
  table so an internal-services fetcher can reach its internal services.
- **An `allowed_networks` entry that a translation prefix would decide is refused at
  construction.** The allowlist is consulted before the table gets to decode, so
  `allowed_networks=("64:ff9b::/96",)` reads as "let NAT64 through" and permitted
  `64:ff9b::7f00:1` and `64:ff9b::a9fe:a9fe`, loopback and the metadata endpoint behind a NAT64
  gateway, with the most important row in the shipped table silently switched off. The test is
  the table's own longest-prefix rule rather than mere overlap, so `::1/128` is still allowed:
  it sits inside the deprecated `::/96` wrapper but has its own row, and refusing IPv6 loopback
  would be a wrong deny. A deliberately wide entry that merely *contains* a wrapper, such as `::/0`,
  is still honoured, because a control with no off switch gets replaced by no control at all.
- **Resolution.** `ssrfguard.resolve()` performs exactly one lookup and validates every answer,
  returning `Address` objects that carry the `sockaddr` `getaddrinfo` produced, four elements
  for IPv6, so the flow label and scope identifier survive to the connection.
- A name resolving to both permitted and denied addresses is refused whole. `on_partial_block`
  defaults to `"reject"` because that pattern is the signature of a DNS rebinding attempt rather
  than of a misconfiguration; `"drop"` keeps the permitted answers, and the refusal names it.
- `allowed_networks` governs addresses and `on_partial_block` governs names: an explicitly
  allowed address does **not** rescue a name whose other address is denied.
- A target carrying a literal address is looked up with `AI_NUMERICHOST`, so no lookup is
  possible even if the host is not the address it claims.
- **Connection.** `ssrfguard.connect()` opens a socket to the first reachable address among
  those already validated, passing the `sockaddr` through untouched. It takes the whole tuple
  rather than the first address, because failing over is routine for dual-stack hosts. It is
  only safe because a partially-denied name never reaches it.
- `connect()` requires the policy rather than accepting one, so there is no path through this
  package to a socket that skipped the check, and it confirms the connected peer is the address
  that was validated before returning.
- **`Policy.max_connection_attempts`, defaulting to 4, bounds how many validated addresses a
  connection may try.** The timeout is per attempt and the answer count belongs to whoever runs
  the name's authoritative server, so an uncapped sequence multiplies the caller's timeout by a
  number an attacker chose: a zone answering with two hundred permitted addresses that all drop
  packets held one worker for two hundred times the timeout it asked for, on a path that reads
  as a slow upstream rather than as an attack. Four keeps the dual-stack failover that is the
  reason for trying more than one at all. The refusal names the field and says how many
  addresses it did not try. Every address is still *checked*: the cap bounds what is attempted,
  never what is validated, and a denied address beyond it still refuses the whole sequence.
- **A sequence in which every attempt timed out raises `TimeoutError` rather than `OSError`.**
  `TimeoutError` is an `OSError`, so the plain one was caught by both adapters' `except OSError`
  before their `except TimeoutError` could run. That made those branches unreachable and
  turned a connect timeout into `requests.exceptions.ConnectionError` and `httpx.ConnectError`,
  where the unguarded clients raise `ConnectTimeout`. A caller whose retry or circuit breaker
  keys on `requests.exceptions.Timeout` stopped matching. A single refusal among the attempts
  still reports as `OSError`, because a refusal is the more informative of the two.
- **The async backend fails over past a timed-out address**, which it did not: it raised on the
  first timeout while the synchronous path moved on, so a host answering with one dead address
  and one live one succeeded on `Client` and failed on `AsyncClient`. It now raises
  `httpcore.ConnectTimeout` only when every attempt timed out, and honours
  `max_connection_attempts` like the synchronous path.
- `BlockedURLError`, `ProxyUnsupportedError` and `TooManyRedirectsError` complete the hierarchy.
  The last two were defined before the layers that raise them existed, so that every
  `except SSRFGuardError` written against an earlier tree already covers them.
- **The requests adapter.** `ssrfguard.requests.Session` is a `requests.Session` whose every
  connection resolves once, validates every answer and connects to one of the answers it
  validated, so redirects, retries and pool refills are covered by the seam rather than by
  three rules to remember. `SafeAdapter` is the same guarantee as a transport adapter, for
  callers assembling a session of their own.
- The pin lives in urllib3's `HTTPConnection._new_conn()`, the only place the address is used,
  so `.host` is left holding the hostname. TLS therefore verifies the certificate against the
  **hostname** and `Host:` still carries the hostname. Both are read off the server in the test
  suite rather than off the client, because a client can only be asked what it believes it sent.
- The function that opens the socket re-checks the whole URL policy: scheme, port, and a
  literal address, so a connection pool reached by any route is still bound by it.
- A proxy is refused. `HTTPAdapter.send` receives the merged proxy mapping, environment
  variables included, and the same function requests uses to select a proxy decides whether one
  applies, so `no_proxy` still means no proxy rather than a false refusal. `allow_proxy=True`
  accepts that enforcement has moved to the proxy. A connection asked to `CONNECT` refuses at
  the socket, where the host that would be pinned is the proxy rather than the target.
- **The httpx adapter.** `ssrfguard.httpx.SafeTransport` is an `httpx.HTTPTransport` whose
  connections resolve once, validate every answer and connect to one of the answers they
  validated. `SafeBackend` is the seam itself, for a caller assembling an
  `httpcore.ConnectionPool` of their own.
- The seam is httpcore's network backend, which is handed a host and a port and returns a
  stream. httpcore starts TLS itself, on the line after, with the origin hostname, so this
  adapter has no opportunity to verify a certificate against the address it pinned. **The stream
  it returns is httpcore's own class**, so even `start_tls` is httpcore's code rather than a copy
  of it, and a `server_hostname` argument does not appear anywhere in this package.
- The whole URL policy runs in `handle_request`, once per request rather than once per
  connection, because a network backend never learns the scheme. The backend independently
  checks the port and every address, so a pool built around it directly is still bound.
- A unix socket is refused, at the transport when `uds=` is given and again at the backend, and
  there is no flag to permit one: the question a policy answers has no meaning for a path in the
  filesystem.
- A proxy on the transport is refused unless the policy permits one, and permitting one leaves
  httpx's own proxy pool in place. Pinning the *proxy's* address while leaving the target
  unchecked would be a guard reporting a decision it never made.
- `connect()` now accepts every shape of `setsockopt` argument its clients can express,
  including httpcore's four-element form, and applies each unchanged rather than taking it
  apart and putting it back together.
- **`ssrfguard.httpx.Client`, the entry point, because a transport is not a client.**
  `httpx.Client(transport=…)` already ignores `HTTP_PROXY`, because httpx computes
  `allow_env_proxies = trust_env and transport is None`. But an explicit `proxy=` or `mounts=`
  builds a *separate* transport that httpx prefers, and the request never reaches the guarded
  one. Only a class that owns its own construction can refuse that, so this one does.
- An environment proxy is **refused rather than quietly ignored**, which is what the transport
  alone does. Ignoring the proxy an operator configured can put traffic outside an egress
  control that was assumed to be carrying it. The question is asked with httpx's own parser, so
  `NO_PROXY` means exactly what it means to httpx, `NO_PROXY=*` included, and a false refusal
  is not possible.
- `verify`, `cert`, `http1`, `http2` and `limits` are routed to the transport. On an
  `httpx.Client` that was given a transport they configure nothing at all, silently. For
  `verify` that is a caller believing they set certificate verification when they did not.
- An argument neither httpx nor this package knows is refused rather than passed through, and a
  test asserts `httpx.Client` has not grown one that has never been considered. A new way to
  route a request is a decision here, not something to inherit.
- **Redirects, on both adapters, under one matrix.** Every hop opens a connection and every
  connection validates, so pinning across a chain is free. Everything else about a chain is
  not. The chain is capped by `Policy.max_redirects` rather than by the client's own counter,
  which exists to stop loops, defaults to thirty and twenty, and can be changed without touching
  the policy. Over the limit raises `TooManyRedirectsError`, naming every URL walked.
- A hop that changes the scheme is refused by this package on both adapters. It was not before:
  nothing is mounted for `file://` in requests, so the answer was requests' own "no connection
  adapters were found", which a caller catching `SSRFGuardError` would have missed.
- `Policy.sensitive_headers`, dropped when a hop leaves the origin, defaulting to the three
  whose *definition* is credentials. `x-api-key` is a credential by convention rather than by
  specification, so it is named by the caller who uses it rather than guessed at here. Both
  clients already dropped `Authorization`; neither dropped anything else.
- A relative `Location` resolves against the hostname URL, asserted rather than assumed. That is
  the failure the URL-rewrite approach to pinning has, a `Location: /admin` resolving against a
  rewritten address. It is absent here because nothing rewrites a URL.
- **One matrix over all three client surfaces**, so the two seams cannot drift apart. Every
  guarantee that is supposed to hold of this package rather than of one client is asserted
  once and runs three times, against `requests`, `httpx` and `httpx` async:
  the pin, the `Host:` header, the TLS `server_name`, a certificate for another name, an
  untrusted chain, a denied address, scheme, port, credentials in the authority, a literal
  address, a pooled request, a fresh connection, the partial-block rule under both settings, and
  a network failure not arriving dressed as a policy refusal. Adding an adapter is a row rather
  than a suite.
- **The two asymmetries are a list rather than an assumption**, each with a test asserting it
  still holds: a unix socket is refused only where one can be asked for (urllib3 has no such
  path), and the low-level object is enough for requests but not for httpx (requests hands the
  adapter the merged proxy mapping; httpx builds a second transport and never consults ours).
- **`ssrfguard.httpx.AsyncClient`, and it resolves off the event loop.** `getaddrinfo` blocks and
  has no timeout, so an async backend that resolved inline would stall the whole loop and one
  hostile hostname would freeze every unrelated request in the process. Resolution runs in a
  worker thread through `anyio.to_thread.run_sync`, chosen over `loop.getaddrinfo`
  because httpx supports trio as well as asyncio, and because anyio is already a hard dependency
  of httpx. A test counts a concurrent task's ticks while a lookup blocks; another asserts two
  stalled lookups overlap rather than queue.
- The async connection is made by `anyio.connect_tcp` from the validated address, which performs
  no name resolution at all when given one, measured rather than assumed. The stream it returns
  is wrapped in httpcore's own, so TLS stays httpcore's code there too. The peer is confirmed after
  the connection is up, as on the synchronous path.
- The async client is a third row in the shared matrix rather than a third suite: every
  guarantee already asserted of the two synchronous surfaces is asserted of it, driven through a
  blocking portal so it runs the same tests rather than a translation of them.
- `SECURITY.md` now separates the two resolution paths. Unbounded lookup time stays out of scope
  on the synchronous clients, where it holds up the caller that asked for it; **a stall that
  reaches the event loop is in scope**, because it holds up everyone else.
- **The `leaks` lane runs.** `tests/ssrfguard_leakcheck.py` is a pytest plugin, loaded by that
  lane and by nothing else, which fails the test that leaves a socket open and names the peer it
  was connected to. It compares open file descriptors rather than walking the object graph,
  because a test that asserts on a refusal is holding a traceback that holds the socket. It
  collects and waits before reporting, because the far end of a loopback connection closes a
  moment after this end does. Its own two assertions are checked by `tests/test_leakcheck.py`: a
  leak check that has never caught anything is indistinguishable from one that cannot.
- **The encoding corpus.** Thirteen ways of writing 127.0.0.1 that are not `127.0.0.1`: octal,
  decimal, hex, short form, a bare `0`, circled digits, the ideographic full stop U+3002, an
  IPv4-mapped address and a trailing dot. Each is asserted refused, and each is asserted against
  the platform's own resolver so the half of the argument that belongs to `getaddrinfo` is pinned
  rather than assumed. The corpus is split by *which* layer refuses each form, because four of
  them are well-formed hostnames the URL layer has no business refusing: `0x7f.0.0.1` is caught
  only after the resolver decodes it, and there is no code here that knows what hexadecimal is.

- **Cloud metadata endpoints are denied by address and never by name**, and two tests keep it
  that way: no vendor metadata hostname appears anywhere in the shipped code, and a request to
  `metadata.google.internal` is shown passing the URL layer and being refused by where it
  resolves to. A hostname denial would read as a stronger control and be a weaker one, because a
  trailing dot defeats it, as does the wrong case and a CNAME. The error quality it would
  have bought is bought instead by naming the addresses, after resolution, where the name cannot
  be spoofed.

- **`max_redirects=0` means "a redirect is refused", not "redirects are not followed"**, and now
  says so. At the boundary a single `302` raises even with following switched off at the call,
  because both clients build the next request in order to expose it, as `response.next_request`
  on httpx and `response.next` on requests, and the cap fires on the build. The two agree, so this
  was never a parity bug; it was a defensible semantic nobody had written down, which is exactly the
  kind that gets "fixed" later by someone who did not know it was decided. Asserted on all three
  client surfaces, along with the shape a caller who wants the `302` back should use.
- **`Policy.max_url_length`, defaulting to 8192, bounds the string `check_url` will read.**
  It had no ceiling, and `SECURITY.md` says any way one request can consume wall-clock without
  one is in scope, so the two documents disagreed. Not a ReDoS: measured across four octaves,
  both paths are strictly linear and `_HOSTNAME` cannot backtrack, because every repetition in it
  must consume a literal dot. What it lacked was a bound. The non-ASCII path costs about 1.9
  microseconds per character, because the `idna` codec runs nameprep per label, so a 10MB URL
  was roughly 19 CPU-seconds of one worker. Checked first, before anything that scans the string,
  and the refusal quotes the length rather than the URL: echoing eight kilobytes of
  attacker-supplied text into a log line is the second half of the problem. 8192 is where nginx,
  Apache and IIS converge for a request line. `SECURITY.md` now also says plainly that the
  *response body* is the client's to bound and not this package's, which is the other half of
  that sentence and was left to inference.
- **The `socket_options` ordering asymmetry is documented and pinned rather than discovered.**
  They are applied before connect on `Client` and after connect on `AsyncClient`, because anyio
  owns socket creation on the asynchronous path. So `SO_SNDBUF` and `SO_RCVBUF` window scaling,
  `TCP_FASTOPEN`, `SO_BINDTODEVICE` and `IP_TOS` on the SYN work on one and are silent no-ops on
  the other. Reaching an unconnected socket there means writing the stream, and with it the
  `server_hostname` line this seam exists in order not to have, so the asymmetry stands and is
  now the third entry in the parity matrix's list. The existing tests asserted only that an
  option *lands*, which is why this was invisible.
- **The two failover loops share the message they raise, and the async one chains its cause.**
  `connect()` and the async backend implement the same rule: try in order, cap the attempts,
  say what was left untried. The loops cannot merge, because one drives a socket and the
  other drives anyio. The *message* was a second copy, which is the half that drifts without
  anyone noticing, so it is one function now. The async path also raised outside any `except`,
  so `__cause__` and `__context__` were both `None` and an operator got "could not connect to any
  validated address" with nothing underneath it; the sync path has always chained. A
  synchronous-versus-asynchronous axis in the parity matrix asserts both, which is the axis that
  file did not have.
- **The registry generator no longer writes a network-fetched field into Python source
  unescaped.** `scripts/refresh_registry.py` hand-quoted three values from IANA's CSV, and
  `cidr`, unlike its sibling `name`, had its quotes neither stripped nor escaped, so a `"` in
  the *Address Block* column closed the literal and the rest of the cell became code in a module
  `import ssrfguard` executes. Every interpolated field is now `repr`'d, and a block that is not
  a network stops the generator instead of reaching the file, which is the likelier failure and
  the one with no attacker in it.
- **The generator produces the file that is committed again.** `_registry.py` says *Generated.
  Do not edit by hand*; it had been hand-repaired after generation, so running the documented
  workflow emitted a `typing.Union` left over from the abandoned 3.9 floor and an unsorted
  `__all__`, giving a module that failed this repository's own lint gate. A test compares the
  emitted header against the committed one offline, and the `egress` lane regenerates from IANA and
  compares the table as values, so a registry that moved is a failing test rather than a table
  nobody re-read.
- **The `fast` lane measures branch coverage**, which is what its own rationale always described:
  "an untested branch in an address table is an address nobody has ever asked about". Statement
  coverage cannot see a branch, because both lines of an `if` execute while only one edge
  between them ever does. The suite sat at 100% statements with two branches unexercised. One of
  them was `AsyncClient(transport=…)`, a documented path on a shipped client surface that no test
  had ever constructed. Both are now covered and the floor is 99%.

### Proven

- **The central claim is demonstrated, not designed.** A DNS server on loopback, serving real
  wire-format answers from a dict a test edits mid-flight, drives ten tests: the connection lands
  on the validated address after the record moves to the metadata endpoint; it does so even when
  the record moves to an address that would also have been permitted; and `connect` asks the
  nameserver nothing at all, counted rather than argued.
- The same fixture carries a test of the **bug**: validate, then hand the name back to something
  that resolves it again, which reaches the metadata address. If that ever stops working, the
  fixture can no longer demonstrate rebinding and the tests above stop meaning anything.
- **Nothing in urllib3 resolves or connects behind the adapter.** Asserted by making
  `create_connection`, the one function urllib3 would look a name up in, raise for the
  duration of a request that then succeeds.
- **httpcore does not coalesce HTTP/2 connections**, so a pin that is per-origin is a policy that
  is per-origin. Every connection class it has gates reuse on an exact origin match, asserted
  here including the HTTP/2 one; and ALPN negotiates `h2` over a pinned stream, measured. `http2`
  stays off by default because that is httpx's default, not because of a doubt.
- **Nothing in httpcore resolves or connects behind the adapter either.** The one call
  httpcore's stock backend makes, `socket.create_connection`, is made to raise for the duration
  of a request that then succeeds.
- The TLS handshake carries the hostname, read from the server rather than from the client: a
  server-side SNI callback records what the client offered, and Python will not put an IP literal
  in `server_name`, so a name arriving there is the pinned address *not* having reached TLS.
- **The seam this adapter did not take is measured and pinned.** urllib3's `.host` is a property
  over `_dns_host`, so writing the validated address into `_dns_host` writes it into `.host`,
  and `HTTPSConnection.connect` reads `server_hostname` from there. Against a loopback server
  holding a certificate for one name: as specified, every request fails on an IP-address
  mismatch; `assert_hostname=False`, which is the one-line repair for that failure, connects and
  accepts a certificate issued to a name nobody checked; and `assert_hostname=<hostname>`
  restores the check while still sending the address as the `Host` header and no name at all in
  the handshake. Three tests hold that, so a urllib3 release that changes any of it fails this
  build rather than quietly retiring the argument for the seam that was taken.

### Notes

- This table deliberately disagrees with `ipaddress.is_private` and `is_global` on 13 addresses,
  each enumerated with its reason and asserted to *still* disagree, so a CPython release that
  changes one fails the build instead of moving the answer silently. Twelve of the thirteen are
  addresses the strongest standard-library guard permits and this one refuses.

All three client surfaces are built. There is no release.
