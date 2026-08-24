# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- **The promise is written down: this guards the connection, and the fetch around it is not
  ours.** `SECURITY.md` gains a section saying so with a table of each side, and naming the
  alternative that was rejected, because a boundary reads as arbitrary without the thing it was
  chosen over.

  Two open questions fell out of it at once and both fell against the way they had been leaning:
  a response-size ceiling stays out, and a detector for the bug this package prevents stays a
  different product. The argument for each was good in isolation and neither survived being asked
  what the package is. "We safely fetch an untrusted URL" has no edge: everything a fetch touches
  becomes in scope, and the first casualty is the structural claim on the front of the README.

  **Fenced rather than merely stated.** `tests/test_scope.py` fails if a `Policy` field, a client
  argument or an exported name grows the vocabulary of a response, if `pyproject.toml` declares a
  console script, or if the sentence leaves `SECURITY.md`. Each of the three was checked by
  making it fail. A boundary nothing checks is a boundary that moves one convenient argument at a
  time, and every one of those arguments is individually reasonable.


- **`RebindingWatch`: noticing that a name moved, not just surviving it.** The pin already means
  a moved record cannot move the connection, and that is silent by construction: an attacker
  points a name at a public address, waits for the lookup, moves it to `169.254.169.254`, and the
  only trace is that nothing went wrong. `on_partial_block` catches the version of this that
  happens inside one lookup; across two lookups the signal is identical and nothing remembered
  the first answer.

  It is an observer that wraps an observer, so there is no new plumbing anywhere: it watches
  address decisions go past, remembers the permitted ones per host, and fills in
  `Decision.also_seen` when a refusal arrives for a host with others on file.

  **It detects and does not enforce**, which is what makes its limit acceptable: it cannot see a
  name that is only ever resolved once, because a pooled second request does not re-resolve. It
  is not a reason to relax `on_partial_block`. It is bounded on purpose, since the keys are
  hostnames an attacker chooses, and it is **not a cache**: what it stores is compared, never
  reused, because handing back a remembered answer would be a stale pin.
  [`docs/observing.md`](docs/observing.md) has the limits written out.


- **`Policy(allowed_hosts=...)`: reaching only what you meant to.** The policy could narrow
  schemes, ports, networks and userinfo, and there was no way to say "only `api.stripe.com` and
  `*.githubusercontent.com`". The workaround was `allowed_networks`, which is the wrong control
  three ways over: unstable, because the address behind an API is a CDN's; far too wide, because
  allowing a CDN's ranges allows every other tenant on it; and a *widening* of the denylist, so a
  mistake in it is a bypass rather than a refusal.

  Empty by default, and empty means no name restriction, so no existing policy's behaviour moves.
  A bare entry is exact and does not carry its subdomains; `*` is meaningful only as the whole of
  the leftmost label and anything else is refused at construction; a literal address is not a
  host pattern and is permitted only by being listed verbatim.

  **Matching is on label boundaries and is never a suffix test**, which is the single line that
  would turn this into a way in: `"evil-github.com".endswith("github.com")` is `True`.
  `tests/test_policy_hosts.py` carries a corpus of hosts that nearly match a listed entry, and a
  property test requiring anything permitted to be exactly a listed name or a proper subdomain of
  a listed wildcard.

  **This is the opposite direction from the one this package refuses, and the asymmetry is the
  argument.** Denying by name is defeated by a trailing dot, a case change, an IDN homograph or a
  `CNAME`, which is why the address table denies addresses and never names. Allowlisting inverts
  every term: an attacker has to match the string rather than evade it, evasion means refusal,
  and matching buys only the right to be resolved and then checked against the address table like
  anything else. There is no permit to spoof into. The spellings that defeat a denylist are
  folded on both the entry and the host, so `API.STRIPE.COM.` matches `api.stripe.com` and an
  entry may be written in the script you read rather than in punycode.

  A refusal names the host, the field, and the entry it nearly matched, because the first mistake
  anybody makes is listing `example.com` and then fetching `api.example.com`.
  [`docs/policy.md`](docs/policy.md) has the table.

### Fixed

- **A bad `allowed_hosts` entry is a `ValueError`, not a `BlockedURLError`.** Entries go through
  the same normalisation a URL's host does, and that function reports failure as a *URL* refusal,
  which is right where `check_url` calls it and wrong from a constructor: the message read
  "'...' is not permitted", naming a URL that does not exist, to a caller who was configuring a
  policy rather than fetching anything. Every other check in `__post_init__` raises `ValueError`.
  Found by mutation testing, which noticed that nothing distinguished the argument carrying the
  name in that message from `None`.

## 0.2.0 - 2026-08-24

### Added

- **An `observer`, so a decision survives the function that made it.** Every permit and every
  refusal this package makes was discarded unless it raised, and the usual shape of calling code
  flattens the refusal too: `except SSRFGuardError: log.warning("bad url")` is a control working
  perfectly and telling nobody what it caught. A blocked SSRF attempt is an indicator of
  compromise, and **the permits matter as much**: a name that resolved public yesterday and
  private today is the whole subject of this package, and nothing in it could say so, because
  yesterday's answer left no trace.

  `Decision` is a frozen record carrying the stage, the outcome, the rule that refused, the
  address, and the URL with any credentials replaced. It is a constructor argument on all three
  clients and a keyword on `check_url`, `resolve` and `connect`. Four stages: `url`, `address`
  (**one record per address**, not per name, because which of four was refused is the point),
  `peer`, and `redirect`. [`docs/observing.md`](docs/observing.md) is the guide.

  **Three rules make it safe rather than a new way to break a request.** An observer that raises
  cannot fail one, because a sink with a bug in it would otherwise turn an allow into a deny and
  report a logging error as a refused request; `KeyboardInterrupt` and `SystemExit` still travel,
  because a process being torn down is not a sink misbehaving. An observer never sees
  credentials, on permits as well as refusals and in every URL of a redirect chain, redacted
  textually so it works on URLs no parser accepts. And nobody listening costs nothing: no record
  is built when `observer` is `None`, gated by counting constructions rather than timing them.

  **It is a callback rather than `logging`.** A library that picks a logger name, a level and a
  format makes three decisions for a caller who made none of them, and an event that arrives as a
  formatted string has to be parsed back into fields by whoever wants to alert on it. The guide
  carries the four lines that hand it to `logging`.

### Changed


- **The citation scanner can see an `async def` test.** `test_every_test_the_docs_cite_is_there`
  matched test definitions with `^def (test_\w+)`, so every asynchronous test read as undefined
  and citing one in a document was impossible: the claim would be reported missing while the test
  sat in the file it pointed at. Found by citing one. The async client is a documented guarantee
  of this package, so its evidence has to be nameable, and the pattern's own self-check now
  carries the case that was broken.
- **The async overlap test is a rendezvous rather than a stopwatch.** It timed two concurrent
  lookups and required them to finish inside 1.8 stalls, which measured the runner as much as the
  code: it went red on a macOS CI
  runner against a change to one script that cannot touch async resolution at all. The property
  it was reaching for is that two lookups are in flight *at the same time*, which is scheduling
  rather than duration. A `threading.Barrier` of two parties states it directly, so reaching the
  assertions is itself the result and a serialised implementation cannot get there. It is now
  named `test_two_lookups_are_in_flight_at_the_same_time`, it carries no clock, and it is a
  stronger claim than the one it replaces: overlap is observed rather than inferred from a
  number consistent with it. Checked both ways, with `resolver_slots=1` forcing the serialisation
  it guards against, and stressed twenty times against eight busy cores.

### Added

- **`ssrfguard.resolvers.UdpResolver`: a resolver with a deadline.** `socket.getaddrinfo` has no
  timeout and `socket.setdefaulttimeout` does not reach it, which `SECURITY.md` documented as a
  denial-of-service surface and `docs/threat-model.md` named twice more, once per path. All three
  statements were downstream of one decision: the lookup belonged to the platform. This speaks
  DNS over a datagram socket the package owns, so one call returns inside its `timeout` whatever
  the far end does, proved against a server that receives queries and says nothing rather than
  argued from the `settimeout` call.

  **It adds no API.** `resolver=` has been a constructor argument on all three clients since
  0.1.0 and `Resolver` has always been `getaddrinfo`'s shape; what was missing was something to
  pass. It is opt-in and the default does not move, because the platform's resolver knows
  `/etc/hosts`, `nsswitch.conf`, search domains and RFC 6724 ordering, and this one knows none of
  them. [`docs/resolvers.md`](docs/resolvers.md) is the list of what the trade costs.

  **An incomplete answer set is refused rather than used**, which is the one decision here that
  trades availability for security and is not obvious. Returning the half that arrived looks
  conservative, and is not: `on_partial_block='reject'` refuses a name that resolves to both
  permitted and denied addresses, and it can only see that if it is shown every answer. A zone
  that answers `A` and stalls `AAAA` would otherwise pick which half the policy gets to judge.
  `families` is the documented escape for a network that drops `AAAA` instead of answering it.

  **The parser is the risk and the bounds are on termination rather than on decoding.** Every
  address it returns is validated by the policy before anything connects, so a mis-parse cannot
  become a permit; what it could do is never return, which would have replaced a bounded stall
  with an unbounded one. A name may follow at most 64 compression pointers and run to at most 255
  bytes, and two property tests over arbitrary bytes require every input to decode or raise.

  **What this does not do is make the asynchronous path cancellable.** `AsyncClient` still
  offloads a synchronous call to a worker thread, so a lookup in flight is waited out rather than
  cancelled. The thread is now released at the deadline instead of at the platform's discretion,
  which bounds the accumulation `resolver_slots` exists to cap. Cancellation is a change to the
  client, and it is not made here. `SECURITY.md` and `docs/threat-model.md` say so in place.

### Changed

- **The `zero-deps` lane imports `ssrfguard.resolvers`, not just `ssrfguard`.** The probe imported
  the package, and a shipped module the package does not import itself was therefore outside the
  claim the lane exists to gate. Verified by injecting a third-party import and watching it go
  red. Its diagnosis no longer says "an adapter", because it is no longer only adapters.
- **One deadline check, written once.** `_over_udp`, `_over_tcp` and `_recv_exactly` each had
  their own copy of "if the deadline has passed, raise", and two of the three could only be
  reached by winning a race against the timeout `recv` raises on its own, so no test could drive
  them. `_time_left` is the single bound, and it has a test.

- **`_normalise` catches `ValueError` rather than `(UnicodeError, ValueError)`.** `UnicodeError`
  is a subclass of `ValueError`, so the pair caught nothing the broader name did not and only
  read as though it did. The narrower name is the one removed, deliberately: narrowing the other
  way would turn a codec raising anything but a `UnicodeError` into an unhandled crash in the
  middle of a guard, where today it is a refusal that names the host. Nothing in CPython takes
  that path, which is why `test_a_codec_failure_that_is_not_a_unicode_error_is_still_a_refusal`
  exists to hold it. That test drives the failure through a `str` subclass rather than a patched
  `encodings.idna.Codec`, because `codecs` caches a *bound* method on first use: the patched form
  passes alone and passes **vacuously** in a suite where anything encoded first.
- **Three type-checker suppressions, none of which changes a runtime path.** pyright reports ten
  errors that mypy `--strict` does not, and all ten are the checker or its stubs rather than this
  code. `setsockopt(*option)` in `_connect._open` and `AsyncSafeBackend.connect_tcp` unpacks a
  union of tuple shapes, which pyright cannot follow: it joins the element types across positions
  and then calls every argument wrong. httpcore carries the same pattern in its own backends. A
  length dispatch would satisfy pyright without a suppression and was rejected, because unpacking
  is what keeps the value whole: a 5-tuple raises `TypeError` today and a dispatch on `len` would
  silently apply the first three elements and drop the rest, which is the failure the
  `SocketOption` note already warns about. `ConnectionCls` in `requests._pool_classes` is
  urllib3's own defect, reproduced exactly by assigning urllib3's unmodified `HTTPConnection` to
  it. All three are spelled `pyright:` rather than `type:`, because mypy is right about these
  lines and an ignore it cannot use would fail `warn_unused_ignores` under strict.

## 0.1.0 - 2026-08-24

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
- **What this package costs is published, and the three source comments that asserted a cost
  without carrying one now carry one.** A reader deciding whether to put this in front of every
  outbound request had no way to find out what that costs except by measuring it. The README's new
  "What it costs" section gives the shape that stays true, which is that the URL check runs once
  per request and resolution once per connection, a table of measured per-call figures with the
  machine that produced them, and the command that reproduces them on the reader's own hardware:
  a headline number is wrong on somebody else's CPU the moment they read it.

  It publishes the unflattering half too, because a section that did not would be marketing: an
  internationalised name costs about five times an ASCII one and the faster alternative is a
  dependency this package will not take; the most expensive URL a default policy accepts costs
  about 130 times an ordinary one; and the async client's lookups are bounded by its resolver
  pool. `SECURITY.md` gains the same ceiling in its own terms, where it is a security property
  rather than a performance note, and states the currency explicitly: the question a ceiling has
  to answer is not how long a URL may be but how much more one URL may cost than another, which
  is the distinction `max_url_length` alone got wrong.

  In the source, `requests.py` said the URL check at the socket seam "costs nothing" and now says
  4 to 9 microseconds against a handshake three orders of magnitude larger; the address table's
  precomputed index says what it is worth, 3.47us against 5.11us, and, more usefully, why it
  should not be improved further; and `max_url_length` carries both per-character figures rather
  than only the expensive one.
- **The async client resolves through a pool of its own rather than anyio's process-wide one.**
  Moving `getaddrinfo` off the event loop fixed the failure where one hostile name froze every
  task in the process. It did not remove the bound, because a thread blocked in `getaddrinfo`
  cannot be cancelled, and the bound it left was **anyio's default `CapacityLimiter` of 40,
  shared with every other caller on that event loop including the host application's own thread
  work**. Measured with a stalling resolver: at 39 held lookups an unrelated request completes
  immediately, and at 40 it does not complete at all. The two tests behind the claim in
  `_resolve.py` exercised two.

  Resolution now has a limiter of its own, sized from the pool's `max_connections` and
  overridable with `resolver_slots` on `AsyncClient`, `AsyncSafeTransport` and `AsyncSafeBackend`.
  Taking the pool's number is the point rather than a convenience: a resolver bound tighter than
  the pool is a second queue nobody configured, and one that refuses to open connections the pool
  was still willing to make. This cannot make a stalled lookup cancellable, because nothing can;
  it keeps the blast radius inside the client and makes the number one somebody chose.

  A test asserts all three halves of what that means, because only the three together say the
  bound is a limit rather than an outage: one slot short of full a new name still resolves, with
  every slot held a new name waits, and with every slot held a connection already in the pool
  still serves. The note in `_resolve.py` now names the bound instead of implying there is none.

  `resolver_slots` is spelled out on the async surfaces rather than routed through the shared
  option table, because the synchronous `Client` shares that table and has no such argument: a
  lookup on the synchronous path holds up the caller that made it and nobody else.
- **`check_url` no longer parses its host as an address twice, or at all for a name.** It was
  40% of the check. `_check_host` parsed the host to find out whether the hostname rules applied,
  used the answer as a boolean and discarded it, and `check_url` then parsed the same string again
  to get the value back; on a name each of those raised three exceptions inside
  `ipaddress.ip_address` to arrive at `None`. `_check_host` now returns what it parsed, and a
  one-character test runs in front of the parse: everything `ip_address` accepts either holds a
  colon or is nothing but digits and dots, and the second half of that was already being computed
  two lines further down. An ordinary hostname now reaches `ip_address` zero times.

  Measured on the five supported interpreters, `check_url` on a corpus of distinct hostnames:
  **8.84 to 5.62 microseconds on 3.10 and 7.59 to 4.02 on 3.13**, between 36% and 47%. Literal
  addresses gain 13 to 18%, internationalised names 14 to 16%. No behaviour change: same inputs,
  same outputs, same order of refusals.

  **The shortcut is a wrong-permit surface if the rule behind it is ever wrong** -- a literal
  address mistaken for a name skips `check_address` entirely -- so the rule is asserted rather
  than argued. Two Hypothesis properties in `tests/test_policy_properties.py` say that nothing
  `ip_address` accepts fails the one-character test, over generated text and over generated
  addresses in both spellings. The branch itself was already covered: dropping the colon arm turns
  every IPv6-literal URL into a wrong deny and six existing tests go red.
- **A host longer than DNS can carry is refused before normalisation, at 253 characters.**
  `max_url_length` bounded the wrong quantity and the gap was three orders of magnitude wide. It
  counts characters of URL; the `idna` codec runs on characters of *host*, once per label, at
  roughly 250 times the price of the scan. So a URL sitting comfortably inside the 8192-character
  ceiling could carry 389 non-ASCII labels, cost **14.9 milliseconds of one worker**, measured,
  and be *accepted* -- and the name it produced was 10 508 characters, which no resolver can look
  up, so the work was certain to be wasted before it started. One core absorbed 67 of those per
  second. The cap is a constant rather than a policy field because a longer name cannot resolve
  anywhere, so a knob would only offer the choice of paying more to reach the same refusal, and it
  is applied to the host as written rather than to its A-label form because punycode only grows a
  name, so this bounds the work without narrowing what can resolve. Checked before `_normalise`
  for the reason the URL ceiling is checked before anything scans the string. The refusal quotes
  the length, not the host.

  **This is a behaviour change.** Such a host was refused before too, but by `socket.gaierror` at
  resolution rather than `BlockedURLError` at check time, so a caller that tells "the policy
  refused this" apart from "DNS could not find this", which is what a retry or a circuit breaker
  does, sees one class of input move between the two.
- **A `cost` lane, and three cost assertions on the gating one.** Ten lanes gated ten things and
  none of them was cost, in a package that states measured costs in three docstrings. None of the
  new assertions is a stopwatch: a threshold in microseconds is a threshold about the runner. One
  counts how many times `check_url` parses its host as an address. One measures that an 8 KiB URL
  costs no more than 16x a 1 KiB one, which is the linearity `max_url_length` always rested on,
  argued from the regex until now and measured since. One measures that the `idna` arm costs no
  more than 30x the ASCII arm at the same URL length, which is the assertion that would have
  caught the ceiling above: it read 251x before the host cap and reads 9 to 11x after. Both ratios
  are taken on `time.thread_time_ns` in the same run, which is what makes them survive a shared
  runner: measured under load, the same comparison on wall clock moved by 5x and on the thread
  clock by 1%. The `cost` lane itself reports and does not gate.
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
- **A documentation tree, and nine examples that run.** `docs/` carries eight task-shaped guides:
  getting started, configuring a policy, the clients, errors, using the pieces directly, the
  address table, what it costs, and why this exists. The README was one page trying to be all of
  them, so the arguments that make this package worth installing were competing for space with
  the field reference somebody needs on their second day.
- **`examples/` is executed rather than described.** Nine runnable files, each working with no
  arguments, no network and no fixtures, and every one of them run as a subprocess by
  `tests/test_examples.py`. A documented snippet that stopped working is worse than no snippet:
  it is copied, blessed by its position in a README, and wrong. The headline is
  `examples/03_the_pin.py`, which scripts a nameserver that answers honestly once and then moves
  the record to the metadata endpoint, and shows the lookup count that gives the seam away. It
  says in its own docstring what a stand-in resolver cannot prove, and points at the real
  nameserver in `tests/test_rebinding.py` for the half it cannot.
- **`tests/test_docs.py`, because prose rots silently and for readers rather than for
  maintainers.** Every relative link in every committed markdown file has to resolve, anchors
  included, so a renamed heading fails a build instead of leaving a link that still looks right.
  The counts `docs/address-table.md` quotes, 60 rows and 13 permitted and 5 translated and 5
  metadata endpoints, are read out of the shipped table rather than typed, so refreshing the
  registry updates the prose or fails. The registry snapshot date is checked the same way. And
  the cost table appears in both the README and `docs/cost.md` on purpose, so every row of the
  first is required to appear in the second.
- **`docs/`, `examples/`, `scripts/` and `CONTRIBUTING.md` now ship in the sdist**, which is a
  correctness fix rather than a courtesy and was found by the two files above. `tests/` ships so
  downstream rebuilds can run the suite, and that suite reads outside itself: the new tests open
  `docs/` and `examples/`, and `tests/test_packaging.py` imports `lanes` from `scripts/`, so
  without it the suite could not be *collected* from an sdist at all. Separately, the shipped
  README links to `CONTRIBUTING.md`, which was not in the distribution, so the PyPI page carried
  a dead link aimed at the one reader who cannot clone the repository to work around it.
  `test_the_sdist_carries_everything_the_suite_reads` and
  `test_the_sdist_carries_every_document_the_readme_links_to` keep the list honest.

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
