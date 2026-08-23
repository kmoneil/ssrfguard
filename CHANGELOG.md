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
  four blocks those registries do not carry — IPv4-compatible IPv6, IPv4 and IPv6 multicast, and
  deprecated site-local — each of which a registry-only table was measured to permit.
- **Translation-prefix decoding.** An address inside NAT64, 6to4, Teredo, IPv4-mapped or
  IPv4-compatible space is unwrapped and its payload re-checked, so `64:ff9b::7f00:1` is refused
  as loopback and `64:ff9b::808:808` is permitted as 8.8.8.8. Teredo decodes both the server and
  the bit-inverted client address.
- `AddressTable` for callers who need a different answer, which refuses duplicate networks at
  construction rather than silently shadowing one of them.
- `SSRFGuardError` and `BlockedAddressError`, whose messages name the block, its RFC and any
  translation hop walked to reach it.
- **The policy layer.** `Policy.check_url()` decides everything about a URL that can be decided
  without the network — scheme, port, credentials in the authority, host shape — and returns a
  `Target`, which is an origin rather than a URL: no path, no query, no `geturl`, and a `__str__`
  that renders `<Target https host=example.com port=443>`. A policy check is necessary and not
  sufficient, and the return type is what keeps that true.
- Host normalisation through the `idna` codec, the same transformation `socket.getaddrinfo`
  applies internally, so `http://①②⑦.0.0.1/` is refused as loopback before any lookup happens.
- URLs containing a control character are refused rather than normalised, because `urlsplit`
  strips tab, newline and carriage return silently — so the URL that was checked would not be
  the URL that was parsed.
- `Policy.check_address()` and `permits_address()`, where `allowed_networks` beats the denied
  table so an internal-services fetcher can reach its internal services.
- **Resolution.** `ssrfguard.resolve()` performs exactly one lookup and validates every answer,
  returning `Address` objects that carry the `sockaddr` `getaddrinfo` produced — four elements
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
  rather than the first address, because failing over is routine for dual-stack hosts — and is
  only safe because a partially-denied name never reaches it.
- `connect()` requires the policy rather than accepting one, so there is no path through this
  package to a socket that skipped the check, and it confirms the connected peer is the address
  that was validated before returning.
- `BlockedURLError`, `ProxyUnsupportedError` and `TooManyRedirectsError` complete the hierarchy.
  The last two are raised by layers not built yet; they exist now so that every current
  `except SSRFGuardError` already covers them.
- **The requests adapter.** `ssrfguard.requests.Session` is a `requests.Session` whose every
  connection resolves once, validates every answer and connects to one of the answers it
  validated — so redirects, retries and pool refills are covered by the seam rather than by
  three rules to remember. `SafeAdapter` is the same guarantee as a transport adapter, for
  callers assembling a session of their own.
- The pin lives in urllib3's `HTTPConnection._new_conn()`, the only place the address is used,
  so `.host` is left holding the hostname. TLS therefore verifies the certificate against the
  **hostname** and `Host:` still carries the hostname — both read off the server in the test
  suite rather than off the client, because a client can only be asked what it believes it sent.
- The whole URL policy — scheme, port, and a literal address — is re-checked by the function
  that opens the socket, so a connection pool reached by any route is still bound by it.
- A proxy is refused. `HTTPAdapter.send` receives the merged proxy mapping, environment
  variables included, and the same function requests uses to select a proxy decides whether one
  applies — so `no_proxy` still means no proxy rather than a false refusal. `allow_proxy=True`
  accepts that enforcement has moved to the proxy. A connection asked to `CONNECT` refuses at
  the socket, where the host that would be pinned is the proxy rather than the target.

### Proven

- **The central claim is demonstrated, not designed.** A DNS server on loopback, serving real
  wire-format answers from a dict a test edits mid-flight, drives ten tests: the connection lands
  on the validated address after the record moves to the metadata endpoint; it does so even when
  the record moves to an address that would also have been permitted; and `connect` asks the
  nameserver nothing at all, counted rather than argued.
- The same fixture carries a test of the **bug** — validate, then hand the name back to something
  that resolves it again — which reaches the metadata address. If that ever stops working, the
  fixture can no longer demonstrate rebinding and the tests above stop meaning anything.
- **Nothing in urllib3 resolves or connects behind the adapter.** Asserted by making
  `create_connection` — the one function urllib3 would look a name up in — raise for the
  duration of a request that then succeeds.
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
  each enumerated with its reason and asserted to *still* disagree — so a CPython release that
  changes one fails the build instead of moving the answer silently. Twelve of the thirteen are
  addresses the strongest standard-library guard permits and this one refuses.

The httpx client is not built yet. There is no release.
