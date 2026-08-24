# Security Policy

## Reporting a vulnerability

**Please report security issues privately, not as a public issue.**

- **Preferred:** [open a private security advisory](https://github.com/kmoneil/ssrfguard/security/advisories/new).
  This gives us a private thread, and it is the channel that can issue a CVE at the end of it.
- **If you cannot use GitHub, or you would rather not:** email **kevin@oneil.xyz**. A reporter
  who will not open a GitHub account is exactly the reporter worth hearing from, so this is a
  real fallback and not a formality.

**Response window:** an acknowledgement within 3 working days, and an assessment within 10. If
you have not heard back inside the first window, assume the mail was lost rather than ignored
and use the other channel.

A proof of concept helps enormously, but do not let its absence stop you from reporting. A clear
description of the mechanism is worth more than a working exploit that arrives three weeks
later.

**Please test against infrastructure you own.** Everything in scope below can be demonstrated
against loopback, a local resolver, or the fixtures in this repository's own test suite. There
is no need to point this library at anybody else's network to show it is wrong.

## What is in scope

Everything under `src/ssrfguard/`. Concretely, the classes of bug this project considers its
own:

- **A permit that should have been a deny.** This is the product failing, and it outranks
  everything else here. If a URL, hostname, or DNS answer reaches an address inside the
  configured denied set, that is a vulnerability.
- **Any gap between the address that was validated and the address that was connected to.**
  DNS rebinding is the named case; it is not the only one. A redirect hop, a retry, a
  connection-pool refill, or a client-internal re-resolution that reaches a different address
  than the one the policy approved is the same bug.
- **A certificate verified against anything other than the original hostname.** An
  implementation that passes the pinned IP as `server_hostname` silently disables hostname
  verification and trades an SSRF hole for a worse one. This is the single failure this project
  most wants to hear about.
- **An address form we decode incorrectly.** Encodings that defeat string matching, IPv6
  transition prefixes that embed an IPv4 destination (NAT64, 6to4, Teredo, IPv4-mapped), zone
  identifiers, and IDN forms that normalise to an address.
- **Enforcement silently relocating.** If a proxy, a Unix socket, a mounted transport, or any
  other construction causes a request to leave the process without passing the policy, and the
  library does not refuse, that is a vulnerability. Silent pass-through is worse than not
  shipping.
- **Credential and header leakage across a redirect**, including onto a host the policy allowed
  for a different reason.

## What is not in scope

These are scope decisions with reasons, not deflections.

- **This library is not an egress control, and its absence of one is not a finding.** A
  compromised process can open a socket without asking us. Every deployment that matters needs
  a network-layer control as well, and this package's documentation says so in its own README.
  A report that amounts to "a program that does not call ssrfguard is not protected by
  ssrfguard" is correct and is not a vulnerability.
- **Application logic that constructs the URL.** If a program interpolates attacker input into
  a hostname and then asks us to fetch a host that is on the allowlist for the wrong reason, the
  bug is upstream of this library. What *is* ours is everything from the URL inwards.
- **Unbounded DNS resolution time, on the synchronous path.** `socket.getaddrinfo` has no
  timeout and `socket.setdefaulttimeout` does not apply to it, so a hostile authoritative server
  can stall a lookup. On the synchronous clients this is a known denial-of-service surface rather
  than something fixed, because fixing it inside the standard library means a thread that may
  leak, and it is the caller's to supervise. A report of a *new* unbounded path is in scope; this
  one is known.

  **The exception is this one lookup, and the rest of the path is bounded on purpose.**
  Connection attempts are not a second instance of it: the connect timeout is per attempt, so a
  name answering with hundreds of permitted-but-blackholed addresses would multiply the caller's
  timeout by a number the attacker picked. `Policy.max_connection_attempts` caps that, and
  `Policy.max_url_length` caps the string handed to `check_url`, which is otherwise linear in a
  length nobody bounded. Any way one request can consume attempts, sockets, memory or wall-clock
  **inside this package** without a ceiling is in scope.

  **A ceiling in the wrong unit is the shape this has already taken once**, so the currency is
  written down rather than left to inference: the question is not how long a URL may be but how
  much more one URL may cost than another. `max_url_length` alone did not answer it. It counts
  characters of URL, and the expensive characters are the ones in the *host*, because the `idna`
  codec runs nameprep per label at roughly 250 times the price of the scan; a URL comfortably
  inside 8192 characters could carry 389 non-ASCII labels, cost 14.9 milliseconds of one worker,
  and be accepted. The host is therefore capped separately at the 253 characters DNS can carry,
  before normalisation rather than after. **The most expensive URL a default policy accepts now
  costs about 130 times an ordinary one**, and a URL that beats that by an order of magnitude is
  a finding. What `tests/test_cost.py` gates is the mechanism rather than that headline: the
  `idna` arm may not cost more than thirty times the ASCII arm at the same URL length, on every
  supported interpreter. The headline is reported by the `cost` lane and not asserted, because
  making the ordinary case faster raises it without anything getting slower.

  **The response body is not**, and the boundary is worth stating because the sentence above
  would otherwise cover it. Once a permitted host is reached, what it sends back is the client's
  to bound, with `stream=True` and a read limit on requests or `client.stream()` on httpx, and
  this package does not sit in that path. The README says the same thing in its own words. A report
  that a permitted host can return a large body is not a finding here; a report that *this*
  package holds memory or wall-clock without a ceiling is.

  **The asynchronous client is different, and a stall there would be in scope.** A lookup that
  blocked an event loop would freeze every unrelated request in the process rather than the one
  that asked for it, so `ssrfguard.httpx.AsyncClient` resolves off the loop in a worker thread.
  A request through it that does stall the loop is a bug, not a documented limitation.

  **What that leaves is a bound, and the bound is documented rather than in scope.** A thread
  blocked in `getaddrinfo` cannot be cancelled, so held lookups accumulate until the client's
  `resolver_slots` are gone, and past that point a new *name* waits. Connections already open are
  unaffected, which is what keeps this a limit rather than an outage, and the pool is the
  client's own rather than a process-wide default, so a stall cannot starve unrelated thread
  work elsewhere on the event loop. A held lookup blocking a request over an already-open
  connection would be a finding.
- **A host you deliberately allowed, behaving badly within its own rights.** Adding a network to
  `allowed_networks` is an authorization decision you made.
- **Vulnerabilities in httpx, requests or urllib3 themselves.** Those belong to their projects.
  What is ours is how we integrate with them: the seam, and every assumption we make about it.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

Only the latest release is supported. A fix goes into a new version rather than back into an old
one, which is what a single maintainer can actually promise and keep.

Python 3.10 and newer. A report against an interpreter below the floor is out of scope. Not
because old interpreters do not matter, but because this project cannot type-check or fully test
one, and a support claim it cannot verify is worth nothing to the person relying on it.

## Provenance

Releases are published to PyPI via [Trusted Publishing](https://docs.pypi.org/trusted-publishers/),
so there is no long-lived API token in this repository. Each artifact carries a signed
[PEP 740](https://peps.python.org/pep-0740/) attestation naming the workflow that built it.

Every release also carries a CycloneDX SBOM. It is nearly empty, which is the whole point: this
package has no runtime dependencies, and the SBOM is that claim in a form a procurement process
can read without taking our word for it.
