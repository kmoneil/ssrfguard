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
  library does not refuse, that is a vulnerability — silent pass-through is worse than not
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
- **Unbounded DNS resolution time.** `socket.getaddrinfo` has no timeout and
  `socket.setdefaulttimeout` does not apply to it, so a hostile authoritative server can stall a
  lookup. This is documented as a known denial-of-service surface rather than fixed, because
  fixing it inside the standard library means a thread that may leak. A report of a *new*
  unbounded path is in scope; this one is known.
- **A host you deliberately allowed, behaving badly within its own rights.** Adding a network to
  `allowed_networks` is an authorization decision you made.
- **Vulnerabilities in httpx, requests or urllib3 themselves.** Those belong to their projects.
  What is ours is how we integrate with them — the seam, and every assumption we make about it.

## Supported versions

Alpha. Only the latest release is supported, and there is no release yet. This section becomes a
table when there is something to put in it.

Python 3.10 and newer. A report against an interpreter below the floor is out of scope — not
because old interpreters do not matter, but because this project cannot type-check or fully test
one, and a support claim it cannot verify is worth nothing to the person relying on it.

## Provenance

Releases are published to PyPI via [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
— there is no long-lived API token in this repository — and each artifact carries a signed
[PEP 740](https://peps.python.org/pep-0740/) attestation naming the workflow that built it.

Every release also carries a CycloneDX SBOM. It is nearly empty, which is the whole point: this
package has no runtime dependencies, and the SBOM is that claim in a form a procurement process
can read without taking our word for it.
