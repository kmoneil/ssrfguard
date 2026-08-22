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
- `BlockedURLError`, `ProxyUnsupportedError` and `TooManyRedirectsError` complete the hierarchy.
  The last two are raised by layers not built yet; they exist now so that every current
  `except SSRFGuardError` already covers them.

### Notes

- This table deliberately disagrees with `ipaddress.is_private` and `is_global` on 13 addresses,
  each enumerated with its reason and asserted to *still* disagree — so a CPython release that
  changes one fails the build instead of moving the answer silently. Twelve of the thirteen are
  addresses the strongest standard-library guard permits and this one refuses.

Nothing else is implemented yet. There is no release.
