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

### Notes

- This table deliberately disagrees with `ipaddress.is_private` and `is_global` on 13 addresses,
  each enumerated with its reason and asserted to *still* disagree — so a CPython release that
  changes one fails the build instead of moving the answer silently. Twelve of the thirteen are
  addresses the strongest standard-library guard permits and this one refuses.

Nothing else is implemented yet. There is no release.
