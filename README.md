# ssrfguard

**SSRF protection that connects to the address it validated.**

Zero runtime dependencies, enforced by a test rather than by intent.

## Status

**Alpha.** The address table, the policy layer, resolution, the connection layer and all three
client surfaces (`httpx`, `httpx` async and `requests`) are built. The central claim is
demonstrated rather than argued: a DNS server on loopback moves a record between the validation
call and the connect call, and the connection lands on the address that was validated.

The classifier stays at `3 - Alpha`. The rebinding proof that no higher classifier was honest
without now exists, and there is no release yet.

## The problem

Every SSRF guard in Python validates a hostname and then hands the URL to an HTTP client that
resolves DNS a second time. The attacker moves the record in between. The guard validates an IP
it then discards; the connection re-resolves an unpinned hostname.

2026 alone produced this bug in `datamodel-code-generator` (CVE-2026-55391), `mcp-atlassian`
(CVE-2026-27826), `crewAI` (CVE-2026-62240), `mlflow`, AutoGPT, Craft CMS and `pydantic-ai`.

## The fix

Resolve once, validate every answer, and connect to that address, never to a name. The pinning
lives at the client's connection seam, so redirects, retries and pool refills all pass through
it, and the certificate is still verified against the *hostname*.

```python
from ssrfguard import Policy
from ssrfguard.httpx import Client

with Client(policy=Policy()) as client:
    client.get(untrusted_url)
```

`ssrfguard.httpx.AsyncClient` and `ssrfguard.requests.Session` are the same guarantee for the
async client and for `requests`. All three are ordinary clients of their libraries, so everything
they do goes through the same seam: redirects, retries, pooled connections. A proxy is refused
rather than silently bypassing it.

The async client resolves off the event loop. `getaddrinfo` blocks and has no timeout, so a
hostile nameserver that stalled a lookup on the loop would freeze every unrelated request in the
process. That is how a security library becomes an outage and then gets removed.

## Requirements

Python 3.10 or newer, and nothing else. The floor is 3.10 because that is the lowest interpreter
this project can fully verify: below it, `requests` and `urllib3` cap at releases older than the
connection seam was measured against, and mypy refuses to type-check the floor at all. Ubuntu
22.04 LTS ships 3.10 and is supported into 2027.

## Why zero dependencies

A capable library with a dependency tree is a procurement problem. A capable library without one
is a single approval.

`pip install ssrfguard` installs exactly one thing. The adapters live behind extras
(`ssrfguard[httpx]`, `ssrfguard[requests]`) and import their client lazily, so importing the
package never touches third-party code. This is checked two ways: `tests/test_zero_deps.py`
reads the built metadata, and the `zero-deps` CI lane installs the wheel alone into a clean
interpreter and fails if importing it loads anything that is not ours.

The SBOM attached to every release is nearly empty. That is the point.

## What this is not

**This is not a replacement for network egress control.** A library cannot stop a compromised
process from opening a socket, and claiming otherwise is how teams end up with one control where
they needed two. It also does not inspect application-layer traffic once a permitted host is
reached, and it does not bound DNS resolution time.

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) has the setup, how to run the lanes, and the handful of
things a review will send back. Two lines to start:

```sh
uv sync --frozen --all-extras
python scripts/lanes.py            # every lane, what it checks, whether it gates
```

**Found a vulnerability?** [`SECURITY.md`](SECURITY.md), not an issue.

## License

Apache-2.0.
