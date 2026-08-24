# ssrfguard

**SSRF protection that connects to the address it validated.**

Every other SSRF guard in Python validates a hostname and then hands the URL to an HTTP client
that resolves DNS a second time. The attacker moves the record in between. This one resolves
once, validates every answer, and connects to that address, never to a name.

[![PyPI](https://img.shields.io/pypi/v/ssrfguard)](https://pypi.org/project/ssrfguard/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](#requirements)
[![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](#why-zero-dependencies)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

```console
pip install "ssrfguard[httpx]"      # or ssrfguard[requests], or both
```

[Status](#status) says what is and is not done, and [`CHANGELOG.md`](CHANGELOG.md) says what has
moved. [Examples](#examples) has the two commands for running the nine examples from a clone.

```python
from ssrfguard import Policy
from ssrfguard.httpx import Client

with Client(policy=Policy()) as client:
    response = client.get(untrusted_url)
```

That is the whole of it. **There is nothing to remember to call**: no `validate_url_first()`, no
decorator, no middleware ordering. `Client` is an `httpx.Client`, so verbs, headers, timeouts,
streaming and pooling all behave the way they already do, and the check happens at the seam where
a socket is opened. Redirects, retries and pool refills go through it whether or not anyone
thought about them.

`ssrfguard.httpx.AsyncClient` and `ssrfguard.requests.Session` are the same guarantee for the
async client and for `requests`.

**Jump to:** [The problem](#the-problem) &nbsp;·&nbsp; [What you get](#what-you-get)
&nbsp;·&nbsp; [Documentation](#documentation) &nbsp;·&nbsp; [Examples](#examples)
&nbsp;·&nbsp; [What it costs](#what-it-costs) &nbsp;·&nbsp; [Status](#status)

## The problem

An SSRF guard is three lines long and the third one is the vulnerability.

```python
address = socket.gethostbyname(urlparse(url).hostname)   # lookup 1
if is_private(address):                                  # validated ...
    raise Forbidden
return httpx.get(url)                                    # ... and discarded
```

The third line resolves the name **again**. Whatever the second line approved is not what the
third line connects to, and the gap between them is where the record moves.

2026 alone produced this bug in `datamodel-code-generator` (CVE-2026-55391), `mcp-atlassian`
(CVE-2026-27826), `crewAI` (CVE-2026-62240), `mlflow`, AutoGPT, Craft CMS and `pydantic-ai`. The
advisories describe it in their own words. mcp-atlassian: "the guard validates an IP it then
discards; the connection re-resolves an unpinned hostname."

Same bug, seven times, in one year, in libraries written by people who knew what SSRF was. It
keeps happening because a validator that takes a URL and returns a URL is the most natural API in
the world and is structurally incapable of being correct.

## The fix

```
check_url(url) -> Target          no I/O; scheme, port, credentials, host shape, literal address
resolve(target) -> Address[]      exactly one lookup, every answer checked against the policy
connect(addresses) -> socket      no name in scope, so nothing to re-resolve
```

**`connect` cannot resolve anything, because it is not given anything to resolve.** That is a
property of the signature rather than a promise in a docstring, and it is the whole argument.

The pinning lives at the client's connection seam rather than in a wrapper around `get()`, so the
certificate is still verified against the **hostname**. Pinning that reached TLS as an IP would
silently disable hostname verification and trade an SSRF hole for a worse one; the suite reads
the SNI off the wire to prove it does not.

## What you get

|                                                           |                                                                                                                                                                |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **One lookup per connection, and the socket lands on it** | Proved against a real nameserver on a real UDP socket that moves its record mid-request, not against a Python stub that cannot                                 |
| **Three drop-in clients**                                 | `httpx`, `httpx` async and `requests`. Ordinary subclasses, so redirects, retries and pooling all pass through the same seam                                   |
| **Refusals you can act on**                               | Every message names the value **and** the rule that refused it. Whole messages are pinned by tests, because a refusal nobody can act on gets configured around |
| **An address table generated from IANA**                  | 60 rows, refreshed by a script and re-fetched in CI. Wrappers such as `::ffff:169.254.169.254` and `64:ff9b::a9fe:a9fe` are decoded rather than answered about |
| **Encoded hosts refused twice**                           | `0177.0.0.1`, `2130706433`, `127.1`, circled digits. Refused at the URL layer, and again at resolution wherever the platform's resolver decodes them                                                          |
| **Redirects counted by the policy**                       | Not by the client, whose limit exists to stop loops. Every hop re-checked; credentials dropped when the origin changes                                         |
| **A proxy is refused, not silently bypassed**             | A proxy resolves the target itself, so pinning cannot reach it. Saying so beats leaving you believing in a control that stopped running                        |
| **Zero runtime dependencies**                             | Enforced by a test against the built metadata, and by a lane that installs the wheel alone into a clean interpreter                                            |

## Documentation

Start with **[Getting started](docs/getting-started.md)**. After that the guides are shaped by
task rather than by module.

| Guide                                                | What is in it                                                                                                              |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| [Getting started](docs/getting-started.md)           | Install, your first request, what the default policy does, what a refusal looks like                                       |
| [Configuring a policy](docs/policy.md)               | Every field and its default, reaching your own internal services, partial answers, redirects, proxies                      |
| [The clients](docs/clients.md)                       | The three surfaces, why they are clients and not transports, TLS, the async resolver pool, and the three named asymmetries |
| [Errors](docs/errors.md)                             | The hierarchy, what each carries, how to handle them, and what is deliberately not wrapped                                 |
| [Using the pieces directly](docs/building-blocks.md) | `check_url` / `resolve` / `connect` for a protocol this package ships no client for, including the correct TLS wrap        |
| [The address table](docs/address-table.md)           | What is in it, how a wrapper is decoded, building your own, and every place it departs from IANA                           |
| [Resolvers](docs/resolvers.md)                       | `getaddrinfo` has no timeout; a resolver that does, what it does not know in exchange, and why half an answer is refused |
| [Watching what it decides](docs/observing.md)        | Reporting every permit and refusal to an observer, the four stages, and why a broken sink cannot fail a request |
| [What it costs](docs/cost.md)                        | The measured numbers, the shape that matters more, and what is not bounded                                                 |
| [Why this exists](docs/architecture.md)              | The bug, the fix, and the failures this prevents with the test that proves each one                                        |
| [Threat model](docs/threat-model.md)                 | What an attacker controls, what meets each capability, and the residual risk stated in detail                              |

## Examples

**[`examples/`](examples/README.md) is the other half of the documentation**, and it is executed
rather than described: nine runnable files, each of which works with **no arguments**, no network
and no fixtures, and every one is run by the test suite.

```sh
git clone https://github.com/kmoneil/ssrfguard && cd ssrfguard
uv sync --frozen --all-extras
.venv/bin/python examples/03_the_pin.py
```

[`03_the_pin.py`](examples/03_the_pin.py) is the one to run first. It stands up a nameserver that
answers honestly once and then moves the record to the metadata endpoint, and shows the three
things that happen:

```
1. Validated, then connected, with the record moving in between
  check_url  -> <Target http host=inside.example port=42165>
  resolve    -> ['127.0.0.1:42165 (via inside.example)']   (lookups: 1)
  ... the nameserver now answers 169.254.169.254 for that name ...
  connect    -> peer 127.0.0.1   (lookups: 1)

2. The same seam, inside a client, over three requests
  request 1: 200 'ok'   (lookups: 1)
  request 2: 200 'ok'   (lookups: 1)
             the pool reused the connection, so nothing was resolved
  request 3: BlockedAddressError: 169.254.169.254 is not permitted: 169.254.169.254/32 is
             Cloud metadata (AWS, GCP, Azure IMDS) (RFC3927)
```

The rest cover refusal messages, policy recipes, the async client, `requests`, redirects, the
building blocks and the address table. [`examples/README.md`](examples/README.md) is the index.

## What it costs

> **The URL check runs once per request. Resolution and the address check run once per
> connection.**

So the per-request cost is one `check_url`, and everything expensive is amortised over a
connection's lifetime.

| Measured                                                     | Per call |
| ------------------------------------------------------------ | -------- |
| `check_url`, ordinary hostname                               | 4.2 us   |
| `check_url`, literal IPv4                                    | 9.0 us   |
| `check_url`, internationalised name                          | 20.9 us  |
| `check_url`, the most expensive URL a default policy accepts | 560 us   |
| `import ssrfguard`, over an empty interpreter                | 19 ms    |

Python 3.13 on aarch64, CPU time on the calling thread. httpx spends roughly 170 microseconds of
its own CPU on a request over loopback, so an ordinary check is a couple of percent of that and
nothing measurable against a request that crosses a network. `python scripts/lanes.py cost`
prints the numbers for your hardware.

**None of these is a promise.** What is enforced is in `tests/test_cost.py`, and none of it is a
stopwatch: two of the three assertions compare one measurement to another taken in the same run,
and the third counts calls and holds no clock at all. [What it costs](docs/cost.md) has the three
surprises worth knowing about before you meet them.

## Requirements

**Python 3.10 or newer, and nothing else.**

The floor is 3.10 because that is the lowest interpreter this project can fully verify: below it,
`requests` and `urllib3` cap at releases older than the connection seam was measured against, and
mypy refuses to type-check the floor at all. Ubuntu 22.04 LTS ships 3.10 and is supported into 2027.

## Why zero dependencies

A capable library with a dependency tree is a procurement problem. A capable library without one
is a single approval.

`pip install ssrfguard` installs exactly one thing. The adapters live behind extras
(`ssrfguard[httpx]`, `ssrfguard[requests]`) and import their client lazily, so importing the
package never touches third-party code. This is checked two ways: `tests/test_zero_deps.py` reads
the built metadata, and the `zero-deps` lane installs the wheel alone into a clean interpreter
and fails if importing it loads anything that is not ours.

The SBOM attached to every release is nearly empty. That is the point.

## What this is not

**This is not a replacement for network egress control.** A library cannot stop a compromised
process from opening a socket, and claiming otherwise is how teams end up with one control where
they needed two. Run both; this is the cheap one, and it fails closed with a message naming what
it refused, which is what makes it useful in the case that is a bug rather than an intruder.

It also does not inspect application-layer traffic once a permitted host is reached, does not
bound DNS resolution time on the synchronous path, and does not guard a request made by anything
that is not one of its clients. [`SECURITY.md`](SECURITY.md) has the scope in full.

**An address wrongly refused is a bug too.** A guard with false positives gets removed, and a
removed control protects nothing. Both directions are worth reporting.

## Status

**0.3.0.** The address table, the policy layer, resolution, the connection layer and all three
client surfaces are built. The central claim is demonstrated rather than argued: a DNS server on
loopback moves a record between the validation call and the connect call, and the connection
lands on the address that was validated.

**0.2.0 added a lookup with a deadline and an observer.** [`UdpResolver`](docs/resolvers.md)
gives a lookup a deadline, which `getaddrinfo` cannot be given, and closes the denial-of-service
surface `SECURITY.md` used to document as simply known. [An observer](docs/observing.md) makes
every permit and refusal something a caller can see, where before a decision survived only by
being raised and only if nobody caught it.

**0.3.0 adds the narrowing that was missing and the detection that was silent**, both opt-in,
both leaving the defaults where they were. [`allowed_hosts`](docs/policy.md) is how a fetcher
says it only ever talks to two APIs, which is the strongest control here and had no expression
before. [`RebindingWatch`](docs/observing.md) says when a name resolved somewhere else, which
this package has always survived and never mentioned.

**And it writes down which promise this package makes.** It guards the connection; the fetch
around it is not ours. [`SECURITY.md`](SECURITY.md) says so with the alternative it was chosen
over, and `tests/test_scope.py` fails if the boundary erodes.

**There is still no maturity label, and that is a decision rather than a deferral.** The package
carried `3 - Alpha` while the rebinding proof was missing, which was the one claim worth
withholding; the proof exists, so keeping it would have asserted a maturity rather than withheld
one. Promoting it to `4 - Beta` would swap one unearned claim for another. What is true instead
is measurable and is on this page: 1102 tests, 100% branch coverage, ten gating lanes, a mutation
register of 166 survivors the suite is held against, and **no independent audit**. A reader can
weigh those. A one-word classifier only asks them to take our word for something.

**0.3.0 rather than 1.0.0**, because the API may still move. Nothing here is known to be wrong;
the number is about what we are willing to promise not to change.
[`CHANGELOG.md`](CHANGELOG.md) has what has moved.

## How this was built

**This library was built with AI assistance.** This work is a collaboration between human writing
and AI generation. It was directed, reviewed, and accepted by a human author who takes full
responsibility for the final result.

Humans and models produce slop in roughly equal measure. What decides whether software is good is
the verification: what is actually tested, what is measured against a real system instead of
recalled, and which claims something would catch if they stopped being true. The failure mode
worth designing against is **confident plausibility**, and
[Why this exists](docs/architecture.md#how-this-was-built) says what is done about it here.

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
