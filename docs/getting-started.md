# Getting started

## Install

```sh
pip install "ssrfguard[httpx]"      # or ssrfguard[requests], or both
```

**This package is not on PyPI yet**, so that command is what it will be rather than what works
today. Until the first release, clone the repository:

```sh
git clone https://github.com/kmoneil/ssrfguard && cd ssrfguard
uv sync --frozen --all-extras
```

`ssrfguard` itself has **no runtime dependencies**. The extra pulls in the HTTP client you
already use; it does not pull in anything else. If you install the bare package you get the
policy layer, the address table, resolution and the connection layer, and no client adapters.

Python 3.10 or newer. Nothing else.

## Your first request

```python
from ssrfguard import Policy
from ssrfguard.httpx import Client

with Client(policy=Policy()) as client:
    response = client.get(untrusted_url)
```

That is the whole of it. `ssrfguard.httpx.Client` is a subclass of `httpx.Client`, so every verb,
every header, every timeout, `follow_redirects`, streaming, pooling and `Response` all behave the
way they already do. The one difference is where it connects.

**There is nothing to remember to call.** No `validate_url_first()`, no decorator, no middleware
ordering. The check happens at the seam where the client opens a socket, which means redirects,
retries and pool refills all pass through it whether or not you thought about them.

The other two surfaces are the same guarantee:

```python
from ssrfguard.httpx import AsyncClient        # httpx, async
from ssrfguard.requests import Session         # requests
```

## What the default policy does

`Policy()` with no arguments is deny-by-default and is what a webhook fetcher, a URL-preview
service or an avatar importer should want:

|                        | Default                                                                                                                                                         |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Schemes                | `http`, `https`                                                                                                                                                 |
| Ports                  | `80`, `443`                                                                                                                                                     |
| Addresses              | Everything IANA marks special-purpose is denied: loopback, RFC 1918, link-local, carrier-grade NAT, unique-local, the cloud metadata endpoints, and 50-odd more |
| Credentials in the URL | Refused                                                                                                                                                         |
| Redirects              | 5 hops, each one fully re-checked                                                                                                                               |
| Proxies                | Refused, because a proxy resolves the target itself                                                                                                             |

Change nothing until something breaks. When something does,
[Configuring a policy](policy.md) is the field-by-field guide, and every refusal message names
the field that refused, so you can usually go straight to it.

## What a refusal looks like

```python
>>> Policy().check_url("http://169.254.169.254/latest/meta-data/")
ssrfguard.errors.BlockedURLError: 'http://169.254.169.254/latest/meta-data/' is not permitted:
169.254.169.254/32 is Cloud metadata (AWS, GCP, Azure IMDS) (RFC3927)
```

Every refusal names **the value that was refused and the rule that refused it**. That is not
politeness. A refusal a user cannot act on gets configured around, and a control that gets
configured around protects nothing.

Catch them all with the base class:

```python
from ssrfguard import SSRFGuardError

try:
    response = client.get(untrusted_url)
except SSRFGuardError as refused:
    log.warning("refused %s", refused)
    return 400
```

`SSRFGuardError` catches everything this package refuses and nothing it does not. A connection
that failed because the host was down stays an `httpx.ConnectError`, because an outage is not a
policy decision and dressing it as one sends people hunting for a security problem they do not
have. [Errors](errors.md) has the hierarchy and the attributes each one carries.

## The one thing worth understanding

A URL check is **necessary and not sufficient**, and this package is shaped around that sentence.

```python
>>> Policy().check_url("http://metadata.google.internal/")
<Target http host=metadata.google.internal port=80>
```

That URL is permitted. It points at the GCP metadata endpoint. Nothing in the policy layer
resolves anything, so nothing in the policy layer can know that; the address check happens when
the name is resolved, one layer down, and that is where this one is refused.

Which is why `check_url` returns a `Target` rather than a URL. A `Target` carries a scheme, a
host and a port, and nothing else. No path, no query, no `geturl()`, and its `repr` is
deliberately not a URL. Handing back something an HTTP client would accept is the exact shape of
every advisory this package exists to answer: the guard validates, returns a URL, and the next
line of code resolves the name a second time.

If you are using one of the three clients you will never see a `Target`. If you are using the
building blocks directly, [Using the pieces directly](building-blocks.md) is the guide.

## Try it

Nine runnable examples, none of which need a network:

```sh
git clone https://github.com/kmoneil/ssrfguard && cd ssrfguard
uv sync --frozen --all-extras
.venv/bin/python examples/03_the_pin.py
```

[`examples/03_the_pin.py`](../examples/03_the_pin.py) is the one to run first. It stands up a
nameserver that moves its record between validation and connection, which is a DNS rebinding
attack in five lines, and shows what happens. [`examples/README.md`](../examples/README.md) is
the index.

## Where to go next

| If you want to                                | Read                                            |
| --------------------------------------------- | ----------------------------------------------- |
| Decide what to configure                      | [Configuring a policy](policy.md)               |
| Know what each client does and does not cover | [The clients](clients.md)                       |
| Handle refusals well                          | [Errors](errors.md)                             |
| Reach something that is not HTTP              | [Using the pieces directly](building-blocks.md) |
| Change what counts as a denied address        | [The address table](address-table.md)           |
| Know what it costs per request                | [What it costs](cost.md)                        |
| Understand why it is built this way           | [Why this exists](architecture.md)              |
