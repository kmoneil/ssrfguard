# Errors

## The hierarchy

```
Exception
  SSRFGuardError                 catch this to catch every refusal
    BlockedURLError              a URL is not permitted, decided without resolving anything
    BlockedAddressError          an address is not permitted
    ProxyUnsupportedError        a proxy is configured and pinning cannot reach it
    TooManyRedirectsError        a chain exceeded the policy's own limit
```

All five import from the top level or from `ssrfguard.errors`:

```python
from ssrfguard import SSRFGuardError, BlockedURLError, BlockedAddressError
```

The `Error` suffix is a departure from the internal naming and is deliberate: PEP 8 asks for it
on anything that is an error condition, ruff's `N818` gates it, and a refused address is an error
condition.

## What each one means

### `BlockedURLError`

The URL as written is not permitted. Raised **before any name resolution happens**, so the
reason is always about the URL itself: its scheme, its authority, its port, its length, a control
character in it, or a host that is an encoded address. Never about where a hostname points.

```python
url: str      # the URL that was refused, as given
reason: str   # why, naming the rule that refused it
```

A URL that survives this can still be refused once its addresses are known, and that refusal is
a `BlockedAddressError` instead.

### `BlockedAddressError`

An IP address is not permitted by the policy. This is the one a **name** produces, because a
name has to be resolved before anything can be said about it.

```python
address: str  # the address that was refused, as text
reason: str   # why, naming the block and its RFC
```

### `ProxyUnsupportedError`

A proxy is configured, and a proxy resolves the target itself. Raised at client construction, not
at request time, so a misconfigured deployment fails on start-up.

```python
proxy: str    # the proxy that was configured, as text
```

### `TooManyRedirectsError`

A redirect chain exceeded the policy's own limit, which is counted by this package rather than by
the HTTP client.

```python
limit: int              # the configured maximum
chain: tuple[str, ...]  # the URLs walked, in order
```

At `max_redirects=0` this is raised by a single redirect **response**, even when following is
switched off at the client, because both clients build the next request in order to expose it and
the cap fires on the build.

## Handling them

The usual shape is one `except` at the boundary where an untrusted URL entered:

```python
from ssrfguard import SSRFGuardError

try:
    response = client.get(untrusted_url)
except SSRFGuardError as refused:
    log.warning("refused fetch: %s", refused)
    return HTTPResponse(400, "that URL is not reachable from here")
```

Distinguish them when the response differs:

```python
from ssrfguard import BlockedAddressError, BlockedURLError, TooManyRedirectsError

try:
    response = client.get(untrusted_url)
except BlockedURLError as refused:
    return problem("url-not-permitted", refused.reason)
except BlockedAddressError as refused:
    return problem("address-not-permitted", refused.reason)
except TooManyRedirectsError as refused:
    return problem("too-many-redirects", f"{len(refused.chain)} hops")
```

**Log the attributes, not the parsed message.** Every message is a whole sentence pinned by the
test suite, which is good for a human reading a log and bad as an interface. `refused.reason` and
`refused.address` are the parts to put in structured logging.

## What is deliberately not wrapped

Network errors from the underlying client are **not** turned into `SSRFGuardError`.

```python
try:
    client.get("https://host-that-is-down.example/")
except SSRFGuardError:
    ...          # does not fire
except httpx.ConnectError:
    ...          # this does
```

A connection that failed because the host was down is not a policy decision, and dressing it as
one would hide an outage behind a security message. The same applies to `socket.gaierror` from a
name that does not exist: that is the network's answer, not the policy's, and it propagates
unchanged.

The parity suite asserts this on all three surfaces, in both directions, so a future change
cannot quietly start swallowing outages.

## `connect` raises `TimeoutError` rather than `OSError` when it can

If you use [the building blocks](building-blocks.md) directly, `connect` raises:

- `BlockedAddressError` if any address it was handed is not permitted, immediately rather than
  skipping it. For a sequence that came from `resolve` this cannot happen, so it happening means
  the caller bypassed resolution, and that is exactly when a loud failure beats a quiet fallback.
- `TimeoutError` if **every** attempt timed out, so a caller with a retry or a circuit breaker
  gets the same answer an unguarded client would have given it.
- `OSError` otherwise, naming each address tried, what it failed with, and how many were left
  untried, with the last failure chained as the cause. A single refusal among the attempts makes
  it an `OSError` rather than a `TimeoutError`, because the refusal is the more informative of
  the two.
- `ValueError` if the sequence is empty, since `resolve` never returns an empty tuple.

## Errors that are not refusals

`Policy.__post_init__` raises `ValueError` for a configuration that cannot mean anything, at
construction rather than at the first request. `check_url` raises `TypeError` if handed something
that is not a string, and `check_address` raises `ValueError` if handed text that is not an IP
address, because that function never resolves anything and a hostname there is a programming
error rather than a policy question.

None of those is an `SSRFGuardError`, because none of them is a refusal. See
[Configuring a policy](policy.md#a-policy-that-cannot-mean-anything-is-refused-at-construction).

## Why the messages are so long

A refusal a user cannot act on gets configured around, and a control that gets configured around
protects nothing. So every message names **the value that was refused and which rule refused
it**, and where the rule has a legitimate escape hatch, the message names that too:

```
both.example is not permitted: resolves to both permitted and denied addresses; permitted:
93.184.216.34; denied: 169.254.169.254 (169.254.169.254/32 is Cloud metadata (AWS, GCP, Azure
IMDS) (RFC3927)). A name that resolves both ways is the signature of a DNS rebinding attempt
rather than of a misconfiguration, so on_partial_block='reject' refuses the whole name. Set
on_partial_block='drop' to use only the permitted answers, which is safe only if you know this
name
```

The test suite pins whole messages rather than matching substrings, which is why
`raises-require-match-for = []` is set in `pyproject.toml`. Expect to update tests when you
change one. [`examples/02_what_a_refusal_says.py`](../examples/02_what_a_refusal_says.py) prints
the gallery.
