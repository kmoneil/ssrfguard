# Why this exists

## The bug

Every SSRF guard in Python is three lines long and the third one is the vulnerability.

```python
address = socket.gethostbyname(urlparse(url).hostname)   # lookup 1
if is_private(address):                                  # validated ...
    raise Forbidden
return httpx.get(url)                                    # ... and discarded
```

The third line resolves the name **again**. Whatever the second line approved is not what the
third line connects to, and the gap between them is where an attacker's nameserver moves the
record. This is DNS rebinding, it is thirty years old, and it is still how the guard is beaten.

The guard was not wrong. The next line of code was.

2026 alone produced this bug in `datamodel-code-generator` (CVE-2026-55391), `mcp-atlassian`
(CVE-2026-27826), `crewAI` (CVE-2026-62240), `mlflow`, AutoGPT, Craft CMS and `pydantic-ai`. The
advisories describe it in their own words. mcp-atlassian: "the guard validates an IP it then
discards; the connection re-resolves an unpinned hostname". crewAI's `validate_url` "resolves and
blocklists the supplied hostname once, then returns the original URL string".

Same bug, seven times, in one year, in libraries written by people who knew what SSRF was.

## Why it keeps happening

Not because the check is hard. Because **the check and the connection are in different places**,
and nothing in the type system says they have to agree.

A validator that takes a URL and returns a URL is the most natural API in the world, and it is
structurally incapable of being correct. Whatever it validated is thrown away, and the thing it
hands back is an instruction to do the work again.

## The fix, and its one shape

Resolve once, validate every answer, and **connect to that address, never to a name.**

```
check_url(url) -> Target          no I/O; scheme, port, credentials, host shape, literal address
resolve(target) -> Address[]      exactly one lookup, every answer checked against the policy
connect(addresses) -> socket      no name in scope, so nothing to re-resolve
```

`connect` cannot resolve anything because it is not given anything to resolve. That is the whole
argument, and it is a property of the signature rather than a promise in a docstring.

Two supporting decisions follow from it.

**`check_url` returns a `Target`, not a URL.** A `Target` has a scheme, a host and a port, and no
path, no query, no `geturl()`, and a `repr` that is deliberately not a URL. Handing back
something an HTTP client would accept is the exact shape of every advisory above, so the type is
made awkward to misuse on purpose. `tests/test_target_is_not_a_url.py` keeps it awkward.

**The pinning lives at the client's connection seam**, not in a wrapper around `get()`. Redirects,
retries and pool refills all open connections, and all of them therefore pass through it, whether
or not anyone remembered they would. And because the seam is below the client rather than around
it, the certificate is still verified against the **hostname**, which is the thing that makes
pinning safe rather than a second hole.

## Where the seam is

| Client                        | Seam                                                               |
| ----------------------------- | ------------------------------------------------------------------ |
| `ssrfguard.httpx.Client`      | `httpcore.NetworkBackend.connect_tcp`, via `SafeBackend`           |
| `ssrfguard.httpx.AsyncClient` | `httpcore.AsyncNetworkBackend.connect_tcp`, via `AsyncSafeBackend` |
| `ssrfguard.requests.Session`  | `urllib3`'s pool classes, via `SafeAdapter`                        |

Each library's own connect path is **never entered**, which is asserted rather than assumed:
`test_the_clients_own_connect_path_is_never_entered` in `tests/test_adapter_parity.py` breaks
what would have to be used if the claim were false.

## The failures this prevents, and where each is proved

| Failure                                                                               | Proved by                                                                                                                                            |
| ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| A record that moves between validation and connection moves the connection            | `tests/test_rebinding.py::test_the_connection_lands_on_the_validated_address_after_the_record_moves`, against a real nameserver on a real UDP socket |
| Pinning is really just "preferring whichever answer looked public"                    | `tests/test_rebinding.py::test_pinning_is_not_merely_preferring_a_public_address`                                                                    |
| A nameserver that flips on every single query eventually wins                         | `tests/test_rebinding.py::test_a_nameserver_that_flips_on_every_query_cannot_move_the_connection`                                                    |
| Connecting quietly asks the nameserver something                                      | `tests/test_rebinding.py::test_connecting_asks_the_nameserver_nothing`                                                                               |
| The vulnerable pattern is not actually vulnerable, so the fixture proves nothing      | `tests/test_rebinding.py::test_the_vulnerable_pattern_reaches_the_metadata_endpoint`                                                                 |
| An address reaches TLS as `server_hostname`, silently disabling hostname verification | `tests/test_adapter_parity.py::test_the_handshake_carries_the_hostname_and_never_the_address`, read off the wire from a server-side SNI callback     |
| Pinning loosens certificate checking as a side effect                                 | `test_a_certificate_issued_to_another_name_is_still_refused`, `test_an_untrusted_authority_is_still_refused`                                         |
| The `Host:` header leaks the pinned address instead of the name                       | `test_the_host_header_is_the_hostname_and_not_the_pinned_address`                                                                                    |
| A pooled connection is silently re-resolved                                           | `test_a_pooled_second_request_asks_nothing`                                                                                                          |
| A later connection inherits the first one's blessing                                  | `test_every_new_connection_is_validated_on_its_own_merits`                                                                                           |
| An encoded address slips past the host check                                          | `tests/test_encodings.py`, which refuses every form twice, at the URL layer and again at resolution                                                  |
| A name resolving both ways is quietly accepted                                        | `test_a_name_resolving_both_ways_is_refused_whole`                                                                                                   |
| A custom table reaches a branch that fails open                                       | `tests/test_fail_closed.py`, which is the set of branches only a custom table can reach                                                              |
| A `Target` can be turned back into a URL                                              | `tests/test_target_is_not_a_url.py`                                                                                                                  |
| A runtime dependency appears                                                          | `tests/test_zero_deps.py` against the built metadata, and the `zero-deps` lane against a wheel in a clean interpreter                                |
| The two client seams drift apart                                                      | `tests/test_adapter_parity.py`, one matrix over all three surfaces, with the three genuine asymmetries named and pinned                              |

A prevention claim without a test is a rumour. Every row above names the test, and
`python scripts/lanes.py` prints every lane, what it checks and whether it gates.

## Why zero dependencies

A capable library with a dependency tree is a procurement problem. A capable library without one
is a single approval.

`pip install ssrfguard` installs exactly one thing. The adapters live behind extras and import
their client lazily, so importing the package never touches third-party code. This is checked two
ways: `tests/test_zero_deps.py` reads the built metadata, and the `zero-deps` lane installs the
wheel alone into a clean interpreter and fails if importing it loads anything that is not ours.

The isolation is what makes the lane a lane rather than a flag. A development checkout has both
clients installed, so it cannot see an adapter that imports eagerly; only a clean interpreter
can.

The SBOM attached to every release is nearly empty. That is the point.

## What this is not

**This is not a replacement for network egress control.** A library cannot stop a compromised
process from opening a socket, and claiming otherwise is how teams end up with one control where
they needed two. Run both. This one is the cheap one, and it fails closed with a message naming
what it refused, which is what makes it useful in the ninety percent case that is a bug rather
than an intruder.

It also:

- does not inspect application-layer traffic once a permitted host is reached,
- does not bound DNS resolution time on the synchronous path,
- does not guard a request made by anything that is not one of its clients, including a
  `subprocess` call to `curl` or a second HTTP client in the same process,
- does not survive an adapter you mounted over ours.

Each of those is in `SECURITY.md` under what is and is not in scope, which is the document to
read before reporting something.

## An address wrongly refused is a bug too

A guard with false positives gets removed, and a removed control protects nothing. So the address
table is not "everything that looks internal": it is the IANA registries, plus a small set of
documented departures, and half of those departures exist to prevent a wrong **deny** rather than
a wrong allow. `::ffff:93.184.216.34` is an ordinary public address written oddly, and it is
permitted.

Both directions are worth reporting as bugs. See
[The address table](address-table.md#where-the-table-departs-from-iana-and-why).

## How this was built

**This library was built with AI assistance.** This work is a collaboration between human writing
and AI generation. It was directed, reviewed, and accepted by a human author who takes full
responsibility for the final result.

Humans and models produce slop in roughly equal measure. Neither one is the reason software is
good or bad. What decides that is the verification: what is actually tested, what is measured
against a real system instead of recalled, and which claims something would catch if they stopped
being true.

So the rules here are aimed at that, and they are enforced rather than professed. The failure
mode worth designing against is **confident plausibility**: an address block recalled from memory
looks exactly like one read out of a registry, and a docstring describing a refusal reads exactly
like a refusal somebody tested.

- **The address table is generated from IANA**, not typed, and the `egress` lane refetches and
  compares. Every departure carries a `note` saying why.
- **The central claim is demonstrated against a real nameserver on a real socket**, because a
  Python callable standing in for a resolver is structurally incapable of demonstrating it.
- **The vulnerable pattern is in the suite too**, and a test asserts it _does_ reach the metadata
  endpoint. A fixture that cannot catch the bug proves nothing about the fix.
- **The examples are executed by the suite**, so a documented snippet that stopped working fails
  a build rather than misleading a reader.
- **Coverage is measured as branches**, at 99%, because an untested branch in an address table is
  an address nobody has ever asked about, and statement coverage cannot see one.
- **Refusal messages are pinned whole**, not matched by substring, because the message is the
  part a user acts on.

None of that makes the code correct. It makes the claims checkable, which is the part you cannot
verify by reading a diff.
