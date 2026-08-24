# Examples

**Every file here runs with no arguments, no network and no fixtures**, and every one of them is
executed by the test suite, so an example that stops working fails a build rather than
misleading a reader. If you would rather read code than prose, start here instead of in
[`docs/`](../docs/).

```sh
uv sync --frozen --all-extras
.venv/bin/python examples/03_the_pin.py
```

Run the lot:

```sh
for f in examples/0*.py; do .venv/bin/python "$f"; done
```

## The files

| Example                                                  | What it shows                                                                                                                                                                    |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`01_first_request.py`](01_first_request.py)             | The whole library in twelve lines: a policy, a client, a request. Then the same client refusing the four URLs it exists to refuse.                                               |
| [`02_what_a_refusal_says.py`](02_what_a_refusal_says.py) | Every refusal message, grouped. Loopback and metadata, the encoded forms of both, schemes and ports and credentials, and the URLs that would parse differently somewhere else.   |
| [`03_the_pin.py`](03_the_pin.py)                         | **The claim on the front of the package, run rather than argued.** A nameserver that moves its record between validation and connection, and the three things that happen.       |
| [`04_policy_recipes.py`](04_policy_recipes.py)           | Six policies for six jobs, each run against the same probe set so the table shows the difference a field makes. Plus the policies that are refused at construction.              |
| [`05_async_client.py`](05_async_client.py)               | `AsyncClient`, concurrency, and a measured demonstration that a lookup blocking for 250 ms does not stop the event loop. `resolver_slots` and where its default comes from.      |
| [`06_requests_session.py`](06_requests_session.py)       | `requests.Session`, the adapter on its own, and the silent failure of mounting it on one scheme.                                                                                 |
| [`07_redirects.py`](07_redirects.py)                     | A hop to the metadata endpoint refused at the hop; the chain cap, including what `max_redirects=0` means; and which headers survive a crossing, measured at the second origin.   |
| [`08_building_blocks.py`](08_building_blocks.py)         | `check_url` / `resolve` / `connect` by hand, for a protocol this package ships no client for. Includes the correct TLS wrap and why the wrong one is worse than no guard at all. |
| [`09_address_table.py`](09_address_table.py)             | What is in the table, how a wrapper is decoded, longest-prefix-wins, and how to extend or replace it.                                                                            |

[`_support.py`](_support.py) is the scaffolding the examples share: a loopback HTTP server and a
scripted resolver, about forty lines of standard library. **Nothing in it is part of the
package.** `ssrfguard` ships no test server and no resolver.

## Reading order

`01`, then `03`. Those two are the argument. After that go wherever your problem is: `04` if you
are deciding what to configure, `05` or `06` if you are not on synchronous httpx, `08` if you
need to reach something that is not HTTP.

## Why a resolver can be handed in

Six of these examples pass a `resolver=` to a client or to `resolve`. That is a supported
argument on every surface, not a test hook, and the reason it is safe is worth stating: **every
address a resolver returns is validated before it is used.** A resolver that lies about where a
name points buys nothing, which is what makes it a reasonable thing to accept from a caller.

The one thing carried through unchecked is the _port_ in the answer, because `getaddrinfo` echoes
the port it was handed and the two can only disagree for a stand-in you installed yourself.

## What these cannot show

A stand-in resolver cannot change its mind between two calls that a single `resolve` brackets,
because there is only one call to change it between. So `03_the_pin.py` demonstrates the shape of
the mechanism and the lookup count that gives it away, and it says so in its own docstring.

The end-to-end proof runs against a real DNS server on a real UDP socket in
`tests/test_rebinding.py`: a test resolves a name, moves the record in the server's own answer
table, connects, and fails if anything looked the name up a second time. That is the `rebind`
lane, and `python scripts/lanes.py rebind` runs it.
