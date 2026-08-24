# What it costs

Every check this package makes sits in front of somebody's outbound request, so the price is a
fair thing to ask about before installing it.

**Quoting a single headline number would be the wrong way to answer**, because it would be wrong
on your hardware the moment you read it. The shape is stable and is the useful part.

## The shape

> **The URL check runs once per request. Resolution and the address check run once per
> connection.**

So the per-request cost is one `check_url`, and everything expensive is amortised over a
connection's lifetime. A service making a hundred requests over a pooled connection pays for one
resolution and a hundred URL checks.

## The numbers

| Measured                                                     | Per call |
| ------------------------------------------------------------ | -------- |
| `check_url`, ordinary hostname                               | 4.2 us   |
| `check_url`, literal IPv4                                    | 9.0 us   |
| `check_url`, internationalised name                          | 20.9 us  |
| `check_url`, the most expensive URL a default policy accepts | 560 us   |
| `import ssrfguard`, over an empty interpreter                | 19 ms    |

Python 3.13 on aarch64, CPU time on the calling thread.

For comparison, httpx spends roughly 170 microseconds of its own CPU on a request over loopback,
so an ordinary check is a couple of percent of that, and nothing measurable at all against a
request that crosses a network.

```sh
python scripts/lanes.py cost
```

That prints the numbers for your hardware, with the environment that produced them.

## Three things worth knowing before you meet them

**An internationalised name costs about five times an ASCII one.** CPython's `idna` codec runs
nameprep per label in pure Python. The faster alternative is a dependency, and this package does
not take dependencies.

**The most expensive URL a default policy will accept costs about 130 times an ordinary one.**
Two ceilings bound it and it takes both. `max_url_length` counts characters of URL, and the cost
is in characters of _host_, which is capped separately at the 253 that DNS can carry.

The second ceiling is the one that matters and it is why the first is not enough on its own: the
`idna` arm runs at roughly 250 times the price of the ASCII scan, per character, once per label.
A URL sitting comfortably inside 8192 could otherwise carry 389 non-ASCII labels, cost 14.9
milliseconds, be accepted, and then be handed to a lookup that could never succeed.

**The async client's lookups are bounded by its own pool.** `resolver_slots` defaults to the
connection pool's `max_connections`. A held lookup cannot be cancelled, so past that number a
_new_ name waits; connections already open are unaffected. See
[The clients](clients.md#the-async-client).

## Linearity, and what it is not

`check_url` is strictly linear on both paths: doubling the input doubles the time, measured
across four octaves. The hostname pattern cannot backtrack because every repetition in it must
consume a literal dot.

`max_url_length` is therefore a **ceiling, not a ReDoS fix**. What the scan did not have was a
bound: re-measured 2026-08-23 on 3.13, the ASCII scan costs about 7 nanoseconds per character and
the non-ASCII path about 1785 per character _of host_, so a 10 MB URL was about 19 CPU-seconds of
one worker. `SECURITY.md` says any way one request can consume wall-clock without a ceiling is in
scope, and this had none.

The linearity is no longer argued from the regex alone. `tests/test_cost.py` measures an 8 KiB
URL against a 1 KiB one and fails if the ratio approaches what quadratic scanning would produce.

## None of these numbers is a promise

What is enforced is in `tests/test_cost.py`, and **none of it is a stopwatch**. A threshold in
microseconds is a threshold about the machine that ran it, which is how a suite acquires a test
that fails on a busy CI runner and gets marked flaky and then deleted.

Two of the three assertions compare one measurement to another taken in the same run. The third
counts calls and holds no clock at all.

## What is not bounded

**DNS resolution time, with the default resolver.** `socket.getaddrinfo` has no timeout and
`socket.setdefaulttimeout` does not apply to it, so a hostile authoritative nameserver can stall
a lookup for as long as it likes. `SECURITY.md` has this as out of scope for the *default*: it
holds up the caller that made it and nobody else, and supervising it is the caller's job.
[`UdpResolver`](resolvers.md) bounds it and is one constructor argument away.

On the async path it is bounded by `resolver_slots`, which is the difference between a limit and
an outage.

**Connection time for one hop** is bounded by `timeout * max_connection_attempts`, because
`timeout` is per attempt. See [the attempt cap](policy.md#the-attempt-cap) for why the cap
exists.

**Connection time for one request is that multiplied by the hops**, and it is the number worth
knowing because it is the one a caller does not compute. A redirect chain is this package's own,
counted by `max_redirects` rather than by the client, and every hop is a fresh name, a fresh
resolution and a fresh connection that gets the whole per-hop budget again:

```
attempts per request  =  (max_redirects + 1) * max_connection_attempts
                      =  (5 + 1) * 4
                      =  24
```

**Measured rather than derived.** `tests/test_adapter_redirects.py` walks a chain whose every hop
answers with dead addresses and one live one, counts the sockets opened, and holds all three
clients to that product. It is a count rather than a duration, so it gates on any runner.

Twenty-four times the timeout a caller asked for is a large number to arrive at by multiplying
two small ones, which is the reason it is written here. It is a *bound* rather than a hole: both
factors are configurable, and a caller who wants it tighter turns one of them down. At
`max_redirects=1` it is eight.

## Memory, and what is held

The address table is 60 rows, built once at import and shared by every policy that does not
replace it. It is indexed by address family at construction, so a lookup does not walk sixty
networks.

`AddressTable.__repr__` renders a count rather than sixty blocks, and
`tests/test_fail_closed.py::test_a_table_renders_as_a_count_rather_than_as_sixty_blocks` asserts
it. A table that spelled itself out in every traceback would be its own problem for a log sink.

Sockets and file descriptors are what this package can actually leak, so that is what is checked:
the `leaks` lane runs the whole suite again with a leak-check plugin armed. It is a separate lane
rather than a flag on `fast`, because a library that opens sockets for a living should not make
the gating lane pay for the check on every run.

```sh
python scripts/lanes.py leaks
```
