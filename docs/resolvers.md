# Resolvers

**`socket.getaddrinfo` has no timeout, and `socket.setdefaulttimeout` does not reach it.** A
hostile authoritative server can hold a lookup for as long as the platform's own configuration
allows, and nothing in this package could shorten it, because the lookup was never ours.

`ssrfguard.resolvers.UdpResolver` is the other choice. It speaks DNS over a datagram socket this
package owns, so a deadline is a `settimeout` call rather than a wish.

```python
from ssrfguard import Policy
from ssrfguard.httpx import Client
from ssrfguard.resolvers import UdpResolver

with Client(policy=Policy(), resolver=UdpResolver(timeout=2.0)) as client:
    response = client.get(untrusted_url)
```

**This adds no API.** `resolver=` has been a constructor argument on all three clients since
0.1.0, and `Resolver` has always been the shape of `socket.getaddrinfo`. What was missing was
something to pass. Nothing in [the clients](clients.md), [`resolve`](building-blocks.md) or the
policy layer changes, and every address this returns is still validated by the policy before
anything connects to it, so installing it grants nothing.

It works the same way everywhere a resolver is accepted:

```python
from ssrfguard.httpx import AsyncClient
from ssrfguard.requests import Session

AsyncClient(policy=Policy(), resolver=UdpResolver(timeout=2.0))
Session(policy=Policy(), resolver=UdpResolver(timeout=2.0))
resolve(target, policy=Policy(), resolver=UdpResolver(timeout=2.0))
```

**Jump to:** [Every field](#every-field) &nbsp;·&nbsp; [What it does not know](#what-it-does-not-know)
&nbsp;·&nbsp; [Why half an answer is refused](#why-half-an-answer-is-refused)
&nbsp;·&nbsp; [What is bounded and what is cancellable](#what-is-bounded-and-what-is-cancellable)

## It is not the default, and should not be

`socket.getaddrinfo` stays the default because it knows things this does not, and the list is in
[What it does not know](#what-it-does-not-know). Choosing this resolver is choosing a bound over
that knowledge. That is a good trade for a service fetching URLs a stranger chose, and a bad one
for a program that resolves names out of its own `/etc/hosts`.

## Every field

| Field              | Default                 | What it does                                                                                         |
| ------------------ | ----------------------- | ---------------------------------------------------------------------------------------------------- |
| `nameservers`      | from `/etc/resolv.conf` | Addresses of the recursive resolvers to ask, in order, until one answers. Addresses, never names     |
| `timeout`          | `5.0`                   | **The ceiling on one call**, covering every query, retry and TCP fallback, on a monotonic clock       |
| `attempt_timeout`  | `1.0`                   | How long to wait for one server before trying the next. Never allowed to run past `timeout`           |
| `attempts`         | `2`                     | How many times to ask each server before moving on                                                    |
| `families`         | `(AF_INET6, AF_INET)`   | Which families to ask about, and the order answers come back in                                       |
| `nameserver_port`  | `53`                    | The port the resolvers listen on                                                                      |

`timeout` is the field the module exists for, and it is asserted rather than argued:
`test_a_server_that_never_answers_fails_inside_the_deadline` points a resolver at a server that
receives queries and says nothing, which is what a hostile zone does, and requires the call to
return. `test_the_total_ceiling_binds_even_when_the_attempts_would_run_longer` requires the
ceiling to bind even when `attempt_timeout * attempts` would run past it.

**The policy is deliberately not applied to `nameservers`.** They are infrastructure rather than
a target, and the `127.0.0.53` that systemd-resolved writes into every Linux `resolv.conf` is
denied by the shipped table. A resolver that refused to talk to your own recursive resolver would
be useless exactly where it is most wanted.

## What it does not know

Each of these is a real behaviour difference from the platform resolver, and none of them is
going to be fixed, because fixing them means being the platform resolver.

| Not known                                       | What that means                                                                                      |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `/etc/hosts`, `nsswitch.conf`, mDNS             | A name that resolves only through one of those does not resolve here                                  |
| Search domains                                  | A bare `intranet` is asked for as written, not as `intranet.corp.example`                             |
| The macOS system resolver                       | It does not live in `resolv.conf`. Pass `nameservers=` explicitly on macOS                            |
| RFC 6724 destination-address selection          | `getaddrinfo` orders answers better than this can. Here the order is `families`, then the server's    |
| DNSSEC                                          | Nothing is validated cryptographically. The answers are the recursive resolver's word, as they are with `getaddrinfo` |

**Legacy address forms are a difference in the safe direction.** `getaddrinfo` on glibc reads
`0177.0.0.1` as octal and reaches `127.0.0.1`. This parses literals with `ipaddress`, which
refuses `0177.0.0.1`, `2130706433` and `127.1`, so all three are treated as names and looked up
rather than decoded. `Policy.check_url` already refuses every one of them at the URL layer before
resolution is reached, so this is one defence more rather than one fewer. See
[the address table](address-table.md).

## Why half an answer is refused

**If one query answers and the other does not complete, the whole call fails**, rather than
returning the half that arrived.

The half looks like the safe outcome. Fewer addresses can only ever reach fewer places, so
returning them seems strictly more conservative. In this package it is not.
`on_partial_block` defaults to `"reject"` precisely because a name resolving to both permitted
and denied addresses is the signature of a rebinding attempt rather than of a misconfiguration,
and it can only see that signature if it is shown every answer. A zone that answers `A` and
stalls `AAAA` would otherwise choose which half of its own answer set the policy is allowed to
judge. `test_a_query_that_does_not_complete_fails_the_call_rather_than_halving_the_answer` is the
assertion.

**`NODATA` and `NXDOMAIN` are answers and do not trigger this.** They are the server saying there
is nothing, which is complete information. Only a query that never completed is missing.

**The escape hatch is `families`.** A network that drops `AAAA` queries instead of answering them
would fail every lookup under this rule. `UdpResolver(families=(socket.AF_INET,))` asks one
question instead of two, and then there is no incomplete set to have.

## What is bounded and what is cancellable

Worth being precise about, because the two are not the same and only one of them is finished.

**Bounded, on both paths.** A lookup through this resolver returns inside `timeout`, on the
synchronous clients and on the asynchronous one. On `AsyncClient`, resolution runs in a worker
thread; with `getaddrinfo` that thread could be held indefinitely, and with this one it is
released when the deadline passes.

**Not cancellable, yet.** `AsyncClient` still calls the resolver synchronously in a worker
thread, so a lookup in flight cannot be cancelled, only waited out. Making it genuinely
cancellable means the client awaiting an async resolver rather than offloading a synchronous one,
which is a change to the client rather than to this module. Until then, held lookups are bounded
by `timeout` instead of by nothing, and `resolver_slots` on
[`AsyncClient`](clients.md) still bounds how many can be held at once.

## Lifetimes

`getaddrinfo` discards the TTL, and `Resolver`'s row shape has nowhere to put one, so
`UdpResolver.__call__` discards it too. `records()` is the same lookup with the lifetimes kept:

```python
resolver = UdpResolver(timeout=2.0)
for record in resolver.records("example.com"):
    print(record.ip, record.ttl)
```

**Nothing in this package caches what it returns**, and a cache here would be its own bug:
reusing an answer past its lifetime pins a name to an address it may no longer own, which is the
mirror image of the bug this package exists to prevent.

## The parser, and why it is the risky part

Reading DNS off the wire means reading bytes an attacker chose, which this package does nowhere
else. Worth knowing what that does and does not put at stake.

**A parser bug cannot grant a permit.** Every address is checked against the policy before
anything connects to it, so a mis-parse produces a wrong address that is then refused or allowed
on its own merits. What a parser bug *can* do is never return, which would replace the bounded
stall this module exists to remove with an unbounded one.

So the bounds are on termination rather than on correctness of decoding. A name may follow at
most 64 compression pointers and may be at most 255 bytes, and those two together mean every
input either decodes or raises. `test_no_message_can_make_name_decoding_hang` and
`test_no_message_can_make_parsing_hang_or_raise_something_unplanned` are property tests over
arbitrary bytes; `test_a_pointer_that_points_at_itself_raises_rather_than_looping` is the oldest
denial of service in DNS, written out.

Three more checks are worth naming because they are what makes a forged reply hard:

- **The transaction id is random** and is compared, the source port is the ephemeral one the
  kernel chose, and the socket is connected so the kernel drops datagrams from anywhere else.
- **The question is compared**, name and type and class, so a reply that answers something else
  is not believed.
- **An answer whose owner nothing pointed at is dropped.** A recursive resolver answering an
  aliased name returns the `CNAME` chain, and only records owned by the name asked for or by a
  name some accepted `CNAME` pointed at are read.
  `test_an_address_for_an_owner_nothing_pointed_at_is_dropped` is that one.

A forged reply arriving before the real one is dropped without ending the wait, which is
`test_a_forged_reply_arriving_first_does_not_end_the_wait_for_the_real_one`. The whole file is
`tests/test_resolvers.py`.

---

Where a resolver fits in the whole: [Using the pieces directly](building-blocks.md). What the
clients do with one: [The clients](clients.md). What is still unbounded and what is not:
[Threat model](threat-model.md).
