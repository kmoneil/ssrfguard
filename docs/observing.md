# Watching what it decides

**Every decision this package makes is thrown away unless it raises.** A URL's scheme, port and
authority; every address a name resolved to, with a named block deciding each; the peer once the
socket is up. All of it is discarded, and the only thing that survives is a refusal, and only if
nobody catches it.

Pass an `observer` and it survives:

```python
from ssrfguard import Decision, Policy
from ssrfguard.httpx import Client

def watch(decision: Decision) -> None:
    print(decision.stage, decision.outcome, decision.host, decision.reason)

with Client(policy=Policy(), observer=watch) as client:
    client.get(untrusted_url)
```

It is a constructor argument on all three clients, and a keyword on
[the pieces directly](building-blocks.md): `check_url(url, observer=...)`,
`resolve(target, policy=..., observer=...)` and `connect(addresses, policy=..., observer=...)`.

**Jump to:** [Why the permits matter](#why-the-permits-matter-as-much-as-the-refusals)
&nbsp;·&nbsp; [The record](#the-record) &nbsp;·&nbsp; [The four stages](#the-four-stages)
&nbsp;·&nbsp; [Three rules](#three-rules-this-keeps)
&nbsp;·&nbsp; [Handing it to logging](#handing-it-to-logging)

## Why the permits matter as much as the refusals

A blocked SSRF attempt is an indicator of compromise: somebody pointed a URL at
`169.254.169.254` on purpose. Today that is a string inside an exception, and the usual shape of
calling code flattens it:

```python
try:
    fetch(url)
except SSRFGuardError:
    log.warning("bad url")     # the control worked, and told nobody what it caught
```

**The permits are the half that is completely invisible without this.** A name that resolved to a
public address yesterday and a private one today is the entire subject of this package, and
nothing in it could tell you that happened, because yesterday's answer left no trace.

## The record

`Decision` is a frozen dataclass, so it compares by value and can be used as a key.

| Field | What it carries |
| --- | --- |
| `stage` | `"url"`, `"address"`, `"peer"` or `"redirect"` |
| `outcome` | `"permitted"` or `"refused"`. There is no third answer |
| `reason` | On a refusal, the same sentence the exception carries, naming the value and the rule. `None` on a permit, because no rule approved it: only none refused it |
| `url` | The URL, **with any credentials replaced by `[redacted]`** |
| `host` | The hostname or literal, as the policy normalised it |
| `port` | The port, once one is known |
| `address` | The address this decision was about, at the stages that have one |
| `chain` | The redirect chain walked so far, at the redirect stage |

## The four stages

| Stage | When | One record per |
| --- | --- | --- |
| `url` | `check_url`, before anything is resolved | request, and again per redirect hop |
| `address` | each answer a name resolved to | **address**, not name |
| `peer` | after the socket is up, before anything is sent | connection |
| `redirect` | a chain that ran out of hops | refusal |

**`address` is one record per address and that is the useful part.** A name resolving to four
addresses is four decisions, and which of the four was refused is the thing worth knowing. A name
that answers with one permitted and one denied address is the signature of a rebinding attempt,
and with an observer attached you see both halves rather than only the refusal.

**`url` fires twice per request on `ssrfguard.requests` and once on the two httpx clients**, and
that is a difference in what each client *checks* rather than in what each reports.
`SafeAdapter` validates in `get_adapter`, per request and with the path on it, and again when it
opens a connection, on the origin alone, so a pool reached by some route that never went through
`send` is still bound by the policy. httpx's backend is handed a host and a port and never learns
the scheme, so its transport is the only place a URL exists. A sink that counts records should
know this; `tests/test_adapter_parity.py` names it as one of its asymmetries and asserts the
counts rather than the set.

**`peer` is the only stage deciding something the policy did not settle in advance.** Everything
else is a verdict on a value already in hand; this is a verdict on what the kernel actually
connected to. Nothing reachable through the public API makes it refuse, which is why it is the
one worth logging: it fires for a transparent proxy, a redirecting firewall rule or a platform
quirk, and those are found in a log or not at all.

## Three rules this keeps

**An observer that raises cannot fail a request.** A sink with a bug in it would otherwise turn
an allow into a deny, and the failure would arrive as a refused request whose cause is a logging
error. Every exception the observer raises is swallowed. `KeyboardInterrupt` and `SystemExit` are
not, because a process being torn down is not a sink misbehaving.

This is a deliberate asymmetry with the rest of the package, which wraps nothing and hides
nothing, and it is justified by the direction of the failure rather than by convenience.

**An observer never sees credentials.** A URL whose authority carries `user:password` is
reported with that authority replaced by `[redacted]`, on permits as well as refusals, and in every URL of a redirect
chain. The marker is left in place rather than the whole authority removed, because "somebody put
userinfo in this URL" is itself worth seeing and the value never is. Redaction is textual rather
than parsed, so it runs on URLs no parser accepts, which is exactly where a refusal happens.

**Nobody listening costs nothing.** No record is built when `observer` is `None`, which is the
default. That is a guarantee rather than an implementation detail, and it is gated by counting
constructions rather than by timing anything.

## Handing it to logging

`Decision` is a record rather than a formatted string on purpose: a library that picks a logger
name, a level and a format has made three decisions for a caller who made none of them, and a
security event that arrives as a string has to be parsed back into fields by whoever wants to
alert on it. Four lines are all it takes:

```python
import logging

log = logging.getLogger("ssrfguard")

def to_logging(decision: Decision) -> None:
    level = logging.WARNING if decision.outcome == "refused" else logging.DEBUG
    log.log(level, "%s %s", decision.stage, decision.outcome, extra={"decision": decision})
```

**What this is not is an audit log.** Records are handed to the sink synchronously on the
requesting thread, in the order the decisions were made, and nothing buffers, retries or persists
them. A sink that blocks blocks the request that produced it.

---

Where the decisions are made: [Why this exists](architecture.md). What each refusal carries:
[Errors](errors.md). What the guard does not defend: [Threat model](threat-model.md).
