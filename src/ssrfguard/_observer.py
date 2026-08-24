"""What this package decided, for somebody who is not the caller of the moment.

Every decision this package makes is thrown away unless it raises. A URL's scheme, port and
authority; every address a name resolved to, against a sixty-row table, with a named block
deciding each; the peer once the socket is up. All of it is discarded, and the only thing that
survives the function that decided it is a refusal, and only if nobody catches it.

:mod:`ssrfguard.errors` already argues why a refusal has to name the value and the rule: "a
refusal a user cannot act on gets configured around, and a control that gets configured around
protects nothing". **That reasoning does not stop at the exception.** A caller who catches
:class:`~ssrfguard.BlockedAddressError` around a webhook fetch, logs "bad url" and moves on has a
control that is working perfectly and telling nobody, and somebody pointing a URL at
``169.254.169.254`` on purpose is worth more than a flattened ``except``.

**The permits matter at least as much as the refusals, and they are the half that is completely
invisible today.** A name that resolved to a public address yesterday and a private one today is
the entire subject of this package, and nothing in it can tell you that happened, because
yesterday's answer left no trace.

Three decisions in here are worth reading before changing anything.

**An observer that raises may not fail a request.** A sink that throws on a *permitted* request
would turn an allow into a deny, which is the second-worst thing this package can do, arriving
through the logging path of all places. So :func:`report` swallows whatever the observer raises.
That is a deliberate asymmetry with the rest of the package, which wraps nothing and hides
nothing, and it is justified by the direction of the failure rather than by convenience.

**An observer may not see credentials.** ``ssrfguard.requests`` already reasons about values
landing where "they reach logs, hooks and retry keys". A record is exactly such a place, so
userinfo is stripped by :func:`redacted` before the record is built, rather than being left for
the sink to remember.

**It costs nothing when nobody is listening.** Every call site tests the observer before building
anything, so a caller who wants none pays for none. That is a guarantee rather than an
implementation detail, and ``tests/test_cost.py`` gates it by counting.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from ssrfguard._address import IPAddress

__all__ = ["Decision", "Observer", "Outcome", "Stage", "redacted", "report"]

#: Which question was being answered. The four are the four places this package decides
#: anything: the URL as written, each address a name resolved to, the peer once a socket is up,
#: and whether a redirect chain may take another hop.
Stage = Literal["url", "address", "peer", "redirect"]

#: What was decided. Deliberately two values: a package whose whole argument is deny-by-default
#: has no third answer, and a record that could carry one would invite a caller to treat some
#: refusals as softer than others.
Outcome = Literal["permitted", "refused"]

#: What replaces credentials in a reported URL. Present rather than removed, because "somebody
#: put userinfo in this URL" is itself worth seeing, and the value never is.
_REDACTION = "[redacted]"


@dataclass(frozen=True)
class Decision:
    """One thing this package decided, and everything needed to act on it.

    Attributes:
        stage: Which question was being answered.
        outcome: What the answer was.
        reason: Why, when the answer was ``"refused"``: the same sentence the exception carries,
            naming the value and the rule. ``None`` on a permit, because there is no rule that
            approved it, only the absence of one that refused.
        url: The URL, **with any credentials replaced**. ``None`` at stages that are about an
            address rather than a URL.
        host: The hostname or literal address from the authority, as the policy normalised it.
        port: The port, once one is known.
        address: The address this decision was about, at the stages that have one.
        chain: The redirect chain walked so far, in order, at the redirect stage.
    """

    stage: Stage
    outcome: Outcome
    reason: str | None = None
    url: str | None = None
    host: str | None = None
    port: int | None = None
    address: IPAddress | None = None
    chain: tuple[str, ...] = field(default=())


#: What a caller passes as ``observer=``. Called once per decision, with the decision.
#:
#: **Deliberately a callback rather than the standard library's logging.** ``logging`` is free
#: and would not touch the zero-dependency claim, and a library that reaches for it picks a
#: logger name, a level and a format, which is three decisions made on behalf of a caller who
#: made none of them. A security event arriving as a formatted string also has to be parsed back
#: into fields by whoever wants to alert on it. This ships the fields; four lines hand them to
#: ``logging``, and ``docs/observing.md`` is where those four lines are.
Observer = Callable[[Decision], None]


def redacted(url: str) -> str:
    """Replace any credentials in a URL's authority.

    Deliberately textual rather than parsed. This runs on URLs that are *about to be refused*,
    including ones no parser accepts, so anything that could raise here would turn a refusal into
    a crash in the middle of a guard. Splitting on the two delimiters that bound an authority
    cannot fail on any input.

    Args:
        url: The URL as given.

    Returns:
        The URL with anything before the last ``@`` of the authority replaced. Unchanged when
        the authority carries no ``@``, which is the ordinary case.
    """
    scheme, separator, rest = url.partition("//")
    if not separator:
        return url
    authority, slash, tail = rest.partition("/")
    if "@" not in authority:
        return url
    _credentials, _at, host = authority.rpartition("@")
    return f"{scheme}//{_REDACTION}@{host}{slash}{tail}"


def report(observer: Observer | None, decision: Decision) -> None:
    """Hand a decision to an observer, and let nothing it does reach the request.

    Args:
        observer: Where to send it, or ``None``, which is the common case and does nothing.
        decision: What was decided.

    Note:
        **Every exception the observer raises is swallowed, and that is the point.** A sink that
        throws on a permitted request would otherwise turn an allow into a deny: the caller's
        request fails, the cause is a logging bug, and the message names neither. Reporting is
        not part of the decision and may not be able to change it.

        ``BaseException`` is not swallowed, so ``KeyboardInterrupt`` and ``SystemExit`` still
        travel. A process being torn down is not a sink misbehaving.
    """
    if observer is None:
        return
    with contextlib.suppress(Exception):
        observer(decision)
