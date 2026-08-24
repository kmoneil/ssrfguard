"""Resolution: one lookup, every answer validated, nothing thrown away.

This is where the package stops being a URL checker. :func:`resolve` performs exactly one name
lookup and returns the addresses it validated, in a form :func:`ssrfguard.connect` can use
without asking the resolver anything a second time. That second lookup is the vulnerability in
every advisory this package exists to answer, and the way to not have it is to not need it.

Three decisions in here are worth reading before changing anything:

* **Every answer is validated, not the first one.** A name that returns four addresses returns
  four chances to reach somewhere internal, and the resolver chooses between them.
* **A name that resolves both ways is refused whole.** See :data:`ssrfguard.Policy` --
  ``on_partial_block`` defaults to ``"reject"`` because a name pointing at both a public and a
  private address is the signature of a rebinding attempt rather than of a misconfiguration.
* **The sockaddr is kept intact.** ``getaddrinfo`` returns a 4-tuple for IPv6 whose last two
  elements carry the flow label and the scope identifier; re-parsing the first element into a
  string and reconnecting from that silently drops them.
"""

from __future__ import annotations

import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any

from ssrfguard._address import IPAddress
from ssrfguard._observer import Decision, Observer, report
from ssrfguard._policy import Policy, Target
from ssrfguard.errors import BlockedAddressError

__all__ = ["Address", "Resolver", "ResolverAnswer", "SockAddr", "resolve"]

#: A socket address as ``getaddrinfo`` hands it over. Deliberately loose: it is two elements for
#: IPv4 and four for IPv6, and this package's job is to carry it to ``connect`` unchanged rather
#: than to have an opinion about its shape. Narrowing it here would mean rebuilding the tuple,
#: which is exactly how the IPv6 scope identifier gets lost.
SockAddr = tuple[Any, ...]

#: One row of a resolver's answer: family, socket type, protocol, canonical name, address.
ResolverAnswer = tuple[int, int, int, str, SockAddr]

#: The shape of ``socket.getaddrinfo``. Accepted by :func:`resolve` so that tests can drive it
#: without a network, and so that a caller who already has an answer, from a resolver they
#: trust or from a fixture, can supply it. **Every address it returns is validated before it
#: is used**, so a resolver that lies about where a name points buys nothing.
#:
#: The *port* in the sockaddr is a narrower claim and is written out because the sentence above
#: would otherwise be read as covering it. It is carried through as the resolver gave it, not
#: re-checked against ``allowed_ports``. ``socket.getaddrinfo`` echoes the port it was handed,
#: so the two can only disagree for a stand-in the caller installed themselves, which makes
#: this the caller's trust to place rather than a boundary this function defends.
Resolver = Callable[..., Iterable[ResolverAnswer]]

#: What a v4 sockaddr looks like, versus a v6 one. Named because the difference is the entire
#: reason this module carries the tuple around instead of an address string.
_V6_SOCKADDR_LENGTH = 4


@dataclass(frozen=True)
class Address:
    """One validated answer, in the form the socket layer wants.

    Attributes:
        family: ``AF_INET`` or ``AF_INET6``.
        sockaddr: The tuple ``getaddrinfo`` produced, unmodified. Two elements for IPv4;
            **four for IPv6**, where the third is the flow label and the fourth is the scope
            identifier. Passing anything else to ``connect`` loses them.
        ip: The parsed address, which is what the policy was asked about.
        hostname: The name this answer came from, as an A-label. This is what TLS must verify
            against, and it is the reason an ``Address`` is not just an address.
    """

    family: socket.AddressFamily
    sockaddr: SockAddr
    ip: IPAddress
    hostname: str

    @property
    def port(self) -> int:
        """The port carried in the sockaddr.

        Returns:
            The port this answer will connect to.
        """
        return int(self.sockaddr[1])

    def __str__(self) -> str:
        """Render for a log line or a refusal.

        Returns:
            The address and port, with the name it came from when that differs.
        """
        literal = f"[{self.ip}]" if self.family is socket.AF_INET6 else str(self.ip)
        via = "" if self.hostname == str(self.ip) else f" (via {self.hostname})"
        return f"{literal}:{self.port}{via}"


def _addresses_from(infos: Iterable[ResolverAnswer], hostname: str) -> tuple[Address, ...]:
    """Turn ``getaddrinfo`` output into addresses, in order, without duplicates.

    Args:
        infos: What the resolver returned.
        hostname: The name that was looked up.

    Returns:
        One :class:`Address` per distinct answer, preserving the resolver's ordering, which is
        not arbitrary: ``getaddrinfo`` already applies RFC 6724 destination-address selection,
        and reordering here would discard a decision the platform made better than we can.

    Raises:
        ValueError: If an answer cannot be read as an address. The resolver returning something
            unparseable is not a condition this package can interpret, so it stops.
    """
    seen: set[tuple[int, SockAddr]] = set()
    out: list[Address] = []
    for family, _socktype, _proto, _canonname, sockaddr in infos:
        key = (family, sockaddr)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Address(
                family=socket.AddressFamily(family),
                sockaddr=sockaddr,
                ip=ip_address(str(sockaddr[0])),
                hostname=hostname,
            )
        )
    return tuple(out)


def _refuse_all_denied(target: Target, denied: tuple[tuple[Address, str], ...]) -> None:
    """Refuse a name none of whose answers are permitted.

    Args:
        target: The origin that was resolved.
        denied: Pairs of (address, reason).

    Raises:
        BlockedAddressError: Always.
    """
    first, reason = denied[0]
    if len(denied) == 1:
        raise BlockedAddressError(str(first.ip), reason)
    listed = "; ".join(f"{address.ip} ({why})" for address, why in denied)
    raise BlockedAddressError(target.host, f"every address it resolves to is refused: {listed}")


def _refuse_partial(
    target: Target,
    permitted: tuple[Address, ...],
    denied: tuple[tuple[Address, str], ...],
) -> None:
    """Refuse a name that resolves to both permitted and denied addresses.

    The message names both halves on purpose. A user shown only the denied address cannot tell
    this apart from an ordinary internal host, and the two need different responses: one is a
    configuration question and the other is somebody probing.

    Args:
        target: The origin that was resolved.
        permitted: The answers the policy allows.
        denied: Pairs of (address, reason) the policy refuses.

    Raises:
        BlockedAddressError: Always.
    """
    allowed = ", ".join(str(address.ip) for address in permitted)
    refused = "; ".join(f"{address.ip} ({why})" for address, why in denied)
    raise BlockedAddressError(
        target.host,
        f"resolves to both permitted and denied addresses; permitted: {allowed}; "
        f"denied: {refused}. A name that resolves both ways is the signature of a DNS "
        f"rebinding attempt rather than of a misconfiguration, so on_partial_block='reject' "
        f"refuses the whole name. Set on_partial_block='drop' to use only the permitted "
        f"answers, which is safe only if you know this name",
    )


def resolve(
    target: Target,
    *,
    policy: Policy,
    resolver: Resolver | None = None,
    observer: Observer | None = None,
) -> tuple[Address, ...]:
    """Resolve an origin and validate every answer.

    Performs **one** lookup. The addresses returned are the addresses that were checked, and
    :func:`ssrfguard.connect` uses them directly. There is no second resolution anywhere in
    this package, which is the whole of its argument.

    A target carrying a literal address is not resolved at all. It is re-validated, because a
    function that returns validated addresses must validate everything it returns, and the
    caller should not have to know which path their target took.

    Args:
        target: The origin, from :meth:`ssrfguard.Policy.check_url`.
        policy: The policy to validate against.
        resolver: A stand-in for ``socket.getaddrinfo``, for tests and for callers with their
            own. Whatever it returns is validated, so supplying one grants no permission.
        observer: Where to report each answer's verdict, or ``None`` to report nothing.
            **One record per address**, not one per name: a name resolving to four addresses is
            four decisions, and which of them was refused is the thing worth knowing.

    Returns:
        Every permitted answer, in the resolver's own order. Never empty.

    Raises:
        BlockedAddressError: If no answer is permitted, or if the name resolves to both
            permitted and denied addresses while ``on_partial_block`` is ``"reject"``.
        socket.gaierror: If the name does not resolve. **Not wrapped**: a name that does not
            exist is not a policy decision, and dressing a DNS failure as a refusal would send
            a user looking for a security problem they do not have.

    Note:
        ``socket.getaddrinfo`` has no timeout and ``socket.setdefaulttimeout`` does not apply to
        it, so a hostile authoritative server can stall this call for as long as it likes.

        **The two paths have different answers and one sentence covering both would be wrong for
        one of them.** On the synchronous path this is a known denial-of-service surface,
        documented in ``SECURITY.md`` as out of scope, and it is the caller's to supervise: a
        stalled call holds up the caller that made it and nobody else.

        On the asynchronous path a stalled call would hold up *every* task in the process, so
        ``ssrfguard.httpx.AsyncClient`` never calls this on the event loop. It runs it in a
        worker thread, and a test asserts a concurrent task keeps being scheduled while a lookup
        blocks.

        **That moves the bound rather than removing it, and the number is worth knowing.** A
        thread blocked in ``getaddrinfo`` cannot be cancelled, so held lookups accumulate until
        the client's resolver slots are gone, and past that point no *new* name can be resolved
        until one returns. Connections already in the pool are unaffected, which is what keeps
        this a limit rather than an outage. The client owns that pool of slots rather than
        borrowing anyio's process-wide default, so the number is its own and a stall cannot
        starve unrelated thread work elsewhere on the loop; see ``resolver_slots`` on
        :class:`ssrfguard.httpx.AsyncClient`.
    """
    lookup = resolver if resolver is not None else socket.getaddrinfo
    flags = socket.AI_NUMERICHOST if target.is_literal_address else 0
    infos = lookup(target.host, target.port, 0, socket.SOCK_STREAM, 0, flags)
    answers = _addresses_from(infos, target.host)
    if not answers:  # pragma: no cover - getaddrinfo raises rather than returning nothing
        raise socket.gaierror(f"{target.host} resolved to no addresses")

    permitted: list[Address] = []
    denied: list[tuple[Address, str]] = []
    for answer in answers:
        try:
            policy.check_address(answer.ip)
        except BlockedAddressError as refused:
            denied.append((answer, refused.reason))
            if observer is not None:
                report(
                    observer,
                    Decision(
                        stage="address",
                        outcome="refused",
                        reason=refused.reason,
                        host=target.host,
                        port=target.port,
                        address=answer.ip,
                    ),
                )
        else:
            permitted.append(answer)
            if observer is not None:
                report(
                    observer,
                    Decision(
                        stage="address",
                        outcome="permitted",
                        host=target.host,
                        port=target.port,
                        address=answer.ip,
                    ),
                )

    if not permitted:
        _refuse_all_denied(target, tuple(denied))
    if denied and policy.on_partial_block == "reject":
        _refuse_partial(target, tuple(permitted), tuple(denied))
    return tuple(permitted)
