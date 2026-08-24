"""Connecting to a validated address, and to nothing else.

This is the shortest module in the package and the one the whole argument reduces to. It takes
addresses that have already been checked and opens a socket to one of them. It has no hostname
to look up, no resolver to call and no code path that could reach either. That is not a
discipline anyone has to maintain; it is the shape of the function's arguments.

Two things here are less obvious than they look.

**It takes the whole tuple, not the first address.** Connecting to ``addresses[0]`` fails
whenever the first answer is unreachable, which is routine for dual-stack hosts and is the most
common way a security library becomes a support burden, then gets removed, then leaves no
control at all. Failing over is only safe because a partially-denied name never gets this far --
see ``on_partial_block`` in :class:`ssrfguard.Policy`. Read the two together: reject-on-partial
is what makes iterating over the survivors safe.

**It stops after ``max_connection_attempts``, and that bound is a security control.** The
timeout is per attempt, and how many attempts there are is decided by whoever runs the
authoritative server for the name being fetched. A zone that answers with two hundred permitted
addresses, all of them silently dropping packets, turns one request into two hundred times the
timeout the caller asked for: a worker held for as long as the attacker cares to hold it, on a
path that looks like a slow upstream rather than like an attack. Failing over needs a handful of
attempts, not all of them.

**The peer is checked after the connection is up.** ``connect`` to a specific address cannot
land somewhere else, so this looks redundant. It is the cheapest possible answer to everything
between this process and the wire, such as a transparent proxy, a redirecting firewall rule or
a platform quirk, and it is what mlflow's own issue recommended when the same bug was found
there: validate the peer after connect and before sending anything.
"""

from __future__ import annotations

import socket
from collections.abc import Iterable, Sequence
from ipaddress import ip_address

from ssrfguard._policy import Policy
from ssrfguard._resolve import Address
from ssrfguard.errors import BlockedAddressError

__all__ = ["SocketOption", "connect", "exhausted"]

#: One ``setsockopt`` call, in every shape the clients express one. Three elements is the common
#: form; four is CPython's ``setsockopt(level, optname, None, optlen)``, which httpcore's own
#: type allows and which this therefore has to be able to carry. **Applied to the socket
#: unchanged**, for the same reason the sockaddr is: a value taken apart here is a value that can
#: lose something on the way back together.
SocketOption = tuple[int, int, "int | bytes | bytearray"] | tuple[int, int, None, int]


def exhausted(failures: Sequence[str], skipped: int, cap: int) -> str:
    """Say what was tried, what each attempt cost, and what was left untried.

    **Shared with the asynchronous backend rather than written twice.** The two failover loops
    cannot merge, since one drives a socket and the other drives anyio, but this half is pure and
    was character-identical in both, which makes it the half that drifts silently: a reworded
    failure line on one client and not the other is invisible until somebody greps a log.

    Args:
        failures: One line per attempt, in the order they were tried.
        skipped: How many validated addresses were never tried.
        cap: The ``max_connection_attempts`` that stopped the sequence, named because a caller
            who sees addresses go untried needs to know which field to widen.

    Returns:
        The message for the raised error.
    """
    untried = (
        ""
        if not skipped
        else f"; {skipped} further address(es) not tried (max_connection_attempts={cap})"
    )
    return f"could not connect to any validated address: {'; '.join(failures)}{untried}"


def _open(
    address: Address,
    timeout: float | None,
    source_address: tuple[str, int] | None,
    socket_options: Iterable[SocketOption] | None,
) -> socket.socket:
    """Open one socket to one address.

    Args:
        address: The validated answer to connect to.
        timeout: Seconds to wait for this attempt. Per attempt rather than for the whole
            sequence, matching ``socket.create_connection``.
        source_address: Local address to bind before connecting.
        socket_options: ``setsockopt`` arguments applied before connecting.

    Returns:
        The connected socket.

    Raises:
        OSError: If the socket cannot be created, bound or connected.
        BlockedAddressError: If the connected peer is not the address that was validated.
    """
    sock = socket.socket(address.family, socket.SOCK_STREAM)
    try:
        # **`*option` unpacks a union of tuple shapes, which pyright cannot follow**: it joins
        # the element types across positions and then reports every argument as wrong. mypy
        # reads it correctly, and httpcore carries the same pattern in its own backends. The
        # suppression is preferred to a length dispatch because unpacking is what keeps the
        # value intact: a 5-tuple still raises TypeError here, where a dispatch on len would
        # silently apply the first three and drop the rest.
        for option in socket_options or ():
            sock.setsockopt(*option)  # pyright: ignore[reportCallIssue, reportArgumentType]
        if timeout is not None:
            sock.settimeout(timeout)
        if source_address is not None:
            sock.bind(source_address)
        # **The pin.** `address.sockaddr` is the tuple the resolver produced and the policy
        # approved, passed through untouched, so for IPv6 the scope identifier is still on it.
        sock.connect(address.sockaddr)
        _verify_peer(sock, address)
    except BaseException:
        sock.close()
        raise
    return sock


def _verify_peer(sock: socket.socket, address: Address) -> None:
    """Check that the socket is connected to the address that was validated.

    Args:
        sock: The connected socket.
        address: The address it was supposed to reach.

    Raises:
        BlockedAddressError: If the peer is somewhere else.
    """
    peer = ip_address(str(sock.getpeername()[0]))
    if peer != address.ip:
        raise BlockedAddressError(
            str(peer),
            f"the connection was made to {peer} after {address.ip} was validated, so something "
            f"between this process and the network rewrote the destination",
        )


def connect(
    addresses: Sequence[Address],
    *,
    policy: Policy,
    timeout: float | None = None,
    source_address: tuple[str, int] | None = None,
    socket_options: Iterable[SocketOption] | None = None,
) -> socket.socket:
    """Connect to the first reachable address among those validated, up to the attempt cap.

    Args:
        addresses: Validated answers, in the resolver's own order, from
            :func:`ssrfguard.resolve`. Every one of them is checked again here, and the first
            ``policy.max_connection_attempts`` of them are tried.
        policy: The policy they were validated against. **Required, not optional**, so that
            there is no path through this package to a socket that skipped the check. An
            optional security check is a security check somebody forgets. Also supplies
            ``max_connection_attempts``, which bounds how long a hostile answer set can hold
            this call.
        timeout: Seconds to wait per attempt, not for the sequence. ``None`` uses the system
            default, which may be several minutes. The whole call is therefore bounded by
            ``timeout * policy.max_connection_attempts``, which is the reason that cap exists.
        source_address: Local address to bind before connecting.
        socket_options: ``setsockopt`` arguments applied to every attempt.

    Returns:
        A connected socket, whose peer has been confirmed to be the address that was validated.

    Raises:
        ValueError: If ``addresses`` is empty. :func:`ssrfguard.resolve` never returns an empty
            tuple, so this means the caller assembled the sequence some other way.
        BlockedAddressError: If any address is not permitted by ``policy``. Raised immediately
            rather than skipped, because for a sequence that came from :func:`ssrfguard.resolve`
            it cannot happen, so it happening means the caller bypassed resolution, and that
            is exactly when a loud failure beats a quiet fallback.
        OSError: If every attempt was refused by the network. The message names each address
            tried, what it failed with, and how many were left untried; the last failure is
            chained as the cause.
        TimeoutError: If every attempt timed out, rather than a plain :class:`OSError`. A
            caller that distinguishes a timeout from a refusal, which is what a retry or a
            circuit breaker is for, gets the same answer the unguarded client would have
            given it. A single refusal among the attempts makes this an ``OSError`` instead,
            because the refusal is the more informative of the two.

    Note:
        This function performs no name resolution and has nothing to resolve: an
        :class:`~ssrfguard.Address` carries a socket address, not a name. That is the whole
        claim of this package, and it is a property of the signature rather than of the body.
    """
    if not addresses:
        raise ValueError("connect needs at least one address; resolve never returns none")
    for address in addresses:
        policy.check_address(address.ip)

    attempted = addresses[: policy.max_connection_attempts]
    failures: list[str] = []
    last: OSError | None = None
    # Every failure so far having been a timeout, which starts true because the loop below
    # always runs at least once, because `addresses` is non-empty and the cap is at least one.
    only_timeouts = True
    for address in attempted:
        try:
            return _open(address, timeout, source_address, socket_options)
        except OSError as failed:
            failures.append(f"{address} ({failed})")
            last = failed
            only_timeouts = only_timeouts and isinstance(failed, TimeoutError)

    message = exhausted(failures, len(addresses) - len(attempted), policy.max_connection_attempts)
    # `TimeoutError` is an `OSError`, so a plain `OSError` here would be caught by the adapters'
    # `except OSError` before their `except TimeoutError` ever ran, and a caller who
    # distinguishes "timed out" from "refused", which is what every retry and circuit-breaker
    # does, would be told the wrong one. Only when *every* attempt timed out: a refusal mixed
    # in is the more informative answer of the two.
    raise (TimeoutError(message) if only_timeouts else OSError(message)) from last
