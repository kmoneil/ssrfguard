"""Connecting to a validated address, and to nothing else.

This is the shortest module in the package and the one the whole argument reduces to. It takes
addresses that have already been checked and opens a socket to one of them. It has no hostname
to look up, no resolver to call and no code path that could reach either -- which is not a
discipline anyone has to maintain, it is the shape of the function's arguments.

Two things here are less obvious than they look.

**It takes the whole tuple, not the first address.** Connecting to ``addresses[0]`` fails
whenever the first answer is unreachable, which is routine for dual-stack hosts and is the most
common way a security library becomes a support burden, then gets removed, then leaves no
control at all. Failing over is only safe because a partially-denied name never gets this far --
see ``on_partial_block`` in :class:`ssrfguard.Policy`. Read the two together: reject-on-partial
is what makes iterating over the survivors safe.

**The peer is checked after the connection is up.** ``connect`` to a specific address cannot
land somewhere else, so this looks redundant. It is the cheapest possible answer to everything
between this process and the wire -- a transparent proxy, a redirecting firewall rule, a
platform quirk -- and it is what mlflow's own issue recommended when the same bug was found
there: validate the peer after connect and before sending anything.
"""

from __future__ import annotations

import socket
from collections.abc import Iterable, Sequence
from ipaddress import ip_address

from ssrfguard._policy import Policy
from ssrfguard._resolve import Address
from ssrfguard.errors import BlockedAddressError

__all__ = ["SocketOption", "connect"]

#: One ``setsockopt`` call, as the HTTP clients pass them around.
SocketOption = tuple[int, int, "int | bytes"]


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
        socket_options: ``setsockopt`` triples applied before connecting.

    Returns:
        The connected socket.

    Raises:
        OSError: If the socket cannot be created, bound or connected.
        BlockedAddressError: If the connected peer is not the address that was validated.
    """
    sock = socket.socket(address.family, socket.SOCK_STREAM)
    try:
        for level, option, value in socket_options or ():
            sock.setsockopt(level, option, value)
        if timeout is not None:
            sock.settimeout(timeout)
        if source_address is not None:
            sock.bind(source_address)
        # **The pin.** `address.sockaddr` is the tuple the resolver produced and the policy
        # approved, passed through untouched -- so for IPv6 the scope identifier is still on it.
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
    """Connect to the first reachable address among those already validated.

    Args:
        addresses: Validated answers, in the resolver's own order, from
            :func:`ssrfguard.resolve`. Every one of them is checked again here.
        policy: The policy they were validated against. **Required, not optional**, so that
            there is no path through this package to a socket that skipped the check -- an
            optional security check is a security check somebody forgets.
        timeout: Seconds to wait per attempt, not for the sequence. ``None`` uses the system
            default, which may be several minutes.
        source_address: Local address to bind before connecting.
        socket_options: ``setsockopt`` triples applied to every attempt.

    Returns:
        A connected socket, whose peer has been confirmed to be the address that was validated.

    Raises:
        ValueError: If ``addresses`` is empty. :func:`ssrfguard.resolve` never returns an empty
            tuple, so this means the caller assembled the sequence some other way.
        BlockedAddressError: If any address is not permitted by ``policy``. Raised immediately
            rather than skipped, because for a sequence that came from :func:`ssrfguard.resolve`
            it cannot happen -- so it happening means the caller bypassed resolution, and that
            is exactly when a loud failure beats a quiet fallback.
        OSError: If every address was refused by the network. The message names each address and
            what it failed with; the last failure is chained as the cause.

    Note:
        This function performs no name resolution and has nothing to resolve: an
        :class:`~ssrfguard.Address` carries a socket address, not a name. That is the whole
        claim of this package, and it is a property of the signature rather than of the body.
    """
    if not addresses:
        raise ValueError("connect needs at least one address; resolve never returns none")
    for address in addresses:
        policy.check_address(address.ip)

    failures: list[str] = []
    last: OSError | None = None
    for address in addresses:
        try:
            return _open(address, timeout, source_address, socket_options)
        except OSError as failed:
            failures.append(f"{address} ({failed})")
            last = failed
    raise OSError(f"could not connect to any validated address: {'; '.join(failures)}") from last
