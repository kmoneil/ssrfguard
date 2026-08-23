"""The exception hierarchy.

Names carry the ``Error`` suffix, which is a departure from the design's ``BlockedAddress`` and
``BlockedURL``. PEP 8 asks for it on anything that is an error condition, `N818` gates it, and a
refused address is an error condition, so the design is amended rather than the rule waived.

Every message names the value that was refused **and which rule refused it**. That is not
politeness: a refusal a user cannot act on gets configured around, and a control that gets
configured around protects nothing. It is also why the test suite pins whole messages rather
than matching substrings; `raises-require-match-for = []` in `pyproject.toml` exists for this.
"""

from __future__ import annotations

__all__ = [
    "BlockedAddressError",
    "BlockedURLError",
    "ProxyUnsupportedError",
    "SSRFGuardError",
    "TooManyRedirectsError",
]


class SSRFGuardError(Exception):
    """Base class for every refusal this package makes.

    Catching this catches everything ssrfguard refuses, and nothing it does not. Network errors
    from the underlying client are deliberately not wrapped: a connection that failed because
    the host was down is not a policy decision, and dressing it as one would hide an outage
    behind a security message.
    """


class BlockedAddressError(SSRFGuardError):
    """An IP address is not permitted by the policy.

    Attributes:
        address: The address that was refused, as text.
        reason: Why, naming the block and its RFC.
    """

    def __init__(self, address: str, reason: str) -> None:
        self.address = address
        self.reason = reason
        super().__init__(f"{address} is not permitted: {reason}")


class BlockedURLError(SSRFGuardError):
    """A URL is not permitted by the policy.

    Raised before any name resolution happens, so the reason is always about the URL as written
    its scheme, its authority or its port, and never about where a hostname points. A URL
    that survives this can still be refused once its addresses are known, and that refusal
    carries :class:`BlockedAddressError` instead.

    Attributes:
        url: The URL that was refused, as given.
        reason: Why, naming the rule that refused it.
    """

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"{url!r} is not permitted: {reason}")


class ProxyUnsupportedError(SSRFGuardError):
    """A proxy is configured, and a proxy resolves the target itself.

    When a client connects through a proxy, the proxy performs the DNS lookup and opens the
    socket. Pinning happens in this process and the proxy is not in it, so every guarantee this
    package makes stops at the proxy's front door. Refusing is the honest answer: silently
    passing the request through would leave a caller believing in a control that is no longer
    running, which is worse than having no control at all.

    Set ``allow_proxy=True`` to accept that enforcement has moved to the proxy.

    Attributes:
        proxy: The proxy that was configured, as text.
    """

    def __init__(self, proxy: str) -> None:
        self.proxy = proxy
        super().__init__(
            f"a proxy is configured ({proxy}) and it resolves the target itself, so the "
            f"validated address cannot be pinned; set allow_proxy=True to accept that "
            f"enforcement has moved to the proxy"
        )


class TooManyRedirectsError(SSRFGuardError):
    """A redirect chain exceeded the policy's own limit.

    Counted by this package rather than by the HTTP client, because the client's counter is not
    a security control: it exists to stop loops, it is configurable independently, and a chain
    that stays under it still gets one policy evaluation per hop from us either way.

    At ``max_redirects=0`` this is raised by a single redirect **response**, even when the caller
    switched following off at the client, because both clients build the next request in order to
    expose it, and the cap fires on the build rather than on the send. That is the honest reading
    of a policy that permits no redirect, and it is asserted on all three client surfaces so it
    cannot be "fixed" by somebody who did not know it was decided.

    Attributes:
        limit: The configured maximum.
        chain: The URLs walked, in order.
    """

    def __init__(self, limit: int, chain: tuple[str, ...]) -> None:
        self.limit = limit
        self.chain = chain
        walked = " -> ".join(chain)
        super().__init__(f"redirect chain exceeded max_redirects={limit}: {walked}")
