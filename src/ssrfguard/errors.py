"""The exception hierarchy.

Names carry the ``Error`` suffix, which is a departure from the design's ``BlockedAddress`` and
``BlockedURL``. PEP 8 asks for it on anything that is an error condition, `N818` gates it, and a
refused address is an error condition -- so the design is amended rather than the rule waived.

Every message names the value that was refused **and which rule refused it**. That is not
politeness: a refusal a user cannot act on gets configured around, and a control that gets
configured around protects nothing. It is also why the test suite pins whole messages rather
than matching substrings -- `raises-require-match-for = []` in `pyproject.toml` exists for this.
"""

from __future__ import annotations

__all__ = ["BlockedAddressError", "SSRFGuardError"]


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
