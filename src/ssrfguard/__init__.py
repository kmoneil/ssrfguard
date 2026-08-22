"""SSRF protection that connects to the address it validated.

Every SSRF guard in Python validates a hostname and then hands the URL to an HTTP client that
resolves DNS a second time. The attacker moves the record in between. This package resolves
once, validates every answer, and connects to the address it validated -- never to a name.

Only the address layer is built so far::

    >>> from ssrfguard import DEFAULT_DENIED
    >>> DEFAULT_DENIED.classify("8.8.8.8").blocked
    False
    >>> DEFAULT_DENIED.classify("64:ff9b::7f00:1").blocked   # NAT64 carrying loopback
    True

**This package has no runtime dependencies and never will.** That is enforced by
`tests/test_zero_deps.py` and, against a built wheel in a clean interpreter, by the `zero-deps`
lane -- not by intent.
"""

from __future__ import annotations

from ssrfguard._address import DEFAULT_DENIED, AddressTable, Verdict
from ssrfguard._registry import REGISTRY_SNAPSHOT, Block, Reach
from ssrfguard.errors import BlockedAddressError, SSRFGuardError

__all__ = [
    "DEFAULT_DENIED",
    "REGISTRY_SNAPSHOT",
    "AddressTable",
    "Block",
    "BlockedAddressError",
    "Reach",
    "SSRFGuardError",
    "Verdict",
    "__version__",
]

__version__ = "0.0.0"
