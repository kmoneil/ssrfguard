"""SSRF protection that connects to the address it validated.

Every SSRF guard in Python validates a hostname and then hands the URL to an HTTP client that
resolves DNS a second time. The attacker moves the record in between. This package resolves
once, validates every answer, and connects to the address it validated — never to a name.

Nothing below is built yet.

**This package has no runtime dependencies and never will.** That is enforced by
``tests/test_zero_deps.py`` and, against a built wheel in a clean interpreter, by the
``zero-deps`` lane — not by intent.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.0.0"
