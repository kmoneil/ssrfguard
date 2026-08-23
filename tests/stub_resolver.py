"""A ``getaddrinfo`` stand-in the adapter suites share.

One copy, because two copies is how the httpx suite and the requests suite start asserting
subtly different things about the same guarantee.

**This cannot demonstrate DNS rebinding and is not meant to.** A stand-in cannot change its mind
between two calls that a single ``resolve`` brackets, which is why the central claim is proved
against a real nameserver on a real socket in ``tests/test_rebinding.py``. What this is for is
the property that matters one layer up: counting what the client asked, so a second lookup is
visible, and giving a *later* connection a different answer from an earlier one.
"""

from __future__ import annotations

import socket


class Resolver:
    """Answers from a dict, and records what it was asked.

    Attributes:
        answers: Host to address. Writable while a test runs.
        asked: Every host looked up, in order. The number that shows a second lookup did not
            happen.
    """

    def __init__(self, **answers: str) -> None:
        """Build the resolver.

        Args:
            **answers: Host to address, as keyword arguments or a splatted dict.
        """
        self.answers: dict[str, str] = dict(answers)
        self.asked: list[str] = []

    def __call__(self, host: str, port: int, *_args: object) -> list[tuple]:
        """Answer one lookup.

        Args:
            host: The name to look up.
            port: The port, which is carried into the sockaddr.
            *_args: The rest of ``getaddrinfo``'s signature, unused.

        Returns:
            One ``getaddrinfo`` row.

        Raises:
            socket.gaierror: If the name is not in ``answers``, which is what a real resolver
                does and is not a policy decision.
        """
        self.asked.append(host)
        address = self.answers.get(host)
        if address is None:
            raise socket.gaierror(socket.EAI_NONAME, f"{host}: no answer")
        if ":" in address:
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, port, 0, 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]
