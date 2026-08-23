"""The leak check, checked.

A leak check written after the leaks exist is a leak check written to pass, and one that has
never caught anything is indistinguishable from one that cannot. So the mechanism is exercised
directly here: hold a socket open and assert it is seen; close it and assert it is not.

These run in every lane. Importing the plugin does not arm it, because the autouse fixture only
exists for a run that loaded it with ``-p ssrfguard_leakcheck``, so this costs the gating lane
two cheap tests and nothing else.
"""

from __future__ import annotations

import socket

import pytest

import ssrfguard_leakcheck as leakcheck


def test_it_sees_a_socket_that_was_left_open(monkeypatch: pytest.MonkeyPatch) -> None:
    """The assertion that stops this being a lane which cannot fail.

    The socket is bound rather than merely created, so it is a real endpoint on the machine and
    not something the platform could be lazy about. It is held by a local, so nothing collects
    it out from under the check.
    """
    monkeypatch.setattr(leakcheck, "_SETTLE_SECONDS", 0.05)
    before = leakcheck._open_sockets()
    leaked = socket.socket()
    leaked.bind(("127.0.0.1", 0))
    try:
        seen = leakcheck._settled(before)
        assert seen, "an open socket went unnoticed; the leaks lane would pass on anything"
        assert leaked.fileno() in seen
    finally:
        leaked.close()


def test_it_says_nothing_about_a_socket_that_was_closed() -> None:
    """The other half. A check that reports every test is a check that gets turned off."""
    before = leakcheck._open_sockets()
    tidy = socket.socket()
    tidy.bind(("127.0.0.1", 0))
    tidy.close()

    assert leakcheck._settled(before) == set()


def test_a_leak_is_described_by_where_it_points() -> None:
    """A report naming a descriptor number and nothing else is a report nobody can act on."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])
    try:
        described = leakcheck._describe(listener.fileno())
    finally:
        listener.close()

    assert str(port) in described
