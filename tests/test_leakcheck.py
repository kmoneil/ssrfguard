"""The leak check, checked.

A leak check written after the leaks exist is a leak check written to pass, and one that has
never caught anything is indistinguishable from one that cannot. So the mechanism is exercised
directly here: hold a socket open and assert it is seen; close it and assert it is not.

These run in every lane. Importing the plugin does not arm it, because the autouse fixtures only
exist for a run that loaded it with ``-p ssrfguard_leakcheck``, so this costs the gating lane a
few cheap tests, one of which starts a second interpreter, and nothing else.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path

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


#: A test that resolves the row the `leaks` lane used to blame, and a name, which is what reaches
#: mDNSResponder on macOS. Neither needs the network.
FIRST_LOOKUP = """
import socket


def test_the_first_lookup_in_the_process():
    socket.getaddrinfo("0177.0.0.1", 80)
    socket.getaddrinfo("localhost", 80)
"""


def test_regression_platform_resolver_the_first_lookup_is_not_blamed_on_its_test(
    tmp_path: Path,
) -> None:
    """macOS's resolver keeps two sockets open after its first lookup, and that test was blamed.

    So the `leaks` lane failed on every Mac, on `test_encodings.py`'s octal row: the first test in
    the suite to call `getaddrinfo` for real. Linux keeps nothing open, which is why CI's `leaks`
    job, on Ubuntu, was green.

    **In a fresh interpreter, because the sockets are opened once per process.** In this one an
    earlier test has usually opened them already, and this would pass with or without the fix.
    Plugin autoloading is off so the run is this file and the leak check, and nothing else that
    might resolve a name first.
    """
    (tmp_path / "test_first_lookup.py").write_text(FIRST_LOOKUP, encoding="utf-8")
    plugin_directory = str(Path(leakcheck.__file__).parent)
    environment = {
        **os.environ,
        "PYTHONPATH": plugin_directory,
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "ssrfguard_leakcheck", "-p", "no:cacheprovider"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert run.returncode == 0, run.stdout + run.stderr
