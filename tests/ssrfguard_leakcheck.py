"""A pytest plugin that fails the test which leaves a socket open.

Loaded with ``-p ssrfguard_leakcheck`` by the `leaks` lane and by nothing else. It is off by
default deliberately: this walks the process's open file descriptors twice per test, and the
gating lane should not pay for that on every run.

**Why this library in particular.** It opens sockets for a living, it holds a pinned connection
across a redirect chain, and a socket leaked on an exception path is two problems rather than
one. The resource half is ordinary. The other half is not: a connection that was validated for
one request and then outlives the object that validated it is a connection whose policy has
stopped applying to it, which is the same failure this package exists to prevent, arriving from
the inside.

**File descriptors, not object graphs.** The obvious implementation walks ``gc.get_objects()``
for live ``socket.socket`` instances and asks which are open. An open file descriptor that was
not open before the test is an objective fact about the process, and it does not depend on what
is holding a reference to what.

What it *does* depend on is timing, and two things had to be handled before this stopped being a
flaky check. Both are written up on ``_settled``, because both are the difference between a leak
report and a report about a socket that was closed correctly a moment ago.

A third is not timing, and is handled before the first test rather than after each one: the
sockets the platform's resolver opens on its first lookup and keeps for the life of the process.
That is written up on ``_platform_resolver_opened``.

A leak is described by its peer rather than by its number. A leak report nobody can act on is a
lane that goes red until somebody deletes it.
"""

from __future__ import annotations

import contextlib
import gc
import os
import resource
import socket
import stat
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

#: How far up to probe when the platform has no ``/proc``. macOS's soft limit is usually 256 and
#: Linux's 1024; the cap stops a machine with an enormous limit turning each test into a million
#: ``fstat`` calls.
_MAX_PROBED_FD = 4096

#: How long to wait for the far end of a closed connection to notice. Long enough that a
#: loaded machine does not produce a false report, short enough that a real leak is not a
#: minute of waiting per test.
_SETTLE_SECONDS = 2.0

#: A name every platform answers without the network: from ``/etc/hosts`` on Linux, and from
#: mDNSResponder's own records on macOS. A name rather than an address, because only a name
#: reaches mDNSResponder.
_WARM_UP_NAME = "localhost"


def _candidate_fds() -> Iterator[int]:
    """Every file descriptor number worth asking about.

    Yields:
        Descriptor numbers. On Linux this is exactly the open ones; elsewhere it is a bounded
        range, and the ``fstat`` below sorts out which are real.
    """
    try:
        entries = [entry.name for entry in Path(f"/proc/{os.getpid()}/fd").iterdir()]
    except OSError:  # pragma: no cover - only off Linux, where the fallback is the path taken
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        limit = _MAX_PROBED_FD if soft in (resource.RLIM_INFINITY, -1) else soft
        yield from range(min(limit, _MAX_PROBED_FD))
        return
    for entry in entries:
        try:
            yield int(entry)
        except ValueError:  # pragma: no cover - /proc does not name anything else
            continue


def _open_sockets() -> set[int]:
    """Which file descriptors are currently open sockets.

    Returns:
        The descriptor numbers.
    """
    found: set[int] = set()
    for fd in _candidate_fds():
        try:
            if stat.S_ISSOCK(os.fstat(fd).st_mode):
                found.add(fd)
        except OSError:
            continue
    return found


def _describe(fd: int) -> str:
    """Say what a leaked descriptor is connected to.

    The descriptor is duplicated before it is wrapped, so that closing the wrapper closes the
    copy and leaves the leak itself exactly as it was. A leak checker that tidied up after the
    thing it is reporting would make the second run of a suite disagree with the first.

    Args:
        fd: The descriptor to describe.

    Returns:
        A line naming the peer, or as much of it as the socket will say.
    """
    try:
        duplicate = socket.socket(fileno=os.dup(fd))
    except OSError as unusable:  # pragma: no cover - the descriptor closed underneath us
        return f"fd {fd} (could not be inspected: {unusable})"
    try:
        try:
            peer = duplicate.getpeername()
        except OSError:
            peer = None
        local = duplicate.getsockname()
        where = f"{local} -> {peer}" if peer else f"{local}, unconnected"
        return f"fd {fd} ({where})"
    finally:
        duplicate.close()


def _settled(before: set[int]) -> set[int]:
    """What is still open once the process has had a fair chance to close it.

    Two things happen between a test ending and its sockets being gone, and neither is a leak:

    * **A socket referenced only by a cycle closes when the collector reaches it.** The usual
      cycle is an exception's traceback, which every test that asserts on a refusal is holding,
      and a socket somebody still has a reference to is not a socket nobody can close. So
      collect first, and report what survives that.
    * **The other end of a loopback connection closes when this end does, but not instantly.**
      A server thread blocked on a read needs a scheduler slot to notice the peer went away, so
      checking immediately reports the far end of a connection that was closed correctly. A
      bounded wait turns that from an intermittent failure into no failure, which matters: the
      response to a flaky check is to delete it, and then nothing is checked at all.

    Args:
        before: What was open when the test started.

    Returns:
        The descriptors still open, after collecting and after waiting.
    """
    gc.collect()
    deadline = time.monotonic() + _SETTLE_SECONDS
    while True:
        leaked = _open_sockets() - before
        if not leaked or time.monotonic() > deadline:
            return leaked
        time.sleep(0.01)


@pytest.fixture(scope="session", autouse=True)
def _platform_resolver_opened() -> None:
    """Let the C library open the sockets it keeps for good, before any test is watched.

    **macOS's ``getaddrinfo`` opens two sockets on its first call and never closes them**: a
    kernel control socket, ``com.apple.netsrc``, that it orders answers with, and a connection
    to ``/var/run/mDNSResponder``, which answers every name on that platform. Both belong to the
    process rather than to any lookup, so the first test in a run to resolve anything was reported
    as leaking them: ``test_encodings.py``'s octal row, on the order this suite runs in. That is a
    report about the platform, and it failed the lane on macOS while CI, on Ubuntu, was green.

    **One lookup of a name opens both, and nothing opens a third.** Measured on macOS: after this,
    no further socket appeared across every form in the encodings corpus, ``getfqdn`` and
    ``gethostbyaddr``, repeated over three rounds 90 seconds apart. CI's Ubuntu job was green
    without this, so whatever the C library does there it keeps nothing, and this costs it one
    lookup of a name every machine has.

    Opened rather than exempted, because exempting needs to say what a socket is, and the control
    socket cannot be asked: Python refuses to wrap it, which is what the report's "could not be
    inspected" was. And an exemption is a rule about which open sockets do not count, in a check
    whose whole value is that every one does.

    Session-scoped and autouse, so pytest sets it up before the first test's function-scoped
    fixtures, and so before ``_no_leaked_sockets`` takes its first ``before``.
    """
    with contextlib.suppress(OSError):
        socket.getaddrinfo(_WARM_UP_NAME, None)


@pytest.fixture(autouse=True)
def _no_leaked_sockets() -> Iterator[None]:
    """Fail the test that leaves a socket open.

    Autouse, and defined in a plugin rather than a conftest so it is set up before every other
    fixture and therefore torn down after all of them. A server fixture that closes its listener
    in teardown has already done so by the time this looks.

    Yields:
        Control to the test.
    """
    before = _open_sockets()
    yield
    leaked = _settled(before)
    if not leaked:
        return
    described = "\n  ".join(_describe(fd) for fd in sorted(leaked))
    raise AssertionError(
        f"this test left {len(leaked)} socket(s) open:\n  {described}\n"
        f"A socket that outlives the test that made it is a connection whose policy has stopped "
        f"applying to it."
    )
