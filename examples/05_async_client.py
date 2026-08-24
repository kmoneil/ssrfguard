"""The async client, and the reason it does not resolve on the event loop.

Run it:

    python examples/05_async_client.py

`ssrfguard.httpx.AsyncClient` is the asynchronous twin of `Client` and refuses the same things
for the same reasons. It has one extra argument, `resolver_slots`, and the reason for it is
worth more than the argument is.

`socket.getaddrinfo` blocks, has no timeout, and `socket.setdefaulttimeout` does not apply to
it. A hostile authoritative nameserver can therefore stall a lookup for as long as it likes. On
the synchronous path that holds up the caller who made it and nobody else. On an event loop it
would freeze **every unrelated task in the process**, which is how a security library becomes an
outage and then gets removed. So the async client runs its lookups in a worker thread pool of
its own.

That moves the bound rather than removing it, and the honest version is the number: a thread
blocked in `getaddrinfo` cannot be cancelled, so held lookups accumulate until the slots are
gone, and past that point a *new* name waits. Connections already in the pool are unaffected,
which is what keeps this a limit rather than an outage.
"""

from __future__ import annotations

import asyncio
import socket
import time

import httpx
from _support import ScriptedResolver, heading, loopback_server

from ssrfguard import Policy
from ssrfguard.errors import SSRFGuardError
from ssrfguard.httpx import AsyncClient


async def concurrent_requests(port: int) -> None:
    """Fire several requests at once, which is what the async client is for.

    Args:
        port: The loopback port to aim at.
    """
    heading("Ordinary concurrent use")
    policy = Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={port})
    async with AsyncClient(policy=policy) as client:
        started = time.perf_counter()
        responses = await asyncio.gather(
            *(client.get(f"http://127.0.0.1:{port}/thing/{n}") for n in range(8))
        )
        elapsed = time.perf_counter() - started
    codes = sorted({r.status_code for r in responses})
    print(f"  8 concurrent requests -> {codes} in {elapsed * 1000:.0f} ms")


async def a_stalled_lookup_does_not_stop_the_loop(port: int) -> None:
    """Show a blocking resolver failing to starve an unrelated task.

    Args:
        port: The loopback port, so the unrelated task has real work to do.
    """
    heading("A lookup that blocks does not freeze the event loop")

    ticks = 0

    async def heartbeat() -> None:
        """Count how many times the loop got a turn while a lookup was stuck."""
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    class StallingResolver:
        """A nameserver that takes its time, which is not a thing you can time out."""

        def __call__(self, host: str, prt: int, *_rest: object) -> list[tuple]:
            time.sleep(0.25)  # blocking on purpose: this is what getaddrinfo does
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", prt))]

    policy = Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={port})
    beat = asyncio.create_task(heartbeat())
    async with AsyncClient(policy=policy, resolver=StallingResolver()) as client:
        response = await client.get(f"http://slow.example:{port}/")
    beat.cancel()

    print("  the lookup blocked for 250 ms in a worker thread")
    print(f"  the response arrived: {response.status_code}")
    print(f"  an unrelated task was scheduled {ticks} times while it was stuck")
    print("  on the loop, that number would have been 0")


async def slots(port: int) -> None:
    """Say what `resolver_slots` is and where its default comes from.

    Args:
        port: The loopback port to aim at.
    """
    heading("resolver_slots: the bound, named")
    policy = Policy(allowed_networks=["127.0.0.0/8"], allowed_ports={port})

    # Left alone, the number is the pool's max_connections, because a lookup exists to open a
    # connection and there is no point holding more lookups than connections you could use.
    async with AsyncClient(policy=policy, limits=httpx.Limits(max_connections=20)) as client:
        print("  default: taken from limits.max_connections, here 20")
        response = await client.get(f"http://127.0.0.1:{port}/")
        print(f"  request: {response.status_code}")

    # Set it lower when a stalled lookup should cost fewer threads than a connection would.
    async with AsyncClient(policy=policy, resolver_slots=4) as client:
        print("  explicit: resolver_slots=4, so at most four names resolve at once")
        response = await client.get(f"http://127.0.0.1:{port}/")
        print(f"  request: {response.status_code}")

    print("  the pool is the client's own, so a stall here cannot starve unrelated thread work")


async def refusals(port: int) -> None:
    """Confirm the async surface refuses what the synchronous one refuses.

    Args:
        port: The loopback port, used for the rebinding half.
    """
    heading("The same refusals, on the async surface")
    async with AsyncClient(policy=Policy()) as client:
        try:
            await client.get("http://169.254.169.254/latest/meta-data/")
        except SSRFGuardError as refused:
            print(f"  {type(refused).__name__}: {refused}")

    dns = ScriptedResolver("169.254.169.254")
    async with AsyncClient(policy=Policy(), resolver=dns) as client:
        try:
            await client.get("http://metadata.google.internal/")
        except SSRFGuardError as refused:
            print(f"  {type(refused).__name__}: {refused}")
            print("  a name that resolves to a denied address is refused at resolution,")
            print("  which is the check the URL layer could not make")


async def main() -> None:
    """Run every section against one loopback server."""
    with loopback_server() as server:
        await concurrent_requests(server.port)
        await a_stalled_lookup_does_not_stop_the_loop(server.port)
        await slots(server.port)
        await refusals(server.port)


if __name__ == "__main__":
    asyncio.run(main())
