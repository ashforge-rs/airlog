#!/usr/bin/env python3
"""Example demonstrating async audit context.

This shows how to use audit context with asyncio applications.
"""

import asyncio

from airlog import LoguruAuditStream, Principal, async_audit_context, current_context

stream = LoguruAuditStream()


async def handle_async_request(user_id: str, request_id: str) -> None:
    """Handle an async request with audit context."""
    async with async_audit_context(
        principal=Principal(subject=user_id, auth_method="api_key"),
        correlation_id=request_id,
        service="async-api",
    ):
        ctx = current_context()
        print(f"[{ctx.correlation_id}] Processing async request...")

        stream.record(
            "async_task_started",
            resource="task",
            resource_id=request_id,
        )

        # Simulate async work
        await asyncio.sleep(0.1)

        stream.record(
            "async_task_completed",
            resource="task",
            resource_id=request_id,
            outcome="success",
        )


async def main() -> None:
    """Run multiple async tasks concurrently."""
    print("Processing concurrent async requests with isolated contexts...\n")

    tasks = [
        handle_async_request("alice", "async-req-001"),
        handle_async_request("bob", "async-req-002"),
        handle_async_request("charlie", "async-req-003"),
    ]

    await asyncio.gather(*tasks)

    print("\n✓ All async requests processed with isolated contexts")


if __name__ == "__main__":
    asyncio.run(main())
