"""Protect decorator and tool calling for async client."""

import asyncio
import functools
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from .client import AsyncToolGuard


class AsyncProtectMixin:
    """Mixin providing protect decorator and tool calling methods."""

    def protect(
        self: "AsyncToolGuard",
        func: Callable = None,
        *,
        context_id: Optional[str] = None,
    ):
        """Decorator to protect an async function from threats.

        Can be used with or without arguments:
        - @guard.protect
        - @guard.protect(context_id="session-123")

        Args:
            func: Async function to protect
            context_id: Optional context ID

        Returns:
            Decorated async function

        Raises:
            TypeError: If decorated function is not async

        Example:
            ```python
            @guard.protect
            async def fetch_data(query: str):
                return await db.execute(query)

            @guard.protect(context_id="session-123")
            async def call_api(endpoint: str):
                async with httpx.AsyncClient() as client:
                    return await client.get(endpoint)
            ```
        """

        def decorator(f: Callable) -> Callable:
            # Check if function is async
            if not asyncio.iscoroutinefunction(f):
                raise TypeError(
                    f"{f.__name__} must be an async function. "
                    f"Use @guard.protect with async def, or use sync ToolGuard for sync functions."
                )

            @functools.wraps(f)
            async def wrapper(*args, **kwargs):
                # Extract text from arguments
                text = None
                for arg in args:
                    if isinstance(arg, str):
                        text = arg
                        break
                if text is None:
                    for value in kwargs.values():
                        if isinstance(value, str):
                            text = value
                            break

                if text is None:
                    raise ValueError("No text argument found to protect")

                # Check for threats
                await self.check(text, context_id=context_id)

                # If no threat, call original function
                return await f(*args, **kwargs)

            return wrapper

        # Handle both @protect and @protect()
        if func is None:
            return decorator
        else:
            return decorator(func)

    async def call_tool(
        self: "AsyncToolGuard",
        tool_func: Callable,
        *args,
        context_id: Optional[str] = None,
        **kwargs,
    ) -> Any:
        """Call a tool function with protection.

        Alternative to decorator approach for dynamic tool calls.
        Supports both sync and async tool functions.

        Args:
            tool_func: Tool function to call (sync or async)
            *args: Arguments to pass to tool
            context_id: Optional context ID
            **kwargs: Keyword arguments to pass to tool

        Returns:
            Result from tool function

        Raises:
            ThreatBlockedError: If threat detected
            ValueError: If no text argument found

        Example:
            ```python
            # Async tool
            result = await guard.call_tool(
                fetch_data,
                "SELECT * FROM users",
                context_id="session-123"
            )

            # Sync tool (will run in executor)
            result = await guard.call_tool(
                sync_function,
                "some input"
            )
            ```
        """
        # Extract text from arguments
        text = None
        for arg in args:
            if isinstance(arg, str):
                text = arg
                break
        if text is None:
            for value in kwargs.values():
                if isinstance(value, str):
                    text = value
                    break

        if text is None:
            raise ValueError("No text argument found to protect")

        # Check for threats
        await self.check(text, context_id=context_id)

        # If no threat, call tool
        # Handle both sync and async functions
        if asyncio.iscoroutinefunction(tool_func):
            # Async function - await it
            return await tool_func(*args, **kwargs)
        else:
            # Sync function - run in executor to avoid blocking
            # Use get_running_loop() instead of deprecated get_event_loop()
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, lambda: tool_func(*args, **kwargs))
