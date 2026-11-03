"""Compatibility layer for the MCP Python SDK.

SDK 1.x ships ``mcp.server.fastmcp.FastMCP``. SDK 2.x renamed it to
``mcp.server.mcpserver.MCPServer`` and changed several constructor options.
Everything in this package talks to the SDK only through this module, so the
server runs unchanged on either line.

Only the surface both versions share is used: the constructor's ``name`` /
``instructions`` / ``lifespan``, the ``tool()`` decorator, ``list_tools``,
``call_tool`` and ``run("stdio")``. Tool dependencies are captured in closures
rather than pulled from the request ``Context``, whose import path also moved.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any

try:  # SDK 2.x
    from mcp.server.mcpserver import MCPServer as _ServerClass
    from mcp.server.mcpserver.exceptions import ToolError

    SDK_MAJOR = 2
except ImportError:  # SDK 1.x
    from mcp.server.fastmcp import FastMCP as _ServerClass  # type: ignore[no-redef,attr-defined]
    from mcp.server.fastmcp.exceptions import ToolError  # type: ignore[no-redef,import-not-found]

    SDK_MAJOR = 1

from mcp.types import ToolAnnotations

__all__ = [
    "SDK_MAJOR",
    "ToolAnnotations",
    "ToolError",
    "create_server",
    "register_tool",
    "tool_result_payload",
]


def create_server(
    name: str,
    *,
    instructions: str,
    version: str,
    lifespan: Callable[[Any], Any] | None = None,
) -> Any:
    """Build an MCP server instance for whichever SDK is installed."""
    kwargs: dict[str, Any] = {"instructions": instructions}
    if lifespan is not None:
        kwargs["lifespan"] = lifespan
    if SDK_MAJOR >= 2:
        kwargs["version"] = version
    return _ServerClass(name, **kwargs)


def register_tool(
    server: Any,
    func: Callable[..., Any],
    *,
    name: str | None = None,
    description: str | None = None,
    read_only: bool = False,
    destructive: bool = False,
    open_world: bool = False,
    idempotent: bool | None = None,
) -> Callable[..., Any]:
    """Register ``func`` as a tool, converting failures into agent-readable errors.

    Both SDKs only forward an exception's message to the client when it is a
    ``ToolError``; anything else becomes a generic "Error executing tool".
    The wrapper turns every exception into a ``ToolError`` that keeps the
    original message, so agents always see why a call failed.
    """
    tool_name = name or func.__name__
    # SDK 1.x names these fields in camelCase; SDK 2.x uses snake_case with
    # camelCase aliases. Validating from the wire (camelCase) form suits both.
    annotations = ToolAnnotations.model_validate(
        {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "openWorldHint": open_world,
            "idempotentHint": idempotent if idempotent is not None else read_only,
        }
    )

    if inspect.iscoroutinefunction(func):

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return await func(*args, **kwargs)
            except ToolError:
                raise
            except Exception as exc:  # noqa: BLE001 - surfaced to the agent
                raise ToolError(_format_error(exc)) from exc

        wrapper: Callable[..., Any] = async_wrapper
    else:

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except ToolError:
                raise
            except Exception as exc:  # noqa: BLE001 - surfaced to the agent
                raise ToolError(_format_error(exc)) from exc

        wrapper = sync_wrapper

    server.tool(
        name=tool_name,
        description=description or inspect.getdoc(func) or tool_name,
        annotations=annotations,
    )(wrapper)
    return wrapper


def _format_error(exc: Exception) -> str:
    message = str(exc) or type(exc).__name__
    hint = getattr(exc, "hint", None)
    if hint:
        message = f"{message} | hint: {hint}"
    return message


def tool_result_payload(result: Any) -> Any:
    """Extract the JSON payload from ``call_tool`` output on either SDK (tests)."""
    import json

    content = result
    if hasattr(result, "content"):
        content = result.content
    elif isinstance(result, tuple):
        content = result[0]
    if isinstance(content, list) and content and hasattr(content[0], "text"):
        text = content[0].text
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    return content
