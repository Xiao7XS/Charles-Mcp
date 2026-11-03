"""Charles Web Interface access."""

from charles5_mcp.charles.client import (
    EXPORT_ENDPOINTS,
    THROTTLE_ALIASES,
    TOOL_SLUGS,
    CharlesClient,
    detect_charles_version,
)

__all__ = [
    "EXPORT_ENDPOINTS",
    "THROTTLE_ALIASES",
    "TOOL_SLUGS",
    "CharlesClient",
    "detect_charles_version",
]
