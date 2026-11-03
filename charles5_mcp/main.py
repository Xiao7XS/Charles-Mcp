"""Command-line entry point (stdio transport)."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from charles5_mcp import TARGET_CHARLES_VERSION, __version__


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="charles5-mcp", description="MCP server for Charles Proxy 5.2.x"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"charles5-mcp {__version__} (Charles {TARGET_CHARLES_VERSION})",
    )
    parser.add_argument("--check", action="store_true", help="check Charles connectivity and exit")
    parser.add_argument("--log-level", default=os.getenv("CHARLES_LOG_LEVEL", "WARNING"))
    args = parser.parse_args(argv)

    # stdout carries the MCP protocol; logs must go to stderr.
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.WARNING),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    from charles5_mcp.server import create_mcp_server

    if args.check:
        import asyncio
        import json

        from charles5_mcp.server import build_app

        async def check() -> dict:
            app = build_app()
            try:
                return await app.control.status()
            finally:
                await app.close()

        print(json.dumps(asyncio.run(check()), ensure_ascii=False, indent=2))
        return

    create_mcp_server().run("stdio")


if __name__ == "__main__":
    main()
