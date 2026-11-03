"""Async client for the Charles Web Interface (``http://control.charles``).

Charles serves its Web Interface on a virtual host that is only reachable
through Charles' own proxy port, so every request is sent via the proxy.
Enable it in Charles under Proxy > Web Interface Settings.

Behaviour verified against Charles 5.2.2 (see tests/fixtures/charles-5.2.2):

* Every page answers HTTP 200. With the Web Interface switched off the body
  is a "The Web Interface is disabled" page; with bad credentials Charles
  answers 401.
* Session exports only work while Charles is recording. When recording is
  stopped, ``/session/export-*`` returns the HTML session menu instead, and
  starting recording again begins a new, empty session.
* ``/throttling/activate`` accepts any preset name without complaint, so
  presets are validated against the list on ``/throttling/``.
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import plistlib
import re
import subprocess
from pathlib import Path
from typing import Any

import httpx

from charles5_mcp.config import Settings
from charles5_mcp.errors import (
    CharlesAPIError,
    CharlesAuthError,
    CharlesNotRecordingError,
    CharlesUnavailableError,
)
from charles5_mcp.session import parsers
from charles5_mcp.session.model import Transaction

logger = logging.getLogger(__name__)

# Short aliases for the presets Charles 5.2.2 ships with. Custom presets are
# matched by name against the live list.
THROTTLE_ALIASES: dict[str, str] = {
    "3g": "3G",
    "4g": "4G",
    "56k": "56 kbps Modem",
    "256k": "256 kbps ISDN/DSL",
    "512k": "512 kbps ISDN/DSL",
    "2m": "2 Mbps ADSL",
    "8m": "8 Mbps ADSL2",
    "16m": "16 Mbps ADSL2+",
    "32m-vdsl": "32 Mbps VDSL",
    "32m-fibre": "32 Mbps Fibre",
    "fibre": "100 Mbps Fibre",
    "100m": "100 Mbps Fibre",
}

# Tool slugs offered by the 5.2.2 Web Interface (/tools/). The live page is
# authoritative; this list documents the expected set and backs older builds.
TOOL_SLUGS: dict[str, str] = {
    "breakpoints": "Breakpoints",
    "no-caching": "No caching",
    "block-cookies": "Block cookies",
    "map-remote": "Map remote",
    "map-local": "Map local",
    "rewrite": "Rewrite",
    "dns-spoofing": "DNS spoofing",
    "block-list": "Block list",
    "allow-list": "Allow list",
    "auto-save": "Auto save",
    "client-process": "Client process",
}
_LEGACY_TOOL_SLUGS = {"block-list": "black-list", "allow-list": "white-list"}

EXPORT_ENDPOINTS: dict[str, str] = {
    "chlsj": "/session/export-json",
    "xml": "/session/export-xml",
    "har": "/session/export-har",
    "csv": "/session/export-csv",
    "trace": "/session/export-trace",
    "chlz": "/session/download",
}

_STATUS = re.compile(r"Status:\s*([^<\n]+)", re.IGNORECASE)
_OPTION = re.compile(r'<option value="([^"]+)">')
_TOOL_LINK = re.compile(r'<a href="([a-z0-9-]+)/">([^<]+)</a>')
_VERSION = re.compile(r"Charles(?:\s+Proxy)?\s+v?(\d+\.\d+(?:\.\d+)?(?:b\d+)?)", re.IGNORECASE)

_SETUP_HINT = (
    "Start Charles, then enable Proxy > Web Interface Settings > 'Enable web interface' "
    "with the same username/password as CHARLES_USER/CHARLES_PASS. Charles must be "
    "listening on CHARLES_PROXY_HOST:CHARLES_PROXY_PORT (default 127.0.0.1:8888)."
)
SELF_RECORDING_WARNING = (
    "charles_records_its_own_web_interface: Charles is recording this server's control.charles "
    "requests, and every export it records contains the previous export, so the session grows "
    "exponentially with each poll (measured: 1.6 GB after ~30 polls). Fix once in Charles: "
    "Proxy > Recording Settings > Exclude > Add, Host: control.charles"
)

_NOT_RECORDING_HINT = (
    "Charles only exports the session it is currently recording. Start recording "
    "(start_live_capture does this) and reproduce the traffic; to analyse an earlier "
    "session, save it in Charles (File > Save Session) and open the file instead."
)


def _page_status(text: str) -> str | None:
    match = _STATUS.search(text)
    return html.unescape(match.group(1)).strip() if match else None


def detect_charles_version(cli_path: str | None) -> str | None:
    """Read the installed Charles version (the Web Interface does not report it)."""
    if not cli_path:
        return None
    path = Path(cli_path)
    # macOS: /Applications/Charles.app/Contents/MacOS/Charles -> Contents/Info.plist
    plist = path.parent.parent / "Info.plist"
    if plist.is_file():
        try:
            with plist.open("rb") as handle:
                version = plistlib.load(handle).get("CFBundleShortVersionString")
            if version:
                return str(version)
        except (OSError, plistlib.InvalidFileException, ValueError):
            pass
    try:
        result = subprocess.run(
            [str(path), "--version"], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = _VERSION.search(result.stdout + result.stderr)
    return match.group(1) if match else None


class CharlesClient:
    """Reconnecting wrapper over the Web Interface endpoints."""

    def __init__(
        self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings = settings
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()
        self._version: str | None = None
        self._version_checked = False
        # Observations from the latest session export (see export_session).
        self.last_export_bytes: int | None = None
        self.records_control_requests: bool | None = None

    # ------------------------------------------------------------------ plumbing

    def _build(self) -> httpx.AsyncClient:
        kwargs: dict[str, Any] = {
            "base_url": self.settings.control_base_url,
            "auth": httpx.BasicAuth(self.settings.charles_user, self.settings.charles_pass),
            "timeout": httpx.Timeout(self.settings.request_timeout),
            "follow_redirects": True,
            # Ignore HTTP(S)_PROXY from the environment: control.charles only
            # resolves through Charles itself.
            "trust_env": False,
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport
        else:
            kwargs["proxy"] = self.settings.proxy_url
        return httpx.AsyncClient(**kwargs)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get(
        self, path: str, *, params: dict[str, str] | None = None, timeout: float | None = None
    ) -> httpx.Response:
        async with self._lock:
            if self._client is None:
                self._client = self._build()
            client = self._client
        try:
            response = await client.get(
                path, params=params, timeout=timeout or httpx.USE_CLIENT_DEFAULT
            )
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ProxyError) as exc:
            await self.close()
            raise CharlesUnavailableError(
                f"cannot reach Charles at {self.settings.proxy_url}: {exc}", hint=_SETUP_HINT
            ) from exc
        except httpx.TimeoutException as exc:
            raise CharlesUnavailableError(
                f"Charles did not answer {path} within {self.settings.request_timeout}s",
                hint="Large sessions export slowly; raise CHARLES_REQUEST_TIMEOUT or clear old traffic.",
            ) from exc
        except httpx.HTTPError as exc:
            await self.close()
            raise CharlesUnavailableError(
                f"request to Charles failed: {exc}", hint=_SETUP_HINT
            ) from exc

        if response.status_code == 401:
            raise CharlesAuthError(
                "Charles Web Interface rejected the credentials (HTTP 401)",
                hint="Match CHARLES_USER/CHARLES_PASS to Proxy > Web Interface Settings.",
            )
        if response.status_code in (502, 503, 504):
            raise CharlesUnavailableError(
                f"Charles returned HTTP {response.status_code} for {path}", hint=_SETUP_HINT
            )
        if response.status_code >= 400:
            raise CharlesAPIError(
                f"Charles Web Interface returned HTTP {response.status_code} for {path}"
            )
        head = response.content[:2048].decode("utf-8", errors="ignore").lower()
        if "web interface is disabled" in head:
            raise CharlesUnavailableError(
                "Charles is running but its Web Interface is disabled",
                hint="In Charles open Proxy > Web Interface Settings, tick 'Enable web interface' "
                "and set the username/password to match CHARLES_USER/CHARLES_PASS.",
            )
        return response

    async def _page(self, path: str, **kwargs: Any) -> str:
        return (await self._get(path, **kwargs)).text

    # -------------------------------------------------------------------- status

    async def info(self) -> dict[str, Any]:
        await self._get("/")
        if not self._version_checked:
            self._version_checked = True
            self._version = await asyncio.to_thread(
                detect_charles_version, self.settings.charles_cli_path
            )
        return {"reachable": True, "version": self._version}

    async def recording_status(self) -> bool | None:
        """True if recording, False if stopped, None if the page could not be read."""
        status = _page_status(await self._page("/recording/"))
        if status is None:
            return None
        lowered = status.lower()
        if "stopped" in lowered:
            return False
        return lowered.startswith("recording")

    # ----------------------------------------------------------------- recording

    async def start_recording(self) -> None:
        await self._get("/recording/start")

    async def stop_recording(self) -> None:
        await self._get("/recording/stop")

    async def clear_session(self) -> None:
        await self._get("/session/clear")

    # ------------------------------------------------------------------- exports

    async def export_raw(self, fmt: str) -> bytes:
        """Raw bytes of one export format (see ``EXPORT_ENDPOINTS``)."""
        endpoint = EXPORT_ENDPOINTS.get(fmt)
        if endpoint is None:
            raise CharlesAPIError(
                f"unknown export format `{fmt}`", hint=f"one of {', '.join(EXPORT_ENDPOINTS)}"
            )
        response = await self._get(endpoint)
        content_type = response.headers.get("content-type", "").lower()
        if content_type.startswith("text/html") and b"<html" in response.content[:200].lower():
            raise CharlesNotRecordingError(
                "Charles is not recording, so there is no current session to export",
                hint=_NOT_RECORDING_HINT,
            )
        return response.content

    async def export_session(self) -> list[Transaction]:
        """Export the current session; JSON first, XML if the JSON is unusable."""
        try:
            raw = await self.export_raw("chlsj")
            self.last_export_bytes = len(raw)
            payload = json.loads(raw) if raw.strip() else []
            transactions = parsers.parse_charles_json(payload, source_format="live-json")
            self.records_control_requests = any(t.is_control for t in transactions)
            return transactions
        except CharlesNotRecordingError:
            raise
        except (CharlesAPIError, ValueError, RecursionError) as exc:
            logger.info("JSON export unusable (%s); falling back to XML export", exc)
        raw_xml = await self.export_raw("xml")
        return parsers.parse_charles_xml(raw_xml) if raw_xml.strip() else []

    # ---------------------------------------------------------------- throttling

    async def throttling_status(self) -> dict[str, Any]:
        page = await self._page("/throttling/")
        status = _page_status(page) or "unknown"
        presets = [html.unescape(value) for value in _OPTION.findall(page)]
        return {"active": status.lower() == "throttling", "status": status, "presets": presets}

    async def resolve_preset(self, preset: str) -> str:
        presets = (await self.throttling_status())["presets"]
        wanted = preset.strip()
        candidates = [THROTTLE_ALIASES.get(wanted.lower(), wanted)]
        for candidate in candidates:
            for name in presets:
                if name.lower() == candidate.lower():
                    return name
        raise CharlesAPIError(
            f"Charles has no throttling preset `{preset}`",
            hint="available: " + "; ".join(presets) if presets else "no presets reported",
        )

    async def set_throttling(self, preset: str | None) -> str:
        """Activate a preset (alias or exact name, validated); None deactivates."""
        if preset is None:
            await self._get("/throttling/deactivate")
            return "deactivated"
        name = await self.resolve_preset(preset)
        await self._get("/throttling/activate", params={"preset": name})
        return name

    # ---------------------------------------------------------------- tool toggles

    async def list_tools(self) -> dict[str, str]:
        """``{slug: display name}`` from the live /tools/ page."""
        page = await self._page("/tools/")
        found = {slug: html.unescape(name) for slug, name in _TOOL_LINK.findall(page)}
        return found or dict(TOOL_SLUGS)

    async def tool_status(self, slug: str) -> bool | None:
        status = _page_status(await self._page(f"/tools/{slug}/"))
        if status is None:
            return None
        return status.lower() == "enabled"

    async def tools_status(self) -> dict[str, dict[str, Any]]:
        tools = await self.list_tools()
        states = await asyncio.gather(*(self.tool_status(slug) for slug in tools))
        return {
            slug: {"name": name, "enabled": state}
            for (slug, name), state in zip(tools.items(), states, strict=True)
        }

    async def set_tool(self, tool: str, enabled: bool) -> dict[str, Any]:
        tools = await self.list_tools()
        slug = tool if tool in tools else _LEGACY_TOOL_SLUGS.get(tool)
        if slug not in tools:
            raise CharlesAPIError(
                f"unknown Charles tool `{tool}`", hint=f"one of: {', '.join(sorted(tools))}"
            )
        page = await self._page(f"/tools/{slug}/{'enable' if enabled else 'disable'}")
        status = _page_status(page)
        return {"tool": slug, "name": tools[slug], "enabled": (status or "").lower() == "enabled"}

    # ---------------------------------------------------------------------- quit

    async def quit(self) -> None:
        try:
            await self._get("/quit", timeout=3.0)
        except (CharlesUnavailableError, CharlesAPIError):
            pass  # the connection drops while Charles exits
        finally:
            await self.close()
