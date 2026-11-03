"""Shared fixtures: an in-process fake Charles Web Interface and session builders."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest

from charles5_mcp.charles.client import CharlesClient
from charles5_mcp.compat import tool_result_payload
from charles5_mcp.config import Settings
from charles5_mcp.server import build_app, create_mcp_server

_counter = {"n": 0}


def make_txn(
    path: str = "/api/items",
    *,
    method: str = "GET",
    host: str = "api.example.com",
    status: int | None = 200,
    query: str | None = None,
    start: str | None = None,
    response_json: Any = None,
    response_text: str | None = None,
    response_type: str = "application/json",
    request_headers: list[tuple[str, str]] | None = None,
    request_body: str | None = None,
    request_type: str | None = None,
    charles_status: str = "COMPLETE",
    end: str | None = "auto",
) -> dict[str, Any]:
    """Build one transaction in the Charles JSON export schema."""
    _counter["n"] += 1
    n = _counter["n"]
    start = start or f"2026-10-11T10:{n // 60 % 60:02d}:{n % 60:02d}.000+08:00"
    body_text = response_text
    if response_json is not None:
        body_text = json.dumps(response_json)
    headers = [{"name": k, "value": v} for k, v in (request_headers or [])]
    if request_type:
        headers.append({"name": "Content-Type", "value": request_type})
    txn: dict[str, Any] = {
        "status": charles_status,
        "method": method,
        "protocolVersion": "HTTP/1.1",
        "scheme": "https",
        "host": host,
        "port": 443,
        "actualPort": 443,
        "path": path,
        "query": query,
        "clientPort": 50000 + n,
        "times": {"start": start, "end": start if end == "auto" else end},
        "durations": {"total": 42},
        "totalSize": len(body_text or "") + 100,
        "request": {
            "header": {
                "firstLine": f"{method} {path}{'?' + query if query else ''} HTTP/1.1",
                "headers": headers,
            },
            "mimeType": request_type,
        },
        "response": {
            "status": status,
            "mimeType": response_type,
            "header": {
                "firstLine": f"HTTP/1.1 {status} OK" if status else None,
                "headers": [{"name": "Content-Type", "value": response_type}],
            },
        },
    }
    if request_body is not None:
        txn["request"]["body"] = {"text": request_body}
    if body_text is not None:
        txn["response"]["body"] = {
            "text": base64.b64encode(body_text.encode()).decode(),
            "encoded": True,
        }
    if status is None:
        del txn["response"]["status"]
    return txn


FIXTURES = Path(__file__).parent / "fixtures" / "charles-5.2.2"


def _page(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class FakeCharles:
    """Replays the Charles 5.2.2 Web Interface, using pages captured from the real app.

    Mirrors verified behaviour: exports only work while recording (otherwise the
    HTML session menu is returned); starting a stopped recording opens a new,
    empty session; throttling accepts any preset name; Charles records its own
    control.charles requests while recording.
    """

    def __init__(self, user: str = "admin", password: str = "123456") -> None:
        self.session: list[dict[str, Any]] = []
        self.recording = True
        self.throttle_active = False
        self.throttle_preset: str | None = None
        self.tools: dict[str, bool] = {}
        self.calls: list[str] = []
        self.json_export_enabled = True
        self.reachable = True
        self.web_interface_enabled = True
        self.record_control_requests = True
        self._auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def _status_page(self, template: str, status: str) -> str:
        return re.sub(r"Status: [^<]+", f"Status: {status}", _page(template))

    def handler(self, request: httpx.Request) -> httpx.Response:
        if not self.reachable:
            raise httpx.ConnectError("connection refused", request=request)
        if not self.web_interface_enabled:
            return httpx.Response(
                200, text=_page("page-disabled.html"), headers={"content-type": "text/html"}
            )
        path = request.url.path
        self.calls.append(path)
        if request.headers.get("authorization") != self._auth:
            return httpx.Response(401, text="Unauthorized")
        if (
            self.recording
            and self.record_control_requests
            and not path.startswith("/session/export")
        ):
            self.session.append(
                make_txn(
                    path, host="control.charles", response_type="text/html", response_text="<html/>"
                )
            )
        html_ok = {"content-type": "text/html"}
        if path == "/":
            return httpx.Response(200, text=_page("page-index.html"), headers=html_ok)
        if path == "/recording/":
            return httpx.Response(
                200,
                text=_page(
                    "page-recording.html" if self.recording else "page-recording-stopped.html"
                ),
                headers=html_ok,
            )
        if path == "/recording/start":
            if not self.recording:
                self.session = []  # Charles opens a new session
            self.recording = True
            return httpx.Response(200, text=_page("page-recording.html"), headers=html_ok)
        if path == "/recording/stop":
            self.recording = False
            return httpx.Response(200, text=_page("page-recording-stopped.html"), headers=html_ok)
        if path == "/session/clear":
            self.session.clear()
            return httpx.Response(
                200, text=_page("page-export-not-recording.html"), headers=html_ok
            )
        if path.startswith("/session/export") or path == "/session/download":
            if not self.recording:
                return httpx.Response(
                    200, text=_page("page-export-not-recording.html"), headers=html_ok
                )
            if path == "/session/export-json":
                if not self.json_export_enabled:
                    return httpx.Response(404, text="not found")
                return httpx.Response(200, json=self.session)
            if path == "/session/export-xml":
                return httpx.Response(
                    200, content=self._xml(), headers={"content-type": "text/xml"}
                )
            return httpx.Response(
                200,
                content=b"PK\x03\x04fake",
                headers={"content-type": "application/x-octet-stream"},
            )
        if path == "/throttling/":
            page = _page(
                "page-throttling-active.html" if self.throttle_active else "page-throttling.html"
            )
            return httpx.Response(200, text=page, headers=html_ok)
        if path == "/throttling/activate":
            self.throttle_active = True  # real Charles accepts any preset name
            self.throttle_preset = request.url.params.get("preset")
            return httpx.Response(200, text=_page("page-throttling-active.html"), headers=html_ok)
        if path == "/throttling/deactivate":
            self.throttle_active = False
            self.throttle_preset = None
            return httpx.Response(200, text=_page("page-throttling.html"), headers=html_ok)
        if path == "/tools/":
            return httpx.Response(200, text=_page("page-tools.html"), headers=html_ok)
        match = re.match(r"^/tools/([a-z-]+)/(enable|disable)?$", path)
        if match:
            slug, action = match.groups()
            if f'href="{slug}/"' not in _page("page-tools.html"):
                return httpx.Response(404, text="not found")
            if action:
                self.tools[slug] = action == "enable"
            state = "Enabled" if self.tools.get(slug) else "Disabled"
            return httpx.Response(
                200, text=self._status_page("page-tools_map-remote.html", state), headers=html_ok
            )
        if path == "/quit":
            return httpx.Response(200, text="<html><p>Charles has quit</p></html>")
        return httpx.Response(404, text="not found")

    def _xml(self) -> bytes:
        parts = ['<?xml version="1.0"?><charles-session>']
        for txn in self.session:
            parts.append(
                f'<transaction status="{txn["status"]}" method="{txn["method"]}" protocol="{txn["scheme"]}" host="{txn["host"]}" '
                f'path="{txn["path"]}" startTime="{txn["times"]["start"]}">'
                f"<request><headers><first-line>{txn['method']} {txn['path']} HTTP/1.1</first-line></headers></request>"
                f'<response status="{txn["response"].get("status", "")}"><headers></headers></response>'
                "</transaction>"
            )
        parts.append("</charles-session>")
        return "".join(parts).encode()

    def add(self, *txns: dict[str, Any]) -> None:
        self.session.extend(txns)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(state_dir=tmp_path / "state", charles_cli_path=None, charles_config_path=None)


@pytest.fixture
def fake() -> FakeCharles:
    return FakeCharles()


@pytest.fixture
def app(settings, fake):
    client = CharlesClient(settings, transport=httpx.MockTransport(fake.handler))
    application = build_app(settings, client=client)
    yield application
    application.store.close()


@pytest.fixture
def server(app):
    return create_mcp_server(app=app)


@pytest.fixture
def call(server):
    """Call a tool through the MCP layer and return its JSON payload."""

    async def _call(_tool_name: str, **arguments: Any) -> Any:
        result = await server.call_tool(_tool_name, arguments)
        return tool_result_payload(result)

    return _call
