"""End-to-end tests against a running Charles (opt-in).

Run with a Charles 5.2.x whose Web Interface is enabled (admin/123456 by
default) and which is recording:

    CHARLES5_MCP_LIVE=1 CHARLES_PROXY_PORT=8888 pytest tests/live -q

Traffic goes to a local origin server started by the test, through Charles.
Nothing is sent to the internet. The Charles session is not cleared; Charles'
own throttling and tool state is restored afterwards.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import threading
import time
import uuid
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import zstandard

from charles5_mcp.compat import tool_result_payload
from charles5_mcp.config import Settings
from charles5_mcp.server import build_app, create_mcp_server

pytestmark = pytest.mark.skipif(
    os.getenv("CHARLES5_MCP_LIVE") != "1", reason="set CHARLES5_MCP_LIVE=1 to run against Charles"
)

PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06"
    b"\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\xdac\xfc\xcf\xc0P\x0f\x00\x04"
    b"\x85\x01\x80\x84\xa9\x8c!\x00\x00\x00\x00IEND\xaeB`\x82"
)
SECRET = "live-secret"
TOKEN = "T0KEN-live-0123456789abcdef"


def _sign(ts: str, body: str) -> str:
    return hashlib.md5(f"{ts}{body}{SECRET}".encode()).hexdigest()


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status, body, ctype="application/json", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        doc = json.dumps({"path": path, "ok": True}).encode()
        if path == "/zstd":
            return self._send(
                200, zstandard.ZstdCompressor().compress(doc), extra={"Content-Encoding": "zstd"}
            )
        if path == "/deflate":
            return self._send(200, zlib.compress(doc), extra={"Content-Encoding": "deflate"})
        if path == "/proto":
            return self._send(200, b"\x08\x96\x01\x12\x05hello", "application/x-protobuf")
        if path == "/logo.png":
            return self._send(200, b"\x89PNG\r\n\x1a\n", "image/png")
        if path == "/gzip-png":
            return self._send(
                200, gzip.compress(PNG), "image/png", extra={"Content-Encoding": "gzip"}
            )
        if path == "/missing":
            return self._send(404, b'{"code":404}')
        return self._send(200, doc)

    def do_POST(self):
        url = urlsplit(self.path)
        if url.path.startswith("/upload"):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            return self._send(200, json.dumps({"msg": "上传成功"}, ensure_ascii=False).encode())
        params = {k: v[0] for k, v in parse_qs(url.query).items()}
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        if self.headers.get("X-Token") != TOKEN:
            return self._send(401, b'{"code":401,"msg":"unauthorized"}')
        ts = params.get("ts", "")
        if not ts.isdigit() or abs(int(ts) - time.time()) > 300:
            return self._send(200, json.dumps({"code": 40002, "msg": "timestamp expired"}).encode())
        if params.get("sign") != _sign(ts, body):
            return self._send(200, json.dumps({"code": 40001, "msg": "签名错误"}).encode())
        return self._send(200, json.dumps({"code": 0, "data": {"order": 1}}).encode())


@pytest.fixture
def origin():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture
def settings(tmp_path):
    base = Settings.from_env()
    base.state_dir = tmp_path / "state"
    base.recordings_dir = tmp_path / "state" / "recordings"
    return base


@pytest.fixture
def call(settings):
    app = build_app(settings)
    server = create_mcp_server(app=app)

    async def _call(_tool: str, **arguments):
        return tool_result_payload(await server.call_tool(_tool, arguments))

    yield _call
    app.store.close()


@pytest.fixture
def via_charles(settings):
    with httpx.Client(proxy=settings.proxy_url, trust_env=False, timeout=15) as client:
        yield client


def _signed_post(client, origin, item):
    ts = str(int(time.time()))
    body = json.dumps({"item": item, "nonce": uuid.uuid4().hex})
    return client.post(
        f"{origin}/api/order",
        params={"ts": ts, "sign": _sign(ts, body)},
        content=body,
        headers={"Content-Type": "application/json", "X-Token": TOKEN},
    )


async def test_status_and_controls(call):
    status = await call("charles_status")
    assert status["connected"] is True, status
    assert status["recording"] == "recording", (
        "start recording in Charles before running live tests"
    )
    controls = await call("get_charles_controls")
    assert "3G" in controls["throttling"]["presets"]
    assert "map-remote" in controls["tools"]
    original = controls["tools"]["map-remote"]["enabled"]
    try:
        assert (await call("set_charles_tool", tool="map-remote", enabled=not original))[
            "enabled"
        ] is (not original)
    finally:
        await call("set_charles_tool", tool="map-remote", enabled=original)
    was_throttling = controls["throttling"]["active"]
    if not was_throttling:
        assert (await call("throttling", preset="4g"))["preset"] == "4G"
        assert (await call("charles_status"))["throttling"] == "on"
        await call("throttling", preset="off")


async def test_live_capture_end_to_end(call, origin, via_charles, settings):
    capture_id = (await call("start_live_capture"))["capture_id"]
    for path in ("/json", "/zstd", "/deflate", "/proto", "/logo.png", "/missing"):
        via_charles.get(origin + path)
    for item in range(2):
        assert _signed_post(via_charles, origin, item).json()["code"] == 0

    read = await call("read_live_capture", capture_id=capture_id, limit=50)
    paths = [i["path"] for i in read["items"]]
    assert {"/json", "/zstd", "/proto", "/missing"} <= {p.split("?")[0] for p in paths}

    query = await call(
        "query_live_capture_entries", capture_id=capture_id, host_contains="127.0.0.1"
    )
    by_path = {i["path"].split("?")[0]: i for i in query["items"]}
    assert "/logo.png" not in by_path  # api_focus hides images
    zstd = await call(
        "get_traffic_entry_detail",
        entry_id=by_path["/zstd"]["entry_id"],
        capture_id=capture_id,
        include_full_body=True,
    )
    assert json.loads(zstd["response"]["body"]["text"])["path"] == "/zstd"
    proto = await call(
        "get_traffic_entry_detail", entry_id=by_path["/proto"]["entry_id"], capture_id=capture_id
    )
    assert proto["response"]["body"]["kind"] == "protobuf"

    errors = await call(
        "query_live_capture_entries",
        capture_id=capture_id,
        preset="errors_only",
        host_contains="127.0.0.1",
    )
    assert [i["path"] for i in errors["items"]] == ["/missing"]

    exported = await call("export_charles_session", format="chlz", name="live-test")
    history = await call(
        "analyze_recorded_traffic",
        recording_path=exported["recording_path"],
        host_contains="127.0.0.1",
        preset="all_http",
        max_items=50,
    )
    assert {"/zstd", "/proto"} <= {i["path"].split("?")[0] for i in history["items"]}
    if settings.charles_cli_path:
        converted = await call(
            "convert_session_file",
            path=exported["recording_path"],
            output_format="har",
            include_hosts=["127.0.0.1"],
            exclude_mime=["image/*"],
        )
        filtered = await call(
            "analyze_recorded_traffic",
            recording_path=converted["recording_path"],
            preset="all_http",
            max_items=50,
        )
        assert "/logo.png" not in {i["path"] for i in filtered["items"]}

    stopped = await call("stop_live_capture", capture_id=capture_id)
    assert stopped["status"] == "stopped" and stopped["total_entries"] >= 8


async def test_reverse_live_signature_workflow(call, origin, via_charles):
    session_id = (await call("reverse_start_live_analysis"))["live_session_id"]
    for item in range(3):
        _signed_post(via_charles, origin, item)
    workflow = await call("reverse_analyze_live_signature_flow", live_session_id=session_id)
    assert workflow["status"] == "ok", workflow
    assert workflow["selected"]["path"] == "/api/order"
    assert workflow["signature"]["signature_fields"] == ["query.sign"]
    assert "query.ts" in workflow["signature"]["timestamp_fields"]
    entry_id = workflow["selected"]["entry_id"]

    # Replay through Charles so the replays are recorded too.
    plan = await call("reverse_run_mutation_plan", entry_id=entry_id, delay_ms=0, use_proxy=True)
    assert plan["replayable"] is True, plan
    assert plan["conclusions"]["query.sign"] == "enforced"
    assert plan["conclusions"]["query.ts"] == "enforced"
    await call("reverse_stop_live_analysis", live_session_id=session_id)


async def test_bodies_of_every_shape_end_to_end(call, origin, via_charles):
    """Uploads (multipart image, gzip JSON, GBK form, raw image) and a gzip image response."""
    capture_id = (await call("start_live_capture", include_existing=False))["capture_id"]
    via_charles.post(
        origin + "/upload/multipart?album=1",
        files={"photo": ("头像.png", PNG, "image/png")},
        data={"title": "照片"},
    )
    via_charles.post(
        origin + "/upload/gzip-json",
        content=gzip.compress(json.dumps({"user": "张三"}, ensure_ascii=False).encode()),
        headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
    )
    via_charles.post(
        origin + "/upload/form-gbk",
        content="name=%D5%C5%C8%FD",
        headers={"Content-Type": "application/x-www-form-urlencoded; charset=GBK"},
    )
    via_charles.post(origin + "/upload/raw", content=PNG, headers={"Content-Type": "image/png"})
    via_charles.get(origin + "/gzip-png")

    page = await call(
        "get_traffic_entries",
        source="live",
        capture_id=capture_id,
        host_contains="127.0.0.1",
        preset="all_http",
        max_entries=50,
    )
    by_path = {
        i["url"].split("127.0.0.1")[1].split("/", 1)[1].split("?")[0]: i for i in page["items"]
    }
    multipart = by_path["upload/multipart"]
    assert ["album", "1"] in multipart["query_params"]
    parts = {p["name"]: p for p in multipart["request"]["body"]["parts"]}
    assert (
        parts["photo"]["filename"] == "头像.png" and parts["photo"]["detected_type"] == "image/png"
    )
    assert parts["title"]["value"] == "照片"
    assert multipart["response"]["body"]["json"] == {"msg": "上传成功"}
    assert by_path["upload/gzip-json"]["request"]["body"]["json"] == {"user": "张三"}
    assert by_path["upload/form-gbk"]["request"]["body"]["fields"] == {"name": "张三"}
    assert by_path["upload/raw"]["request"]["body"]["kind"] == "image"
    assert by_path["gzip-png"]["response"]["body"]["kind"] == "image"

    saved = await call(
        "get_traffic_entries",
        source="live",
        capture_id=capture_id,
        host_contains="127.0.0.1",
        preset="all_http",
        save_to_file=True,
    )
    assert saved["matched"] >= 5

    files = await call(
        "extract_entry_bodies", entry_id=multipart["entry_id"], capture_id=capture_id
    )
    photo = next(f for f in files["files"] if f.get("part") == "photo")
    with open(photo["path"], "rb") as handle:
        assert handle.read() == PNG
    image = await call(
        "extract_entry_bodies", entry_id=by_path["gzip-png"]["entry_id"], capture_id=capture_id
    )
    with open(image["files"][0]["path"], "rb") as handle:
        assert handle.read() == PNG
    await call("stop_live_capture", capture_id=capture_id)
