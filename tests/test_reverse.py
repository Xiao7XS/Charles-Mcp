"""Reverse analysis: import, signatures, replay and mutation plans against a real local server."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
from google.protobuf import descriptor_pb2

from charles5_mcp.compat import ToolError
from tests.conftest import make_txn

SECRET = "s3cr3t"


def sign(ts: str, body: str) -> str:
    return hashlib.md5(f"{ts}{body}{SECRET}".encode()).hexdigest()


class SignedApi(BaseHTTPRequestHandler):
    """Verifies token, timestamp freshness and an md5 signature; ignores the nonce."""

    def log_message(self, *args):  # silence test output
        pass

    def do_POST(self):
        url = urlsplit(self.path)
        params = {k: v[0] for k, v in parse_qs(url.query).items()}
        body = self.rfile.read(int(self.headers.get("content-length") or 0)).decode()
        if self.headers.get("x-token") != "T0KEN-abcdef0123456789":
            return self._reply(401, {"code": 401, "msg": "unauthorized"})
        ts = params.get("ts", "")
        if not ts.isdigit() or abs(int(ts) - time.time()) > 300:
            return self._reply(200, {"code": 40002, "msg": "timestamp expired"})
        if params.get("sign") != sign(ts, body):
            return self._reply(200, {"code": 40001, "msg": "签名错误"})
        return self._reply(200, {"code": 0, "msg": "ok", "data": {"order": 1}})

    def _reply(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def api_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), SignedApi)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()


def signed_txn(port: int, offset: int = 0) -> dict:
    ts = str(int(time.time()) - offset)
    body = json.dumps({"item": 1, "nonce": uuid.uuid4().hex})
    txn = make_txn(
        "/api/order",
        method="POST",
        host="127.0.0.1",
        query=f"ts={ts}&sign={sign(ts, body)}",
        request_headers=[("x-token", "T0KEN-abcdef0123456789"), ("Accept-Encoding", "gzip")],
        request_body=body,
        request_type="application/json",
        response_json={"code": 0, "msg": "ok"},
        start=datetime.now(timezone.utc).isoformat(),
    )
    txn["scheme"] = "http"
    txn["port"] = txn["actualPort"] = port
    return txn


@pytest.fixture
def capture_file(tmp_path, api_server):
    path = tmp_path / "signed.chlsj"
    path.write_text(
        json.dumps(
            [signed_txn(api_server, offset=i) for i in range(3)]
            + [make_txn("/img/a.png", response_type="image/png", response_text="x")]
        )
    )
    return path


async def test_import_query_detail_decode(call, capture_file):
    imported = await call("reverse_import_session", path=str(capture_file))
    capture_id = imported["capture_id"]
    assert imported["entries"] == 4 and imported["format"] == "chlsj"
    listing = await call("reverse_query_entries", capture_id=capture_id, path_contains="order")
    assert listing["total_matching"] == 3
    entry_id = listing["items"][0]["entry_id"]
    detail = await call("reverse_get_entry_detail", entry_id=entry_id)
    assert (
        "query.sign" in detail["request_parameters"]
        and "json.nonce" in detail["request_parameters"]
    )
    decoded = await call("reverse_decode_entry_body", entry_id=entry_id, side="response")
    assert decoded["kind"] == "json"
    captures = await call("reverse_list_captures")
    assert captures["captures"][0]["capture_id"] == capture_id


async def test_signature_discovery_labels_roles(call, capture_file):
    capture_id = (await call("reverse_import_session", path=str(capture_file)))["capture_id"]
    result = await call(
        "reverse_discover_signature_candidates", capture_id=capture_id, path_contains="/api/order"
    )
    assert result["signature_fields"] == ["query.sign"]
    assert "query.ts" in result["timestamp_fields"]
    assert "json.nonce" in result.get("nonce_fields", []) or "json.nonce" in result[
        "signature_fields"
    ] + [c["field"] for c in result["candidates"]]
    assert any(s["field"] == "header.x-token" for s in result["static_secrets"])
    # `items`-style names must not be mistaken for timestamps
    roles = {c["field"]: c["role"] for c in result["candidates"]}
    assert roles.get("json.item") in (None, "dynamic")
    findings = await call("reverse_list_findings", capture_id=capture_id)
    assert findings["findings"][0]["finding_type"] == "signature_candidates"


async def test_replay_and_business_level_rejection(call, capture_file):
    capture_id = (await call("reverse_import_session", path=str(capture_file)))["capture_id"]
    entry_id = (await call("reverse_query_entries", capture_id=capture_id, limit=1))["items"][0][
        "entry_id"
    ]
    same = await call("reverse_replay_entry", entry_id=entry_id)
    assert same["status"] == 200 and same["comparison"]["outcome"] == "same"
    tampered = await call(
        "reverse_replay_entry", entry_id=entry_id, query_overrides={"sign": "0" * 32}
    )
    assert tampered["status"] == 200
    assert tampered["comparison"]["outcome"] == "rejected"
    assert tampered["comparison"]["replay_business"]["code"] == 40001
    assert "签名" in tampered["comparison"]["rejection_keywords"]
    no_token = await call(
        "reverse_replay_entry", entry_id=entry_id, header_overrides={"x-token": None}
    )
    assert no_token["status"] == 401 and no_token["comparison"]["outcome"] == "rejected"
    nonce_changed = await call(
        "reverse_replay_entry", entry_id=entry_id, json_overrides={"nonce": "other"}
    )
    assert nonce_changed["comparison"]["outcome"] == "rejected"  # body is covered by the signature


async def test_mutation_plan_finds_enforced_fields(call, capture_file):
    capture_id = (await call("reverse_import_session", path=str(capture_file)))["capture_id"]
    entry_id = (await call("reverse_query_entries", capture_id=capture_id, limit=1))["items"][0][
        "entry_id"
    ]
    plan = await call("reverse_build_mutation_plan", entry_id=entry_id)
    targeted = [t["field"] for t in plan["targets"]]
    assert targeted[0] == "query.sign" and "query.ts" in targeted
    result = await call("reverse_run_mutation_plan", entry_id=entry_id, delay_ms=0)
    assert result["replayable"] is True
    assert result["conclusions"]["query.sign"] == "enforced"
    assert result["conclusions"]["query.ts"] == "enforced"
    assert (
        "header.x-token" not in result["conclusions"]
        or result["conclusions"]["header.x-token"] == "enforced"
    )
    findings = await call("reverse_list_findings", finding_type="verified_parameters")
    assert "query.sign" in findings["findings"][0]["title"]


async def test_mutation_plan_stops_when_control_fails(call, tmp_path, api_server):
    stale = signed_txn(api_server, offset=3600)
    path = tmp_path / "stale.chlsj"
    path.write_text(json.dumps([stale]))
    capture_id = (await call("reverse_import_session", path=str(path)))["capture_id"]
    entry_id = (await call("reverse_query_entries", capture_id=capture_id))["items"][0]["entry_id"]
    result = await call(
        "reverse_run_mutation_plan", entry_id=entry_id, fields=["query.sign"], delay_ms=0
    )
    assert result["replayable"] is False and "time-bound" in result["conclusion"]


async def test_protobuf_descriptor_decode(call, tmp_path):
    file_proto = descriptor_pb2.FileDescriptorProto(name="t.proto", package="demo", syntax="proto3")
    message = file_proto.message_type.add(name="Login")
    message.field.add(name="user", number=1, type=9, label=1)  # string
    message.field.add(name="code", number=2, type=5, label=1)  # int32
    descriptor_path = tmp_path / "t.desc"
    descriptor_path.write_bytes(
        descriptor_pb2.FileDescriptorSet(file=[file_proto]).SerializeToString()
    )
    payload = b"\x0a\x05alice\x10\x07"
    txn = make_txn("/pb", method="POST", response_type="application/x-protobuf")
    txn["response"]["body"] = {"text": base64.b64encode(payload).decode(), "encoded": True}
    session = tmp_path / "pb.chlsj"
    session.write_text(json.dumps([txn]))
    capture_id = (await call("reverse_import_session", path=str(session)))["capture_id"]
    entry_id = (await call("reverse_query_entries", capture_id=capture_id))["items"][0]["entry_id"]
    raw = await call("reverse_decode_entry_body", entry_id=entry_id, side="response")
    assert raw["kind"] == "protobuf" and raw["fields"][0]["value"] == "alice"
    named = await call(
        "reverse_decode_entry_body",
        entry_id=entry_id,
        side="response",
        descriptor_path=str(descriptor_path),
        message_type="demo.Login",
    )
    assert named["decoded_message"] == {"user": "alice", "code": 7}


async def test_reverse_live_session_and_workflow(call, fake, app):
    fake.add(make_txn("/old"))
    started = await call("reverse_start_live_analysis")
    session_id, capture_id = started["live_session_id"], started["capture_id"]
    assert started["baseline_entries_skipped"] == 1
    fake.add(
        make_txn(
            "/passport/login",
            method="POST",
            request_body='{"user":"a","pwd":"b"}',
            request_type="application/json",
            response_json={"code": 0, "data": {"access_token": "xyz"}},
        ),
        make_txn("/static/app.js", response_type="application/javascript", response_text="var a"),
    )
    peek = await call("reverse_peek_live_entries", live_session_id=session_id)
    assert peek["new_entries"] == 2
    workflow = await call("reverse_analyze_live_login_flow", live_session_id=session_id)
    assert workflow["status"] == "ok"
    assert workflow["selected"]["path"] == "/passport/login"
    assert "response issues a token" in workflow["selected"]["reasons"]
    again = await call("reverse_analyze_live_login_flow", live_session_id=session_id)
    assert again["status"] == "no_new_entries"

    # Repeated polls append to ONE capture instead of creating a snapshot per poll.
    fake.add(make_txn("/api/next"))
    await call("reverse_read_live_entries", live_session_id=session_id)
    captures = (await call("reverse_list_captures"))["captures"]
    assert len(captures) == 1 and captures[0]["entry_count"] == 3
    stopped = await call("reverse_stop_live_analysis", live_session_id=session_id)
    assert stopped["entries_saved"] == 3 and fake.recording is True  # left as the user had it

    workflow = await call("reverse_analyze_capture", capture_id=capture_id, workflow="api")
    assert workflow["status"] == "ok"
    deleted = await call("reverse_delete_capture", capture_id=capture_id)
    assert deleted["deleted_entries"] == 3
    with pytest.raises(ToolError):
        await call("reverse_query_entries", capture_id=capture_id)


def test_replay_preserves_raw_query_and_cookies():
    from charles5_mcp.reverse.replay import Mutation, build_request
    from charles5_mcp.session import parse_bytes

    txn = make_txn(
        "/q",
        query="a=1&b=%2B&c&x=%7Ea&y=a/b",
        request_headers=[("Cookie", "flag; a=1; b=2"), (":authority", "api.example.com")],
    )
    parsed = parse_bytes(json.dumps([txn]).encode())[0]
    untouched = build_request(parsed, Mutation())
    assert untouched["url"].endswith("/q?a=1&b=%2B&c&x=%7Ea&y=a/b")
    assert all(not k.startswith(":") for k, _ in untouched["headers"])
    changed = build_request(
        parsed, Mutation(query={"a": "2", "z": "new value"}, cookies={"a": "9"})
    )
    assert changed["url"].endswith("/q?a=2&b=%2B&c&x=%7Ea&y=a/b&z=new%20value")
    assert ("Cookie", "flag; a=9; b=2") in changed["headers"]


async def test_invalid_variants_do_not_abort_the_plan(call, capture_file):
    capture_id = (await call("reverse_import_session", path=str(capture_file)))["capture_id"]
    entry_id = (await call("reverse_query_entries", capture_id=capture_id, limit=1))["items"][0][
        "entry_id"
    ]
    result = await call(
        "reverse_run_mutation_plan",
        entry_id=entry_id,
        delay_ms=0,
        variants=[
            {"variant_id": "bad", "mutation": {"query_overrides": "oops"}},
            {"variant_id": "deep", "mutation": {"json_overrides": {"item.x": 1}}},
            {
                "variant_id": "sign",
                "field": "query.sign",
                "mutation": {"query_overrides": {"sign": None}},
            },
        ],
    )
    outcomes = {v["variant"]: v["outcome"] for v in result["variants"]}
    assert outcomes["bad"] == "invalid_variant" and outcomes["deep"] == "invalid_variant"
    assert result["conclusions"]["query.sign"] == "enforced"


async def test_reverse_read_respects_limit_without_skipping(call, fake):
    session_id = (await call("reverse_start_live_analysis"))["live_session_id"]
    fake.add(*[make_txn(f"/r{i}") for i in range(5)])
    seen = []
    for _ in range(3):
        read = await call("reverse_read_live_entries", live_session_id=session_id, limit=2)
        seen += [i["path"] for i in read.get("items", [])]
    assert seen == [f"/r{i}" for i in range(5)]


async def test_large_capture_is_scanned_completely(call, tmp_path, api_server):
    noise = [make_txn("/json", start=None) for _ in range(2100)]
    signed = [signed_txn(api_server, offset=i) for i in range(3)]
    path = tmp_path / "big.chlsj"
    path.write_text(json.dumps(noise + signed))
    capture_id = (await call("reverse_import_session", path=str(path)))["capture_id"]
    workflow = await call("reverse_analyze_capture", capture_id=capture_id, workflow="signature")
    assert workflow["status"] == "ok" and workflow["selected"]["path"] == "/api/order"
    assert workflow["signature"]["signature_fields"] == ["query.sign"]
    last = workflow["selected"]["entry_id"]
    plan = await call("reverse_build_mutation_plan", entry_id=last)
    assert plan["variants"]
    listing = await call("reverse_query_entries", capture_id=capture_id, limit=200)
    assert len(json.dumps(listing)) < 45_000
    with pytest.raises(ToolError):
        await call("reverse_analyze_capture", capture_id="rcap-missing")


async def test_proxied_replays_are_marked_and_kept_out_of_live_analysis(call, fake, capture_file):
    from charles5_mcp.reverse.replay import Mutation, build_request
    from charles5_mcp.session import load_session_file

    txn = load_session_file(capture_file)[0]
    marked = build_request(txn, Mutation(query={"sign": None}), mark="run-1")
    assert ("X-Charles5-MCP-Replay", "run-1") in marked["headers"]
    assert "X-Charles5-MCP-Replay" not in dict(build_request(txn, Mutation())["headers"])

    session_id = (await call("reverse_start_live_analysis"))["live_session_id"]
    replayed = make_txn(
        "/api/order", method="POST", request_headers=[("X-Charles5-MCP-Replay", "run-1")]
    )
    fake.add(make_txn("/api/order", method="POST"), replayed)
    read = await call("reverse_read_live_entries", live_session_id=session_id)
    assert read["returned"] == 1


async def test_replay_echo_shows_removed_fields(call, capture_file):
    capture_id = (await call("reverse_import_session", path=str(capture_file)))["capture_id"]
    entry_id = (await call("reverse_query_entries", capture_id=capture_id, limit=1))["items"][0][
        "entry_id"
    ]
    result = await call("reverse_replay_entry", entry_id=entry_id, query_overrides={"sign": None})
    assert result["mutation"] == {"query_overrides": {"sign": "<removed>"}}
