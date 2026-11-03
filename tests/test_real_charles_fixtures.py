"""Parsing of sessions exported by a real Charles 5.2.2 (tests/fixtures/charles-5.2.2).

The fixtures were recorded by pushing a fixed set of requests through Charles
5.2.2 and exporting the session in every format the Web Interface offers.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from charles5_mcp.session import load_session_file
from charles5_mcp.session.body import render_body
from charles5_mcp.session.classify import classify
from charles5_mcp.session.websocket import websocket_messages

FIXTURES = Path(__file__).parent / "fixtures" / "charles-5.2.2"
FORMATS = ["session.json", "session.xml", "session.har", "session.chlz"]


def _by_path(name: str) -> dict[str, list]:
    entries: dict[str, list] = {}
    for txn in load_session_file(FIXTURES / name):
        if not txn.is_control:
            entries.setdefault(txn.path, []).append(txn)
    return entries


@pytest.mark.parametrize("name", FORMATS)
def test_every_body_shape_decodes(name):
    entries = _by_path(name)
    expect_json = ["/json", "/gzip", "/br", "/zstd", "/deflate"]
    for path in expect_json:
        view = render_body(entries[path][0].response)
        assert view.kind == "json" and view.parsed["path"].startswith(path), (name, path, view)
    assert render_body(entries["/proto"][0].response).parsed[1]["value"] == "hello"
    assert render_body(entries["/binary"][0].response).kind == "binary"
    assert render_body(entries["/gbk"][0].response).text == "中文内容"
    assert render_body(entries["/img.png"][0].response).kind == "image"
    assert render_body(entries["/chunked"][0].response).text == "hello chunked world"
    assert render_body(entries["/gzreq"][0].request).parsed == {"gz": True}
    assert render_body(entries["/form"][0].request).parsed == {"a": "1", "b": "two"}
    multipart = render_body(entries["/upload"][0].request)
    assert multipart.kind == "multipart" and multipart.parts[0]["name"] == "user"
    business = render_body(entries["/biz-error"][0].response).parsed
    assert business == {"code": 40001, "msg": "签名错误"}


@pytest.mark.parametrize("name", FORMATS)
def test_early_hints_are_linked_whatever_the_order(name):
    early = _by_path(name)["/early"]
    interim = [t for t in early if t.is_interim]
    final = [t for t in early if not t.is_interim]
    assert len(interim) == 1 and len(final) == 1
    assert interim[0].linked_to_seq == final[0].seq
    assert [i.status for i in final[0].interim_responses] == [103]
    assert classify(interim[0]).resource_class == "interim"


@pytest.mark.parametrize("name", FORMATS)
def test_errors_ports_and_query_strings(name):
    entries = _by_path(name)
    refused = entries["/refused"][0]
    assert refused.has_error and refused.is_complete and refused.port == 1
    encoded = [t for t in entries["/json"] if t.query]
    assert encoded[0].query == "a=1&b=%2B&c&x=%7E"
    https = [t for t in entries["/json"] if t.scheme == "https"]
    assert https and https[0].port == 18443


@pytest.mark.parametrize("name", ["session.json", "session.xml", "session.chlz"])
def test_in_flight_request_is_not_complete(name):
    slow = _by_path(name)["/slow"][0]
    assert slow.status == "RECEIVED_REQUEST_BODY"
    assert not slow.is_complete and not slow.has_error


def test_control_requests_are_recognised():
    transactions = load_session_file(FIXTURES / "session.json")
    control = [t for t in transactions if t.is_control]
    assert control and all(classify(t).resource_class == "control" for t in control)


def test_formats_agree_on_the_transactions():
    signatures = {}
    for name in FORMATS:
        signatures[name] = sorted(
            (t.method, t.path, t.response_status)
            for t in load_session_file(FIXTURES / name)
            if not t.is_control and t.is_complete
        )
    reference = signatures["session.json"]
    for name, rows in signatures.items():
        assert rows == reference, name


def test_websocket_frames_are_decoded():
    txn = next(t for t in load_session_file(FIXTURES / "websocket.json") if not t.is_control)
    messages, notes = websocket_messages(txn)
    assert notes == []
    kinds = [(m.direction, m.kind) for m in messages]
    assert kinds == [
        ("client", "text"),
        ("client", "binary"),
        ("client", "close"),
        ("server", "text"),
        ("server", "binary"),
        ("server", "close"),
    ]
    assert messages[0].to_dict()["json"] == {"op": "login", "sign": "deadbeef"}
    assert messages[1].to_dict()["protobuf"][0]["value"] == 150


@pytest.mark.skipif(not os.getenv("CHARLES_CLI_PATH"), reason="needs the Charles executable")
def test_binary_chls_via_charles_cli():
    entries = {}
    for txn in load_session_file(
        FIXTURES / "session.chls", charles_cli=os.environ["CHARLES_CLI_PATH"]
    ):
        entries.setdefault(txn.path, txn)
    assert render_body(entries["/zstd"].response).kind == "json"
    assert render_body(entries["/proto"].response).kind == "protobuf"
