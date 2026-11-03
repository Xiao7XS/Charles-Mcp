"""Parsing of every session representation, including Charles 5.x specifics."""

from __future__ import annotations

import base64
import gzip
import io
import json
import zipfile
import zlib

import brotli
import pytest
import zstandard

from charles5_mcp.errors import SessionFormatError
from charles5_mcp.session import parse_bytes
from charles5_mcp.session.body import decode_content, render_body
from charles5_mcp.session.classify import classify
from charles5_mcp.session.loader import detect_format, load_session_file
from charles5_mcp.session.parsers import iso_to_ms
from charles5_mcp.session.writer import write_chlsj
from tests.conftest import make_txn


def test_json_export_key_order_does_not_matter():
    txn = make_txn("/v1/login", method="POST", response_json={"ok": True})
    reordered = {key: txn[key] for key in reversed(list(txn))}
    reordered["request"] = {k: txn["request"][k] for k in reversed(list(txn["request"]))}
    a = parse_bytes(json.dumps([txn]).encode())[0]
    b = parse_bytes(json.dumps([reordered]).encode())[0]
    assert (a.method, a.url(), a.response_status) == (b.method, b.url(), b.response_status)
    assert render_body(b.response).parsed == {"ok": True}


@pytest.mark.parametrize(
    ("coding", "compress"),
    [
        ("gzip", gzip.compress),
        ("deflate", zlib.compress),
        ("br", brotli.compress),
        ("zstd", lambda data: zstandard.ZstdCompressor().compress(data)),
        ("gzip, br", lambda data: brotli.compress(gzip.compress(data))),
    ],
)
def test_content_encodings(coding, compress):
    payload = b'{"value": 42}'
    data, notes = decode_content(compress(payload), coding)
    assert data == payload
    assert notes


def test_zstd_without_content_size_frame():
    compressor = zstandard.ZstdCompressor(write_content_size=False)
    data, _ = decode_content(compressor.compress(b"hello zstd"), "zstd")
    assert data == b"hello zstd"


def test_body_already_decoded_by_charles_is_tolerated():
    data, notes = decode_content(b'{"plain": true}', "br")
    assert data == b'{"plain": true}'
    assert notes == ["br_already_decoded_by_charles"]


def test_interim_103_is_linked_to_final_response():
    early = make_txn("/page", response_text="", response_type="text/html", status=103)
    early["response"]["header"]["headers"].append(
        {"name": "Link", "value": "</app.css>; rel=preload"}
    )
    final = make_txn("/page", response_text="<html>", response_type="text/html")
    final["times"]["start"] = early["times"]["start"]
    transactions = parse_bytes(json.dumps([early, final]).encode())
    assert transactions[0].is_interim and transactions[0].linked_to_seq == 2
    assert [i.status for i in transactions[1].interim_responses] == [103]
    assert classify(transactions[0]).resource_class == "interim"


def test_inline_informational_responses_and_trailers():
    txn = make_txn("/grpc.Service/Call", response_type="application/grpc")
    txn["response"]["informationalResponses"] = [{"status": 103, "header": {"headers": []}}]
    txn["response"]["trailers"] = [{"name": "grpc-status", "value": "0"}]
    parsed = parse_bytes(json.dumps([txn]).encode())[0]
    assert parsed.interim_responses[0].status == 103
    assert parsed.response.trailers == [("grpc-status", "0")]


def _chlz(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_native_chlz_ignores_hidden_members_and_orders_numerically():
    meta = make_txn("/one")
    meta["response"].pop("body", None)
    meta["response"]["contentEncoding"] = "gzip"
    second = make_txn("/two")
    second["response"].pop("body", None)
    archive = _chlz(
        {
            "10-meta.json": json.dumps(second).encode(),
            "10-res.json": b'{"n": 10}',
            "2-meta.json": json.dumps(meta).encode(),
            "2-res-enc.json": gzip.compress(b'{"n": 2}'),  # "-enc": still gzip
            ".DS_Store": b"junk",
            "__MACOSX/._2-meta.json": b"junk",
            ".hidden/3-meta.json": b"{not json",
        }
    )
    transactions = parse_bytes(archive, suffix=".chlz")
    assert [t.path for t in transactions] == ["/one", "/two"]
    assert render_body(transactions[0].response).parsed == {"n": 2}
    assert render_body(transactions[1].response).parsed == {"n": 10}


def test_charles_xml_and_har():
    xml = (
        b'<?xml version="1.0"?><charles-session><transaction method="POST" protocol="https" '
        b'host="h.example" path="/login" startTimeMillis="1000" endTimeMillis="1300">'
        b"<request><headers><first-line>POST /login HTTP/1.1</first-line>"
        b"<header><name>Content-Type</name><value>application/x-www-form-urlencoded</value></header>"
        b"</headers><body>user=a&amp;pw=b</body></request>"
        b'<response status="401" mime-type="application/json"><headers></headers>'
        b'<body encoding="base64">' + base64.b64encode(b'{"code":401}') + b"</body></response>"
        b"</transaction></charles-session>"
    )
    txn = parse_bytes(xml)[0]
    assert txn.response_status == 401 and txn.has_error
    assert render_body(txn.request).kind == "form"
    assert render_body(txn.response).parsed == {"code": 401}

    har = {
        "log": {
            "entries": [
                {
                    "startedDateTime": "2026-10-11T02:00:00.5Z",
                    "time": 10,
                    "request": {
                        "method": "GET",
                        "url": "https://h.example:8443/p?q=1",
                        "headers": [],
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {
                            "mimeType": "application/json",
                            "text": "eyJhIjoxfQ==",
                            "encoding": "base64",
                        },
                    },
                }
            ]
        }
    }
    txn = parse_bytes(json.dumps(har).encode(), suffix=".har")[0]
    assert txn.url() == "https://h.example:8443/p?q=1"
    assert render_body(txn.response).parsed == {"a": 1}


def test_binary_chls_without_cli_gives_actionable_error(tmp_path):
    path = tmp_path / "old.chls"
    path.write_bytes(b"\xac\xed\x00\x05serialized")
    with pytest.raises(SessionFormatError) as info:
        load_session_file(path, charles_cli=None)
    assert "CHARLES_CLI_PATH" in (info.value.hint or "")


def test_format_detection():
    assert detect_format(b"PK\x03\x04...") == "chlz"
    assert detect_format(b"\xef\xbb\xbf<?xml") == "xml"
    assert detect_format(b'{"log": {"entries": []}}') == "har"
    assert detect_format(b"[]") == "chlsj"


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-11T10:00:00Z",
        "2026-10-11T18:00:00+0800",
        "2026-10-11T18:00:00.1+08:00",
        "2026-10-11T18:00:00.123456789+08:00",
    ],
)
def test_iso_timestamps_with_any_precision(value):
    assert iso_to_ms(value) == 1791712800000 + (
        100 if ".1+" in value else 123 if "123456789" in value else 0
    )


def test_writer_round_trip(tmp_path):
    original = parse_bytes(
        json.dumps(
            [
                make_txn(
                    "/rt",
                    method="POST",
                    request_body="a=1",
                    request_type="application/x-www-form-urlencoded",
                    response_json={"x": 1},
                )
            ]
        ).encode()
    )
    path = write_chlsj(tmp_path / "rt.chlsj", original)
    again = load_session_file(path)[0]
    assert again.url() == original[0].url()
    assert render_body(again.response).parsed == {"x": 1}
    assert render_body(again.request).parsed == {"a": "1"}
