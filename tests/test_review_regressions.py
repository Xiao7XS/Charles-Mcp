"""Regressions for issues found in the 1.2.0 code review."""

from __future__ import annotations

import gzip
import json
import zlib

import brotli
import pytest
import zstandard

from charles5_mcp.reverse.replay import Mutation, build_request
from charles5_mcp.session import body as body_mod
from charles5_mcp.session import parse_bytes
from charles5_mcp.session.body import (
    declared_charset,
    decode_content,
    parse_multipart,
    render_body,
    safe_charset,
)
from charles5_mcp.session.model import Message
from charles5_mcp.session.parsers import parse_har
from charles5_mcp.traffic.extract import extract_bodies
from tests.conftest import make_txn


def _msg(content_type, data, **extra):
    return Message(headers=[("Content-Type", content_type)], body=data, body_decoded=True, **extra)


@pytest.mark.parametrize("name", ["base64", "hex", "zlib", "rot13", "idna", "punycode", "bogus"])
def test_non_text_codecs_are_not_charsets(name):
    assert safe_charset(name) == "utf-8"
    message = _msg(f"text/html; charset={name}", "héllo".encode())
    assert declared_charset(message) is None
    assert render_body(message).text == "héllo"
    txn = make_txn("/c", response_type=f"text/html; charset={name}", response_text="ok")
    assert parse_bytes(json.dumps([txn]).encode())[0].response.body == b"ok"


def test_weak_magic_does_not_override_text():
    form = render_body(_msg("application/x-www-form-urlencoded", b"BMI=22&x=1"))
    assert form.kind == "form" and form.parsed == {"BMI": "22", "x": "1"}
    assert render_body(_msg("text/plain", b"ID3 tag list")).kind == "text"
    png = render_body(_msg("text/plain", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"))
    assert png.kind == "image"  # real binary still wins over a wrong label


def test_multipart_edge_cases():
    no_headers = parse_multipart(b"--b\r\n\r\nhello\r\n--b--", "multipart/form-data; boundary=b")
    assert [(p.headers, p.data) for p in no_headers] == [({}, b"hello")]
    body = (
        b'--ab\r\nContent-Disposition: form-data; filename="a.png"; name="file"\r\n\r\n'
        b"foo--abbar\r\n--ab\r\nContent-Disposition: form-data; name=plain\r\n\r\nv\r\n--ab--\r\n"
    )
    parts = parse_multipart(body, "multipart/form-data; boundary=ab")
    assert [(p.name, p.filename, p.data) for p in parts] == [
        ("file", "a.png", b"foo--abbar"),
        ("plain", None, b"v"),
    ]
    star = parse_multipart(
        b"--b\r\nContent-Disposition: form-data; name=f; filename*=GBK'zh'%D5%C5.txt\r\n\r\nx\r\n--b--",
        "multipart/form-data; boundary=b",
    )
    assert star[0].filename == "张.txt"


def _form_txn(body: bytes, content_type: str):
    txn = make_txn("/f", method="POST", request_type=content_type)
    import base64

    txn["request"]["body"] = {"encoding": "base64", "encoded": base64.b64encode(body).decode()}
    return parse_bytes(json.dumps([txn]).encode())[0]


def test_form_replay_keeps_untouched_bytes_and_rejects_other_bodies():
    gbk = _form_txn(b"name=\xc4\xe3\xba\xc3&sign=x", "application/x-www-form-urlencoded")
    request = build_request(gbk, Mutation(form={"sign": "y"}))
    assert request["body"] == b"name=\xc4\xe3\xba\xc3&sign=y"
    multipart = _form_txn(b"--b\r\n\r\nv\r\n--b--", "multipart/form-data; boundary=b")
    with pytest.raises(Exception, match="url-encoded"):
        build_request(multipart, Mutation(form={"t": "y"}))


def test_har_multipart_boundary_case_and_text_files():
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "http://h/u",
                        "headers": [],
                        "postData": {
                            "mimeType": "multipart/form-data; Boundary=XYZ",
                            "params": [
                                {"name": "a", "value": "1"},
                                {"name": "f", "fileName": "a.txt", "value": "test"},
                                {"name": 'q"x', "fileName": "b.bin", "value": "AAEC"},
                            ],
                        },
                    },
                    "response": {"status": 200, "headers": [], "content": {}},
                }
            ]
        }
    }
    view = render_body(parse_har(har)[0].request)
    parts = {p["name"]: p for p in view.parts}
    assert view.kind == "multipart" and parts["a"]["value"] == "1"
    assert parts["f"]["value"] == "test"
    assert parts['q"x']["size"] == 3


def test_websocket_extract_writes_entry_json(tmp_path):
    txn = make_txn("/ws", status=101)
    txn["response"]["status"] = 101
    txn["response"]["header"] = {
        "firstLine": "HTTP/1.1 101",
        "headers": [{"name": "Upgrade", "value": "websocket"}],
    }
    parsed = parse_bytes(json.dumps([txn]).encode())[0]
    extract_bodies(parsed, "w1", tmp_path)
    assert (tmp_path / "entry.json").is_file()


@pytest.mark.parametrize(
    "coding,compress",
    [
        ("gzip", gzip.compress),
        ("deflate", zlib.compress),
        ("br", brotli.compress),
        ("zstd", zstandard.ZstdCompressor().compress),
    ],
)
def test_decompression_is_capped(monkeypatch, coding, compress):
    monkeypatch.setattr(body_mod, "MAX_DECODED_BYTES", 1000)
    small, notes = decode_content(compress(b"a" * 900), coding)
    assert small == b"a" * 900 and notes == [f"decoded:{coding}"]
    bomb = compress(b"a" * 100_000)
    data, notes = decode_content(bomb, coding)
    assert data == bomb and "over" in notes[0]


def test_concatenated_gzip_members():
    data, _ = decode_content(gzip.compress(b"ab") + gzip.compress(b"cd"), "gzip")
    assert data == b"abcd"
