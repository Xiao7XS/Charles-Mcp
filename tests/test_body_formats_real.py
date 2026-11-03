"""Request and response bodies in every shape, as recorded by a real Charles 5.2.2.

tests/fixtures/charles-5.2.2/formats.* hold one session exported four ways.
The requests cover JSON (plain, gzip, br, zstd, deflate, BOM, mislabelled),
url-encoded forms (UTF-8 and GBK), multipart uploads with an image, raw binary
uploads, protobuf, XML, chunked uploads and empty bodies; the responses cover
the same encodings plus images, PDF, zip, JSONP, SSE, 204 and 304.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from charles5_mcp.session import load_session_file
from charles5_mcp.session.body import render_body
from charles5_mcp.traffic.extract import extract_bodies, full_record

FIXTURES = Path(__file__).parent / "fixtures" / "charles-5.2.2"
FORMATS = ["formats.json", "formats.xml", "formats.har", "formats.chlz"]
DOC = {"msg": "你好", "items": [1, 2, 3], "ok": True}
SENT = {"user": "张三", "pwd": "p@ss", "n": 1}


def entries(name):
    found = {}
    for txn in load_session_file(FIXTURES / name):
        if not txn.is_control:
            key = txn.path + ("?" if txn.query else "")
            found.setdefault(key, txn)
    return found


@pytest.mark.parametrize("name", FORMATS)
@pytest.mark.parametrize(
    "path",
    [
        "/r/json",
        "/r/json-bom",
        "/r/json-as-html",
        "/r/gzip-json",
        "/r/br-json",
        "/r/zstd-json",
        "/r/deflate-json",
    ],
)
def test_json_responses_decode_with_chinese_intact(name, path):
    view = render_body(entries(name)[path].response)
    assert view.kind == "json" and view.parsed == DOC, (name, path, view.text, view.notes)


@pytest.mark.parametrize("name", FORMATS)
@pytest.mark.parametrize(
    "path",
    [
        "/u/json",
        "/u/gzip-json",
        "/u/br-json",
        "/u/zstd-json",
        "/u/deflate-json",
        "/u/json-bom",
        "/u/json-as-text",
    ],
)
def test_json_requests_decode_with_chinese_intact(name, path):
    view = render_body(entries(name)[path].request)
    assert view.kind == "json" and view.parsed == SENT, (name, path, view.text, view.notes)


@pytest.mark.parametrize("name", FORMATS)
def test_forms_text_and_xml(name):
    found = entries(name)
    assert render_body(found["/u/form-utf8"].request).parsed == {
        "name": "张三",
        "tags": ["a", "b"],
        "empty": "",
    }
    assert render_body(found["/u/form-gbk"].request).parsed == {"name": "张三", "city": "北京"}
    assert render_body(found["/u/text"].request).text == "纯文本内容"
    assert "<Login>" in render_body(found["/u/xml"].request).text
    assert render_body(found["/r/gbk-html"].response).text == "<p>中文页面</p>"
    assert render_body(found["/u/chunked"].request).parsed == {"part": "chunked"}
    assert render_body(found["/u/graphql"].request).parsed["query"] == "{ me { id } }"
    assert render_body(found["/u/patch"].request).parsed == {"op": "replace"}
    assert render_body(found["/u/no-ct"].request).text == "raw=1"


@pytest.mark.parametrize("name", FORMATS)
def test_multipart_upload_with_image(name):
    view = render_body(entries(name)["/u/multipart"].request)
    assert view.kind == "multipart"
    parts = {p["name"]: p for p in view.parts}
    assert parts["meta"]["json"] == {"album": "相册"}
    assert parts["title"]["value"] == "照片"
    assert (
        parts["photo"]["filename"] == "头像.png" and parts["photo"]["detected_type"] == "image/png"
    )
    assert parts["photo"]["size"] == 76
    assert parts["doc"]["value"] == "plain text file"


@pytest.mark.parametrize("name", FORMATS)
def test_binary_bodies_are_identified(name):
    found = entries(name)
    for path, kind, mime in [
        ("/r/png", "image", "image/png"),
        ("/r/jpeg", "image", "image/jpeg"),
        ("/r/png-as-octet", "image", "image/png"),
        ("/r/gzip-png", "image", "image/png"),
        ("/r/pdf", "file", "application/pdf"),
        ("/r/zip", "file", "application/zip"),
    ]:
        view = render_body(found[path].response)
        assert (view.kind, view.detected_type) == (kind, mime), (name, path, view)
    assert render_body(found["/u/raw-png"].request).kind == "image"
    assert render_body(found["/u/octet-png"].request).detected_type == "image/png"
    assert render_body(found["/u/proto"].request).parsed[1]["value"] == "hello"
    assert render_body(found["/r/proto"].response).kind == "protobuf"


@pytest.mark.parametrize("name", FORMATS)
def test_jsonp_sse_and_empty_bodies(name):
    found = entries(name)
    jsonp = render_body(found["/r/jsonp"].response)
    assert jsonp.kind == "jsonp" and jsonp.parsed == DOC
    assert render_body(found["/r/sse"].response).text.startswith("data: ")
    for path in ("/r/empty-json", "/r/204", "/r/304"):
        assert render_body(found[path].response).kind == "empty"
    assert render_body(found["/u/empty"].request).kind == "empty"


@pytest.mark.parametrize("name", FORMATS)
def test_full_record_has_url_query_headers_and_bodies(name):
    txn = entries(name)["/r/json?"]
    record = full_record(txn, "e1")
    assert record["url"].startswith("http://127.0.0.1:18090/r/json?q=")
    assert ["q", "中文 搜索"] in record["query_params"] and ["list", "b"] in record["query_params"]
    assert any(k.lower() == "accept-encoding" for k, _ in record["request"]["headers"])
    assert record["response"]["body"]["kind"] == "json"


def test_extract_bodies_writes_upload_parts_and_images(tmp_path):
    found = entries("formats.chlz")
    files = extract_bodies(found["/u/multipart"], "m1", tmp_path / "m1")
    by_part = {f.get("part"): f for f in files}
    photo = Path(by_part["photo"]["path"])
    assert photo.name.endswith("头像.png") and photo.read_bytes().startswith(b"\x89PNG")
    assert json.loads(Path(by_part["meta"]["path"]).read_text(encoding="utf-8")) == {
        "album": "相册"
    }
    image = extract_bodies(found["/r/gzip-png"], "g1", tmp_path / "g1")
    assert image[0]["path"].endswith("response_body.png")
    assert Path(image[0]["path"]).read_bytes().startswith(b"\x89PNG")  # gzip removed
    assert (tmp_path / "g1" / "entry.json").is_file()
