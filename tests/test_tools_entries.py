"""get_traffic_entries / extract_entry_bodies through the MCP layer."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from charles5_mcp.reverse.params import request_parameters, rewrite_urlencoded
from charles5_mcp.session import parse_bytes
from tests.conftest import make_txn

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)


def _png_txn():
    txn = make_txn("/img/logo.png", response_type="image/png")
    txn["response"]["body"] = {"encoding": "base64", "encoded": base64.b64encode(PNG).decode()}
    return txn


async def _history(call, fake, *txns):
    fake.add(*txns)
    await call("export_charles_session", name="entries")


async def test_entries_inline_with_filters_and_paging(call, fake):
    await _history(
        call,
        fake,
        make_txn(
            "/api/login",
            method="POST",
            query="from=app&q=%E4%B8%AD",
            request_type="application/json",
            request_body=json.dumps({"user": "张三"}),
            response_json={"token": "abc"},
        ),
        make_txn("/api/me", response_json={"id": 1}),
        _png_txn(),
    )
    page = await call("get_traffic_entries", source="history", path_contains="/api", max_entries=1)
    assert page["matched"] == 2 and page["next_offset"] == 1
    first = page["items"][0]
    assert first["method"] == "POST" and ["q", "中"] in first["query_params"]
    assert first["request"]["body"]["json"] == {"user": "张三"}
    assert first["response"]["body"]["json"] == {"token": "abc"}
    assert first["request"]["headers"]
    second = await call("get_traffic_entries", source="history", path_contains="/api", offset=1)
    assert [i["url"].split("/")[-1] for i in second["items"]] == ["me"]
    assert "next_offset" not in second

    by_id = await call(
        "get_traffic_entries", source="history", entry_ids=[first["entry_id"], "nope"]
    )
    assert by_id["matched"] == 1 and by_id["missing_entry_ids"] == ["nope"]


async def test_entries_save_to_file_and_extract_image(call, fake):
    await _history(call, fake, make_txn("/a", response_json={"x": 1}), _png_txn())
    saved = await call("get_traffic_entries", source="history", save_to_file=True)
    lines = Path(saved["file"]).read_text(encoding="utf-8").splitlines()
    assert len(lines) == saved["matched"] == 2
    again = await call("get_traffic_entries", source="history", save_to_file=True)
    assert again["file"] != saved["file"]  # never overwrites
    image_id = json.loads(lines[1])["entry_id"]
    assert json.loads(lines[1])["response"]["body"]["kind"] == "image"

    extracted = await call("extract_entry_bodies", entry_id=image_id, source="history")
    body = Path(extracted["files"][0]["path"])
    assert body.suffix == ".png" and body.read_bytes() == PNG
    assert (Path(extracted["directory"]) / "entry.json").is_file()


async def test_oversized_entry_still_advances(call, fake):
    big = "x" * 30000
    txns = [
        make_txn(f"/big{i}", request_headers=[("Cookie", big)], response_text=big) for i in range(2)
    ]
    await _history(call, fake, *txns)
    page = await call("get_traffic_entries", source="history", max_body_chars=20000)
    assert len(page["items"]) >= 1 and page.get("next_offset", 2) >= 1


def test_gbk_form_params_and_rewrite_keep_the_charset():
    txn = make_txn(
        "/f",
        method="POST",
        request_type="application/x-www-form-urlencoded; charset=GBK",
        request_body="name=%D5%C5%C8%FD&city=x",
    )
    parsed = parse_bytes(json.dumps([txn]).encode())[0]
    assert request_parameters(parsed)["form.name"] == "张三"
    assert rewrite_urlencoded("name=%D5%C5%C8%FD&city=x", {"city": "北京"}, "gbk") == (
        "name=%D5%C5%C8%FD&city=%B1%B1%BE%A9"
    )
