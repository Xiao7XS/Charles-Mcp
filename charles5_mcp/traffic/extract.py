"""Full request/response records for many entries, and saving bodies to files."""

from __future__ import annotations

import json
import mimetypes
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

from charles5_mcp.session.body import (
    declared_charset,
    decoded_bytes,
    is_textual_type,
    parse_multipart,
    render_body,
    sniff_type,
)
from charles5_mcp.session.model import Message, Transaction
from charles5_mcp.session.websocket import is_websocket, websocket_messages
from charles5_mcp.traffic.views import compact, duration_ms, iso_from_ms

_EXTENSIONS = {
    "application/json": ".json",
    "application/javascript": ".js",
    "text/javascript": ".js",
    "text/html": ".html",
    "text/plain": ".txt",
    "text/css": ".css",
    "text/xml": ".xml",
    "application/xml": ".xml",
    "application/x-www-form-urlencoded": ".form.txt",
    "application/x-protobuf": ".pb",
    "application/protobuf": ".pb",
    "application/octet-stream": ".bin",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "image/gif": ".gif",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
}


def query_params(txn: Transaction) -> list[list[str]] | None:
    pairs = parse_qsl(txn.query or "", keep_blank_values=True)
    return [[name, value] for name, value in pairs] or None


def _extension(mime: str | None, data: bytes) -> str:
    sniffed = sniff_type(data, declared_textual=is_textual_type(mime))
    base = (sniffed[0] if sniffed else (mime or "")).split(";")[0].strip().lower()
    if base in _EXTENSIONS:
        return _EXTENSIONS[base]
    guessed = mimetypes.guess_extension(base) if base else None
    if guessed:
        return guessed
    if "json" in base:
        return ".json"
    return ".bin"


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"[^\w.\-]+", "_", name).strip("._")
    return cleaned[:120] or "part"


def message_record(
    message: Message, *, include_headers: bool, max_body_chars: int
) -> dict[str, Any]:
    record: dict[str, Any] = {}
    if include_headers:
        record["first_line"] = message.first_line
        record["headers"] = [[k, v] for k, v in message.headers]
    if message.body:
        view = render_body(message, max_chars=max_body_chars)
        body = view.to_dict(include_parsed=True)
        if view.kind in ("json", "jsonp") and view.parsed is not None and not view.truncated:
            # Structured JSON is easier to consume than its pretty-printed text.
            body["json"] = view.parsed
            body.pop("text", None)
        record["body"] = body
    elif message.body_size:
        record["body"] = {"kind": "not_captured", "declared_size": message.body_size}
    return record


def full_record(
    txn: Transaction,
    entry_id: str,
    *,
    include_headers: bool = True,
    max_body_chars: int = 4096,
) -> dict[str, Any]:
    """URL, request (headers + body) and response (headers + body) of one entry."""
    record: dict[str, Any] = {
        "entry_id": entry_id,
        "method": txn.method,
        "url": txn.url(),
        "query_params": query_params(txn),
        "status": txn.response_status,
        "charles_status": txn.status if txn.status and txn.status != "COMPLETE" else None,
        "error": txn.error,
        "started": txn.start_time or iso_from_ms(txn.start_ms),
        "duration_ms": duration_ms(txn),
        "request": message_record(
            txn.request, include_headers=include_headers, max_body_chars=max_body_chars
        ),
        "response": message_record(
            txn.response, include_headers=include_headers, max_body_chars=max_body_chars
        ),
    }
    if is_websocket(txn):
        messages, _ = websocket_messages(txn)
        record["request"].pop("body", None)
        record["response"].pop("body", None)
        record["websocket_messages"] = [
            m.to_dict(max_chars=min(max_body_chars, 500)) for m in messages[:200]
        ]
    return compact(record)


def extract_bodies(txn: Transaction, entry_id: str, out_dir: Path) -> list[dict[str, Any]]:
    """Write decoded bodies (and each multipart part / WebSocket message list) to files."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[dict[str, Any]] = []

    def save(name: str, data: bytes, **info: Any) -> None:
        path = out_dir / name
        path.write_bytes(data)
        written.append({"path": str(path), "size": len(data), **info})

    if is_websocket(txn):
        messages, _ = websocket_messages(txn)
        payload = [m.to_dict(max_chars=100_000) for m in messages]
        save(
            "websocket_messages.json",
            json.dumps(payload, ensure_ascii=False, indent=1).encode("utf-8"),
            side="both",
            kind="websocket",
        )
        for index, ws_message in enumerate(messages):
            if ws_message.kind == "binary":
                save(
                    f"ws_{index:04d}_{ws_message.direction}.bin",
                    ws_message.payload,
                    side=ws_message.direction,
                    kind="websocket_binary",
                )
    else:
        _extract_http_bodies(txn, save)
    for item in written:
        for key in [k for k, v in item.items() if v is None]:
            del item[key]
    (out_dir / "entry.json").write_text(
        json.dumps(full_record(txn, entry_id, max_body_chars=2000), ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    return written


def _extract_http_bodies(txn: Transaction, save: Callable[..., None]) -> None:
    for side, message in (("request", txn.request), ("response", txn.response)):
        data, notes = decoded_bytes(message)
        if not data:
            continue
        content_type = message.content_type
        if "multipart/" in (content_type or "").lower():
            parts = parse_multipart(data, content_type or "")
            if parts:
                for index, part in enumerate(parts):
                    stem = part.filename or part.name or f"part{index}"
                    name = _safe_name(stem)
                    if not Path(name).suffix:
                        name += _extension(part.content_type, part.data)
                    save(
                        f"{side}_part{index:02d}_{name}",
                        part.data,
                        side=side,
                        part=part.name,
                        filename=part.filename,
                        content_type=part.content_type,
                        detected_type=(
                            sniff_type(
                                part.data, declared_textual=is_textual_type(part.content_type)
                            )
                            or (None,)
                        )[0],
                    )
                continue
        save(
            f"{side}_body{_extension(content_type, data)}",
            data,
            side=side,
            content_type=content_type,
            detected_type=(
                sniff_type(data, declared_textual=is_textual_type(content_type)) or (None,)
            )[0],
            charset=declared_charset(message),
            note="content-encoding removed"
            if any(n.startswith("decoded:") for n in notes)
            or message.body_decoded
            and message.effective_content_encoding
            else None,
        )
