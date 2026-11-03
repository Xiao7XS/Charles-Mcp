"""Serialise transactions back to the Charles JSON session schema (.chlsj).

Files written here can be reopened by this server and imported by Charles
(File > Import Session).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from charles5_mcp.session.body import charset_of, looks_like_text
from charles5_mcp.session.model import Message, Transaction
from charles5_mcp.traffic.views import iso_from_ms


def _body_json(message: Message) -> dict[str, Any]:
    """Body in the Charles 5.2.2 export shape (text when decodable, base64 otherwise)."""
    data = message.body or b""
    if message.body_decoded and looks_like_text(data):
        charset = charset_of(message)
        try:
            text = data.decode(charset)
        except (UnicodeDecodeError, LookupError):
            text = None
        if text is not None:
            body: dict[str, Any] = {"text": text, "charset": charset}
            if message.effective_content_encoding:
                body["decoded"] = True
            return body
    body = {"encoding": "base64", "encoded": base64.b64encode(data).decode("ascii")}
    if message.body_decoded and message.effective_content_encoding:
        body["decoded"] = True
    return body


def _message_json(message: Message, *, status: int | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "sizes": {
            "headers": message.header_size,
            "body": message.body_size or len(message.body or b""),
        },
        "mimeType": message.mime_type,
        "charset": message.charset,
        "contentEncoding": message.content_encoding,
        "header": {
            "firstLine": message.first_line,
            "headers": [{"name": k, "value": v} for k, v in message.headers],
        },
    }
    if status is not None:
        out["status"] = status
    if message.body:
        out["body"] = _body_json(message)
    if message.trailers:
        out["trailers"] = [{"name": k, "value": v} for k, v in message.trailers]
    return out


def transaction_to_json(txn: Transaction) -> dict[str, Any]:
    return {
        "status": txn.status or ("COMPLETE" if txn.response_status is not None else None),
        "method": txn.method,
        "protocolVersion": txn.protocol,
        "scheme": txn.scheme,
        "host": txn.host,
        "port": txn.port,
        "actualPort": txn.actual_port or txn.port,
        "path": txn.path,
        "query": txn.query,
        "tunnel": txn.tunnel,
        "webSocket": txn.websocket,
        "remoteAddress": txn.remote_address,
        "clientAddress": txn.client_address,
        "clientPort": txn.client_port,
        "times": {
            "start": txn.start_time or iso_from_ms(txn.start_ms),
            "end": iso_from_ms(txn.end_ms),
        },
        "durations": txn.durations,
        "totalSize": txn.total_size,
        "ssl": txn.tls or None,
        "alpn": {"protocol": txn.alpn} if txn.alpn else None,
        "errorMessage": txn.error,
        "notes": txn.notes,
        "request": _message_json(txn.request),
        # Charles keeps 1xx responses as separate transactions and ignores an
        # informationalResponses key, so none is written.
        "response": _message_json(txn.response, status=txn.response_status),
    }


# Charles' importer rejects null for several members (5.2.2: "Expected
# BEGIN_OBJECT but was NULL", "Expected a string but was NULL"); absent keys
# are fine, so nulls are dropped entirely.
def _drop_null_objects(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _drop_null_objects(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_null_objects(v) for v in value]
    return value


def write_chlsj(path: str | Path, transactions: list[Transaction]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = [_drop_null_objects(transaction_to_json(txn)) for txn in transactions]
    tmp = target.with_suffix(target.suffix + ".part")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    tmp.replace(target)
    return target
