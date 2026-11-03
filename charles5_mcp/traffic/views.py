"""Token-efficient summary and detail views of transactions."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl

from charles5_mcp.session.body import render_body
from charles5_mcp.session.classify import Classification
from charles5_mcp.session.model import Message, Transaction
from charles5_mcp.session.websocket import is_websocket, websocket_messages

_HIGHLIGHT_HEADERS = (
    "content-type",
    "authorization",
    "cookie",
    "set-cookie",
    "location",
    "user-agent",
    "x-requested-with",
    "origin",
    "referer",
)
_SIGNAL_SUBSTRINGS = ("token", "sign", "auth", "session", "nonce", "timestamp", "device", "trace")


def compact(value: Any) -> Any:
    """Drop None / empty containers recursively so responses stay small."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            item = compact(item)
            if item is None or item == [] or item == {} or item is False and key.startswith("is_"):
                continue
            out[key] = item
        return out
    if isinstance(value, list):
        return [compact(item) for item in value]
    return value


# Tool results above this size are trimmed (largest list first) to protect the
# caller's context window; ~40k characters is roughly 10-15k tokens.
RESPONSE_BUDGET_CHARS = 40_000


def fit_budget(
    result: dict[str, Any], key: str = "items", budget: int = RESPONSE_BUDGET_CHARS
) -> dict[str, Any]:
    """Drop trailing ``result[key]`` items until the JSON fits ``budget`` characters."""
    items = result.get(key)
    if not isinstance(items, list) or not items:
        return result
    size = len(json.dumps(result, ensure_ascii=False, default=str))
    if size <= budget:
        return result
    kept = list(items)
    while kept and size > budget:
        removed = kept.pop()
        size -= len(json.dumps(removed, ensure_ascii=False, default=str)) + 1
    result[key] = kept
    result["budget_trimmed"] = {
        "dropped": len(items) - len(kept),
        "hint": "Narrow the filters, lower max_items/limit or turn previews off to see the rest.",
    }
    return result


def iso_from_ms(ms: int | None) -> str | None:
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat(timespec="milliseconds")


def header_highlights(message: Message, limit: int) -> dict[str, str]:
    picked: dict[str, str] = {}
    lowered = [(k.lower(), v) for k, v in message.headers]
    for name in _HIGHLIGHT_HEADERS:
        for key, value in lowered:
            if key == name and name not in picked:
                picked[name] = value[:160]
    for key, value in lowered:
        if len(picked) >= limit:
            break
        if key not in picked and (
            key.startswith("x-") or any(s in key for s in _SIGNAL_SUBSTRINGS)
        ):
            picked[key] = value[:160]
    return dict(list(picked.items())[:limit])


def duration_ms(txn: Transaction) -> int | None:
    total = txn.durations.get("total")
    if isinstance(total, (int, float)):
        return int(total)
    if txn.start_ms is not None and txn.end_ms is not None:
        return max(txn.end_ms - txn.start_ms, 0)
    return None


def summarize(
    txn: Transaction,
    cls: Classification,
    entry_id: str,
    *,
    reasons: list[str] | None = None,
    include_preview: bool = True,
    preview_chars: int = 160,
    max_headers: int = 4,
) -> dict[str, Any]:
    path = txn.path + (f"?{txn.query}" if txn.query else "")
    summary: dict[str, Any] = {
        "entry_id": entry_id,
        "method": txn.method,
        "host": txn.host,
        "path": path if len(path) <= 300 else path[:300] + "…",
        "status": txn.response_status,
        "class": cls.resource_class,
        "priority": cls.priority,
        "size": txn.total_size,
        "duration_ms": duration_ms(txn),
        "started": txn.start_time or iso_from_ms(txn.start_ms),
        "request_type": (txn.request.content_type or "").split(";")[0] or None,
        "response_type": (txn.response.content_type or "").split(";")[0] or None,
        "error": txn.error,
        "in_progress": None if txn.is_complete else True,
        "protocol": txn.protocol if txn.protocol and txn.protocol != "HTTP/1.1" else None,
        "interim": [i.status for i in txn.interim_responses] or None,
        "linked_to_seq": txn.linked_to_seq,
        "matched": reasons or None,
        "replayed_by_mcp": True if txn.request.header("x-charles5-mcp-replay") else None,
    }
    if max_headers > 0:
        summary["request_headers"] = header_highlights(txn.request, max_headers) or None
        summary["response_headers"] = header_highlights(txn.response, max_headers) or None
    if include_preview and is_websocket(txn):
        messages, _ = websocket_messages(txn)
        summary["websocket_messages"] = len(messages)
        first = next((m for m in messages if m.kind in ("text", "binary")), None)
        if first is not None:
            item = first.to_dict(max_chars=preview_chars)
            summary["websocket_preview"] = json.dumps(
                {k: v for k, v in item.items() if k not in ("size",)}, ensure_ascii=False
            )[:preview_chars]
    elif include_preview:
        for side, message in (("request", txn.request), ("response", txn.response)):
            if message.body:
                view = render_body(message, max_chars=preview_chars)
                if view.text:
                    summary[f"{side}_preview"] = view.text + ("…" if view.truncated else "")
    return compact(summary)


def _message_detail(message: Message, *, include_body: bool, max_body_chars: int) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "first_line": message.first_line,
        "headers": [{"name": k, "value": v} for k, v in message.headers],
        "trailers": [{"name": k, "value": v} for k, v in message.trailers] or None,
    }
    if message.body:
        view = render_body(message, max_chars=max_body_chars if include_body else 512)
        body = view.to_dict()
        if not include_body and body.get("text"):
            body["text_preview_only"] = True
        detail["body"] = body
    elif message.body_size:
        detail["body"] = {"kind": "not_captured", "declared_size": message.body_size}
    return detail


def detail(
    txn: Transaction,
    cls: Classification,
    entry_id: str,
    *,
    include_body: bool = False,
    max_body_chars: int = 4096,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "entry_id": entry_id,
        "url": txn.url(),
        "query_params": [list(pair) for pair in parse_qsl(txn.query or "", keep_blank_values=True)]
        or None,
        "method": txn.method,
        "status": txn.response_status,
        "charles_status": txn.status,
        "class": cls.resource_class,
        "priority": cls.priority,
        "priority_reasons": cls.reasons,
        "protocol": txn.protocol,
        "alpn": txn.alpn,
        "tls": txn.tls,
        "remote_address": txn.remote_address,
        "client": f"{txn.client_address}:{txn.client_port}" if txn.client_address else None,
        "started": txn.start_time or iso_from_ms(txn.start_ms),
        "durations_ms": txn.durations,
        "total_size": txn.total_size,
        "error": txn.error,
        "websocket": txn.websocket or None,
        "notes": txn.notes,
        "interim_responses": [
            {"status": i.status, "headers": [{"name": k, "value": v} for k, v in i.headers]}
            for i in txn.interim_responses
        ],
        "linked_to_seq": txn.linked_to_seq,
        "request": _message_detail(
            txn.request, include_body=include_body, max_body_chars=max_body_chars
        ),
        "response": _message_detail(
            txn.response, include_body=include_body, max_body_chars=max_body_chars
        ),
    }
    if is_websocket(txn):
        messages, notes = websocket_messages(txn)
        limit = 200 if include_body else 20
        per_message = (
            max(80, max_body_chars // max(len(messages[:limit]), 1)) if include_body else 160
        )
        # The bodies are raw frames; show decoded messages instead.
        for side in ("request", "response"):
            result[side].pop("body", None)
        result["websocket"] = {
            "message_count": len(messages),
            "messages": [m.to_dict(max_chars=per_message) for m in messages[:limit]],
            "truncated": len(messages) > limit or None,
            "notes": notes or None,
            "order": "client messages first, then server messages (Charles does not keep interleaving)",
        }
    return compact(result)
