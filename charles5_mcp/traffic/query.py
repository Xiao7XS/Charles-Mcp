"""Structured traffic filters shared by the live and history planes."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Literal

import jmespath

from charles5_mcp.errors import CharlesMCPError
from charles5_mcp.session.body import decoded_text, render_body
from charles5_mcp.session.classify import NOISE_CLASSES, RESOURCE_CLASSES, Classification
from charles5_mcp.session.model import Transaction
from charles5_mcp.session.websocket import is_websocket, websocket_messages

Preset = Literal["api_focus", "errors_only", "all_http", "page_bootstrap"]
PRESETS: tuple[str, ...] = ("api_focus", "errors_only", "all_http", "page_bootstrap")

_PRESET_EXCLUDES: dict[str, frozenset[str]] = {
    "api_focus": NOISE_CLASSES | {"document", "script"},
    "errors_only": frozenset({"control", "tunnel"}),
    "all_http": frozenset({"control"}),
    "page_bootstrap": frozenset({"control", "tunnel", "image", "font", "media", "interim"}),
}


@dataclass
class TrafficQuery:
    preset: str = "api_focus"
    host_contains: str | None = None
    path_contains: str | None = None
    method_in: list[str] = field(default_factory=list)
    status_in: list[int] = field(default_factory=list)
    resource_class_in: list[str] = field(default_factory=list)
    min_priority_score: int | None = None
    has_error: bool | None = None
    request_header_name: str | None = None
    request_header_value_contains: str | None = None
    response_header_name: str | None = None
    response_header_value_contains: str | None = None
    request_content_type: str | None = None
    response_content_type: str | None = None
    request_body_contains: str | None = None
    response_body_contains: str | None = None
    request_json_query: str | None = None
    response_json_query: str | None = None
    keyword_regex: str | None = None
    min_total_size: int | None = None
    max_total_size: int | None = None
    since_seconds: int | None = None

    def __post_init__(self) -> None:
        if self.preset not in PRESETS:
            raise CharlesMCPError(
                f"unknown preset `{self.preset}`", hint=f"use one of {', '.join(PRESETS)}"
            )
        if self.preset == "errors_only" and self.has_error is None:
            self.has_error = True
        self.method_in = [m.strip().upper() for m in self.method_in if m and m.strip()]
        unknown = [c for c in self.resource_class_in if c not in RESOURCE_CLASSES]
        if unknown:
            raise CharlesMCPError(
                f"unknown resource_class value(s): {unknown}",
                hint=f"valid classes: {', '.join(RESOURCE_CLASSES)}",
            )
        for expression in (self.request_json_query, self.response_json_query):
            if expression:
                try:
                    _compiled(expression)
                except jmespath.exceptions.ParseError as exc:
                    raise CharlesMCPError(
                        f"invalid JMESPath `{expression}`: {exc}",
                        hint="Example: `data.items[?price > `10`]` or `code != `0``",
                    ) from exc
        if self.keyword_regex:
            if len(self.keyword_regex) > 500:
                raise CharlesMCPError("keyword_regex is limited to 500 characters")
            try:
                re.compile(self.keyword_regex)
            except re.error as exc:
                raise CharlesMCPError(f"invalid keyword_regex: {exc}") from exc

    def excluded_by_preset(self, resource_class: str) -> bool:
        if self.resource_class_in:
            # An explicit class selection overrides preset noise filtering.
            return resource_class == "control" and "control" not in self.resource_class_in
        return resource_class in _PRESET_EXCLUDES[self.preset]

    @property
    def needs_bodies(self) -> bool:
        return bool(
            self.request_body_contains
            or self.response_body_contains
            or self.request_json_query
            or self.response_json_query
            or self.keyword_regex
        )


@lru_cache(maxsize=256)
def _compiled(expression: str) -> Any:
    return jmespath.compile(expression)


def _header_match(headers: list[tuple[str, str]], name: str | None, contains: str | None) -> bool:
    lowered_name = name.lower() if name else None
    needle = contains.lower() if contains else None
    for key, value in headers:
        if lowered_name and key.lower() != lowered_name:
            continue
        if needle is None or needle in value.lower():
            return True
    return False


def _json_query(message: Any, expression: str) -> bool:
    view = render_body(message, max_chars=0)
    if view.kind != "json":
        return False
    try:
        result = _compiled(expression).search(view.parsed)
    except jmespath.exceptions.JMESPathError:
        return False  # this entry's JSON has a different shape
    if isinstance(result, bool):
        return result
    return result not in (None, [], {}, "")


def match(
    txn: Transaction, cls: Classification, query: TrafficQuery, *, now_ms: int | None = None
) -> list[str] | None:
    """Return the list of matched-field reasons, or None if ``txn`` is filtered out."""
    reasons: list[str] = []
    if query.since_seconds is not None and txn.start_ms is not None:
        current = now_ms if now_ms is not None else int(time.time() * 1000)
        if txn.start_ms < current - query.since_seconds * 1000:
            return None
        reasons.append(f"within last {query.since_seconds}s")
    if query.host_contains:
        if query.host_contains.lower() not in txn.host.lower():
            return None
        reasons.append("host")
    if query.path_contains:
        if query.path_contains.lower() not in (txn.path + "?" + (txn.query or "")).lower():
            return None
        reasons.append("path")
    if query.method_in:
        if txn.method not in query.method_in:
            return None
        reasons.append("method")
    if query.status_in:
        if txn.response_status not in query.status_in:
            return None
        reasons.append("status")
    if query.resource_class_in:
        if cls.resource_class not in query.resource_class_in:
            return None
        reasons.append("resource_class")
    if query.min_priority_score is not None:
        if cls.priority < query.min_priority_score:
            return None
        reasons.append("priority")
    if query.has_error is not None:
        if txn.has_error != query.has_error:
            return None
        if query.has_error:
            reasons.append("error")
    if query.request_header_name or query.request_header_value_contains:
        if not _header_match(
            txn.request.headers, query.request_header_name, query.request_header_value_contains
        ):
            return None
        reasons.append("request_header")
    if query.response_header_name or query.response_header_value_contains:
        if not _header_match(
            txn.response.headers, query.response_header_name, query.response_header_value_contains
        ):
            return None
        reasons.append("response_header")
    if query.request_content_type:
        if query.request_content_type.lower() not in (txn.request.content_type or "").lower():
            return None
        reasons.append("request_content_type")
    if query.response_content_type:
        if query.response_content_type.lower() not in (txn.response.content_type or "").lower():
            return None
        reasons.append("response_content_type")
    size = txn.total_size or 0
    if query.min_total_size is not None and size < query.min_total_size:
        return None
    if query.max_total_size is not None and size > query.max_total_size:
        return None
    if query.request_body_contains:
        if query.request_body_contains.lower() not in decoded_text(txn.request).lower():
            return None
        reasons.append("request_body")
    if query.response_body_contains:
        if query.response_body_contains.lower() not in decoded_text(txn.response).lower():
            return None
        reasons.append("response_body")
    if query.request_json_query:
        if not _json_query(txn.request, query.request_json_query):
            return None
        reasons.append("request_json")
    if query.response_json_query:
        if not _json_query(txn.response, query.response_json_query):
            return None
        reasons.append("response_json")
    if query.keyword_regex:
        pattern = re.compile(query.keyword_regex, re.IGNORECASE)
        haystacks = [
            txn.url(),
            "\n".join(f"{k}: {v}" for k, v in txn.request.headers),
            "\n".join(f"{k}: {v}" for k, v in txn.response.headers),
            decoded_text(txn.request)[:200_000],
            decoded_text(txn.response)[:200_000],
        ]
        if is_websocket(txn):
            messages, _ = websocket_messages(txn)
            haystacks += [
                m.payload.decode("utf-8", errors="replace") for m in messages if m.kind == "text"
            ]
        if not any(pattern.search(text) for text in haystacks):
            return None
        reasons.append("keyword")
    return reasons
