"""Replay stored requests, optionally mutated, and compare with the original."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from charles5_mcp.config import Settings
from charles5_mcp.errors import CharlesMCPError
from charles5_mcp.reverse.params import (
    TRANSPORT_HEADERS,
    apply_pairs,
    format_cookies,
    parse_cookies,
    rewrite_urlencoded,
    set_json_path,
)
from charles5_mcp.reverse.store import ReverseStore, new_id
from charles5_mcp.session.body import (
    declared_charset,
    decoded_bytes,
    decoded_text,
    render_body,
)
from charles5_mcp.session.model import Message, Transaction

_CODE_KEYS = (
    "code",
    "errcode",
    "err_code",
    "error_code",
    "errno",
    "ret",
    "retcode",
    "status",
    "status_code",
    "success",
    "ok",
    "result",
)
_MSG_KEYS = (
    "msg",
    "message",
    "errmsg",
    "err_msg",
    "error",
    "error_msg",
    "desc",
    "description",
    "reason",
    "tips",
)
_REJECT_WORDS = (
    "sign",
    "signature",
    "invalid",
    "illegal",
    "expired",
    "unauthor",
    "forbidden",
    "denied",
    "verify",
    "token",
    "timestamp",
    "nonce",
    "签名",
    "非法",
    "过期",
    "无效",
    "校验",
    "验证",
    "未登录",
    "登录",
    "权限",
    "频繁",
)


REPLAY_HEADER = "X-Charles5-MCP-Replay"


def is_replay(txn: Transaction) -> bool:
    """True for requests this server replayed through Charles (marked with REPLAY_HEADER)."""
    return txn.request.header(REPLAY_HEADER) is not None


@dataclass
class Mutation:
    query: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, Any] = field(default_factory=dict)
    cookies: dict[str, Any] = field(default_factory=dict)
    json: dict[str, Any] = field(default_factory=dict)
    form: dict[str, Any] = field(default_factory=dict)
    body_text: str | None = None
    method: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Mutation:
        data = data or {}
        allowed = {
            "query_overrides": "query",
            "header_overrides": "headers",
            "cookie_overrides": "cookies",
            "json_overrides": "json",
            "form_overrides": "form",
            "body_text_override": "body_text",
            "method_override": "method",
        }
        if not isinstance(data, dict):
            raise CharlesMCPError("a mutation must be an object of *_overrides keys")
        unknown = set(data) - set(allowed)
        if unknown:
            raise CharlesMCPError(
                f"unknown mutation keys: {sorted(unknown)}", hint=f"allowed: {sorted(allowed)}"
            )
        kwargs = {allowed[k]: v for k, v in data.items() if v is not None}
        for key in ("query", "headers", "cookies", "json", "form"):
            if key in kwargs and not isinstance(kwargs[key], dict):
                raise CharlesMCPError(
                    f'{key} overrides must be an object like {{"name": "value"}}',
                    hint="use null as the value to remove a field",
                )
        for key in ("body_text", "method"):
            if key in kwargs and not isinstance(kwargs[key], str):
                raise CharlesMCPError(f"{key} override must be a string")
        return cls(**kwargs)

    def describe(self) -> dict[str, Any]:
        """Like ``to_dict`` but with removals spelled out, for tool output (nulls get dropped)."""

        def show(value: Any) -> Any:
            if isinstance(value, dict):
                return {k: "<removed>" if v is None else show(v) for k, v in value.items()}
            return value

        return show(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, name in (
            ("query_overrides", "query"),
            ("header_overrides", "headers"),
            ("cookie_overrides", "cookies"),
            ("json_overrides", "json"),
            ("form_overrides", "form"),
        ):
            value = getattr(self, name)
            if value:
                out[key] = value
        if self.body_text is not None:
            out["body_text_override"] = self.body_text
        if self.method:
            out["method_override"] = self.method
        return out

    @property
    def is_empty(self) -> bool:
        return not self.to_dict()


def build_request(
    txn: Transaction, mutation: Mutation, *, mark: str | None = None
) -> dict[str, Any]:
    """Assemble method/url/headers/body for a replay of ``txn`` with ``mutation`` applied."""
    query = rewrite_urlencoded(txn.query, mutation.query) if mutation.query else txn.query
    url = txn.url(override_query=True, query=query or None)

    headers: list[tuple[str, str]] = []
    for name, value in txn.request.headers:
        lowered = name.lower()
        # HTTP/2 pseudo-headers (:authority, :path ...) and hop-by-hop headers
        # are regenerated by the HTTP client.
        if lowered.startswith(":") or lowered in TRANSPORT_HEADERS:
            continue
        headers.append((name, value))

    body, body_notes = decoded_bytes(txn.request)
    decode_failed = any(note.endswith("_decode_failed") for note in body_notes)
    content_type = txn.request.content_type or ""
    body_changed = False
    if mutation.body_text is not None:
        body = mutation.body_text.encode("utf-8")
        body_changed = True
    elif mutation.json:
        if decode_failed:
            raise CharlesMCPError("the request body could not be decoded, so it cannot be edited")
        try:
            document = json.loads(decoded_text(txn.request) or "{}")
        except ValueError as exc:
            raise CharlesMCPError("json_overrides need a JSON request body", hint=str(exc)) from exc
        for path, value in mutation.json.items():
            try:
                document = set_json_path(document, path, value)
            except (KeyError, IndexError, TypeError) as exc:
                raise CharlesMCPError(
                    f"json path `{path}` does not fit the body: {exc}",
                    hint="Use dot/bracket paths such as data.items[0].sign",
                ) from exc
        charset = declared_charset(txn.request) if "json" in content_type.lower() else None
        body = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode(
            charset or "utf-8", errors="replace"
        )
        body_changed = True
        if "json" not in content_type.lower():
            headers = [(k, v) for k, v in headers if k.lower() != "content-type"]
            headers.append(("Content-Type", "application/json"))
    elif mutation.form:
        if decode_failed:
            raise CharlesMCPError("the request body could not be decoded, so it cannot be edited")
        lowered_type = content_type.lower()
        if body and (
            "multipart/" in lowered_type
            or "json" in lowered_type
            or body.lstrip()[:1] in (b"{", b"[")
        ):
            raise CharlesMCPError(
                "form_overrides only apply to url-encoded bodies",
                hint="Use json_overrides for JSON bodies, or body_text to replace the whole body.",
            )
        # Work on the raw bytes (latin-1 maps each byte to one character), so parameters
        # that are not overridden keep their exact bytes whatever their encoding.
        body = rewrite_urlencoded(
            body.decode("latin-1"), mutation.form, declared_charset(txn.request)
        ).encode("latin-1", errors="replace")
        body_changed = True

    if decode_failed and not body_changed:
        # Send the original bytes with their Content-Encoding intact.
        body = txn.request.body or b""
    elif body and txn.request.effective_content_encoding:
        # The body is sent decoded, so the Content-Encoding header no longer applies.
        headers = [(k, v) for k, v in headers if k.lower() != "content-encoding"]

    if mutation.cookies:
        cookies = apply_pairs(parse_cookies(txn.request.header_values("cookie")), mutation.cookies)
        headers = [(k, v) for k, v in headers if k.lower() != "cookie"]
        if cookies:
            headers.append(("Cookie", format_cookies(cookies)))

    for name, value in mutation.headers.items():
        headers = [(k, v) for k, v in headers if k.lower() != name.lower()]
        if value is not None:
            headers.append((name, str(value)))

    if mark:
        # Lets live tracking tell replays apart from the app's own traffic.
        headers = [(k, v) for k, v in headers if k.lower() != REPLAY_HEADER.lower()]
        headers.append((REPLAY_HEADER, mark))

    return {
        "method": (mutation.method or txn.method).upper(),
        "url": url,
        "headers": headers,
        "body": body or None,
        "body_changed": body_changed,
        "notes": body_notes,
    }


def business_status(message: Message) -> dict[str, Any]:
    """Pull app-level result fields (``code``/``msg``...) out of a JSON body."""
    view = render_body(message, max_chars=0)
    if view.kind != "json" or not isinstance(view.parsed, dict):
        return {}
    doc = view.parsed
    found: dict[str, Any] = {}
    for scope in (doc, doc.get("data") if isinstance(doc.get("data"), dict) else None):
        if not scope:
            continue
        for key in _CODE_KEYS:
            if key in scope and not isinstance(scope[key], (dict, list)) and "code" not in found:
                found["code"] = scope[key]
                found["code_key"] = key
        for key in _MSG_KEYS:
            if key in scope and isinstance(scope[key], str) and "message" not in found:
                found["message"] = scope[key][:200]
    return found


def compare(
    baseline: Transaction, status: int | None, response: Message, error: str | None
) -> dict[str, Any]:
    """Classify a replay as same / changed / rejected relative to the baseline."""
    if error:
        return {"outcome": "error", "error": error}
    base_biz = business_status(baseline.response)
    new_biz = business_status(response)
    base_len = len(decoded_bytes(baseline.response)[0])
    new_len = len(decoded_bytes(response)[0])
    diff: dict[str, Any] = {
        "baseline_status": baseline.response_status,
        "replay_status": status,
        "baseline_size": base_len,
        "replay_size": new_len,
    }
    if base_biz or new_biz:
        diff["baseline_business"] = base_biz or None
        diff["replay_business"] = new_biz or None

    message = str(new_biz.get("message", "")).lower()
    rejected_words = [w for w in _REJECT_WORDS if w in message]
    http_rejected = (
        status is not None
        and status >= 400
        and not (baseline.response_status is not None and baseline.response_status >= 400)
    )
    biz_changed = bool(base_biz) and bool(new_biz) and base_biz.get("code") != new_biz.get("code")
    if http_rejected or (
        biz_changed
        and (rejected_words or new_biz.get("code") not in (0, "0", 200, True, "success", "ok"))
    ):
        outcome = "rejected"
    elif status != baseline.response_status or biz_changed:
        outcome = "changed"
    elif base_len and abs(new_len - base_len) > max(64, base_len * 0.3):
        outcome = "changed"
    else:
        outcome = "same"
    diff["outcome"] = outcome
    if rejected_words:
        diff["rejection_keywords"] = rejected_words
    return diff


class ReplayService:
    def __init__(self, settings: Settings, store: ReverseStore) -> None:
        self.settings = settings
        self.store = store

    async def send(
        self,
        request: dict[str, Any],
        *,
        follow_redirects: bool,
        use_proxy: bool,
        verify_tls: bool,
    ) -> tuple[int | None, Message, int, str | None]:
        options: dict[str, Any] = {
            "timeout": self.settings.replay_timeout,
            "follow_redirects": follow_redirects,
            "trust_env": False,
            "verify": verify_tls,
        }
        if use_proxy:
            options["proxy"] = self.settings.proxy_url
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(**options) as client:
                response = await client.request(
                    request["method"],
                    request["url"],
                    headers=request["headers"],
                    content=request["body"],
                )
                content = response.content
        except httpx.HTTPError as exc:
            hint = ""
            if "CERTIFICATE_VERIFY_FAILED" in str(exc) and use_proxy:
                hint = " (through Charles TLS is re-signed: pass verify_tls=false)"
            return (
                None,
                Message(),
                int((time.monotonic() - started) * 1000),
                f"{type(exc).__name__}: {exc}{hint}",
            )
        message = Message(
            first_line=f"{response.http_version} {response.status_code} {response.reason_phrase}",
            headers=[(k, v) for k, v in response.headers.multi_items()],
            mime_type=response.headers.get("content-type"),
            body=content,
            body_decoded=True,  # httpx already removed the content-encoding
        )
        return response.status_code, message, int((time.monotonic() - started) * 1000), None

    async def replay(
        self,
        entry_id: str,
        mutation: Mutation,
        *,
        label: str | None = None,
        follow_redirects: bool = False,
        use_proxy: bool = False,
        verify_tls: bool = True,
        preview_chars: int = 600,
        record: bool = True,
        emit_finding: bool = True,
        mark_replay: bool = True,
    ) -> dict[str, Any]:
        meta, txn = self.store.get_entry(entry_id)
        run_id = new_id("run")
        # Mark only replays that pass through Charles; direct replays stay byte-exact.
        request = build_request(txn, mutation, mark=run_id if use_proxy and mark_replay else None)
        status, response, latency, error = await self.send(
            request, follow_redirects=follow_redirects, use_proxy=use_proxy, verify_tls=verify_tls
        )
        diff = compare(txn, status, response, error)
        if record:
            self.store.add_run(
                {
                    "run_id": run_id,
                    "entry_id": entry_id,
                    "label": label,
                    "mutation": mutation.to_dict(),
                    "request": {
                        "method": request["method"],
                        "url": request["url"],
                        "headers": request["headers"],
                    },
                    "outcome": diff["outcome"],
                    "response_status": status,
                    "latency_ms": latency,
                    "response_headers": dict(response.headers),
                    "diff": diff,
                    "error": error,
                },
                response.body,
            )
        result: dict[str, Any] = {
            "run_id": run_id,
            "entry_id": entry_id,
            "label": label,
            "request": {"method": request["method"], "url": request["url"]},
            "mutation": mutation.describe() or None,
            "status": status,
            "latency_ms": latency,
            "comparison": diff,
        }
        if response.body and preview_chars:
            view = render_body(response, max_chars=preview_chars)
            result["response_preview"] = view.text
        if error:
            result["error"] = error
        if record and emit_finding and diff["outcome"] in ("rejected", "error"):
            self.store.add_finding(
                subject_type="run",
                subject_id=run_id,
                capture_id=meta["capture_id"],
                finding_type="replay_rejected" if diff["outcome"] == "rejected" else "replay_error",
                severity="medium",
                confidence=0.8 if mutation.is_empty else 0.7,
                title=(
                    "Unmodified replay was rejected: request is time-bound or single-use"
                    if mutation.is_empty
                    else f"Server rejected mutation {label or mutation.to_dict()}"
                ),
                evidence={"entry_id": entry_id, "mutation": mutation.to_dict(), **diff},
            )
        return result

    async def run_plan(
        self,
        entry_id: str,
        variants: list[dict[str, Any]],
        *,
        use_proxy: bool = False,
        verify_tls: bool = True,
        delay_ms: int = 300,
        stop_on_control_failure: bool = True,
    ) -> dict[str, Any]:
        """Replay unmodified first (control), then each variant, and conclude per field."""
        meta, _ = self.store.get_entry(entry_id)
        control = await self.replay(
            entry_id,
            Mutation(),
            label="control",
            use_proxy=use_proxy,
            verify_tls=verify_tls,
            preview_chars=200,
        )
        control_outcome = control["comparison"]["outcome"]
        results: list[dict[str, Any]] = []
        conclusions: dict[str, str] = {}
        if control_outcome in ("rejected", "error") and stop_on_control_failure:
            return {
                "entry_id": entry_id,
                "control": control,
                "replayable": False,
                "conclusion": (
                    "The unmodified request no longer succeeds, so mutation results would be "
                    "meaningless. Capture a fresh request (it is likely time-bound or single-use) "
                    "and run the plan straight away."
                ),
            }
        for variant in variants:
            await asyncio.sleep(max(delay_ms, 0) / 1000)
            label = (
                variant.get("name") or variant.get("variant_id")
                if isinstance(variant, dict)
                else None
            )
            try:
                if not isinstance(variant, dict):
                    raise CharlesMCPError("each variant must be an object with a `mutation`")
                mutation = Mutation.from_dict(
                    variant.get("mutation") or variant.get("replay_recipe")
                )
                outcome = await self.replay(
                    entry_id,
                    mutation,
                    label=label,
                    use_proxy=use_proxy,
                    verify_tls=verify_tls,
                    preview_chars=160,
                    emit_finding=False,
                )
            except CharlesMCPError as exc:
                results.append({"variant": label, "outcome": "invalid_variant", "error": str(exc)})
                continue
            verdict = outcome["comparison"]["outcome"]
            field = variant.get("field") or variant.get("target_id") or outcome["label"]
            if verdict == "rejected":
                conclusions[field] = "enforced"
            elif verdict == "same" and conclusions.get(field) != "enforced":
                conclusions[field] = "not_enforced"
            elif field not in conclusions:
                conclusions[field] = "inconclusive" if verdict != "changed" else "affects_response"
            results.append(
                {
                    "variant": outcome["label"],
                    "mutation": outcome["mutation"],
                    "status": outcome["status"],
                    "outcome": verdict,
                    "business": outcome["comparison"].get("replay_business"),
                }
            )
        enforced = [f for f, c in conclusions.items() if c == "enforced"]
        if enforced:
            self.store.add_finding(
                subject_type="entry",
                subject_id=entry_id,
                capture_id=meta["capture_id"],
                finding_type="verified_parameters",
                severity="high",
                confidence=0.85,
                title=f"Server verifies: {', '.join(enforced)}",
                evidence={"conclusions": conclusions, "variants": results},
                recommendation="Locate where the client computes these values (hook the signing routine).",
            )
        return {
            "entry_id": entry_id,
            "replayable": True,
            "control": {"status": control["status"], "outcome": control_outcome},
            "conclusions": conclusions,
            "enforced_fields": enforced,
            "variants": results,
        }
