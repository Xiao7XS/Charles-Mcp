"""Task-oriented analysis: login/auth, API and signature workflows, plus mutation plans."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from charles5_mcp.reverse import signature
from charles5_mcp.reverse.params import request_parameters
from charles5_mcp.session.body import decoded_text
from charles5_mcp.session.classify import classify
from charles5_mcp.session.model import Transaction


@dataclass(frozen=True)
class Profile:
    name: str
    keywords: tuple[str, ...]
    label: str
    operators: tuple[str, ...]
    target_limit: int
    variant_limit: int


PROFILES: dict[str, Profile] = {
    "login": Profile(
        "login",
        (
            "login",
            "signin",
            "sign-in",
            "sign_in",
            "logon",
            "auth",
            "oauth",
            "token",
            "session",
            "passport",
            "account",
            "sso",
            "verify",
            "sms",
            "captcha",
            "otp",
            "register",
        ),
        "login/auth",
        ("drop", "tamper", "stale_timestamp", "replay_other"),
        4,
        8,
    ),
    "api": Profile(
        "api",
        (
            "api",
            "gateway",
            "rpc",
            "graphql",
            "list",
            "detail",
            "query",
            "search",
            "feed",
            "submit",
            "report",
            "info",
            "config",
            "get",
            "v1",
            "v2",
            "v3",
        ),
        "API",
        ("drop", "tamper", "empty"),
        4,
        8,
    ),
    "signature": Profile(
        "signature",
        ("sign", "api", "gateway", "auth", "token", "login", "pay", "order", "submit"),
        "signature-protected",
        ("drop", "tamper", "stale_timestamp", "replay_other"),
        5,
        14,
    ),
}


def _score(profile: Profile, txn: Transaction, keywords: tuple[str, ...]) -> tuple[int, list[str]]:
    cls = classify(txn)
    if cls.resource_class in {
        "control",
        "tunnel",
        "image",
        "font",
        "media",
        "stylesheet",
        "interim",
    }:
        return 0, []
    score = 0
    reasons: list[str] = []
    target = (txn.path + "?" + (txn.query or "")).lower()
    hits = [k for k in keywords if k in target]
    if hits:
        score += 5 + min(len(hits), 3)
        reasons.append(f"path matches {hits[:3]}")
    if cls.resource_class in {"api", "grpc"}:
        score += 3
        reasons.append(f"{cls.resource_class} traffic")
    if txn.method in {"POST", "PUT", "PATCH"}:
        score += 2
        reasons.append(txn.method)
    if txn.request.body:
        score += 1

    if profile.name == "login":
        response_text = decoded_text(txn.response)[:20_000].lower() if txn.response.body else ""
        if txn.response.header_values("set-cookie"):
            score += 3
            reasons.append("sets cookies")
        if any(
            k in response_text
            for k in ('"token"', "access_token", "refresh_token", '"sessionid"', '"ticket"')
        ):
            score += 4
            reasons.append("response issues a token")
        if txn.response_status in (401, 403):
            score += 1
    elif profile.name == "api":
        if "json" in (txn.response.content_type or "").lower():
            score += 2
            reasons.append("JSON response")
    elif profile.name == "signature":
        params = request_parameters(txn)
        sig_like = [
            f
            for f, v in params.items()
            if signature.name_tokens(f) & signature._SIGNATURE_TOKENS
            or (signature.value_shape(v) or "").startswith(("hex", "base64"))
        ]
        if sig_like:
            score += 6
            reasons.append(f"signature-like fields {sig_like[:3]}")
        time_like = [
            f
            for f, v in params.items()
            if signature.value_shape(v) in ("unix_seconds", "unix_millis")
        ]
        if time_like:
            score += 2
            reasons.append("carries a timestamp")
    if txn.has_error and txn.response_status not in (401, 403):
        score -= 1
    return score, reasons


def rank(
    profile: Profile, entries: Iterable[tuple[str, Transaction]], keywords: list[str] | None
) -> list[dict[str, Any]]:
    words = tuple(k.lower() for k in keywords) if keywords else profile.keywords
    ranked = []
    for entry_id, txn in entries:
        score, reasons = _score(profile, txn, words)
        if score >= 4:
            ranked.append(
                {
                    "entry_id": entry_id,
                    "score": score,
                    "method": txn.method,
                    "host": txn.host,
                    "path": txn.path,
                    "status": txn.response_status,
                    "reasons": reasons,
                }
            )
    ranked.sort(key=lambda r: (r["score"], r["entry_id"]), reverse=True)
    return ranked


# ------------------------------------------------------------- mutation plans


def _tamper(value: str) -> str:
    if not value:
        return "x"
    last = value[-1]
    if last.isdigit():
        replacement = "0" if last != "0" else "1"
    elif last.isalpha():
        replacement = "a" if last.lower() != "a" else "b"
        replacement = replacement.upper() if last.isupper() else replacement
    else:
        replacement = "A"
    return value[:-1] + replacement


def _stale(value: str) -> str | None:
    shape = signature.value_shape(value)
    if shape == "unix_seconds":
        return str(int(value) - 86_400)
    if shape == "unix_millis":
        return str(int(value) - 86_400_000)
    return None


def _recipe(field: str, value: Any) -> dict[str, Any] | None:
    surface, _, name = field.partition(".")
    container = {
        "query": "query_overrides",
        "form": "form_overrides",
        "json": "json_overrides",
        "header": "header_overrides",
        "cookie": "cookie_overrides",
    }.get(surface)
    if container is None or not name:
        return None
    return {container: {name: value}}


def build_mutation_plan(
    profile: Profile,
    entry_id: str,
    txn: Transaction,
    analysis: dict[str, Any] | None,
    peers: list[Transaction] | None = None,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """One-field-at-a-time variants for the most security-relevant request inputs."""
    params = request_parameters(txn)
    peer_params = [request_parameters(p) for p in (peers or []) if p is not txn]
    candidates = {c["field"]: c for c in (analysis or {}).get("candidates", [])}

    targets: list[tuple[int, str, str]] = []
    for field in params:
        if fields is not None:
            if field in fields:
                targets.append((100, field, "requested"))
            continue
        role = candidates.get(field, {}).get("role")
        tokens = signature.name_tokens(field)
        score = 0
        reason = ""
        if role == "signature":
            score, reason = 90, "signature candidate"
        elif role == "timestamp":
            score, reason = 70, "timestamp candidate"
        elif role == "nonce":
            score, reason = 60, "nonce candidate"
        elif tokens & signature._AUTH_TOKENS:
            score, reason = 50, "credential-like name"
        elif field in candidates:
            score, reason = 30, "varies between requests"
        if score:
            targets.append((score, field, reason))
    missing = sorted(set(fields or []) - set(params))
    targets.sort(reverse=True)
    targets = targets[: profile.target_limit if fields is None else len(targets)]

    variants: list[dict[str, Any]] = []
    for _, field, reason in targets:
        value = params[field]
        for operator in profile.operators:
            mutated: Any
            if operator == "drop":
                mutated = None
            elif operator == "tamper":
                mutated = _tamper(value)
            elif operator == "empty":
                mutated = ""
            elif operator == "stale_timestamp":
                mutated = _stale(value)
                if mutated is None:
                    continue
            elif operator == "replay_other":
                others = [p[field] for p in peer_params if p.get(field) not in (None, value)]
                if not others:
                    continue
                mutated = others[0]
            else:
                continue
            recipe = _recipe(field, mutated)
            if recipe is None:
                continue
            variants.append(
                {
                    "variant_id": f"{field}:{operator}",
                    "field": field,
                    "operator": operator,
                    "why": reason,
                    "mutation": recipe,
                }
            )
    limit = (
        profile.variant_limit if fields is None else max(profile.variant_limit, len(targets) * 4)
    )
    return {
        "entry_id": entry_id,
        "workflow": profile.name,
        "targets": [{"field": f, "why": r} for _, f, r in targets],
        "variants": variants[:limit],
        "missing_fields": missing or None,
        "how_to_run": "reverse_run_mutation_plan(entry_id, variants=<this list>) "
        "replays an unmodified control first, then one change at a time.",
    }
