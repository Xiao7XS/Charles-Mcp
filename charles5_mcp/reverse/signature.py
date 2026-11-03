"""Heuristics for spotting signatures, timestamps, nonces and static secrets.

Compares the same request surface across several captured requests and
labels each field by role. Name matching works on whole tokens (``ts`` in
``x-ts`` or ``reqTs``, not in ``items``), and value shape and per-request
behaviour carry more weight than names.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from charles5_mcp.reverse.params import request_parameters
from charles5_mcp.session.model import Transaction

_SIGNATURE_TOKENS = {
    "sign",
    "sig",
    "signature",
    "hmac",
    "digest",
    "hash",
    "checksum",
    "mac",
    "xs",
    "xsign",
    "abogus",
    "xbogus",
    "mstoken",
    "acsignature",
}
_TIME_TOKENS = {
    "ts",
    "t",
    "timestamp",
    "time",
    "nowtime",
    "reqtime",
    "stime",
    "ctime",
    "tm",
    "date",
}
_NONCE_TOKENS = {
    "nonce",
    "noncestr",
    "rand",
    "random",
    "salt",
    "uuid",
    "reqid",
    "requestid",
    "traceid",
    "rid",
}
_AUTH_TOKENS = {
    "token",
    "auth",
    "authorization",
    "session",
    "sid",
    "ticket",
    "jwt",
    "access",
    "accesstoken",
    "key",
    "apikey",
    "appkey",
    "secret",
}

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_B64 = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_JWT = re.compile(r"^eyJ[\w-]+\.[\w-]+\.[\w-]*$")


def name_tokens(field: str) -> set[str]:
    name = field.split(".", 1)[-1]
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    tokens = {t.lower() for t in re.split(r"[^A-Za-z0-9]+|\s+", spaced) if t}
    tokens.add(re.sub(r"[^a-z0-9]", "", name.lower()))
    return tokens


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


def value_shape(value: str) -> str | None:
    v = value.strip().strip('"')
    if _JWT.match(v):
        return "jwt"
    if _UUID.match(v):
        return "uuid"
    if v.isdigit():
        if len(v) == 10:
            return "unix_seconds"
        if len(v) == 13:
            return "unix_millis"
        return None
    if _HEX.match(v) and len(v) in (32, 40, 64, 128):
        return {32: "hex_md5", 40: "hex_sha1", 64: "hex_sha256", 128: "hex_sha512"}[len(v)]
    if _HEX.match(v) and len(v) >= 16:
        return "hex"
    if len(v) >= 20 and _B64.match(v) and entropy(v) > 4.0:
        return "base64_like"
    return None


def _close_to_request_time(value: str, shape: str | None, start_ms: int | None) -> bool:
    if start_ms is None or shape not in ("unix_seconds", "unix_millis"):
        return False
    stamp = int(value) * (1000 if shape == "unix_seconds" else 1)
    return abs(stamp - start_ms) < 15 * 60 * 1000


def analyze(transactions: list[Transaction]) -> dict[str, Any]:
    """Rank request fields by how signature/timestamp/nonce-like they are."""
    per_txn = [request_parameters(txn) for txn in transactions]
    fields = sorted({key for params in per_txn for key in params})
    candidates: list[dict[str, Any]] = []
    static_secrets: list[dict[str, Any]] = []

    for field in fields:
        observed = [
            (params.get(field), txn.start_ms)
            for params, txn in zip(per_txn, transactions, strict=True)
        ]
        values = [v for v, _ in observed if v is not None]
        if not values:
            continue
        distinct = len(set(values))
        tokens = name_tokens(field)
        shapes = Counter(value_shape(v) for v in values)
        shape, _ = shapes.most_common(1)[0]
        avg_entropy = sum(entropy(v) for v in values) / len(values)
        varies = distinct > 1
        unique_per_request = distinct == len(values) and len(values) > 1
        time_correlated = sum(
            _close_to_request_time(v, value_shape(v), ts) for v, ts in observed if v
        ) >= max(1, len(values) // 2)

        role = None
        score = 0.0
        reasons: list[str] = []
        if tokens & _SIGNATURE_TOKENS:
            score += 0.3
            reasons.append("name looks like a signature")
        if tokens & _TIME_TOKENS:
            score += 0.15
            reasons.append("name looks like a timestamp")
        if tokens & _NONCE_TOKENS:
            score += 0.15
            reasons.append("name looks like a nonce")
        if shape and shape.startswith(("hex", "base64")):
            score += 0.25
            reasons.append(f"value shape {shape}")
        if unique_per_request:
            score += 0.25
            reasons.append("different on every request")
        elif varies:
            score += 0.1
            reasons.append("varies between requests")
        if avg_entropy > 3.5 and len(values[0]) >= 16:
            score += 0.1
            reasons.append("high entropy")

        if time_correlated or (tokens & _TIME_TOKENS and shape in ("unix_seconds", "unix_millis")):
            role = "timestamp"
            score = max(score, 0.6) + (0.2 if time_correlated else 0)
            if time_correlated:
                reasons.append("tracks the request time")
        elif (tokens & _NONCE_TOKENS and not tokens & _SIGNATURE_TOKENS and varies) or (
            shape == "uuid" and not tokens & _SIGNATURE_TOKENS
        ):
            role = "nonce"
        elif shape and shape.startswith(("hex", "base64")) and unique_per_request:
            role = "signature"
        elif tokens & _SIGNATURE_TOKENS and varies:
            role = "signature"
        elif not varies and (
            tokens & _AUTH_TOKENS
            or shape in ("jwt", "hex_md5", "hex_sha1", "hex_sha256", "base64_like")
        ):
            static_secrets.append(
                {
                    "field": field,
                    "shape": shape,
                    "sample": values[0][:64] + ("…" if len(values[0]) > 64 else ""),
                    "note": "constant across requests: session token, API key or device id",
                }
            )
            continue

        if role is None and score < 0.35:
            continue
        candidates.append(
            {
                "field": field,
                "role": role or "dynamic",
                "score": round(min(score, 0.99), 2),
                "shape": shape,
                "distinct_values": distinct,
                "observed": len(values),
                "samples": [v[:64] for v in list(dict.fromkeys(values))[:3]],
                "reasons": reasons,
            }
        )

    candidates.sort(key=lambda c: (c["role"] == "signature", c["score"]), reverse=True)
    endpoints = Counter(f"{t.method} {t.host}{t.path}" for t in transactions)
    notes = []
    if len(endpoints) > 1:
        notes.append(
            "Compared requests span several endpoints; compare calls to one endpoint for sharper results."
        )
    if len(transactions) < 3:
        notes.append("Three or more requests to the same endpoint give more reliable roles.")
    signature_fields = [c["field"] for c in candidates if c["role"] == "signature"]
    timestamp_fields = [c["field"] for c in candidates if c["role"] == "timestamp"]
    nonce_fields = [c["field"] for c in candidates if c["role"] == "nonce"]
    return {
        "compared": len(transactions),
        "endpoints": dict(endpoints.most_common(5)),
        "signature_fields": signature_fields,
        "timestamp_fields": timestamp_fields,
        "nonce_fields": nonce_fields,
        "candidates": candidates[:20],
        "static_secrets": static_secrets[:10],
        "notes": notes,
        "next_step": (
            "Run reverse_run_mutation_plan on one entry to check which of these fields the "
            "server actually verifies."
            if candidates
            else None
        ),
    }
