"""Request parameter extraction and mutation helpers."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, quote, unquote_plus, urlencode

from charles5_mcp.session.body import declared_charset, decoded_text
from charles5_mcp.session.model import Transaction

# Headers that describe the transport rather than the application request.
TRANSPORT_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
        "http2-settings",
    }
)
# Headers too generic to be interesting as signature candidates.
_BORING_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "accept-language",
        "cache-control",
        "pragma",
        "content-type",
        "user-agent",
        "origin",
        "referer",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "priority",
        "cookie",
        "if-none-match",
        "if-modified-since",
    }
)


def parse_cookies(header_values: list[str]) -> list[tuple[str, str | None]]:
    """Cookie pairs in order; a bare token without ``=`` has value None."""
    cookies: list[tuple[str, str | None]] = []
    for value in header_values:
        for chunk in value.split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "=" in chunk:
                name, cookie_value = chunk.split("=", 1)
                if name.strip():
                    cookies.append((name.strip(), cookie_value.strip()))
            else:
                cookies.append((chunk, None))
    return cookies


def format_cookies(cookies: list[tuple[str, str | None]]) -> str:
    return "; ".join(name if value is None else f"{name}={value}" for name, value in cookies)


def _flatten(prefix: str, value: Any, out: dict[str, str], depth: int = 0) -> None:
    if depth > 8:
        out[prefix] = json.dumps(value, ensure_ascii=False)[:500]
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _flatten(f"{prefix}.{key}", item, out, depth + 1)
    elif isinstance(value, list):
        if len(value) <= 20 and all(isinstance(i, (dict, list)) for i in value):
            for index, item in enumerate(value):
                _flatten(f"{prefix}[{index}]", item, out, depth + 1)
        else:
            out[prefix] = json.dumps(value, ensure_ascii=False)[:500]
    elif value is None:
        out[prefix] = "null"
    elif isinstance(value, bool):
        out[prefix] = "true" if value else "false"
    else:
        out[prefix] = str(value)


def request_parameters(txn: Transaction, *, include_headers: bool = True) -> dict[str, str]:
    """Flatten every request input into ``surface.name -> value``.

    Surfaces: ``query``, ``form``, ``json`` (dot paths), ``header``, ``cookie``.
    Repeated keys keep the last value, matching what most servers read.
    """
    params: dict[str, str] = {}
    for name, value in parse_qsl(txn.query or "", keep_blank_values=True):
        params[f"query.{name}"] = value
    content_type = (txn.request.content_type or "").lower()
    text = decoded_text(txn.request) if txn.request.body else ""
    if text:
        stripped = text.lstrip()
        if "json" in content_type or stripped.startswith(("{", "[")):
            try:
                _flatten("json", json.loads(text), params)
            except ValueError:
                pass
        elif "x-www-form-urlencoded" in content_type:
            charset = declared_charset(txn.request) or "utf-8"
            for name, value in parse_qsl(
                text, keep_blank_values=True, encoding=charset, errors="replace"
            ):
                params[f"form.{name}"] = value
    if include_headers:
        for name, value in txn.request.headers:
            lowered = name.lower()
            if (
                lowered.startswith(":")
                or lowered in TRANSPORT_HEADERS
                or lowered in _BORING_HEADERS
            ):
                continue
            params[f"header.{lowered}"] = value
        for name, cookie_value in parse_cookies(txn.request.header_values("cookie")):
            if cookie_value is not None:
                params[f"cookie.{name}"] = cookie_value
    return params


# ------------------------------------------------------------------ mutation


def _split_path(path: str) -> list[str | int]:
    parts: list[str | int] = []
    for chunk in path.replace("]", "").split("."):
        if "[" in chunk:
            head, *indexes = chunk.split("[")
            if head:
                parts.append(head)
            parts += [int(i) for i in indexes if i.lstrip("-").isdigit()]
        elif chunk:
            parts.append(chunk)
    return parts


_DELETE = object()


def set_json_path(document: Any, path: str, value: Any) -> Any:
    """Set (or delete, when ``value is None``) a dot/bracket path such as ``data.items[0].sign``."""
    parts = _split_path(path)
    if not parts:
        return document if value is None else value
    target = _DELETE if value is None else value
    current = document
    for index, key in enumerate(parts):
        last = index == len(parts) - 1
        if isinstance(key, int):
            if not isinstance(current, list) or not -len(current) <= key < len(current):
                raise KeyError(f"index {key} not present at `{path}`")
            if last:
                if target is _DELETE:
                    current.pop(key)
                else:
                    current[key] = target
                return document
            current = current[key]
        else:
            if not isinstance(current, dict):
                raise KeyError(f"`{key}` is not an object member at `{path}`")
            if last:
                if target is _DELETE:
                    current.pop(key, None)
                else:
                    current[key] = target
                return document
            current = current.setdefault(key, {})
    return document


def apply_pairs(
    pairs: list[tuple[str, str | None]], overrides: dict[str, Any]
) -> list[tuple[str, str | None]]:
    """Apply overrides in place (keeping order); None removes, lists repeat the key."""
    result: list[tuple[str, str | None]] = []
    done: set[str] = set()
    for key, value in pairs:
        if key not in overrides:
            result.append((key, value))
            continue
        if key in done:
            continue
        done.add(key)
        result += _override_pairs(key, overrides[key])
    for key, value in overrides.items():
        if key not in done:
            result += _override_pairs(key, value)
    return result


def _override_pairs(key: str, value: Any) -> list[tuple[str, str | None]]:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    return [(key, _stringify(item)) for item in values]


def rewrite_urlencoded(
    raw: str | None, overrides: dict[str, Any], charset: str | None = None
) -> str:
    """Change only the overridden keys of an urlencoded string, byte-for-byte elsewhere.

    Re-encoding the whole string would alter untouched parameters (``%7E``
    vs ``~``, blank values, ``;`` separators) and break request signatures.
    """
    enc = charset or "utf-8"
    segments = raw.split("&") if raw else []
    out: list[str] = []
    done: set[str] = set()
    for segment in segments:
        name_raw = segment.split("=", 1)[0]
        name = unquote_plus(name_raw, encoding=enc, errors="replace")
        if name not in overrides:
            out.append(segment)
            continue
        if name in done:
            continue
        done.add(name)
        out += [
            f"{name_raw}={quote(v or '', safe='', encoding=enc, errors='replace')}"
            for _, v in _override_pairs(name, overrides[name])
        ]
    for name, value in overrides.items():
        if name not in done:
            out += [
                f"{quote(name, safe='', encoding=enc, errors='replace')}={quote(v or '', safe='', encoding=enc, errors='replace')}"
                for _, v in _override_pairs(name, value)
            ]
    return "&".join(out)


def _stringify(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


def encode_pairs(pairs: list[tuple[str, str]]) -> str:
    return urlencode(pairs)
