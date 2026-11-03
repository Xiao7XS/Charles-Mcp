"""Coarse resource classification and API priority scoring."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field

from charles5_mcp.session.model import Transaction

RESOURCE_CLASSES = (
    "api",
    "document",
    "script",
    "stylesheet",
    "image",
    "font",
    "media",
    "websocket",
    "grpc",
    "interim",
    "tunnel",
    "control",
    "other",
)

NOISE_CLASSES = frozenset({"control", "tunnel", "image", "font", "media", "stylesheet", "interim"})

_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".avif", ".bmp", ".heic"}
_FONT_EXT = {".woff", ".woff2", ".ttf", ".otf", ".eot"}
_MEDIA_EXT = {
    ".mp3",
    ".mp4",
    ".m4a",
    ".m4s",
    ".ts",
    ".m3u8",
    ".wav",
    ".webm",
    ".mov",
    ".aac",
    ".flac",
}
_SCRIPT_EXT = {".js", ".mjs", ".cjs"}
_STYLE_EXT = {".css", ".map"}
_API_PATH_HINTS = (
    "/api/",
    "/api.",
    "/v1/",
    "/v2/",
    "/v3/",
    "/graphql",
    "/rpc",
    "/gateway",
    "/auth",
    "/login",
    "/oauth",
    "/token",
    "/session",
    "/user",
)


@dataclass
class Classification:
    resource_class: str
    priority: int
    reasons: list[str] = field(default_factory=list)


def classify(txn: Transaction) -> Classification:
    if txn.is_control:
        return Classification("control", 0)
    if txn.is_interim:
        return Classification("interim", 1, ["1xx informational response"])
    if txn.method == "CONNECT" or (txn.tunnel and not txn.response.headers):
        return Classification("tunnel", 0)

    response_type = (txn.response.content_type or "").lower()
    request_type = (txn.request.content_type or "").lower()
    extension = posixpath.splitext(txn.path.lower())[1]
    upgrade = (txn.request.header("upgrade") or "").lower()

    if txn.websocket or upgrade == "websocket" or txn.response_status == 101:
        return Classification("websocket", 60, ["websocket upgrade"])
    if "application/grpc" in request_type or "application/grpc" in response_type:
        return Classification("grpc", 85, ["grpc content-type"])
    if response_type.startswith("image/") or extension in _IMAGE_EXT:
        return Classification("image", 3)
    if response_type.startswith("font/") or "font" in response_type or extension in _FONT_EXT:
        return Classification("font", 2)
    if response_type.startswith(("audio/", "video/")) or extension in _MEDIA_EXT:
        return Classification("media", 3)
    if "text/css" in response_type or extension in _STYLE_EXT:
        return Classification("stylesheet", 5)
    if "javascript" in response_type or "ecmascript" in response_type or extension in _SCRIPT_EXT:
        return Classification("script", 20)
    if "text/html" in response_type and txn.method == "GET":
        return Classification("document", 35)

    score = 30
    reasons: list[str] = []
    if any(
        t in response_type or t in request_type for t in ("json", "protobuf", "x-www-form", "xml")
    ):
        score += 35
        reasons.append("structured content-type")
    lowered_path = txn.path.lower()
    if any(hint in lowered_path for hint in _API_PATH_HINTS):
        score += 20
        reasons.append("api-like path")
    if txn.method in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 10
        reasons.append("mutating method")
    if txn.request.header("authorization") or txn.request.header("x-requested-with"):
        score += 5
        reasons.append("auth/xhr header")
    if txn.has_error:
        score += 10
        reasons.append("error status")
    if reasons:
        return Classification("api", min(score, 100), reasons)
    return Classification("other", 15)
