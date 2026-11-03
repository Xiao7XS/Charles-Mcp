"""WebSocket frame decoding.

Charles 5.2.2 records a WebSocket as one transaction (``"webSocket": true``,
response status 101) whose request body holds the raw client→server frames
and whose response body holds the raw server→client frames. This module turns
those byte streams back into messages.
"""

from __future__ import annotations

import json
import zlib
from dataclasses import dataclass
from typing import Any

from charles5_mcp.session import protobuf
from charles5_mcp.session.model import Transaction

_OPCODES = {0: "continuation", 1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}
_MAX_MESSAGES = 2000


@dataclass
class WsMessage:
    direction: str  # "client" (sent by the app) or "server"
    kind: str  # text | binary | close | ping | pong
    payload: bytes
    compressed: bool = False

    def to_dict(self, max_chars: int = 500) -> dict[str, Any]:
        out: dict[str, Any] = {"from": self.direction, "type": self.kind, "size": len(self.payload)}
        if self.kind == "text":
            text = self.payload.decode("utf-8", errors="replace")
            try:
                out["json"] = json.loads(text) if len(text) <= max_chars * 4 else None
            except ValueError:
                pass
            if "json" not in out or out["json"] is None:
                out.pop("json", None)
                out["text"] = text[:max_chars] + ("…" if len(text) > max_chars else "")
        elif self.kind == "binary":
            fields = protobuf.decode_raw(self.payload) if self.payload else None
            if fields:
                out["protobuf"] = fields[:50]
            else:
                out["hex"] = self.payload[: max_chars // 2].hex()
        elif self.kind == "close" and len(self.payload) >= 2:
            out["code"] = int.from_bytes(self.payload[:2], "big")
            reason = self.payload[2:].decode("utf-8", errors="replace")
            if reason:
                out["reason"] = reason
        if self.compressed:
            out["permessage_deflate"] = True
        return out


def parse_frames(
    data: bytes, direction: str, *, deflate: bool = False
) -> tuple[list[WsMessage], list[str]]:
    """Decode a stream of WebSocket frames, joining fragments and inflating if negotiated."""
    messages: list[WsMessage] = []
    notes: list[str] = []
    pos = 0
    fragments: list[bytes] = []
    fragment_kind: str | None = None
    fragment_compressed = False
    inflater = zlib.decompressobj(-zlib.MAX_WBITS) if deflate else None
    while pos + 2 <= len(data) and len(messages) < _MAX_MESSAGES:
        first, second = data[pos], data[pos + 1]
        fin = bool(first & 0x80)
        rsv1 = bool(first & 0x40)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        pos += 2
        if length == 126:
            if pos + 2 > len(data):
                break
            length = int.from_bytes(data[pos : pos + 2], "big")
            pos += 2
        elif length == 127:
            if pos + 8 > len(data):
                break
            length = int.from_bytes(data[pos : pos + 8], "big")
            pos += 8
        mask = b""
        if masked:
            mask = data[pos : pos + 4]
            pos += 4
        if pos + length > len(data):
            notes.append("truncated_frame")
            break
        payload = data[pos : pos + length]
        pos += length
        if masked and len(mask) == 4:
            payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        if opcode not in _OPCODES:
            notes.append(f"unknown_opcode_{opcode}")
            break
        if opcode >= 8:  # control frames are never fragmented
            messages.append(WsMessage(direction, _OPCODES[opcode], payload))
            continue
        if opcode != 0:
            fragments = [payload]
            fragment_kind = _OPCODES[opcode]
            fragment_compressed = rsv1
        else:
            fragments.append(payload)
        if fin and fragment_kind is not None:
            body = b"".join(fragments)
            if fragment_compressed and inflater is not None:
                try:
                    body = inflater.decompress(body + b"\x00\x00\xff\xff")
                except zlib.error:
                    notes.append("permessage_deflate_failed")
            messages.append(WsMessage(direction, fragment_kind, body, fragment_compressed))
            fragments, fragment_kind = [], None
    if pos < len(data) and not notes:
        notes.append("trailing_bytes")
    return messages, notes


def is_websocket(txn: Transaction) -> bool:
    return txn.websocket or (
        txn.response_status == 101 and (txn.response.header("upgrade") or "").lower() == "websocket"
    )


def websocket_messages(txn: Transaction) -> tuple[list[WsMessage], list[str]]:
    """Messages in each direction (client first, then server; Charles keeps no interleaving)."""
    if not is_websocket(txn):
        return [], []
    extensions = (txn.response.header("sec-websocket-extensions") or "").lower()
    deflate = "permessage-deflate" in extensions
    client, client_notes = parse_frames(txn.request.body or b"", "client", deflate=deflate)
    server, server_notes = parse_frames(txn.response.body or b"", "server", deflate=deflate)
    return client + server, client_notes + server_notes
