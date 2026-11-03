"""Protobuf decoding: schemaless (wire format) and descriptor-based."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_MAX_DEPTH = 6
_MAX_FIELDS = 512


class _Truncated(Exception):
    pass


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise _Truncated
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 70:
            raise _Truncated


def decode_raw(data: bytes, *, depth: int = 0) -> list[dict[str, Any]] | None:
    """Decode protobuf wire format without a schema.

    Returns ``None`` when the bytes are not a well-formed message, so callers
    can fall back to treating a length-delimited field as a string or bytes.
    """
    fields: list[dict[str, Any]] = []
    pos = 0
    try:
        while pos < len(data):
            key, pos = _read_varint(data, pos)
            field_no = key >> 3
            wire_type = key & 0x7
            if field_no == 0 or field_no > 536_870_911:
                return None
            if wire_type == 0:
                value, pos = _read_varint(data, pos)
                fields.append({"field": field_no, "type": "varint", "value": value})
            elif wire_type == 1:
                if pos + 8 > len(data):
                    return None
                raw = data[pos : pos + 8]
                pos += 8
                fields.append(
                    {"field": field_no, "type": "fixed64", "value": int.from_bytes(raw, "little")}
                )
            elif wire_type == 2:
                length, pos = _read_varint(data, pos)
                if pos + length > len(data):
                    return None
                chunk = data[pos : pos + length]
                pos += length
                fields.append({"field": field_no, "type": "bytes", **_describe_chunk(chunk, depth)})
            elif wire_type == 5:
                if pos + 4 > len(data):
                    return None
                raw = data[pos : pos + 4]
                pos += 4
                fields.append(
                    {"field": field_no, "type": "fixed32", "value": int.from_bytes(raw, "little")}
                )
            else:  # groups (3/4) are deprecated; treat as not-a-message
                return None
            if len(fields) > _MAX_FIELDS:
                fields.append({"truncated": True})
                break
    except _Truncated:
        return None
    return fields


def _describe_chunk(chunk: bytes, depth: int) -> dict[str, Any]:
    if not chunk:
        return {"value": ""}
    text = _as_text(chunk)
    if depth < _MAX_DEPTH and text is None:
        nested = decode_raw(chunk, depth=depth + 1)
        if nested:
            return {"message": nested}
    if text is not None:
        return {"value": text}
    if depth < _MAX_DEPTH:
        nested = decode_raw(chunk, depth=depth + 1)
        if nested:
            return {"message": nested}
    return {"hex": chunk[:256].hex(), "length": len(chunk)}


def _as_text(chunk: bytes) -> str | None:
    try:
        text = chunk.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return text if printable >= max(len(text) * 0.95, 1) else None


def decode_with_descriptor(
    payload: bytes, descriptor_path: str, message_type: str
) -> dict[str, Any]:
    """Decode with a compiled FileDescriptorSet (``protoc --descriptor_set_out``)."""
    from google.protobuf import descriptor_pb2, descriptor_pool, json_format, message_factory

    file_set = descriptor_pb2.FileDescriptorSet()
    file_set.ParseFromString(Path(descriptor_path).expanduser().read_bytes())
    pool = descriptor_pool.DescriptorPool()
    for file_proto in file_set.file:
        pool.Add(file_proto)
    descriptor = pool.FindMessageTypeByName(message_type)
    message_cls = message_factory.GetMessageClass(descriptor)
    message = message_cls()
    message.ParseFromString(payload)
    result = json_format.MessageToDict(message, preserving_proto_field_name=True)
    return json.loads(json.dumps(result))


def split_grpc_frames(payload: bytes) -> list[tuple[bool, bytes]] | None:
    """Split a gRPC body into (compressed_flag, message) frames, or None if malformed."""
    frames: list[tuple[bool, bytes]] = []
    pos = 0
    while pos < len(payload):
        if pos + 5 > len(payload):
            return None
        flag = payload[pos]
        length = int.from_bytes(payload[pos + 1 : pos + 5], "big")
        pos += 5
        if flag not in (0, 1) or pos + length > len(payload):
            return None
        frames.append((flag == 1, payload[pos : pos + length]))
        pos += length
    return frames
