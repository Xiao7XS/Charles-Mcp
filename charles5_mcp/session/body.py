"""Body decoding (content-encoding, charset) and structured rendering."""

from __future__ import annotations

import codecs
import gzip
import json
import re
import zlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl

from charles5_mcp.session import protobuf
from charles5_mcp.session.model import Message

_GZIP_MAGIC = b"\x1f\x8b"
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

_TEXT_HINTS = (
    "json",
    "xml",
    "javascript",
    "ecmascript",
    "text/",
    "graphql",
    "x-www-form-urlencoded",
    "yaml",
    "csv",
    "html",
    "svg",
)


MAX_DECODED_BYTES = 64 * 1024 * 1024
"""Upper bound for a decompressed body, so a compression bomb cannot exhaust memory."""


class DecodedTooLargeError(ValueError):
    pass


def _too_large(name: str) -> DecodedTooLargeError:
    return DecodedTooLargeError(
        f"{name}_decoded_body_over_{MAX_DECODED_BYTES // (1024 * 1024)}MB_kept_encoded"
    )


def _inflate(data: bytes, wbits: int, name: str) -> bytes:
    """zlib/gzip with an output cap; concatenated gzip members are all decoded."""
    out = bytearray()
    while data:
        engine = zlib.decompressobj(wbits)
        out += engine.decompress(data, MAX_DECODED_BYTES - len(out) + 1)
        if len(out) > MAX_DECODED_BYTES or engine.unconsumed_tail:
            raise _too_large(name)
        if not engine.eof:
            raise EOFError(f"{name} stream is truncated")
        data = engine.unused_data
        if wbits != 31 or not data.startswith(_GZIP_MAGIC):
            break
    return bytes(out)


def _decompress(name: str, data: bytes) -> bytes:
    if name in {"gzip", "x-gzip"}:
        return _inflate(data, 31, "gzip")
    if name == "deflate":
        try:
            return _inflate(data, zlib.MAX_WBITS, name)
        except zlib.error:
            return _inflate(data, -zlib.MAX_WBITS, name)  # raw deflate
    if name == "br":
        import brotli

        engine = brotli.Decompressor()
        try:
            out = bytearray(engine.process(data, output_buffer_limit=MAX_DECODED_BYTES + 1))
            while len(out) <= MAX_DECODED_BYTES and not engine.is_finished():
                chunk = engine.process(b"", output_buffer_limit=MAX_DECODED_BYTES + 1)
                if not chunk:
                    break
                out += chunk
        except TypeError:  # brotli < 1.2 has no output limit
            out = bytearray(brotli.decompress(data))
        if len(out) > MAX_DECODED_BYTES:
            raise _too_large(name)
        return bytes(out)
    if name == "zstd":
        import zstandard

        # Streaming reader handles frames that omit the content size.
        decoded = bytearray()
        with zstandard.ZstdDecompressor().stream_reader(data, read_across_frames=True) as reader:
            while len(decoded) <= MAX_DECODED_BYTES:
                chunk = reader.read(1 << 20)
                if not chunk:
                    break
                decoded += chunk
        if len(decoded) > MAX_DECODED_BYTES:
            raise _too_large(name)
        return bytes(decoded)
    raise ValueError(f"unsupported content-encoding `{name}`")


def decode_content(
    data: bytes,
    content_encoding: str | None,
    *,
    already_decoded: bool = False,
) -> tuple[bytes, list[str]]:
    """Undo Content-Encoding. Returns (bytes, notes).

    Charles usually stores bodies already decoded, but exports are not
    consistent about saying so. Each declared coding is attempted; when a
    coding fails on data that does not carry that coding's magic bytes, the
    body is treated as already decoded instead of reported as corrupt.
    """
    notes: list[str] = []
    if not data or not content_encoding or already_decoded:
        return data, notes
    codings = [c.strip().lower() for c in content_encoding.split(",") if c.strip()]
    payload = data
    for coding in reversed(codings):
        if coding == "identity":
            continue
        try:
            payload = _decompress(coding, payload)
            notes.append(f"decoded:{coding}")
        except ValueError as exc:
            notes.append(str(exc))
            break
        except Exception:
            has_magic = (coding in {"gzip", "x-gzip"} and payload.startswith(_GZIP_MAGIC)) or (
                coding == "zstd" and payload.startswith(_ZSTD_MAGIC)
            )
            notes.append(
                f"{coding}_decode_failed" if has_magic else f"{coding}_already_decoded_by_charles"
            )
            break
    return payload, notes


def _valid_charset(name: Any) -> str | None:
    """``name`` if it is a text codec Python can decode with, otherwise None.

    ``codecs.lookup`` alone also accepts bytes-to-bytes codecs (base64, zlib,
    hex) and idna, which fail on ``bytes.decode(..., errors="replace")``.
    """
    if not isinstance(name, str) or not name.strip():
        return None
    candidate = name.strip().strip("'\"")
    try:
        info = codecs.lookup(candidate)
        if not getattr(info, "_is_text_encoding", True) or info.name in ("idna", "punycode"):
            return None
        b"abc\xff".decode(candidate, errors="replace")
    except (LookupError, UnicodeError, TypeError, ValueError):
        return None
    return candidate


def safe_charset(name: Any) -> str:
    """Return ``name`` if it is a usable text codec, otherwise utf-8."""
    return _valid_charset(name) or "utf-8"


def declared_charset(message: Message) -> str | None:
    """The charset the message itself declares (Charles field or Content-Type), if valid."""
    if message.charset:
        valid = _valid_charset(message.charset)
        if valid:
            return valid
    match = re.search(r"charset=\"?([\w.:-]+)", message.content_type or "", re.IGNORECASE)
    return _valid_charset(match.group(1)) if match else None


def charset_of(message: Message) -> str:
    return declared_charset(message) or "utf-8"


def decode_text(data: bytes, declared: str | None = None) -> str:
    """Bytes to text: the declared charset, else UTF-8, else GB18030 (common in Chinese apps).

    A UTF-8 byte-order mark is removed so JSON with a BOM still parses.
    """
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
        if declared is None or declared.lower().replace("-", "") in ("utf8", "utf8sig"):
            declared = "utf-8"
    if declared:
        return data.decode(declared, errors="replace").lstrip("\ufeff")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("gb18030")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def is_textual_type(content_type: str | None) -> bool:
    lowered = (content_type or "").lower()
    return any(hint in lowered for hint in _TEXT_HINTS)


def looks_like_text(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:512]
    if b"\x00" in sample:
        return False
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        # A multi-byte character may be split at the sample boundary.
        try:
            text = sample[:-3].decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = sample[:-1].decode("gb18030")
            except UnicodeDecodeError:
                return False
    control = sum(1 for ch in text if ord(ch) < 32 and ch not in "\r\n\t\f")
    return control <= max(len(text) // 20, 1)


# (prefix, mime type, kind) for formats recognisable from their first bytes.
_MAGIC: tuple[tuple[bytes, str, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png", "image"),
    (b"\xff\xd8\xff", "image/jpeg", "image"),
    (b"GIF87a", "image/gif", "image"),
    (b"GIF89a", "image/gif", "image"),
    (b"BM", "image/bmp", "image"),
    (b"\x00\x00\x01\x00", "image/x-icon", "image"),
    (b"%PDF-", "application/pdf", "file"),
    (b"PK\x03\x04", "application/zip", "file"),
    (b"PK\x05\x06", "application/zip", "file"),
    (b"\x1f\x8b", "application/gzip", "file"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "file"),
    (b"Rar!\x1a\x07", "application/vnd.rar", "file"),
    (b"\x00asm", "application/wasm", "file"),
    (b"SQLite format 3\x00", "application/vnd.sqlite3", "file"),
    (b"ID3", "audio/mpeg", "media"),
    (b"OggS", "audio/ogg", "media"),
    (b"\x1aE\xdf\xa3", "video/webm", "media"),
)


def sniff_type(data: bytes, *, declared_textual: bool = False) -> tuple[str, str] | None:
    """(mime type, kind) detected from magic bytes, or None.

    Some signatures are short (``BM``, ``ID3``); when the body is declared as
    text and reads as text, a match is ignored so ``BMI=22&x=1`` stays a form.
    """
    if declared_textual and looks_like_text(data[:4096]):
        return None
    for prefix, mime, kind in _MAGIC:
        if data.startswith(prefix):
            return mime, kind
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp", "image"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12]
        if brand in (b"heic", b"heix", b"mif1", b"avif"):
            return ("image/avif" if brand == b"avif" else "image/heic"), "image"
        return "video/mp4", "media"
    return None


@dataclass
class BodyView:
    """Structured, size-bounded rendering of a body for agents."""

    # empty|json|jsonp|form|multipart|text|protobuf|grpc|image|media|file|binary
    kind: str = "empty"
    size: int = 0
    content_type: str | None = None
    detected_type: str | None = None
    text: str | None = None
    truncated: bool = False
    parsed: Any = None  # json value, form fields or protobuf field list
    parts: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self, *, include_parsed: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "size": self.size}
        if self.content_type:
            out["content_type"] = self.content_type
        if self.detected_type and self.detected_type != (self.content_type or "").split(";")[0]:
            out["detected_type"] = self.detected_type
        if self.kind == "form" and self.parsed:
            out["fields"] = self.parsed
        if self.text is not None:
            out["text"] = self.text
        if self.truncated:
            out["truncated"] = True
        if self.parts:
            out["parts"] = self.parts
        if include_parsed and self.parsed is not None and self.kind in {"protobuf", "grpc"}:
            out["fields"] = self.parsed
            out.pop("text", None)  # the same data as JSON text
        if self.notes:
            out["notes"] = self.notes
        return out


def decoded_bytes(message: Message) -> tuple[bytes, list[str]]:
    if message.decode_cache is None:
        message.decode_cache = decode_content(
            message.body or b"",
            message.effective_content_encoding,
            already_decoded=message.body_decoded,
        )
    data, notes = message.decode_cache
    return data, list(notes)


def decoded_text(message: Message) -> str:
    data, _ = decoded_bytes(message)
    if not data:
        return ""
    return decode_text(data, declared_charset(message))


_JSONP = re.compile(r"^\s*([A-Za-z_$][\w$.]*)\s*\(\s*([\[{].*[\]}])\s*\)\s*;?\s*$", re.DOTALL)


def form_fields(text: str, charset: str | None) -> dict[str, Any]:
    """Decoded urlencoded fields; repeated names become lists."""
    fields: dict[str, Any] = {}
    for name, value in parse_qsl(
        text, keep_blank_values=True, encoding=charset or "utf-8", errors="replace"
    ):
        if name in fields:
            existing = fields[name]
            fields[name] = existing + [value] if isinstance(existing, list) else [existing, value]
        else:
            fields[name] = value
    return fields


def render_body(message: Message, *, max_chars: int = 2048) -> BodyView:
    """Decode and render a message body, clipping text to ``max_chars``."""
    data, notes = decoded_bytes(message)
    content_type = message.content_type
    view = BodyView(size=len(data), content_type=content_type, notes=notes)
    if not data:
        return view
    lowered = (content_type or "").lower()
    declared = declared_charset(message)

    def clip(text: str) -> None:
        view.text = text[:max_chars]
        view.truncated = len(text) > max_chars

    if "application/grpc" in lowered:
        frames = protobuf.split_grpc_frames(data)
        if frames is not None:
            view.kind = "grpc"
            decoded_frames: list[dict[str, Any]] = []
            for compressed, chunk in frames[:20]:
                if compressed:
                    try:
                        chunk = gzip.decompress(chunk)
                    except Exception:
                        decoded_frames.append({"compressed": True, "length": len(chunk)})
                        continue
                decoded_frames.append({"fields": protobuf.decode_raw(chunk) or chunk[:64].hex()})
            view.parsed = decoded_frames
            clip(json.dumps(decoded_frames, ensure_ascii=False, separators=(",", ":")))
            return view

    if "multipart/" in lowered:
        parts = parse_multipart(data, content_type or "")
        if parts is not None:
            view.kind = "multipart"
            view.parts = [
                part.summary(max(80, max_chars // max(len(parts), 1))) for part in parts[:50]
            ]
            if len(parts) > 50:
                view.notes.append(f"{len(parts) - 50}_more_parts_not_shown")
            return view
        view.notes.append("multipart_boundary_not_found")

    if "protobuf" in lowered or "proto" in lowered.split(";")[0].split("/")[-1]:
        fields = protobuf.decode_raw(data)
        if fields is not None:
            view.kind = "protobuf"
            view.parsed = fields
            clip(json.dumps(fields, ensure_ascii=False, separators=(",", ":")))
            view.notes.append("schemaless_decode: pass descriptor_path + message_type for names")
            return view

    sniffed = sniff_type(data, declared_textual=is_textual_type(content_type))
    if sniffed or lowered.startswith(("image/", "audio/", "video/", "font/")):
        mime, kind = sniffed or (
            lowered.split(";")[0],
            "image"
            if lowered.startswith("image/")
            else "media"
            if lowered.startswith(("audio/", "video/"))
            else "file",
        )
        view.kind = kind
        view.detected_type = mime
        view.text = f"[{mime} {len(data)} bytes]"
        return view

    textual = is_textual_type(content_type) or looks_like_text(data)
    if not textual:
        fields = protobuf.decode_raw(data) if len(data) < 1_000_000 else None
        if fields and _plausible_protobuf(fields):
            view.kind = "protobuf"
            view.parsed = fields
            view.notes.append("guessed_protobuf_from_binary")
            clip(json.dumps(fields, ensure_ascii=False, separators=(",", ":")))
            return view
        view.kind = "binary"
        view.text = f"[binary {len(data)} bytes] hex: {data[:48].hex()}"
        return view

    text = decode_text(data, declared)
    stripped = text.lstrip()
    if "json" in lowered or stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except ValueError:
            if "json" in lowered:
                view.notes.append("json_parse_failed")
        else:
            view.kind = "json"
            view.parsed = parsed
            clip(json.dumps(parsed, ensure_ascii=False, separators=(",", ":")))
            return view

    jsonp = _JSONP.match(text) if len(text) < 5_000_000 and "(" in text[:200] else None
    if jsonp:
        try:
            parsed = json.loads(jsonp.group(2))
        except ValueError:
            pass
        else:
            view.kind = "jsonp"
            view.parsed = parsed
            view.notes.append(f"jsonp_callback:{jsonp.group(1)}")
            clip(json.dumps(parsed, ensure_ascii=False, separators=(",", ":")))
            return view

    if "x-www-form-urlencoded" in lowered:
        view.kind = "form"
        view.parsed = form_fields(text, declared)
        clip(text)
        return view

    view.kind = "text"
    clip(text)
    return view


def _plausible_protobuf(fields: list[dict[str, Any]]) -> bool:
    numbers = [f.get("field", 0) for f in fields if "field" in f]
    return bool(numbers) and max(numbers) < 10_000


@dataclass
class MultipartPart:
    headers: dict[str, str]
    data: bytes

    def _param(self, key: str) -> str | None:
        disposition = self.headers.get("content-disposition", "")
        match = re.search(
            rf'(?:^|;)\s*{key}\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;\s]+))', disposition, re.IGNORECASE
        )
        if not match:
            return None
        if match.group(1) is not None:
            return re.sub(r"\\(.)", r"\1", match.group(1))
        return match.group(2)

    @property
    def name(self) -> str | None:
        return self._param("name")

    @property
    def filename(self) -> str | None:
        extended = self._param(r"filename\*")
        if extended and extended.count("'") >= 2:
            charset, _, encoded = extended.split("'", 2)
            from urllib.parse import unquote

            return unquote(encoded, encoding=safe_charset(charset or "utf-8"), errors="replace")
        return self._param("filename")

    @property
    def content_type(self) -> str | None:
        return self.headers.get("content-type")

    def summary(self, preview_chars: int = 200) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "size": len(self.data)}
        if self.filename is not None:
            out["filename"] = self.filename
        if self.content_type:
            out["content_type"] = self.content_type
        sniffed = sniff_type(self.data, declared_textual=is_textual_type(self.content_type))
        if sniffed:
            out["detected_type"] = sniffed[0]
            return out
        if self.filename is None or looks_like_text(self.data):
            match = re.search(r"charset=\"?([\w.:-]+)", self.content_type or "", re.IGNORECASE)
            text = decode_text(self.data, safe_charset(match.group(1)) if match else None)
            try:
                if text.lstrip().startswith(("{", "[")):
                    out["json"] = json.loads(text) if len(text) <= preview_chars * 4 else None
            except ValueError:
                pass
            if out.get("json") is None:
                out.pop("json", None)
                out["value"] = text[:preview_chars] + ("…" if len(text) > preview_chars else "")
        else:
            out["hex"] = self.data[:24].hex()
        return out


def parse_multipart(data: bytes, content_type: str) -> list[MultipartPart] | None:
    """Split a multipart body at byte level (binary file parts stay intact).

    Delimiters only count at the start of a line (RFC 2046), so a value that
    happens to contain ``--boundary`` is not split.
    """
    match = re.search(r'boundary=(?:"([^"]+)"|([^;\s]+))', content_type, re.IGNORECASE)
    if not match:
        return None
    delimiter = b"--" + (match.group(1) or match.group(2)).encode("latin-1", errors="replace")
    if data.startswith(delimiter):
        position = 0
    else:
        position = data.find(b"\n" + delimiter)
        if position < 0:
            return None
        position += 1
    rest = data[position + len(delimiter) :]
    next_delimiter = re.compile(rb"\r?\n" + re.escape(delimiter))
    parts: list[MultipartPart] = []
    while not rest.startswith(b"--"):
        line_end = rest.find(b"\n")  # skip transport padding after the delimiter
        if line_end < 0:
            break
        rest = rest[line_end + 1 :]
        found = next_delimiter.search(rest)
        chunk = rest[: found.start()] if found else rest.rstrip(b"\r\n")
        if chunk.startswith((b"\r\n", b"\n")):
            head, body = b"", chunk[2 if chunk.startswith(b"\r\n") else 1 :]
        else:
            head, sep, body = chunk.partition(b"\r\n\r\n")
            if not sep:
                head, sep, body = chunk.partition(b"\n\n")
        headers: dict[str, str] = {}
        for line in decode_text(head).splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        parts.append(MultipartPart(headers, body))
        if not found or len(parts) >= 10_000:
            break
        rest = rest[found.end() :]
    return parts
