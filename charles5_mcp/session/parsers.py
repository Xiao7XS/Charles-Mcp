"""Parsers for every Charles session representation.

All parsers are key-order agnostic and tolerant of missing optional fields:
Charles 5.2.2 itself fixed an import bug caused by keys appearing in an
unexpected order across the native and HAR formats, so nothing here relies on
ordering or on optional keys being present.
"""

from __future__ import annotations

import base64
import binascii
import json
import mimetypes
import posixpath
import re
import zipfile
import zlib
from collections.abc import Iterable
from datetime import datetime, timezone
from io import BytesIO
from typing import Any
from urllib.parse import urlsplit

from defusedxml import ElementTree as SafeET

from charles5_mcp.errors import SessionFormatError
from charles5_mcp.session.body import is_textual_type, safe_charset
from charles5_mcp.session.model import (
    InterimResponse,
    Message,
    Transaction,
    link_interim_transactions,
)

# --------------------------------------------------------------------------- utils


def _as_int(value: Any) -> int | None:
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        try:
            return int(value)
        except (ValueError, OverflowError):
            return None
    try:
        return int(str(value).strip())
    except (ValueError, OverflowError):
        try:
            return int(float(str(value).strip()))
        except (ValueError, OverflowError):
            return None


def _text(value: Any) -> str | None:
    """A scalar as a non-empty string; containers, booleans and blanks become None."""
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    text = str(value)
    return text if text.strip() else None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


_FRACTION = re.compile(r"\.(\d+)")
_COMPACT_OFFSET = re.compile(r"([+-]\d{2})(\d{2})$")


def iso_to_ms(value: Any) -> int | None:
    """Parse an ISO-8601 timestamp (any fraction length, Z or +HHMM) to epoch ms."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace(" ", "T", 1)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _COMPACT_OFFSET.sub(r"\1:\2", text)
    text = _FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1000)


def _headers_from_list(items: Any) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    for item in _as_list(items):
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            if name:
                value = item.get("value")
                headers.append((name, "" if value is None else str(value)))
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            headers.append((str(item[0]), str(item[1])))
    return headers


def _decode_text_body(text: str, *, base64_encoded: bool, charset: str | None) -> bytes:
    if base64_encoded:
        try:
            return base64.b64decode(text, validate=False)
        except (binascii.Error, ValueError):
            pass
    return text.encode(safe_charset(charset), errors="replace")


# ------------------------------------------------------------- Charles JSON (.chlsj)


def _apply_json_body(message: Message, body: dict[str, Any], charset: str | None) -> None:
    """Fill ``message.body`` from a Charles JSON body object.

    Charles 5.2.2 writes two shapes:

    * text: ``{"text": "...", "charset": "utf-8", "decoded": true}``; ``decoded``
      means Charles removed the Content-Encoding before storing the text.
    * binary: ``{"encoding": "base64", "encoded": "<base64>"}``; the bytes are
      exactly as received, so they may still carry the Content-Encoding (Charles
      does not decode zstd, for example).

    Older or third-party writers put base64 in ``text`` and flag it with
    ``"encoded": true``; that shape is accepted too.
    """
    body_charset = _text(body.get("charset"))
    if body_charset and not message.charset:
        message.charset = body_charset
    effective_charset = message.charset or charset
    is_base64 = str(body.get("encoding") or "").lower() == "base64"
    encoded_payload = body.get("encoded")
    text = body.get("text")
    if isinstance(encoded_payload, str):
        message.body = _decode_text_body(encoded_payload, base64_encoded=True, charset=None)
        message.body_decoded = bool(body.get("decoded"))
    elif isinstance(text, str):
        base64_text = is_base64 or encoded_payload is True
        if base64_text:
            message.body = _decode_text_body(text, base64_encoded=True, charset=None)
        else:
            message.body = _charles_text_to_bytes(
                text, effective_charset or _content_type_charset(message)
            )
        # Compressed data cannot survive as plain text, so a text body has
        # necessarily had its content-encoding removed.
        message.body_decoded = bool(body.get("decoded")) or not base64_text


_C1_REFERENCE = re.compile(r"&#(\d{1,3});")


def _content_type_charset(message: Message) -> str | None:
    match = re.search(r"charset=\"?([\w.:-]+)", message.header("content-type") or "", re.IGNORECASE)
    return match.group(1) if match else None


def _charles_text_to_bytes(text: str, charset: str | None, *, xml: bool = False) -> bytes:
    """Recover the original body bytes from text Charles wrote into an export.

    When a body declares no charset, Charles 5.2.2 decodes it as ISO-8859-1
    before writing JSON/XML exports, so UTF-8 or GBK text arrives as mojibake
    ("你好" -> "ä½ å¥½"). Encoding such text back with ISO-8859-1 restores
    the exact original bytes, which are then decoded properly at render time.
    In XML exports Charles also writes C1 control characters as ``&#137;``.
    """
    if charset and safe_charset(charset) == charset.strip():
        return text.encode(charset.strip(), errors="replace")
    if xml:
        text = _C1_REFERENCE.sub(
            lambda m: (
                chr(int(m.group(1)))
                if int(m.group(1)) < 256 and (int(m.group(1)) < 32 or 127 <= int(m.group(1)) < 160)
                else m.group(0)
            ),
            text,
        )
    try:
        return text.encode("latin-1")
    except UnicodeEncodeError:
        return text.encode("utf-8")  # already proper Unicode


def _clean_address(value: Any) -> str | None:
    """Charles writes ``/127.0.0.1`` and ``host/1.2.3.4``; drop the empty-host slash."""
    text = _text(value)
    if text and text.startswith("/"):
        text = text[1:]
    return text or None


def _json_message(
    raw: Any, *, is_response: bool
) -> tuple[Message, int | None, list[InterimResponse]]:
    data = _as_dict(raw)
    header_block = _as_dict(data.get("header"))
    headers = _headers_from_list(header_block.get("headers"))
    sizes = _as_dict(data.get("sizes"))
    charset = _text(data.get("charset"))
    message = Message(
        first_line=_text(header_block.get("firstLine")),
        headers=headers,
        mime_type=_text(data.get("mimeType")),
        charset=charset,
        content_encoding=_text(data.get("contentEncoding")),
        header_size=_as_int(sizes.get("headers")),
        body_size=_as_int(sizes.get("body")),
    )

    body = data.get("body")
    if isinstance(body, str):
        message.body = body.encode(safe_charset(charset), errors="replace")
        message.body_decoded = True
    elif isinstance(body, dict):
        _apply_json_body(message, body, charset)

    trailer_source = data.get("trailers") or _as_dict(data.get("trailer")).get("headers")
    if trailer_source is None:
        trailer_source = header_block.get("trailers")
    message.trailers = _headers_from_list(trailer_source)

    interim: list[InterimResponse] = []
    if is_response:
        for key in ("informationalResponses", "interimResponses", "informational"):
            for item in _as_list(data.get(key)):
                item = _as_dict(item)
                status = _as_int(item.get("status"))
                if status is not None:
                    interim.append(
                        InterimResponse(
                            status=status,
                            headers=_headers_from_list(_as_dict(item.get("header")).get("headers")),
                        )
                    )
    status = _as_int(data.get("status")) if is_response else None
    return message, status, interim


def transaction_from_json(raw: dict[str, Any], seq: int, *, source_format: str) -> Transaction:
    """Convert one Charles JSON transaction (export-json / .chlsj / .chlz meta)."""
    times = _as_dict(raw.get("times"))
    request, _, _ = _json_message(raw.get("request"), is_response=False)
    response, response_status, interim = _json_message(raw.get("response"), is_response=True)
    start_ms = _as_int(times.get("startMillis")) or iso_to_ms(times.get("start"))
    end_ms = _as_int(times.get("endMillis")) or iso_to_ms(times.get("end"))
    durations = {
        k: v
        for k, v in _as_dict(raw.get("durations")).items()
        if isinstance(v, (int, float)) and not isinstance(v, bool)
    }
    ssl = _as_dict(raw.get("ssl"))
    # `port` is what the client asked for; `actualPort` is where Charles really
    # connected (they differ under Map Remote / reverse proxies). Replays and
    # URLs use the former.
    port = _as_int(raw.get("port")) or _as_int(raw.get("actualPort"))
    actual_port = _as_int(raw.get("actualPort"))
    return Transaction(
        seq=seq,
        method=(_text(raw.get("method")) or "GET").upper(),
        scheme=(_text(raw.get("scheme")) or "http").lower(),
        host=_text(raw.get("host")) or "",
        port=port,
        actual_port=actual_port if actual_port != port else None,
        path=_text(raw.get("path")) or "/",
        query=_text(raw.get("query")),
        protocol=_text(raw.get("protocolVersion")),
        status=_text(raw.get("status")),
        response_status=response_status,
        start_ms=start_ms,
        end_ms=end_ms,
        start_time=_text(times.get("start")) if isinstance(times.get("start"), str) else None,
        durations=durations,
        total_size=_as_int(raw.get("totalSize")),
        remote_address=_clean_address(raw.get("remoteAddress")),
        client_address=_clean_address(raw.get("clientAddress")),
        client_port=_as_int(raw.get("clientPort")),
        tls={k: v for k, v in ssl.items() if v},
        alpn=_text(_as_dict(raw.get("alpn")).get("protocol")),
        error=_text(raw.get("errorMessage")) or _text(raw.get("error")),
        tunnel=bool(raw.get("tunnel")),
        websocket=bool(raw.get("webSocket")),
        notes=_text(raw.get("notes")),
        request=request,
        response=response,
        interim_responses=interim,
        source_format=source_format,
    )


def _iter_json_transactions(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, list):
        return (item for item in payload if isinstance(item, dict))
    if isinstance(payload, dict):
        for key in ("transactions", "entries", "items", "session"):
            if isinstance(payload.get(key), list):
                return (item for item in payload[key] if isinstance(item, dict))
        if "method" in payload and "host" in payload:
            return iter([payload])
    raise SessionFormatError("JSON session must be a list of Charles transactions")


def parse_charles_json(payload: Any, *, source_format: str = "chlsj") -> list[Transaction]:
    if isinstance(payload, (bytes, str)):
        try:
            payload = json.loads(payload)
        except ValueError as exc:
            raise SessionFormatError(f"invalid JSON session: {exc}") from exc
    transactions = [
        transaction_from_json(raw, seq, source_format=source_format)
        for seq, raw in enumerate(_iter_json_transactions(payload), start=1)
    ]
    link_interim_transactions(transactions)
    return transactions


# --------------------------------------------------------------------- Charles XML


def _xml_headers(element: Any) -> tuple[list[tuple[str, str]], str | None]:
    if element is None:
        return [], None
    headers: list[tuple[str, str]] = []
    for header in element.findall("header"):
        name = (header.findtext("name") or "").strip()
        if name:
            headers.append((name, header.findtext("value") or ""))
    return headers, element.findtext("first-line")


def _xml_message(element: Any) -> Message:
    if element is None:
        return Message()
    headers, first_line = _xml_headers(element.find("headers"))
    charset = element.attrib.get("charset") or None
    if charset and safe_charset(charset) != charset:
        charset = None
    message = Message(
        first_line=first_line,
        headers=headers,
        mime_type=element.attrib.get("mime-type") or element.attrib.get("mimeType") or None,
        charset=charset,
        content_encoding=element.attrib.get("contentEncoding")
        or element.attrib.get("content-encoding")
        or None,
        header_size=_as_int(element.attrib.get("headers")),
        trailers=_xml_headers(element.find("trailers"))[0],
    )
    body = element.find("body")
    if body is not None and body.text:
        encoded = (body.attrib.get("encoding") or "").lower() == "base64"
        if encoded:
            message.body = _decode_text_body(body.text, base64_encoded=True, charset=None)
        else:
            message.body = _charles_text_to_bytes(
                body.text, charset or _content_type_charset(message), xml=True
            )
        message.body_decoded = not encoded or body.attrib.get("decoded") == "true"
    message.body_size = _as_int(element.attrib.get("body"))
    if message.body_size is None:
        message.body_size = len(message.body or b"")
    return message


_XML_DURATIONS = {
    "duration": "total",
    "dnsDuration": "dns",
    "connectDuration": "connect",
    "sslDuration": "ssl",
    "requestDuration": "request",
    "responseDuration": "response",
    "latency": "latency",
}


def parse_charles_xml(data: bytes | str) -> list[Transaction]:
    try:
        root = SafeET.fromstring(data)
    except Exception as exc:  # defusedxml raises several parse error types
        raise SessionFormatError(f"invalid Charles XML session: {exc}") from exc
    if root.tag != "charles-session":
        raise SessionFormatError(f"unexpected XML root <{root.tag}>, expected <charles-session>")
    transactions: list[Transaction] = []
    for seq, txn in enumerate(root.findall("transaction"), start=1):
        attrs = txn.attrib
        response_el = txn.find("response")
        response = _xml_message(response_el)
        start_ms = _as_int(attrs.get("startTimeMillis")) or iso_to_ms(attrs.get("startTime"))
        end_ms = _as_int(attrs.get("endTimeMillis")) or iso_to_ms(attrs.get("endTime"))
        durations = {
            name: value
            for attr, name in _XML_DURATIONS.items()
            if (value := _as_int(attrs.get(attr))) is not None
        }
        if "total" not in durations and start_ms and end_ms:
            durations["total"] = max(end_ms - start_ms, 0)
        ssl_el = txn.find("ssl")
        tls = (
            {child.tag: (child.text or "").strip() for child in ssl_el}
            if ssl_el is not None
            else {}
        )
        port = _as_int(attrs.get("port")) or _as_int(attrs.get("actualPort"))
        actual_port = _as_int(attrs.get("actualPort"))
        transactions.append(
            Transaction(
                seq=seq,
                method=(attrs.get("method") or "GET").upper(),
                scheme=(attrs.get("protocol") or attrs.get("scheme") or "http").lower(),
                host=attrs.get("host") or "",
                port=port,
                actual_port=actual_port if actual_port != port else None,
                path=attrs.get("path") or "/",
                query=attrs.get("query") or None,
                protocol=attrs.get("protocolVersion") or None,
                status=attrs.get("status") or None,
                response_status=_as_int(response_el.attrib.get("status"))
                if response_el is not None
                else None,
                start_ms=start_ms,
                end_ms=end_ms,
                start_time=attrs.get("startTime"),
                durations=durations,
                total_size=_as_int(attrs.get("totalSize")),
                remote_address=_clean_address(attrs.get("remoteAddress")),
                client_address=_clean_address(attrs.get("clientAddress")),
                client_port=_as_int(attrs.get("clientPort")),
                tls={k: v for k, v in tls.items() if v},
                error=attrs.get("error") or attrs.get("errorMessage") or None,
                notes=(txn.findtext("notes") or None),
                request=_xml_message(txn.find("request")),
                response=response,
                source_format="xml",
            )
        )
    link_interim_transactions(transactions)
    return transactions


# ----------------------------------------------------------------------------- HAR

_CHARSET_PARAM = re.compile(r"charset=\"?([\w.:-]+)", re.IGNORECASE)


def _apply_har_body(message: Message, holder: dict[str, Any], text: Any) -> None:
    """HAR ``text`` is decoded unicode; base64 ``text`` holds the raw (maybe still encoded) bytes."""
    if not isinstance(text, str):
        return
    if str(holder.get("encoding") or "").lower() == "base64":
        message.body = _decode_text_body(text, base64_encoded=True, charset=None)
        message.body_decoded = False  # e.g. Charles keeps zstd bodies compressed
        return
    # Re-encode with the declared charset so byte-level replays match the
    # original request and rendering decodes it back correctly.
    match = _CHARSET_PARAM.search(message.content_type or "")
    charset = safe_charset(match.group(1)) if match else "utf-8"
    message.body = text.encode(charset, errors="replace")
    message.charset = charset
    message.body_decoded = True


def _har_total_size(
    req: dict[str, Any], res: dict[str, Any], content: dict[str, Any]
) -> int | None:
    parts = [
        _as_int(req.get("headersSize")),
        _as_int(req.get("bodySize")),
        _as_int(res.get("headersSize")),
        _as_int(res.get("bodySize"))
        if _as_int(res.get("bodySize")) not in (None, -1)
        else _as_int(content.get("size")),
    ]
    known = [max(p, 0) for p in parts if p is not None]
    return sum(known) if known else None


def _har_file_value(value: str, content_type: str | None, file_name: str | None = None) -> bytes:
    """HAR file params: Charles stores binary file contents base64-encoded, text as is."""
    kind = content_type or (mimetypes.guess_type(file_name or "")[0] if file_name else None)
    if not is_textual_type(kind):
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            pass
    return value.encode("utf-8")


def _quote_param(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", " ").replace("\n", " ")


def _har_params_body(mime_type: str | None, params: list[Any]) -> bytes:
    """Rebuild a request body from HAR ``postData.params`` (Charles omits ``text`` for forms)."""
    match = _CHARSET_PARAM.search(mime_type or "")
    charset = safe_charset(match.group(1)) if match else "utf-8"
    items = [p for p in params if isinstance(p, dict)]
    boundary = re.search(r"boundary=\"?([^\";]+)", mime_type or "", re.IGNORECASE)
    if mime_type and "multipart/form-data" in mime_type.lower() and boundary:
        delimiter = boundary.group(1).encode("latin-1", errors="replace")
        body = bytearray()
        for item in items:
            name = str(item.get("name", ""))
            value = str(item.get("value", ""))
            file_name = item.get("fileName")
            part_type = _text(item.get("contentType"))
            disposition = f'form-data; name="{_quote_param(name)}"'
            if file_name is not None:
                disposition += f'; filename="{_quote_param(str(file_name))}"'
            head = f"Content-Disposition: {disposition}\r\n"
            if part_type:
                head += f"Content-Type: {part_type}\r\n"
            data = (
                _har_file_value(value, part_type, str(file_name))
                if file_name is not None
                else value.encode(charset, errors="replace")
            )
            body += b"--" + delimiter + b"\r\n" + head.encode("utf-8") + b"\r\n" + data + b"\r\n"
        body += b"--" + delimiter + b"--\r\n"
        return bytes(body)
    from urllib.parse import urlencode

    pairs = [(str(p.get("name", "")), str(p.get("value", ""))) for p in items]
    return urlencode(pairs, encoding=charset, errors="replace").encode("ascii")


def parse_har(payload: Any) -> list[Transaction]:
    if isinstance(payload, (bytes, str)):
        try:
            payload = json.loads(payload)
        except ValueError as exc:
            raise SessionFormatError(f"invalid HAR: {exc}") from exc
    log = _as_dict(_as_dict(payload).get("log"))
    if not isinstance(log.get("entries"), list):
        raise SessionFormatError("HAR file has no log.entries array")
    transactions: list[Transaction] = []
    for seq, entry in enumerate(_as_list(log.get("entries")), start=1):
        entry = _as_dict(entry)
        req = _as_dict(entry.get("request"))
        res = _as_dict(entry.get("response"))
        url = urlsplit(str(req.get("url") or ""))
        req_headers = _headers_from_list(req.get("headers"))
        res_headers = _headers_from_list(res.get("headers"))

        request = Message(
            first_line=f"{req.get('method', 'GET')} {url.path or '/'}"
            + (f"?{url.query}" if url.query else "")
            + f" {req.get('httpVersion') or 'HTTP/1.1'}",
            headers=req_headers,
            header_size=_as_int(req.get("headersSize")),
            body_size=_as_int(req.get("bodySize")),
        )
        post = _as_dict(req.get("postData"))
        if post:
            request.mime_type = _text(post.get("mimeType"))
            _apply_har_body(request, post, post.get("text"))
            if request.body is None and post.get("params"):
                request.body = _har_params_body(request.mime_type, _as_list(post.get("params")))
                request.body_decoded = True

        content = _as_dict(res.get("content"))
        status = _as_int(res.get("status"))
        response = Message(
            first_line=(
                f"{res.get('httpVersion') or 'HTTP/1.1'} {status} {res.get('statusText') or ''}".strip()
                if status
                else None
            ),
            headers=res_headers,
            mime_type=_text(content.get("mimeType")),
            header_size=_as_int(res.get("headersSize")),
            body_size=_as_int(content.get("size")),
        )
        _apply_har_body(response, content, content.get("text"))

        timings = {
            k: v
            for k, v in _as_dict(entry.get("timings")).items()
            if isinstance(v, (int, float)) and v >= 0
        }
        start_ms = iso_to_ms(entry.get("startedDateTime"))
        total = entry.get("time")
        port = url.port
        transactions.append(
            Transaction(
                seq=seq,
                method=str(req.get("method") or "GET").upper(),
                scheme=(url.scheme or "http").lower(),
                host=url.hostname or "",
                port=port,
                path=url.path or "/",
                query=url.query or None,
                protocol=req.get("httpVersion") or None,
                status="COMPLETE" if status else ("FAILED" if entry.get("_error") else None),
                response_status=status or None,
                start_ms=start_ms,
                end_ms=start_ms + int(total)
                if start_ms is not None and isinstance(total, (int, float))
                else None,
                start_time=entry.get("startedDateTime"),
                durations={"total": total, **timings}
                if isinstance(total, (int, float))
                else timings,
                total_size=_har_total_size(req, res, content),
                remote_address=entry.get("serverIPAddress") or None,
                error=entry.get("_error") or None,
                websocket=bool(entry.get("_webSocketMessages")),
                request=request,
                response=response,
                source_format="har",
            )
        )
    link_interim_transactions(transactions)
    return transactions


# ------------------------------------------------------------ native archive (.chlz)

_META_NAME = re.compile(r"^(\d+)-meta\.json$")
_SIDECAR_NAME = re.compile(r"^(\d+)-(req|res)(?:-enc)?(?:\.[^.]*)?$")


def _is_hidden_member(name: str) -> bool:
    parts = [part for part in name.split("/") if part]
    return any(part.startswith(".") or part == "__MACOSX" for part in parts)


_MAX_ZIP_BODY_BYTES = 512 * 1024 * 1024


def parse_native_zip(data: bytes) -> list[Transaction]:
    """Parse a zip-based Charles native session (.chlz, Charles 5.0+).

    Layout (5.2.2): ``<n>-meta.json`` holds a transaction in the JSON export
    schema, numbered from 0. Bodies live beside it; the meta's ``bodyFile``
    names them (``<n>-res.json``, ``<n>-req.dat`` ...). A ``-enc`` infix
    (``3-res-enc.dat``) marks a body still carrying its Content-Encoding;
    every other body file is already decoded. Hidden members (dot files,
    ``__MACOSX``) are ignored, matching the Charles 5.0.2 fix.
    """
    try:
        archive = zipfile.ZipFile(BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise SessionFormatError(f"not a zip-based Charles session: {exc}") from exc

    with archive:
        if not archive.namelist():
            return []  # Charles exports an empty session as an empty archive
        members = [name for name in archive.namelist() if not _is_hidden_member(name)]
        member_set = set(members)
        sidecars: dict[tuple[str, int], dict[str, str]] = {}
        metas: list[tuple[int, str, str]] = []
        for name in members:
            directory, base = posixpath.split(name)
            meta_match = _META_NAME.match(base)
            if meta_match:
                metas.append((int(meta_match.group(1)), directory, name))
                continue
            side_match = _SIDECAR_NAME.match(base)
            if side_match:
                sidecars.setdefault((directory, int(side_match.group(1))), {})[
                    side_match.group(2)
                ] = name
        if not metas:
            raise SessionFormatError("archive contains no <n>-meta.json transaction files")

        metas.sort(key=lambda item: (item[1], item[0]))
        transactions: list[Transaction] = []
        for seq, (number, directory, meta_name) in enumerate(metas, start=1):
            try:
                raw = _as_dict(json.loads(archive.read(meta_name).decode("utf-8")))
            except (ValueError, zipfile.BadZipFile, zlib.error, RecursionError) as exc:
                raise SessionFormatError(f"{meta_name}: unreadable ({exc})") from exc
            txn = transaction_from_json(raw, seq, source_format="chlz")
            found = sidecars.get((directory, number), {})
            for side, key, message in (
                ("req", "request", txn.request),
                ("res", "response", txn.response),
            ):
                if message.body:
                    continue
                declared = _text(_as_dict(raw.get(key)).get("bodyFile"))
                member = None
                if declared:
                    candidate = posixpath.join(directory, declared) if directory else declared
                    member = candidate if candidate in member_set else None
                member = member or found.get(side)
                if member is None:
                    continue
                size = archive.getinfo(member).file_size
                if size > _MAX_ZIP_BODY_BYTES:
                    message.body_size = message.body_size or size
                    continue  # implausibly large: leave it in the archive
                try:
                    message.body = archive.read(member)
                except (zipfile.BadZipFile, zlib.error) as exc:
                    raise SessionFormatError(f"{member}: unreadable ({exc})") from exc
                message.body_decoded = "-enc" not in posixpath.basename(member)
            transactions.append(txn)
    link_interim_transactions(transactions)
    return transactions
