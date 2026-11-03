"""Format-independent transaction model.

Every session source (Web Interface JSON/XML exports, .chlsj, .chlz, .chls via
`charles convert`, HAR) is parsed into ``Transaction`` objects. The live,
history and reverse-analysis planes all work on this one model.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlunsplit

CONTROL_HOST = "control.charles"

# Values of Charles' ProxyEventStatus as written to exports (5.2.2).
TERMINAL_STATUSES = frozenset({"COMPLETE", "EXCEPTION", "BLOCKED", "FAILED"})
ERROR_STATUSES = frozenset({"EXCEPTION", "BLOCKED", "FAILED"})
IN_FLIGHT_PREFIXES = ("BEFORE", "CONNECTING", "RECEIVING", "RECEIVED", "SENDING")


@dataclass
class Message:
    """One side of an HTTP exchange."""

    first_line: str | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    mime_type: str | None = None
    charset: str | None = None
    content_encoding: str | None = None
    # Body bytes exactly as the source stored them. When ``body_decoded`` is
    # False they may still carry the Content-Encoding (gzip/br/zstd/deflate).
    body: bytes | None = None
    body_decoded: bool = False
    header_size: int | None = None
    body_size: int | None = None
    trailers: list[tuple[str, str]] = field(default_factory=list)
    # Memoised (decoded_bytes, notes); filled lazily by session.body.
    decode_cache: tuple[bytes, list[str]] | None = field(default=None, repr=False, compare=False)

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None

    def header_values(self, name: str) -> list[str]:
        lowered = name.lower()
        return [value for key, value in self.headers if key.lower() == lowered]

    def header_map(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for key, value in self.headers:
            result.setdefault(key.lower(), []).append(value)
        return result

    @property
    def content_type(self) -> str | None:
        return self.header("content-type") or self.mime_type

    @property
    def effective_content_encoding(self) -> str | None:
        return self.content_encoding or self.header("content-encoding")

    @property
    def has_body(self) -> bool:
        return bool(self.body)


@dataclass
class InterimResponse:
    """A 1xx informational response (e.g. 103 Early Hints) attached to a request."""

    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Transaction:
    """A single request/response exchange recorded by Charles."""

    seq: int
    method: str = "GET"
    scheme: str = "http"
    host: str = ""
    port: int | None = None
    actual_port: int | None = None  # set only when Charles connected elsewhere (Map Remote)
    path: str = "/"
    query: str | None = None
    protocol: str | None = None
    status: str | None = None  # Charles transaction status: COMPLETE, FAILED, ...
    response_status: int | None = None
    start_ms: int | None = None
    end_ms: int | None = None
    start_time: str | None = None
    durations: dict[str, Any] = field(default_factory=dict)
    total_size: int | None = None
    remote_address: str | None = None
    client_address: str | None = None
    client_port: int | None = None
    tls: dict[str, Any] = field(default_factory=dict)
    alpn: str | None = None
    error: str | None = None
    tunnel: bool = False
    websocket: bool = False
    notes: str | None = None
    request: Message = field(default_factory=Message)
    response: Message = field(default_factory=Message)
    interim_responses: list[InterimResponse] = field(default_factory=list)
    # Set on a standalone 1xx transaction (Charles 5.2 records them as linked
    # transactions) to the seq of the final exchange it belongs to.
    linked_to_seq: int | None = None
    source_format: str = "unknown"

    # ----- derived properties -------------------------------------------------

    @property
    def is_control(self) -> bool:
        return self.host.lower() == CONTROL_HOST

    @property
    def is_interim(self) -> bool:
        """True for a recorded 1xx informational exchange (101 upgrades excluded)."""
        status = self.response_status
        return status is not None and 100 <= status < 200 and status != 101

    @property
    def is_complete(self) -> bool:
        if self.status:
            upper = self.status.upper()
            return upper in TERMINAL_STATUSES or not upper.startswith(IN_FLIGHT_PREFIXES)
        return self.response_status is not None or self.error is not None

    @property
    def has_error(self) -> bool:
        if self.error:
            return True
        if self.status and self.status.upper() in ERROR_STATUSES:
            return True
        return self.response_status is not None and self.response_status >= 400

    def url(self, *, override_query: bool = False, query: str | None = None) -> str:
        effective_query = query if override_query else self.query
        netloc = self.host
        if self.port and not _is_default_port(self.scheme, self.port):
            netloc = f"{self.host}:{self.port}"
        path = self.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        return urlunsplit((self.scheme or "http", netloc, path, effective_query or "", ""))

    def identity_key(self) -> str:
        """Fields that do not change while a transaction is in flight.

        Used to recognise the same exchange across successive live exports so
        an in-progress request that later completes is updated in place rather
        than counted twice.
        """
        parts = [
            self.method or "",
            self.scheme or "",
            self.host or "",
            str(self.port or ""),
            self.path or "",
            self.query or "",
            str(self.start_ms if self.start_ms is not None else self.start_time or ""),
            str(self.client_port or ""),
            self.request.first_line or "",
        ]
        return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()

    def content_key(self) -> str:
        """Fields that change once the exchange completes; detects in-place updates."""
        parts = [
            self.status or "",
            str(self.response_status or ""),
            str(self.end_ms or ""),
            str(self.total_size or ""),
            str(len(self.response.body or b"")),
        ]
        return "|".join(parts)


def _is_default_port(scheme: str | None, port: int) -> bool:
    return (scheme or "http", port) in {("http", 80), ("https", 443), ("ws", 80), ("wss", 443)}


def link_interim_transactions(transactions: list[Transaction]) -> None:
    """Attach standalone 1xx transactions to the final exchange they belong to.

    Charles 5.2 forwards 1xx responses (including 103 Early Hints) and records
    them as separate transactions; the final one carries a note such as
    "Received interim response: HTTP/1.1 103 Early Hints". Exports do not link
    them explicitly and the order differs between formats (the .chlz archive
    lists the final response first), so each interim transaction is paired
    with the closest-starting final transaction for the same method and URL.
    """
    finals: dict[tuple[str, str, str, int | None, str, str], list[Transaction]] = {}
    for txn in transactions:
        if not txn.is_interim:
            key = (txn.method, txn.scheme, txn.host, txn.port, txn.path, txn.query or "")
            finals.setdefault(key, []).append(txn)
    for interim in transactions:
        if not interim.is_interim:
            continue
        key = (
            interim.method,
            interim.scheme,
            interim.host,
            interim.port,
            interim.path,
            interim.query or "",
        )
        candidates = finals.get(key) or []
        if not candidates:
            continue
        anchor = interim.start_ms
        if anchor is not None:
            timed = [
                c
                for c in candidates
                if c.start_ms is not None and abs(c.start_ms - anchor) <= 60_000
            ]
            if not timed:
                continue
            target = min(timed, key=lambda c: (abs((c.start_ms or 0) - anchor), c.seq))
        else:
            target = min(candidates, key=lambda c: abs(c.seq - interim.seq))
        interim.linked_to_seq = target.seq
        if not any(item.status == interim.response_status for item in target.interim_responses):
            target.interim_responses.append(
                InterimResponse(
                    status=interim.response_status or 0, headers=list(interim.response.headers)
                )
            )
