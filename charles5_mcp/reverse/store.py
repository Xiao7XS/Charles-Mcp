"""SQLite persistence for reverse analysis.

Bodies are content-addressed (sha256) so repeated payloads and replays of the
same request are stored once.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from charles5_mcp.errors import NotFoundError
from charles5_mcp.session.model import Transaction
from charles5_mcp.session.parsers import transaction_from_json
from charles5_mcp.session.writer import transaction_to_json

_SCHEMA = """
CREATE TABLE IF NOT EXISTS captures (
    capture_id TEXT PRIMARY KEY,
    label TEXT,
    source_kind TEXT NOT NULL,
    source_path TEXT,
    source_format TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    entry_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS entries (
    entry_id TEXT PRIMARY KEY,
    capture_id TEXT NOT NULL REFERENCES captures(capture_id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    method TEXT NOT NULL,
    host TEXT NOT NULL,
    path TEXT NOT NULL,
    query TEXT,
    status INTEGER,
    start_ms INTEGER,
    total_size INTEGER,
    has_error INTEGER NOT NULL DEFAULT 0,
    txn_json TEXT NOT NULL,
    req_body TEXT,
    res_body TEXT
);
CREATE INDEX IF NOT EXISTS idx_entries_capture_seq ON entries(capture_id, seq);
CREATE INDEX IF NOT EXISTS idx_entries_capture_host ON entries(capture_id, host);
CREATE TABLE IF NOT EXISTS bodies (
    sha256 TEXT PRIMARY KEY,
    data BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    entry_id TEXT NOT NULL,
    label TEXT,
    mutation_json TEXT NOT NULL,
    request_json TEXT NOT NULL,
    outcome TEXT NOT NULL,
    response_status INTEGER,
    latency_ms INTEGER,
    response_headers_json TEXT,
    response_body TEXT,
    diff_json TEXT,
    error TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_entry ON runs(entry_id);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    capture_id TEXT,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    title TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    recommendation TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_subject ON findings(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_findings_capture ON findings(capture_id);
"""


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class ReverseStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if str(path) != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # ------------------------------------------------------------------ bodies

    def put_body(self, conn: sqlite3.Connection, data: bytes | None) -> str | None:
        if not data:
            return None
        digest = hashlib.sha256(data).hexdigest()
        conn.execute("INSERT OR IGNORE INTO bodies(sha256, data) VALUES (?, ?)", (digest, data))
        return digest

    def get_body(self, digest: str | None) -> bytes | None:
        if not digest:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM bodies WHERE sha256 = ?", (digest,)
            ).fetchone()
        return bytes(row["data"]) if row else None

    # ---------------------------------------------------------------- captures

    def create_capture(
        self,
        *,
        label: str | None,
        source_kind: str,
        source_path: str | None,
        source_format: str | None,
    ) -> str:
        capture_id = new_id("rcap")
        now = time.time()
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO captures VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                (capture_id, label, source_kind, source_path, source_format, now, now),
            )
        return capture_id

    def capture(self, capture_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM captures WHERE capture_id = ?", (capture_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError(
                f"reverse capture `{capture_id}` not found", hint="call reverse_list_captures"
            )
        return dict(row)

    def list_captures(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM captures ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_capture(self, capture_id: str) -> int:
        self.capture(capture_id)
        with self.tx() as conn:
            entry_ids = [
                r[0]
                for r in conn.execute(
                    "SELECT entry_id FROM entries WHERE capture_id = ?", (capture_id,)
                )
            ]
            conn.executemany("DELETE FROM runs WHERE entry_id = ?", [(e,) for e in entry_ids])
            conn.execute("DELETE FROM findings WHERE capture_id = ?", (capture_id,))
            conn.execute("DELETE FROM entries WHERE capture_id = ?", (capture_id,))
            conn.execute("DELETE FROM captures WHERE capture_id = ?", (capture_id,))
            conn.execute(
                """DELETE FROM bodies WHERE sha256 NOT IN (
                       SELECT req_body FROM entries WHERE req_body IS NOT NULL
                       UNION SELECT res_body FROM entries WHERE res_body IS NOT NULL
                       UNION SELECT response_body FROM runs WHERE response_body IS NOT NULL)"""
            )
        return len(entry_ids)

    # ----------------------------------------------------------------- entries

    @staticmethod
    def entry_id_for(capture_id: str, seq: int) -> str:
        return f"{capture_id.replace('rcap-', 'r')}-{seq}"

    def upsert_transactions(self, capture_id: str, transactions: list[Transaction]) -> list[str]:
        ids: list[str] = []
        with self.tx() as conn:
            for txn in transactions:
                entry_id = self.entry_id_for(capture_id, txn.seq)
                record = transaction_to_json(txn)
                record["request"].pop("body", None)
                record["response"].pop("body", None)
                record["_meta"] = {
                    "req_decoded": txn.request.body_decoded,
                    "res_decoded": txn.response.body_decoded,
                    "linked_to_seq": txn.linked_to_seq,
                    "source_format": txn.source_format,
                    "start_ms": txn.start_ms,
                    "end_ms": txn.end_ms,
                }
                conn.execute(
                    """INSERT INTO entries(entry_id, capture_id, seq, method, host, path, query, status,
                           start_ms, total_size, has_error, txn_json, req_body, res_body)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(entry_id) DO UPDATE SET status=excluded.status,
                           total_size=excluded.total_size, has_error=excluded.has_error,
                           txn_json=excluded.txn_json, req_body=excluded.req_body,
                           res_body=excluded.res_body""",
                    (
                        entry_id,
                        capture_id,
                        txn.seq,
                        txn.method,
                        txn.host,
                        txn.path,
                        txn.query,
                        txn.response_status,
                        txn.start_ms,
                        txn.total_size,
                        int(txn.has_error),
                        json.dumps(record, ensure_ascii=False),
                        self.put_body(conn, txn.request.body),
                        self.put_body(conn, txn.response.body),
                    ),
                )
                ids.append(entry_id)
            count = conn.execute(
                "SELECT COUNT(*) FROM entries WHERE capture_id = ?", (capture_id,)
            ).fetchone()[0]
            conn.execute(
                "UPDATE captures SET entry_count = ?, updated_at = ? WHERE capture_id = ?",
                (count, time.time(), capture_id),
            )
        return ids

    def _row_to_txn(self, row: sqlite3.Row) -> Transaction:
        record = json.loads(row["txn_json"])
        meta = record.pop("_meta", {})
        txn = transaction_from_json(
            record, row["seq"], source_format=meta.get("source_format", "store")
        )
        txn.start_ms = meta.get("start_ms", txn.start_ms)
        txn.end_ms = meta.get("end_ms", txn.end_ms)
        txn.linked_to_seq = meta.get("linked_to_seq")
        txn.request.body = self.get_body(row["req_body"])
        txn.request.body_decoded = bool(meta.get("req_decoded"))
        txn.response.body = self.get_body(row["res_body"])
        txn.response.body_decoded = bool(meta.get("res_decoded"))
        return txn

    def get_entry(self, entry_id: str) -> tuple[dict[str, Any], Transaction]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM entries WHERE entry_id = ?", (entry_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError(
                f"reverse entry `{entry_id}` not found",
                hint="Reverse entry ids come from reverse_query_entries / reverse live reads.",
            )
        return {
            "entry_id": row["entry_id"],
            "capture_id": row["capture_id"],
            "seq": row["seq"],
        }, self._row_to_txn(row)

    def endpoint_entries(
        self, capture_id: str, *, method: str, host: str, path: str, limit: int = 10
    ) -> list[tuple[str, Transaction]]:
        """The latest ``limit`` entries for one exact endpoint, oldest first."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM entries WHERE capture_id = ? AND method = ? AND host = ? AND path = ?
                   ORDER BY seq DESC LIMIT ?""",
                (capture_id, method, host, path, limit),
            ).fetchall()
        return [(row["entry_id"], self._row_to_txn(row)) for row in reversed(rows)]

    def busiest_endpoint(
        self, capture_id: str, *, host_contains: str | None, path_contains: str | None
    ) -> tuple[str, str, str] | None:
        """(method, host, path) occurring most often among matching entries."""
        clauses = ["capture_id = ?"]
        params: list[Any] = [capture_id]
        if host_contains:
            clauses.append("instr(lower(host), lower(?)) > 0")
            params.append(host_contains)
        if path_contains:
            clauses.append("instr(lower(path || coalesce('?' || query, '')), lower(?)) > 0")
            params.append(path_contains)
        with self._lock:
            row = self._conn.execute(
                f"""SELECT method, host, path, COUNT(*) AS n FROM entries WHERE {" AND ".join(clauses)}
                    GROUP BY method, host, path ORDER BY n DESC, MAX(seq) DESC LIMIT 1""",
                params,
            ).fetchone()
        return (row["method"], row["host"], row["path"]) if row else None

    def iter_entries(
        self, capture_id: str, *, host_contains: str | None = None, batch: int = 500
    ) -> Iterator[tuple[str, Transaction]]:
        """Stream every entry of a capture in order, ``batch`` rows at a time."""
        last_seq = -1
        while True:
            clauses = ["capture_id = ?", "seq > ?"]
            params: list[Any] = [capture_id, last_seq]
            if host_contains:
                clauses.append("instr(lower(host), lower(?)) > 0")
                params.append(host_contains)
            with self._lock:
                rows = self._conn.execute(
                    f"SELECT * FROM entries WHERE {' AND '.join(clauses)} ORDER BY seq LIMIT ?",
                    params + [batch],
                ).fetchall()
            if not rows:
                return
            for row in rows:
                yield row["entry_id"], self._row_to_txn(row)
            last_seq = rows[-1]["seq"]

    def query_entries(
        self,
        capture_id: str,
        *,
        host_contains: str | None = None,
        path_contains: str | None = None,
        method_in: list[str] | None = None,
        status_in: list[int] | None = None,
        errors_only: bool = False,
        min_seq: int | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[int, list[tuple[str, Transaction]]]:
        clauses = ["capture_id = ?"]
        params: list[Any] = [capture_id]
        if host_contains:
            clauses.append("instr(lower(host), lower(?)) > 0")
            params.append(host_contains)
        if path_contains:
            clauses.append("instr(lower(path || coalesce('?' || query, '')), lower(?)) > 0")
            params.append(path_contains)
        if method_in:
            clauses.append(f"method IN ({','.join('?' * len(method_in))})")
            params += [m.upper() for m in method_in]
        if status_in:
            clauses.append(f"status IN ({','.join('?' * len(status_in))})")
            params += list(status_in)
        if errors_only:
            clauses.append("has_error = 1")
        if min_seq is not None:
            clauses.append("seq >= ?")
            params.append(min_seq)
        where = " AND ".join(clauses)
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM entries WHERE {where}", params
            ).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT * FROM entries WHERE {where} ORDER BY seq LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
        return total, [(row["entry_id"], self._row_to_txn(row)) for row in rows]

    # ----------------------------------------------------------- runs/findings

    def add_run(self, run: dict[str, Any], response_body: bytes | None) -> None:
        with self.tx() as conn:
            body_ref = self.put_body(conn, response_body)
            conn.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    run["run_id"],
                    run["entry_id"],
                    run.get("label"),
                    json.dumps(run.get("mutation") or {}, ensure_ascii=False),
                    json.dumps(run.get("request") or {}, ensure_ascii=False),
                    run["outcome"],
                    run.get("response_status"),
                    run.get("latency_ms"),
                    json.dumps(run.get("response_headers") or {}, ensure_ascii=False),
                    body_ref,
                    json.dumps(run.get("diff") or {}, ensure_ascii=False),
                    run.get("error"),
                    time.time(),
                ),
            )

    def list_runs(self, entry_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM runs WHERE entry_id = ? ORDER BY created_at DESC LIMIT ?",
                (entry_id, limit),
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            for key in ("mutation_json", "request_json", "response_headers_json", "diff_json"):
                item[key.removesuffix("_json")] = json.loads(item.pop(key) or "{}")
            out.append(item)
        return out

    def add_finding(
        self,
        *,
        subject_type: str,
        subject_id: str,
        capture_id: str | None,
        finding_type: str,
        severity: str,
        confidence: float,
        title: str,
        evidence: dict[str, Any],
        recommendation: str | None = None,
    ) -> str:
        finding_id = new_id("finding")
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    finding_id,
                    subject_type,
                    subject_id,
                    capture_id,
                    finding_type,
                    severity,
                    round(confidence, 2),
                    title,
                    json.dumps(evidence, ensure_ascii=False, default=str),
                    recommendation,
                    time.time(),
                ),
            )
        return finding_id

    def list_findings(
        self,
        *,
        capture_id: str | None = None,
        subject_id: str | None = None,
        finding_type: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if capture_id:
            clauses.append("capture_id = ?")
            params.append(capture_id)
        if subject_id:
            clauses.append("subject_id = ?")
            params.append(subject_id)
        if finding_type:
            clauses.append("finding_type = ?")
            params.append(finding_type)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM findings {where} ORDER BY created_at DESC LIMIT ?", params + [limit]
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["evidence"] = json.loads(item.pop("evidence_json"))
            out.append(item)
        return out
