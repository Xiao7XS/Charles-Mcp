"""Reverse-analysis facade: import, query, decode, replay, signatures, live sessions, workflows."""

from __future__ import annotations

import dataclasses
import time
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from charles5_mcp.config import Settings
from charles5_mcp.errors import CharlesMCPError, CharlesNotRecordingError, NotFoundError
from charles5_mcp.reverse import signature
from charles5_mcp.reverse.params import request_parameters
from charles5_mcp.reverse.replay import Mutation, ReplayService, is_replay
from charles5_mcp.reverse.store import ReverseStore
from charles5_mcp.reverse.workflows import PROFILES, build_mutation_plan, rank
from charles5_mcp.session import protobuf
from charles5_mcp.session.body import decoded_bytes, render_body
from charles5_mcp.session.classify import classify
from charles5_mcp.session.loader import load_session_file
from charles5_mcp.session.model import Transaction
from charles5_mcp.session.websocket import is_websocket, websocket_messages
from charles5_mcp.traffic import views
from charles5_mcp.traffic.live import LiveCaptureService
from charles5_mcp.traffic.tracker import SessionTracker


@dataclass
class ReverseLiveSession:
    live_session_id: str
    capture_id: str
    tracker: SessionTracker
    created_at: float
    last_access: float
    initial_recording: bool | None
    managed_recording: bool
    cursor: int = 0
    warnings: list[str] = field(default_factory=list)


def _summary(entry_id: str, txn: Transaction) -> dict[str, Any]:
    return views.summarize(txn, classify(txn), entry_id, include_preview=False, max_headers=0)


class ReverseService:
    def __init__(self, settings: Settings, store: ReverseStore, live: LiveCaptureService) -> None:
        self.settings = settings
        self.store = store
        self.live = live
        self.replayer = ReplayService(settings, store)
        self.sessions: dict[str, ReverseLiveSession] = {}

    # ----------------------------------------------------------------- import

    def import_session(self, path: str, *, label: str | None = None) -> dict[str, Any]:
        file_path = Path(path).expanduser()
        transactions = load_session_file(file_path, charles_cli=self.settings.charles_cli_path)
        fmt = transactions[0].source_format if transactions else file_path.suffix.lstrip(".")
        capture_id = self.store.create_capture(
            label=label or file_path.name,
            source_kind="import",
            source_path=str(file_path.resolve()),
            source_format=fmt,
        )
        self.store.upsert_transactions(capture_id, transactions)
        hosts: dict[str, int] = {}
        for txn in transactions:
            if not txn.is_control:
                hosts[txn.host] = hosts.get(txn.host, 0) + 1
        return {
            "capture_id": capture_id,
            "format": fmt,
            "entries": len(transactions),
            "top_hosts": dict(sorted(hosts.items(), key=lambda kv: kv[1], reverse=True)[:8]),
            "next": "reverse_query_entries(capture_id=...) to narrow down, then detail/decode/replay.",
        }

    def list_captures(self, limit: int) -> dict[str, Any]:
        rows = self.store.list_captures(min(limit, 200))
        for row in rows:
            for key in ("created_at", "updated_at"):
                row[key] = views.iso_from_ms(int(row[key] * 1000))
        return {"captures": rows}

    def delete_capture(self, capture_id: str) -> dict[str, Any]:
        removed = self.store.delete_capture(capture_id)
        for session_id, session in list(self.sessions.items()):
            if session.capture_id == capture_id:
                del self.sessions[session_id]
        return {"capture_id": capture_id, "deleted_entries": removed}

    # ------------------------------------------------------------ query/detail

    def query_entries(self, capture_id: str, **filters: Any) -> dict[str, Any]:
        self.store.capture(capture_id)
        limit = max(1, min(filters.pop("limit", 20), self.settings.reverse_max_query_limit))
        offset = max(0, filters.pop("offset", 0))
        total, rows = self.store.query_entries(capture_id, limit=limit, offset=offset, **filters)
        return views.fit_budget(
            views.compact(
                {
                    "capture_id": capture_id,
                    "total_matching": total,
                    "offset": offset,
                    "returned": len(rows),
                    "next_offset": offset + len(rows) if offset + len(rows) < total else None,
                    "items": [_summary(entry_id, txn) for entry_id, txn in rows],
                }
            )
        )

    def entry_detail(
        self, entry_id: str, *, include_body: bool = True, max_body_chars: int = 4096
    ) -> dict[str, Any]:
        max_body_chars = max(256, min(max_body_chars, self.settings.max_detail_body_chars))
        meta, txn = self.store.get_entry(entry_id)
        result = views.detail(
            txn, classify(txn), entry_id, include_body=include_body, max_body_chars=max_body_chars
        )
        result["capture_id"] = meta["capture_id"]
        result["seq"] = meta["seq"]
        params = request_parameters(txn)
        if params:
            result["request_parameters"] = {k: v[:200] for k, v in list(params.items())[:80]}
        runs = self.store.list_runs(entry_id, limit=5)
        if runs:
            result["recent_replays"] = [
                {
                    "run_id": r["run_id"],
                    "label": r["label"],
                    "outcome": r["outcome"],
                    "status": r["response_status"],
                }
                for r in runs
            ]
        return result

    def decode_body(
        self,
        entry_id: str,
        side: str,
        *,
        descriptor_path: str | None = None,
        message_type: str | None = None,
        max_chars: int = 8192,
    ) -> dict[str, Any]:
        if side not in ("request", "response"):
            raise CharlesMCPError("side must be 'request' or 'response'")
        max_chars = max(256, min(max_chars, self.settings.max_detail_body_chars))
        _, txn = self.store.get_entry(entry_id)
        message = txn.request if side == "request" else txn.response
        if is_websocket(txn):
            messages, notes = websocket_messages(txn)
            direction = "client" if side == "request" else "server"
            mine = [m for m in messages if m.direction == direction]
            return views.compact(
                {
                    "entry_id": entry_id,
                    "side": side,
                    "kind": "websocket",
                    "message_count": len(mine),
                    "messages": [
                        m.to_dict(max_chars=max(200, max_chars // max(len(mine[:200]), 1)))
                        for m in mine[:200]
                    ],
                    "notes": notes or None,
                }
            )
        if not message.body:
            return {"entry_id": entry_id, "side": side, "kind": "empty"}
        view = render_body(message, max_chars=max_chars)
        result: dict[str, Any] = {
            "entry_id": entry_id,
            "side": side,
            **view.to_dict(include_parsed=True),
        }
        result["content_encoding"] = message.effective_content_encoding
        if descriptor_path and message_type:
            data, _ = decoded_bytes(message)
            frames = None
            if "grpc" in (message.content_type or "").lower():
                frames = protobuf.split_grpc_frames(data)
            try:
                if frames:
                    result["decoded_messages"] = [
                        protobuf.decode_with_descriptor(chunk, descriptor_path, message_type)
                        for compressed, chunk in frames
                        if not compressed
                    ]
                else:
                    result["decoded_message"] = protobuf.decode_with_descriptor(
                        data, descriptor_path, message_type
                    )
                result.pop("fields", None)
            except Exception as exc:  # noqa: BLE001 - report decoder failure
                result.setdefault("notes", []).append(f"descriptor_decode_failed: {exc}")
        elif view.kind in ("protobuf", "grpc"):
            result.setdefault("notes", []).append(
                "Field names need a schema: pass descriptor_path (protoc --descriptor_set_out) and message_type."
            )
        return views.compact(result)

    # --------------------------------------------------------------- analysis

    def _entries(self, entry_ids: list[str]) -> list[Transaction]:
        return [self.store.get_entry(entry_id)[1] for entry_id in entry_ids]

    def _peers(self, entry_id: str, limit: int = 8) -> list[tuple[str, Transaction]]:
        """Recent requests to the same endpoint, always including ``entry_id`` itself."""
        meta, txn = self.store.get_entry(entry_id)
        peers = self.store.endpoint_entries(
            meta["capture_id"], method=txn.method, host=txn.host, path=txn.path, limit=limit
        )
        if all(peer_id != entry_id for peer_id, _ in peers):
            peers = peers[1:] + [(entry_id, txn)]
        return peers

    def discover_signatures(
        self,
        *,
        entry_ids: list[str] | None = None,
        capture_id: str | None = None,
        host_contains: str | None = None,
        path_contains: str | None = None,
        record: bool = True,
    ) -> dict[str, Any]:
        if entry_ids:
            if len(entry_ids) < 2:
                peers = self._peers(entry_ids[0])
                if len(peers) < 2:
                    raise CharlesMCPError(
                        "need at least two requests to compare",
                        hint="Trigger the same request again, or pass more entry_ids.",
                    )
                entry_ids = [i for i, _ in peers]
            transactions = self._entries(entry_ids)
        elif capture_id:
            self.store.capture(capture_id)
            endpoint = self.store.busiest_endpoint(
                capture_id, host_contains=host_contains, path_contains=path_contains
            )
            rows = (
                self.store.endpoint_entries(
                    capture_id, method=endpoint[0], host=endpoint[1], path=endpoint[2], limit=10
                )
                if endpoint
                else []
            )
            if len(rows) < 2:
                raise CharlesMCPError(
                    "fewer than two requests to the same endpoint match",
                    hint="relax host/path filters, or trigger the request again",
                )
            entry_ids = [i for i, _ in rows]
            transactions = [t for _, t in rows]
        else:
            raise CharlesMCPError("pass entry_ids or capture_id")

        result = signature.analyze(transactions)
        result["entry_ids"] = entry_ids
        if record and result["signature_fields"]:
            meta, _ = self.store.get_entry(entry_ids[0])
            self.store.add_finding(
                subject_type="entry",
                subject_id=entry_ids[0],
                capture_id=meta["capture_id"],
                finding_type="signature_candidates",
                severity="medium",
                confidence=max(c["score"] for c in result["candidates"])
                if result["candidates"]
                else 0.5,
                title=f"Likely signature fields: {', '.join(result['signature_fields'][:4])}",
                evidence={
                    "signature_fields": result["signature_fields"],
                    "timestamp_fields": result["timestamp_fields"],
                    "nonce_fields": result["nonce_fields"],
                },
                recommendation="Confirm with reverse_run_mutation_plan.",
            )
        return views.compact(result)

    def mutation_plan(
        self, entry_id: str, *, workflow: str = "signature", fields: list[str] | None = None
    ) -> dict[str, Any]:
        profile = PROFILES.get(workflow)
        if profile is None:
            raise CharlesMCPError(
                f"unknown workflow `{workflow}`", hint=f"one of {sorted(PROFILES)}"
            )
        _, txn = self.store.get_entry(entry_id)
        peers = self._peers(entry_id)
        analysis = signature.analyze([t for _, t in peers]) if len(peers) >= 2 else None
        plan = build_mutation_plan(
            profile, entry_id, txn, analysis, [t for _, t in peers], fields=fields
        )
        # Variants keep their nulls: a null override means "remove this field".
        variants = plan.pop("variants")
        return {**views.compact(plan), "variants": variants}

    def findings(self, **filters: Any) -> dict[str, Any]:
        items = self.store.list_findings(**filters)
        for item in items:
            item["created_at"] = views.iso_from_ms(int(item["created_at"] * 1000))
        return {"findings": items}

    # ----------------------------------------------------------------- replay

    async def replay(
        self, entry_id: str, mutation: dict[str, Any] | None, **options: Any
    ) -> dict[str, Any]:
        return views.compact(
            await self.replayer.replay(entry_id, Mutation.from_dict(mutation), **options)
        )

    async def run_mutation_plan(
        self,
        entry_id: str,
        *,
        variants: list[dict[str, Any]] | None = None,
        workflow: str = "signature",
        fields: list[str] | None = None,
        max_variants: int = 12,
        **options: Any,
    ) -> dict[str, Any]:
        if not variants:
            plan = self.mutation_plan(entry_id, workflow=workflow, fields=fields)
            variants = plan.get("variants", [])
            if not variants:
                return {
                    "entry_id": entry_id,
                    "conclusion": "No security-relevant fields were found to mutate.",
                    "hint": "Pass fields=[...] (e.g. ['query.sign', 'header.x-token']) to choose them.",
                }
        return views.compact(
            await self.replayer.run_plan(
                entry_id, variants[: max(1, min(max_variants, 40))], **options
            )
        )

    # ------------------------------------------------------------ live sessions

    def _prune(self) -> None:
        cutoff = time.monotonic() - self.settings.reverse_live_ttl_seconds
        for session_id in [s for s, v in self.sessions.items() if v.last_access < cutoff]:
            del self.sessions[session_id]

    def _session(self, live_session_id: str) -> ReverseLiveSession:
        self._prune()
        session = self.sessions.get(live_session_id)
        if session is None:
            raise NotFoundError(
                f"reverse live session `{live_session_id}` not found or expired",
                hint="call reverse_start_live_analysis",
            )
        session.last_access = time.monotonic()
        return session

    async def start_live(
        self, *, reset_session: bool, start_recording_if_stopped: bool
    ) -> dict[str, Any]:
        self._prune()
        client = self.live.client
        initial = await client.recording_status()
        if reset_session:
            await client.clear_session()
            self.live.invalidate_export()
        managed = False
        if start_recording_if_stopped and initial is not True:
            await client.start_recording()
            managed = initial is False
        live_session_id = f"rlive-{uuid.uuid4().hex[:10]}"
        capture_id = self.store.create_capture(
            label=f"live {time.strftime('%Y-%m-%d %H:%M:%S')}",
            source_kind="live",
            source_path=None,
            source_format="live",
        )
        tracker = SessionTracker(live_session_id, max_entries=self.settings.live_max_entries)
        baseline: list[Transaction] = []
        if not reset_session:
            try:
                baseline = await self.live.export_current()
            except CharlesNotRecordingError:
                baseline = []
        tracker.set_baseline(baseline, include_existing=False)
        now = time.monotonic()
        self.sessions[live_session_id] = ReverseLiveSession(
            live_session_id, capture_id, tracker, now, now, initial, managed
        )
        return {
            "live_session_id": live_session_id,
            "capture_id": capture_id,
            "recording_was": {True: "recording", False: "stopped", None: "unknown"}[initial],
            "recording_started_by_server": managed,
            "baseline_entries_skipped": len([t for t in baseline if not t.is_control]),
            "next": "Exercise the app, then reverse_read_live_entries or a reverse_analyze_live_* workflow.",
        }

    async def _sync(self, session: ReverseLiveSession) -> None:
        """Persist new and updated live entries into the session's capture."""
        try:
            transactions = await self.live.export_current()
        except CharlesNotRecordingError:
            warning = "charles_not_recording: start recording in Charles to continue"
            if warning not in session.warnings:
                session.warnings.append(warning)
            return
        update = session.tracker.ingest(transactions)
        if update.reset_detected:
            session.warnings.append("session_reset_detected")
        changed = set(update.new_ids) | set(update.updated_ids)
        # Replays this server sent through Charles are not app traffic.
        changed -= {
            tracked.entry_id
            for tracked in session.tracker.slice(session.tracker.offset)
            if tracked.entry_id in changed and is_replay(tracked.txn)
        }
        if changed:
            to_store = []
            for tracked in session.tracker.slice(session.tracker.offset):
                if tracked.entry_id in changed:
                    to_store.append(dataclasses.replace(tracked.txn, seq=tracked.position + 1))
            self.store.upsert_transactions(session.capture_id, to_store)

    async def read_live(
        self,
        live_session_id: str,
        *,
        advance: bool,
        limit: int,
        host_contains: str | None = None,
        path_contains: str | None = None,
        method_in: list[str] | None = None,
        status_in: list[int] | None = None,
        consume_all: bool = False,
    ) -> tuple[dict[str, Any], list[tuple[str, Transaction]]]:
        """Return new entries since the session cursor.

        The second element holds every matching entry (workflows rank all of
        them). With ``advance`` the cursor moves past what was returned: all
        new entries when ``consume_all`` or when nothing was cut by ``limit``,
        otherwise only up to the last returned item, so nothing is skipped.
        """
        session = self._session(live_session_id)
        await self._sync(session)
        start = max(session.cursor, session.tracker.offset)
        tracked = session.tracker.slice(start)
        end = session.tracker.total
        limit = max(1, min(limit, self.settings.reverse_max_query_limit))
        methods = {m.upper() for m in method_in or []}
        matching: list[tuple[int, str, Transaction]] = []
        for entry in tracked:
            txn = entry.txn
            if is_replay(txn):
                continue
            if host_contains and host_contains.lower() not in txn.host.lower():
                continue
            if path_contains and path_contains.lower() not in txn.path.lower():
                continue
            if methods and txn.method not in methods:
                continue
            if status_in and txn.response_status not in status_in:
                continue
            store_id = self.store.entry_id_for(session.capture_id, entry.position + 1)
            matching.append((entry.position, store_id, txn))
        returned = matching if consume_all else matching[:limit]
        truncated = len(returned) < len(matching)
        if advance:
            session.cursor = returned[-1][0] + 1 if truncated else end
        warnings = list(dict.fromkeys(session.warnings))
        if advance:
            session.warnings.clear()
        summary = views.compact(
            {
                "live_session_id": live_session_id,
                "capture_id": session.capture_id,
                "new_entries": len(tracked),
                "matching": len(matching),
                "returned": min(len(returned), limit),
                "more_available": truncated or None,
                "cursor_advanced": advance or None,
                "items": [_summary(i, t) for _, i, t in returned[:limit]],
                "warnings": warnings,
            }
        )
        return summary, [(i, t) for _, i, t in matching]

    async def live_items(
        self, live_session_id: str, *, advance: bool, limit: int, **filters: Any
    ) -> dict[str, Any]:
        result, _ = await self.read_live(live_session_id, advance=advance, limit=limit, **filters)
        return views.fit_budget(result)

    async def stop_live(self, live_session_id: str, *, restore_recording: bool) -> dict[str, Any]:
        session = self._session(live_session_id)
        await self._sync(session)
        restored = False
        if restore_recording and session.managed_recording:
            await self.live.client.stop_recording()
            restored = True
        del self.sessions[live_session_id]
        return {
            "live_session_id": live_session_id,
            "capture_id": session.capture_id,
            "entries_saved": self.store.capture(session.capture_id)["entry_count"],
            "recording_stopped": restored,
            "next": "The capture stays in the reverse store; keep using its capture_id.",
        }

    async def status(self, live_session_id: str | None) -> dict[str, Any]:
        recording = await self.live.client.recording_status()
        result: dict[str, Any] = {
            "charles_recording": {True: "recording", False: "stopped", None: "unknown"}[recording],
            "active_live_sessions": [
                {
                    "live_session_id": s.live_session_id,
                    "capture_id": s.capture_id,
                    "entries": s.tracker.total,
                }
                for s in self.sessions.values()
            ],
        }
        if live_session_id:
            session = self._session(live_session_id)
            result["session"] = {
                "live_session_id": live_session_id,
                "capture_id": session.capture_id,
                "entries": session.tracker.total,
                "cursor": session.cursor,
                "recording_started_by_server": session.managed_recording,
            }
        return result

    # --------------------------------------------------------------- workflows

    async def run_workflow(
        self,
        workflow: str,
        *,
        live_session_id: str | None = None,
        capture_id: str | None = None,
        host_contains: str | None = None,
        path_keywords: list[str] | None = None,
        advance: bool = True,
        decode_bodies: bool = True,
        descriptor_path: str | None = None,
        message_type: str | None = None,
        run_replay: bool = False,
        replay_use_proxy: bool = False,
        verify_tls: bool = True,
        limit: int = 200,
    ) -> dict[str, Any]:
        profile = PROFILES[workflow]
        scope: Iterable[tuple[str, Transaction]]
        if live_session_id:
            _, scope = await self.read_live(
                live_session_id,
                advance=advance,
                limit=limit,
                host_contains=host_contains,
                consume_all=True,
            )
            session = self._session(live_session_id)
            capture_ref = session.capture_id
        elif capture_id:
            self.store.capture(capture_id)  # not-found error for unknown ids
            scope = self.store.iter_entries(capture_id, host_contains=host_contains)
            capture_ref = capture_id
        else:
            raise CharlesMCPError("pass live_session_id or capture_id")

        considered = 0

        def counted(
            entries: Iterable[tuple[str, Transaction]],
        ) -> Iterator[tuple[str, Transaction]]:
            nonlocal considered
            for item in entries:
                considered += 1
                yield item

        # Ranking streams the scope, so whole captures are scanned without
        # holding every body in memory.
        candidates = rank(profile, counted(scope), path_keywords)
        base: dict[str, Any] = {
            "workflow": profile.name,
            "capture_id": capture_ref,
            "live_session_id": live_session_id,
        }
        if not considered:
            return views.compact(
                {
                    **base,
                    "status": "no_new_entries",
                    "summary": "No new traffic since the last read.",
                    "next": ["Trigger the flow in the app, then call this workflow again."],
                }
            )
        if not candidates:
            return views.compact(
                {
                    **base,
                    "status": "no_candidates",
                    "summary": f"{considered} entries checked, none looked like {profile.label} traffic.",
                    "next": [
                        "Pass path_keywords matching the endpoint, or drop host_contains.",
                        "Inspect entries with reverse_query_entries.",
                    ],
                }
            )

        selected = candidates[0]
        selected_id = selected["entry_id"]
        _, txn = self.store.get_entry(selected_id)
        peers = self._peers(selected_id)
        analysis = signature.analyze([t for _, t in peers]) if len(peers) >= 2 else None

        decoded: dict[str, Any] = {}
        if decode_bodies:
            for side in ("request", "response"):
                try:
                    body = self.decode_body(
                        selected_id,
                        side,
                        descriptor_path=descriptor_path,
                        message_type=message_type,
                        max_chars=1500,
                    )
                except CharlesMCPError as exc:
                    body = {"error": str(exc)}
                decoded[side] = body

        replay_result = None
        if run_replay:
            replay_result = await self.replay(
                selected_id,
                None,
                use_proxy=replay_use_proxy,
                verify_tls=verify_tls,
                label="workflow-control",
            )

        plan = build_mutation_plan(profile, selected_id, txn, analysis, [t for _, t in peers])
        params = request_parameters(txn)
        actions = []
        if analysis is None:
            actions.append("Trigger the same request 2+ more times so parameters can be compared.")
        if plan["variants"]:
            actions.append(
                f"reverse_run_mutation_plan(entry_id='{selected_id}') to test which fields the server verifies."
            )
        if replay_result and replay_result["comparison"]["outcome"] in ("rejected", "error"):
            actions.insert(
                0, "The unmodified replay failed: the request is time-bound or single-use."
            )
        if decoded.get("request", {}).get("kind") in ("protobuf", "grpc") and not descriptor_path:
            actions.append("Supply a protobuf descriptor_path to name the protobuf fields.")

        return views.compact(
            {
                **base,
                "status": "ok",
                "summary": f"Selected {txn.method} {txn.host}{txn.path} as the top {profile.label} candidate "
                f"(score {selected['score']}, {len(candidates)} candidates in {considered} entries).",
                "selected": {
                    **selected,
                    "url": txn.url(),
                    "parameters": {k: v[:120] for k, v in list(params.items())[:40]},
                },
                "signature": {
                    "compared_requests": analysis["compared"],
                    "signature_fields": analysis["signature_fields"],
                    "timestamp_fields": analysis["timestamp_fields"],
                    "nonce_fields": analysis["nonce_fields"],
                    "static_secrets": [s["field"] for s in analysis["static_secrets"]],
                }
                if analysis
                else None,
                "decoded": decoded or None,
                "replay": {
                    "status": replay_result["status"],
                    "outcome": replay_result["comparison"]["outcome"],
                }
                if replay_result
                else None,
                "other_candidates": candidates[1:6],
                "next": actions,
            }
        ) | {
            "mutation_plan": {
                **views.compact({k: v for k, v in plan.items() if k != "variants"}),
                "variants": plan["variants"],
            }
        }
