"""Live capture: poll the current Charles session with cursors."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from charles5_mcp.charles.client import SELF_RECORDING_WARNING, CharlesClient
from charles5_mcp.config import Settings
from charles5_mcp.errors import CharlesMCPError, CharlesNotRecordingError, NotFoundError
from charles5_mcp.session.model import Transaction
from charles5_mcp.session.writer import write_chlsj
from charles5_mcp.traffic.tracker import SessionTracker, TrackerUpdate


@dataclass
class LiveCapture:
    capture_id: str
    tracker: SessionTracker
    started_at: str
    managed_recording: bool
    include_existing: bool
    cursor: int = 0
    status: str = "active"
    last_update: TrackerUpdate = field(default_factory=TrackerUpdate)
    # Entries whose content changed (e.g. completed) since the last advancing read.
    updated_ids: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)


class LiveCaptureService:
    def __init__(self, settings: Settings, client: CharlesClient) -> None:
        self.settings = settings
        self.client = client
        self.captures: dict[str, LiveCapture] = {}
        self._inflight: asyncio.Future[list[Transaction]] | None = None
        self._export_cache: tuple[float, list[Transaction]] | None = None

    # ------------------------------------------------------------------ export

    async def export_current(self, *, max_age: float = 0.0) -> list[Transaction]:
        """Export the current session.

        Concurrent callers share one in-flight export; ``max_age`` additionally
        allows reusing a recent result (callers that only need a rough view).
        """
        if (
            max_age > 0
            and self._export_cache
            and time.monotonic() - self._export_cache[0] < max_age
        ):
            return self._export_cache[1]
        if self._inflight is None or self._inflight.done():
            self._inflight = asyncio.ensure_future(self._export())
        return await asyncio.shield(self._inflight)

    async def _export(self) -> list[Transaction]:
        transactions = await self.client.export_session()
        self._export_cache = (time.monotonic(), transactions)
        return transactions

    def invalidate_export(self) -> None:
        self._export_cache = None
        self._inflight = None

    # --------------------------------------------------------------- lifecycle

    async def start(
        self,
        *,
        reset_session: bool = False,
        include_existing: bool = False,
        start_recording_if_stopped: bool = True,
    ) -> dict[str, Any]:
        warnings: list[str] = []
        managed = False
        if reset_session:
            await self.client.clear_session()
            self.invalidate_export()
        recording = await self.client.recording_status()
        if recording is not True:
            if start_recording_if_stopped:
                # Starting a stopped recording begins a new, empty Charles session.
                await self.client.start_recording()
                self.invalidate_export()
                managed = recording is False
                if recording is None:
                    warnings.append("recording_state_unknown_start_sent")
            else:
                warnings.append(
                    "charles_not_recording: nothing will be captured until recording starts"
                )

        capture_id = f"cap-{uuid.uuid4().hex[:12]}"
        tracker = SessionTracker(capture_id, max_entries=self.settings.live_max_entries)
        baseline: list[Transaction] = []
        if not reset_session:
            try:
                baseline = await self.export_current()
            except CharlesNotRecordingError:
                baseline = []
        if self.client.records_control_requests:
            warnings.append(SELF_RECORDING_WARNING)
        tracker.set_baseline(baseline, include_existing=include_existing)
        capture = LiveCapture(
            capture_id=capture_id,
            tracker=tracker,
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            managed_recording=managed,
            include_existing=include_existing,
            warnings=warnings,
        )
        self.captures[capture_id] = capture
        return {
            "capture_id": capture_id,
            "status": "active",
            "session_cleared": reset_session,
            "baseline_entries_skipped": 0
            if include_existing
            else len([t for t in baseline if not t.is_control]),
            "existing_entries_included": tracker.total if include_existing else 0,
            "recording_started_by_server": managed,
            "warnings": warnings,
        }

    def require(self, capture_id: str) -> LiveCapture:
        capture = self.captures.get(capture_id)
        if capture is None:
            active = [c.capture_id for c in self.captures.values() if c.status == "active"]
            raise NotFoundError(
                f"live capture `{capture_id}` not found",
                hint=f"active captures: {active}" if active else "call start_live_capture first",
            )
        return capture

    async def refresh(self, capture_id: str) -> LiveCapture:
        capture = self.require(capture_id)
        if capture.status != "active":
            return capture
        try:
            transactions = await self.export_current()
        except CharlesNotRecordingError:
            # Keep what was captured; an empty export must not look like a reset.
            warning = (
                "charles_not_recording: recording was stopped in Charles; captured entries are kept, "
                "start recording again to continue (Charles then opens a new session)"
            )
            if warning not in capture.warnings:
                capture.warnings.append(warning)
            return capture
        if self.client.records_control_requests and SELF_RECORDING_WARNING not in capture.warnings:
            capture.warnings.append(SELF_RECORDING_WARNING)
        update = capture.tracker.ingest(transactions)
        capture.last_update = update
        capture.updated_ids.update(update.updated_ids)
        if update.reset_detected:
            capture.warnings.append("session_reset_detected")
            capture.cursor = min(capture.cursor, capture.tracker.total)
        if update.dropped:
            capture.warnings.append(f"oldest_{update.dropped}_entries_dropped_live_max_entries")
        return capture

    async def stop(
        self, capture_id: str, *, persist: bool = True, stop_recording: bool | None = None
    ) -> dict[str, Any]:
        capture = await self.refresh(capture_id)
        should_stop = capture.managed_recording if stop_recording is None else stop_recording
        stop_error = None
        if should_stop:
            try:
                await self.client.stop_recording()
            except CharlesMCPError as exc:
                stop_error = str(exc)
        path: str | None = None
        if persist and capture.tracker.total:
            assert self.settings.recordings_dir is not None
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            target = Path(self.settings.recordings_dir) / f"live-{stamp}-{capture_id[-6:]}.chlsj"
            path = str(write_chlsj(target, capture.tracker.all_transactions()))
        capture.status = "stopped"
        return {
            "capture_id": capture_id,
            "status": "stopped",
            "total_entries": capture.tracker.total - capture.tracker.offset,
            "recording_path": path,
            "recording_stopped": bool(should_stop and stop_error is None),
            "stop_recording_error": stop_error,
            "next": "Use recording_path with analyze_recorded_traffic or reverse_import_session."
            if path
            else None,
        }

    def forget(self, capture_id: str) -> None:
        self.captures.pop(capture_id, None)

    def active_captures(self) -> list[dict[str, Any]]:
        return [
            {
                "capture_id": c.capture_id,
                "started_at": c.started_at,
                "entries": c.tracker.total,
                "cursor": c.cursor,
            }
            for c in self.captures.values()
            if c.status == "active"
        ]
