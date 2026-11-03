"""Query, group, stats and detail across the live and history planes."""

from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from charles5_mcp.errors import CharlesMCPError, NotFoundError
from charles5_mcp.reverse.store import ReverseStore
from charles5_mcp.session.classify import Classification, classify
from charles5_mcp.session.model import Transaction
from charles5_mcp.traffic import views
from charles5_mcp.traffic.extract import extract_bodies, full_record
from charles5_mcp.traffic.history import RecordingStore
from charles5_mcp.traffic.live import LiveCaptureService
from charles5_mcp.traffic.query import TrafficQuery, match

GROUP_KEYS = (
    "host",
    "path",
    "status",
    "class",
    "method",
    "host_path",
    "host_status",
    "content_type",
)
SORT_ORDERS = ("priority", "time", "time_desc")


@dataclass
class PlaneEntries:
    source: str
    ref: str
    entries: list[tuple[str, Transaction]]
    next_cursor: int | None = None
    total: int = 0
    warnings: list[str] | None = None


def _group_value(key: str, txn: Transaction, cls: Classification) -> str:
    if key == "host":
        return txn.host
    if key == "path":
        return txn.path
    if key == "status":
        return str(txn.response_status) if txn.response_status is not None else "none"
    if key == "class":
        return cls.resource_class
    if key == "method":
        return txn.method
    if key == "host_path":
        return f"{txn.host}{txn.path}"
    if key == "host_status":
        return f"{txn.host} {txn.response_status}"
    if key == "content_type":
        return (txn.response.content_type or "none").split(";")[0]
    raise CharlesMCPError(f"unknown group_by `{key}`", hint=f"one of {', '.join(GROUP_KEYS)}")


class TrafficService:
    def __init__(
        self, live: LiveCaptureService, history: RecordingStore, store: ReverseStore | None = None
    ) -> None:
        self.live = live
        self.history = history
        self.store = store

    # ------------------------------------------------------------- resolution

    async def plane(
        self,
        source: str,
        *,
        capture_id: str | None = None,
        recording_path: str | None = None,
        cursor: int | None = None,
    ) -> PlaneEntries:
        if source == "live":
            if not capture_id:
                raise CharlesMCPError(
                    "capture_id is required for source='live'", hint="call start_live_capture"
                )
            capture = await self.live.refresh(capture_id)
            start = cursor if cursor is not None else 0
            tracked = capture.tracker.slice(start)
            warnings = list(dict.fromkeys(capture.warnings))
            return PlaneEntries(
                "live",
                capture_id,
                [(t.entry_id, t.txn) for t in tracked],
                next_cursor=capture.tracker.total,
                total=len(tracked),
                warnings=warnings,
            )
        if source == "history":
            loaded = self.history.load(recording_path)
            return PlaneEntries(
                "history",
                str(loaded.path),
                list(zip(loaded.ids, loaded.transactions, strict=True)),
                total=len(loaded.transactions),
                warnings=[],
            )
        if source == "reverse":
            if not capture_id or self.store is None:
                raise CharlesMCPError("capture_id (rcap-...) is required for source='reverse'")
            self.store.capture(capture_id)
            rows = list(self.store.iter_entries(capture_id))
            return PlaneEntries("reverse", capture_id, rows, total=len(rows), warnings=[])
        raise CharlesMCPError("source must be 'live', 'history' or 'reverse'")

    # ------------------------------------------------------------------ query

    async def query(
        self,
        *,
        source: str,
        query: TrafficQuery,
        capture_id: str | None = None,
        recording_path: str | None = None,
        cursor: int | None = None,
        max_items: int = 10,
        include_preview: bool = True,
        preview_chars: int = 160,
        max_headers: int = 4,
        scan_limit: int = 2000,
        sort: str = "priority",
    ) -> dict[str, Any]:
        if sort not in SORT_ORDERS:
            raise CharlesMCPError(f"unknown sort `{sort}`", hint=f"one of {', '.join(SORT_ORDERS)}")
        plane = await self.plane(
            source, capture_id=capture_id, recording_path=recording_path, cursor=cursor
        )
        entries = plane.entries
        warnings = list(plane.warnings or [])
        if len(entries) > scan_limit:
            # Scan the most recent entries; older ones are reachable with a cursor.
            entries = entries[-scan_limit:]
            warnings.append(f"scan_limit_reached: scanned newest {scan_limit} of {plane.total}")

        now_ms = int(time.time() * 1000)
        filtered_out: Counter[str] = Counter()
        matched: list[tuple[str, Transaction, Classification, list[str]]] = []
        for entry_id, txn in entries:
            cls = classify(txn)
            if query.excluded_by_preset(cls.resource_class):
                filtered_out[cls.resource_class] += 1
                continue
            reasons = match(txn, cls, query, now_ms=now_ms)
            if reasons is not None:
                matched.append((entry_id, txn, cls, reasons))

        if sort == "priority":
            matched.sort(
                key=lambda m: (m[2].priority, m[1].has_error, m[1].start_ms or 0), reverse=True
            )
        elif sort == "time_desc":
            matched.sort(key=lambda m: m[1].start_ms or 0, reverse=True)
        else:
            matched.sort(key=lambda m: m[1].start_ms or 0)

        max_items = max(1, min(max_items, 200))
        items = [
            views.summarize(
                txn,
                cls,
                entry_id,
                reasons=reasons,
                include_preview=include_preview,
                preview_chars=preview_chars,
                max_headers=max_headers,
            )
            for entry_id, txn, cls, reasons in matched[:max_items]
        ]
        return views.fit_budget(
            views.compact(
                {
                    "source": plane.source,
                    "capture_id": plane.ref if plane.source == "live" else None,
                    "recording_path": plane.ref if plane.source == "history" else None,
                    "scanned": len(entries),
                    "matched": len(matched),
                    "returned": len(items),
                    "truncated": len(matched) > len(items) or None,
                    "filtered_out_by_preset": dict(filtered_out),
                    "next_cursor": plane.next_cursor,
                    "items": items,
                    "warnings": warnings,
                }
            )
        )

    async def group(
        self,
        *,
        source: str,
        group_by: str,
        query: TrafficQuery,
        capture_id: str | None = None,
        recording_path: str | None = None,
        max_groups: int = 15,
    ) -> dict[str, Any]:
        if group_by not in GROUP_KEYS:
            raise CharlesMCPError(
                f"unknown group_by `{group_by}`", hint=f"one of {', '.join(GROUP_KEYS)}"
            )
        plane = await self.plane(source, capture_id=capture_id, recording_path=recording_path)
        groups: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "count": 0,
                "errors": 0,
                "bytes": 0,
                "statuses": Counter(),
                "paths": [],
                "entry_ids": [],
            }
        )
        now_ms = int(time.time() * 1000)
        matched = 0
        for entry_id, txn in plane.entries:
            cls = classify(txn)
            if (
                query.excluded_by_preset(cls.resource_class)
                or match(txn, cls, query, now_ms=now_ms) is None
            ):
                continue
            matched += 1
            bucket = groups[_group_value(group_by, txn, cls)]
            bucket["count"] += 1
            bucket["errors"] += int(txn.has_error)
            bucket["bytes"] += txn.total_size or 0
            bucket["statuses"][str(txn.response_status)] += 1
            if txn.path not in bucket["paths"] and len(bucket["paths"]) < 3:
                bucket["paths"].append(txn.path)
            if len(bucket["entry_ids"]) < 3:
                bucket["entry_ids"].append(entry_id)
        ordered = sorted(
            groups.items(), key=lambda item: (item[1]["count"], item[1]["errors"]), reverse=True
        )
        return views.compact(
            {
                "source": plane.source,
                "group_by": group_by,
                "matched": matched,
                "group_count": len(groups),
                "groups": [
                    {
                        "value": value,
                        "count": data["count"],
                        "errors": data["errors"],
                        "bytes": data["bytes"],
                        "statuses": dict(data["statuses"].most_common(5)),
                        "sample_paths": data["paths"]
                        if group_by not in ("path", "host_path")
                        else None,
                        "sample_entry_ids": data["entry_ids"],
                    }
                    for value, data in ordered[: max(1, min(max_groups, 100))]
                ],
                "truncated": len(groups) > max(1, min(max_groups, 100)) or None,
                "warnings": plane.warnings,
            }
        )

    async def stats(
        self, *, source: str, capture_id: str | None = None, recording_path: str | None = None
    ) -> dict[str, Any]:
        plane = await self.plane(source, capture_id=capture_id, recording_path=recording_path)
        classes: Counter[str] = Counter()
        statuses: Counter[str] = Counter()
        hosts: Counter[str] = Counter()
        errors = 0
        total_bytes = 0
        starts: list[int] = []
        for _, txn in plane.entries:
            cls = classify(txn)
            classes[cls.resource_class] += 1
            if txn.response_status is not None:
                statuses[f"{txn.response_status // 100}xx"] += 1
            if not txn.is_control:
                hosts[txn.host] += 1
            errors += int(txn.has_error)
            total_bytes += txn.total_size or 0
            if txn.start_ms is not None:
                starts.append(txn.start_ms)
        return views.compact(
            {
                "source": plane.source,
                "entries": len(plane.entries),
                "errors": errors,
                "total_bytes": total_bytes,
                "classes": dict(classes.most_common()),
                "status_families": dict(sorted(statuses.items())),
                "top_hosts": dict(hosts.most_common(10)),
                "time_range": [views.iso_from_ms(min(starts)), views.iso_from_ms(max(starts))]
                if starts
                else None,
                "warnings": plane.warnings,
            }
        )

    # ----------------------------------------------------------------- detail

    async def find(
        self,
        entry_id: str,
        *,
        source: str | None = None,
        capture_id: str | None = None,
        recording_path: str | None = None,
    ) -> tuple[str, Transaction]:
        if source in (None, "live"):
            candidates = (
                [self.live.require(capture_id)] if capture_id else list(self.live.captures.values())
            )
            for capture in candidates:
                tracked = capture.tracker.get(entry_id)
                stale = tracked is None or not tracked.txn.is_complete
                if stale and capture.status == "active" and (capture_id or tracked is not None):
                    # Unknown or still in flight: re-export so the latest state is shown.
                    await self.live.refresh(capture.capture_id)
                    tracked = capture.tracker.get(entry_id)
                if tracked is not None:
                    return "live", tracked.txn
        if source in (None, "history"):
            if recording_path:
                loaded = self.history.load(recording_path)
                position = loaded.index.get(entry_id)
                if position is not None:
                    return "history", loaded.transactions[position]
            else:
                found = self.history.find_entry(entry_id)
                if found:
                    loaded, position = found
                    return "history", loaded.transactions[position]
        if source in (None, "reverse") and self.store is not None and entry_id.startswith("r"):
            try:
                _, txn = self.store.get_entry(entry_id)
                return "reverse", txn
            except NotFoundError:
                pass
        raise NotFoundError(
            f"entry `{entry_id}` not found",
            hint="Pass the capture_id or recording_path the entry came from.",
        )

    async def detail(
        self,
        entry_id: str,
        *,
        source: str | None = None,
        capture_id: str | None = None,
        recording_path: str | None = None,
        include_full_body: bool = False,
        max_body_chars: int = 4096,
    ) -> dict[str, Any]:
        plane, txn = await self.find(
            entry_id, source=source, capture_id=capture_id, recording_path=recording_path
        )
        result = views.detail(
            txn,
            classify(txn),
            entry_id,
            include_body=include_full_body,
            max_body_chars=max_body_chars,
        )
        result["source"] = plane
        return result

    # --------------------------------------------------------- live read/peek

    async def read_live(
        self, capture_id: str, *, cursor: int | None, limit: int, advance: bool
    ) -> dict[str, Any]:
        capture = await self.live.refresh(capture_id)
        requested = capture.cursor if cursor is None else max(cursor, 0)
        # Entries before tracker.offset were trimmed (live_max_entries).
        start = max(requested, capture.tracker.offset)
        limit = max(1, min(limit, 200))
        tracked = capture.tracker.slice(start, limit)
        next_cursor = start + len(tracked)
        if advance:
            capture.cursor = next_cursor
        pending = capture.tracker.total - next_cursor
        items = [
            views.summarize(
                t.txn, classify(t.txn), t.entry_id, include_preview=False, max_headers=0
            )
            for t in tracked
        ]
        # Entries already returned earlier that have since completed or changed.
        changed_before = [
            entry_id
            for entry_id in capture.updated_ids
            if (tracked_entry := capture.tracker.get(entry_id)) is not None
            and tracked_entry.position < start
        ]
        warnings = list(dict.fromkeys(capture.warnings))
        if advance:
            capture.warnings.clear()
            capture.updated_ids.clear()
        result = views.compact(
            {
                "capture_id": capture_id,
                "status": capture.status,
                "cursor": start,
                "next_cursor": next_cursor,
                "returned": len(items),
                "remaining": pending if pending > 0 else None,
                "updated_entry_ids": changed_before[:50] or None,
                "items": items,
                "warnings": warnings,
            }
        )
        trimmed = views.fit_budget(result)
        if advance and "budget_trimmed" in trimmed:
            # Only consume what was actually returned.
            capture.cursor = start + len(trimmed["items"])
            trimmed["next_cursor"] = capture.cursor
        return trimmed

    # ------------------------------------------------------- bulk full records

    async def entries(
        self,
        *,
        source: str,
        query: TrafficQuery,
        entry_ids: list[str] | None = None,
        capture_id: str | None = None,
        recording_path: str | None = None,
        include_headers: bool = True,
        max_body_chars: int = 2000,
        max_entries: int = 20,
        offset: int = 0,
        save_to_file: bool = False,
        file_body_chars: int = 1_000_000,
        output_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Full records (URL, headers, bodies) for chosen entries, or every match of ``query``."""
        plane = await self.plane(source, capture_id=capture_id, recording_path=recording_path)
        if entry_ids:
            wanted = {entry_id: n for n, entry_id in enumerate(entry_ids)}
            selected = sorted(
                ((i, t) for i, t in plane.entries if i in wanted), key=lambda item: wanted[item[0]]
            )
            missing = [i for i in entry_ids if i not in {sel[0] for sel in selected}]
        else:
            now_ms = int(time.time() * 1000)
            selected = []
            for entry_id, txn in plane.entries:
                cls = classify(txn)
                if query.excluded_by_preset(cls.resource_class):
                    continue
                if match(txn, cls, query, now_ms=now_ms) is not None:
                    selected.append((entry_id, txn))
            missing = []

        result: dict[str, Any] = {
            "source": plane.source,
            "matched": len(selected),
            "missing_entry_ids": missing or None,
        }
        if save_to_file:
            assert output_dir is not None
            output_dir.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            path = output_dir / f"entries-{plane.source}-{stamp}.jsonl"
            serial = 1
            while path.exists():
                serial += 1
                path = output_dir / f"entries-{plane.source}-{stamp}-{serial}.jsonl"
            with path.open("w", encoding="utf-8") as handle:
                for entry_id, txn in selected:
                    record = full_record(
                        txn, entry_id, include_headers=True, max_body_chars=file_body_chars
                    )
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            result["file"] = str(path)
            result["file_format"] = (
                "JSON Lines: one full record (url, query_params, request/response headers and decoded bodies) per line"
            )
            result["note"] = (
                "Binary bodies (images, uploads) are described, not embedded; use extract_entry_bodies to save them."
            )
            preview = selected[:3]
            result["preview"] = [
                full_record(t, i, include_headers=False, max_body_chars=200) for i, t in preview
            ]
            return views.compact(result)

        offset = max(offset, 0)
        page = selected[offset : offset + max(1, min(max_entries, 100))]
        result["offset"] = offset
        result["items"] = [
            full_record(
                txn, entry_id, include_headers=include_headers, max_body_chars=max_body_chars
            )
            for entry_id, txn in page
        ]
        trimmed = views.fit_budget(views.compact(result))
        returned = len(trimmed.get("items", []))
        if page and returned == 0:
            # One entry alone is over the budget (huge headers/bodies): return it with
            # short bodies so paging always moves forward.
            entry_id, txn = page[0]
            trimmed["items"] = [
                full_record(txn, entry_id, include_headers=include_headers, max_body_chars=500)
            ]
            trimmed["oversized_entry"] = (
                "This entry is too large to show in full; use save_to_file or extract_entry_bodies."
            )
            returned = 1
        if offset + returned < len(selected):
            trimmed["next_offset"] = offset + returned
        return trimmed

    async def extract(
        self,
        entry_id: str,
        *,
        output_dir: Path,
        source: str | None = None,
        capture_id: str | None = None,
        recording_path: str | None = None,
    ) -> dict[str, Any]:
        plane, txn = await self.find(
            entry_id, source=source, capture_id=capture_id, recording_path=recording_path
        )
        target = output_dir / entry_id
        files = extract_bodies(txn, entry_id, target)
        return views.compact(
            {
                "entry_id": entry_id,
                "source": plane,
                "url": txn.url(),
                "directory": str(target),
                "files": files,
                "note": "Bodies are saved decoded (gzip/br/zstd removed); multipart uploads are split into their parts. "
                "entry.json holds the full request/response record.",
            }
        )
