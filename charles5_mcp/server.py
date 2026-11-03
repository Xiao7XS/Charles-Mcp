"""MCP server assembly: services plus tool registration."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import Field

from charles5_mcp import TARGET_CHARLES_VERSION, __version__
from charles5_mcp.charles.client import CharlesClient
from charles5_mcp.compat import create_server, register_tool
from charles5_mcp.config import Settings
from charles5_mcp.control import ControlService
from charles5_mcp.reverse.service import ReverseService
from charles5_mcp.reverse.store import ReverseStore
from charles5_mcp.traffic import views
from charles5_mcp.traffic.history import RecordingStore
from charles5_mcp.traffic.live import LiveCaptureService
from charles5_mcp.traffic.query import TrafficQuery
from charles5_mcp.traffic.service import TrafficService

logger = logging.getLogger(__name__)

INSTRUCTIONS = f"""Charles Proxy {TARGET_CHARLES_VERSION} MCP server.

Planes (never mix their ids):
- live: start_live_capture -> capture_id -> query_live_capture_entries / read_live_capture.
- history: saved files (.chlsj .chlz .chls .xml .har) -> recording_path.
- reverse: reverse_import_session or reverse_start_live_analysis -> reverse capture_id / entry ids,
  then detail, decode, replay, signature discovery and mutation plans.

Rules:
- Default to the live plane for "what is happening now"; use history only for named saved files.
- Summaries first (query/group/stats), then detail for one entry_id. Keep include_full_body=false unless needed.
- read_* advances a cursor; peek_* does not.
- Never pass reset_session=true unless the user explicitly asks to clear Charles' session.
- Replays send real requests to the target server; only replay traffic the user is authorised to test.
"""

SourceParam = Annotated[
    Literal["live", "history"],
    Field(description="'live' (needs capture_id) or 'history' (recording_path, default latest)"),
]
PresetParam = Annotated[
    Literal["api_focus", "errors_only", "all_http", "page_bootstrap"],
    Field(
        description="api_focus hides static/noise; errors_only = HTTP>=400 or failed; all_http = everything; page_bootstrap = documents, scripts, styles and APIs"
    ),
]
CharlesToolName = Literal[
    "allow-list",
    "auto-save",
    "block-cookies",
    "block-list",
    "breakpoints",
    "client-process",
    "dns-spoofing",
    "map-local",
    "map-remote",
    "no-caching",
    "rewrite",
]
ExportFormat = Literal["chlsj", "xml", "har", "csv", "trace", "chlz"]
ConvertFormat = Literal["chlz", "chls", "chlsx", "chlsj", "har", "trace", "xml", "csv"]
GroupKey = Literal[
    "host", "path", "status", "class", "method", "host_path", "host_status", "content_type"
]
OptStr = str | None
OptInt = int | None


@dataclass
class App:
    settings: Settings
    client: CharlesClient
    control: ControlService
    live: LiveCaptureService
    history: RecordingStore
    traffic: TrafficService
    store: ReverseStore
    reverse: ReverseService

    async def close(self) -> None:
        await self.client.close()
        self.store.close()


def build_app(settings: Settings | None = None, *, client: CharlesClient | None = None) -> App:
    settings = settings or Settings.from_env()
    settings.ensure_dirs()
    client = client or CharlesClient(settings)
    live = LiveCaptureService(settings, client)
    history = RecordingStore(settings)
    store = ReverseStore(settings.reverse_db_path)
    return App(
        settings=settings,
        client=client,
        control=ControlService(settings, client),
        live=live,
        history=history,
        traffic=TrafficService(live, history, store),
        store=store,
        reverse=ReverseService(settings, store, live),
    )


def _query(
    preset: str = "api_focus",
    host_contains: OptStr = None,
    path_contains: OptStr = None,
    method_in: list[str] | None = None,
    status_in: list[int] | None = None,
    resource_class_in: list[str] | None = None,
    min_priority_score: OptInt = None,
    request_header_name: OptStr = None,
    request_header_value_contains: OptStr = None,
    response_header_name: OptStr = None,
    response_header_value_contains: OptStr = None,
    request_content_type: OptStr = None,
    response_content_type: OptStr = None,
    request_body_contains: OptStr = None,
    response_body_contains: OptStr = None,
    request_json_query: OptStr = None,
    response_json_query: OptStr = None,
    keyword_regex: OptStr = None,
    since_seconds: OptInt = None,
) -> TrafficQuery:
    return TrafficQuery(
        preset=preset,
        host_contains=host_contains or None,
        path_contains=path_contains or None,
        method_in=method_in or [],
        status_in=status_in or [],
        resource_class_in=resource_class_in or [],
        min_priority_score=min_priority_score,
        request_header_name=request_header_name or None,
        request_header_value_contains=request_header_value_contains or None,
        response_header_name=response_header_name or None,
        response_header_value_contains=response_header_value_contains or None,
        request_content_type=request_content_type or None,
        response_content_type=response_content_type or None,
        request_body_contains=request_body_contains or None,
        response_body_contains=response_body_contains or None,
        request_json_query=request_json_query or None,
        response_json_query=response_json_query or None,
        keyword_regex=keyword_regex or None,
        since_seconds=since_seconds,
    )


def create_mcp_server(settings: Settings | None = None, *, app: App | None = None) -> Any:
    app = app or build_app(settings)

    @asynccontextmanager
    async def lifespan(_server: Any) -> AsyncIterator[App]:
        if app.settings.manage_lifecycle:
            logger.info("config backup: %s", app.control.backup_config())
        for warning in app.settings.warnings():
            logger.warning(warning)
        try:
            yield app
        finally:
            await app.close()

    mcp = create_server(
        "charles5-mcp",
        instructions=INSTRUCTIONS,
        version=__version__,
        lifespan=lifespan,
    )
    mcp._charles_app = app  # exposed for tests and embedding
    _register_control_tools(mcp, app)
    _register_live_tools(mcp, app)
    _register_history_tools(mcp, app)
    _register_reverse_tools(mcp, app)
    return mcp


# =============================================================== control tools


def _register_control_tools(mcp: Any, app: App) -> None:
    async def charles_status() -> dict[str, Any]:
        """Check Charles connectivity, version and recording state, and list active captures.
        Call first when unsure what to do; follow `recommended_next_action`."""
        result = await app.control.status()
        result["live_captures"] = app.live.active_captures()
        result["reverse_live_sessions"] = [
            {"live_session_id": s.live_session_id, "capture_id": s.capture_id}
            for s in app.reverse.sessions.values()
        ]
        if not result.get("connected"):
            result["recommended_next_action"] = "Fix Charles connectivity (see hint), then retry."
        elif result["live_captures"]:
            capture_id = result["live_captures"][0]["capture_id"]
            result["recommended_next_action"] = (
                f"query_live_capture_entries(capture_id='{capture_id}') for current traffic."
            )
        else:
            result["recommended_next_action"] = (
                "start_live_capture for live traffic, or list_recordings for saved sessions."
            )
        return views.compact(result)

    async def throttling(
        preset: Annotated[
            str,
            Field(
                description="A preset from get_charles_controls (e.g. '3G', '4G', '56 kbps Modem', "
                "a custom preset name) or a short alias 3g/4g/56k/256k/512k/2m/8m/16m/32m/fibre; "
                "'off' turns throttling off"
            ),
        ],
    ) -> dict[str, Any]:
        """Turn Charles network throttling on with a preset, or off. Unknown presets are rejected
        (Charles itself would silently accept them)."""
        return await app.control.throttling(preset)

    async def get_charles_controls() -> dict[str, Any]:
        """Throttling state with the available presets, and the on/off state of every Charles tool
        (Breakpoints, Map Remote, Map Local, Rewrite, Block/Allow List, DNS Spoofing, ...)."""
        return await app.control.controls()

    async def set_charles_tool(
        tool: Annotated[CharlesToolName, Field(description="Charles tool to switch")],
        enabled: bool,
    ) -> dict[str, Any]:
        """Enable or disable a Charles tool and report its resulting state. Rules themselves
        (what Map Remote maps, what Rewrite changes) are edited in Charles."""
        return await app.control.set_tool(tool, enabled)

    async def export_charles_session(
        format: Annotated[
            ExportFormat,
            Field(
                description="chlsj (Charles JSON), xml, har, csv (summary only), trace, chlz (native)"
            ),
        ] = "chlsj",
        name: Annotated[OptStr, Field(description="File name without extension")] = None,
    ) -> dict[str, Any]:
        """Save the session Charles is currently recording into the recordings folder (Charles can
        only export while recording). Does not clear the session."""
        return await app.control.export_session(format, name)

    def convert_session_file(
        path: Annotated[
            str, Field(description="Input file (.chlz .chls .chlsj .xml .har .trace .saz .pcap)")
        ],
        output_format: Annotated[ConvertFormat, Field(description="Output format")] = "chlz",
        name: Annotated[OptStr, Field(description="Output file name without extension")] = None,
        include_hosts: Annotated[
            list[str] | None, Field(description="Host globs to keep, e.g. *.example.com")
        ] = None,
        exclude_hosts: list[str] | None = None,
        include_mime: Annotated[
            list[str] | None, Field(description="MIME globs to keep, e.g. application/json")
        ] = None,
        exclude_mime: Annotated[
            list[str] | None, Field(description="MIME globs to drop, e.g. image/*")
        ] = None,
        include_methods: list[str] | None = None,
        exclude_methods: list[str] | None = None,
        max_response_size: Annotated[
            OptStr, Field(description="Drop larger responses, e.g. 1m or 500k")
        ] = None,
    ) -> dict[str, Any]:
        """Convert and/or filter a session file with Charles' own `charles convert` (Charles 5.2 CLI).
        Writes a new file into the recordings folder; the input is never modified."""
        return app.control.convert_file(
            path,
            output_format,
            name=name,
            include_hosts=include_hosts,
            exclude_hosts=exclude_hosts,
            include_mime=include_mime,
            exclude_mime=exclude_mime,
            include_methods=include_methods,
            exclude_methods=exclude_methods,
            max_response_size=max_response_size,
        )

    async def reset_environment(
        confirm: Annotated[
            bool,
            Field(description="Must be true; restores the Charles config backed up at startup"),
        ],
        quit_charles: bool = True,
    ) -> dict[str, Any]:
        """Restore the Charles configuration backed up at startup (CHARLES_MANAGE_LIFECYCLE=true).
        Turns throttling off and optionally quits Charles first. Never deletes recordings."""
        if not confirm:
            return {"restored": False, "reason": "confirm must be true"}
        return await app.control.reset_environment(quit_charles=quit_charles)

    register_tool(mcp, charles_status, read_only=True)
    register_tool(mcp, throttling, idempotent=True)
    register_tool(mcp, get_charles_controls, read_only=True)
    register_tool(mcp, set_charles_tool, idempotent=True)
    register_tool(mcp, export_charles_session)
    register_tool(mcp, convert_session_file)
    register_tool(mcp, reset_environment, destructive=True)


# ================================================================== live tools


def _register_live_tools(mcp: Any, app: App) -> None:
    async def start_live_capture(
        reset_session: Annotated[
            bool,
            Field(
                description="DESTRUCTIVE: clear Charles' session first. Only when the user asks."
            ),
        ] = False,
        include_existing: Annotated[
            bool, Field(description="Also include traffic already in the session")
        ] = False,
        start_recording_if_stopped: bool = True,
    ) -> dict[str, Any]:
        """Start a live capture over Charles' current session and return its capture_id.
        Default keeps existing traffic untouched and only tracks what arrives from now on."""
        return await app.live.start(
            reset_session=reset_session,
            include_existing=include_existing,
            start_recording_if_stopped=start_recording_if_stopped,
        )

    async def read_live_capture(
        capture_id: str,
        cursor: Annotated[
            OptInt, Field(description="Start position; default is the capture's own cursor")
        ] = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Return new entries since the cursor as compact summaries and ADVANCE the cursor."""
        return await app.traffic.read_live(capture_id, cursor=cursor, limit=limit, advance=True)

    async def peek_live_capture(
        capture_id: str, cursor: OptInt = None, limit: int = 50
    ) -> dict[str, Any]:
        """Like read_live_capture but does NOT advance the cursor."""
        return await app.traffic.read_live(capture_id, cursor=cursor, limit=limit, advance=False)

    async def stop_live_capture(
        capture_id: str,
        persist: Annotated[
            bool, Field(description="Save captured entries as a .chlsj recording")
        ] = True,
        stop_recording: Annotated[
            bool | None, Field(description="Default: stop only if this server started recording")
        ] = None,
    ) -> dict[str, Any]:
        """Stop a live capture, optionally saving it as a recording."""
        result = await app.live.stop(capture_id, persist=persist, stop_recording=stop_recording)
        return views.compact(result)

    async def query_live_capture_entries(
        capture_id: str,
        preset: PresetParam = "api_focus",
        host_contains: OptStr = None,
        path_contains: Annotated[OptStr, Field(description="Substring of path+query")] = None,
        method_in: list[str] | None = None,
        status_in: list[int] | None = None,
        resource_class_in: Annotated[
            list[str] | None,
            Field(
                description="api, document, script, stylesheet, image, font, media, websocket, grpc, interim, tunnel, other"
            ),
        ] = None,
        min_priority_score: OptInt = None,
        request_header_name: OptStr = None,
        request_header_value_contains: OptStr = None,
        response_header_name: OptStr = None,
        response_header_value_contains: OptStr = None,
        request_content_type: OptStr = None,
        response_content_type: OptStr = None,
        request_body_contains: OptStr = None,
        response_body_contains: OptStr = None,
        request_json_query: Annotated[
            OptStr, Field(description="JMESPath over the JSON request body; truthy = match")
        ] = None,
        response_json_query: Annotated[
            OptStr, Field(description="JMESPath over the JSON response body, e.g. code != `0`")
        ] = None,
        keyword_regex: Annotated[
            OptStr, Field(description="Case-insensitive regex over URL, headers and bodies")
        ] = None,
        since_seconds: Annotated[
            OptInt, Field(description="Only entries started in the last N seconds")
        ] = None,
        cursor: Annotated[
            OptInt, Field(description="Only entries at or after this position (default all)")
        ] = None,
        sort: Literal["priority", "time", "time_desc"] = "priority",
        include_body_preview: bool = True,
        max_items: int = 10,
        preview_chars: int = 160,
        max_headers: int = 4,
        scan_limit: int = 2000,
    ) -> dict[str, Any]:
        """Filter and rank live traffic (summary view). Does not advance the cursor.
        Drill into one result with get_traffic_entry_detail."""
        query = _query(
            preset,
            host_contains,
            path_contains,
            method_in,
            status_in,
            resource_class_in,
            min_priority_score,
            request_header_name,
            request_header_value_contains,
            response_header_name,
            response_header_value_contains,
            request_content_type,
            response_content_type,
            request_body_contains,
            response_body_contains,
            request_json_query,
            response_json_query,
            keyword_regex,
            since_seconds,
        )
        return await app.traffic.query(
            source="live",
            capture_id=capture_id,
            query=query,
            cursor=cursor,
            max_items=max_items,
            include_preview=include_body_preview,
            preview_chars=preview_chars,
            max_headers=max_headers,
            scan_limit=scan_limit,
            sort=sort,
        )

    register_tool(mcp, start_live_capture)
    register_tool(mcp, read_live_capture)
    register_tool(mcp, peek_live_capture, read_only=True)
    register_tool(mcp, stop_live_capture)
    register_tool(mcp, query_live_capture_entries, read_only=True)


# =============================================================== history tools


def _register_history_tools(mcp: Any, app: App) -> None:
    def list_recordings(limit: int = 30) -> dict[str, Any]:
        """List saved session files (.chlsj .chlz .chls .xml .har), newest first."""
        recordings = app.history.list(limit=max(1, min(limit, 200)))
        return {
            "directories": [str(d) for d in app.history.directories()],
            "recordings": recordings,
            "hint": None
            if recordings
            else "Use export_charles_session or stop_live_capture(persist=true).",
        }

    async def get_recording_snapshot(
        recording_path: Annotated[OptStr, Field(description="Default: newest recording")] = None,
        sample: int = 20,
    ) -> dict[str, Any]:
        """Overview of one recording: stats plus the first `sample` entries in time order."""
        stats = await app.traffic.stats(source="history", recording_path=recording_path)
        listing = await app.traffic.query(
            source="history",
            recording_path=recording_path,
            query=TrafficQuery(preset="all_http"),
            max_items=sample,
            include_preview=False,
            max_headers=0,
            sort="time",
        )
        return {
            "stats": stats,
            "entries": listing.get("items", []),
            "recording_path": listing.get("recording_path"),
        }

    async def query_recorded_traffic(
        recording_path: OptStr = None,
        host_contains: OptStr = None,
        http_method: OptStr = None,
        keyword_regex: OptStr = None,
        max_items: int = 20,
    ) -> dict[str, Any]:
        """Quick filter over a recording by host, method and a regex over URL/headers/bodies."""
        query = TrafficQuery(
            preset="all_http",
            host_contains=host_contains or None,
            method_in=[http_method] if http_method else [],
            keyword_regex=keyword_regex or None,
        )
        return await app.traffic.query(
            source="history",
            recording_path=recording_path,
            query=query,
            max_items=max_items,
            sort="time",
        )

    async def analyze_recorded_traffic(
        recording_path: Annotated[OptStr, Field(description="Default: newest recording")] = None,
        preset: PresetParam = "api_focus",
        host_contains: OptStr = None,
        path_contains: OptStr = None,
        method_in: list[str] | None = None,
        status_in: list[int] | None = None,
        resource_class_in: list[str] | None = None,
        min_priority_score: OptInt = None,
        request_header_name: OptStr = None,
        request_header_value_contains: OptStr = None,
        response_header_name: OptStr = None,
        response_header_value_contains: OptStr = None,
        request_content_type: OptStr = None,
        response_content_type: OptStr = None,
        request_body_contains: OptStr = None,
        response_body_contains: OptStr = None,
        request_json_query: OptStr = None,
        response_json_query: OptStr = None,
        keyword_regex: OptStr = None,
        sort: Literal["priority", "time", "time_desc"] = "priority",
        include_body_preview: bool = True,
        max_items: int = 10,
        preview_chars: int = 160,
        max_headers: int = 4,
        scan_limit: int = 5000,
    ) -> dict[str, Any]:
        """Filter and rank entries in a saved recording (summary view)."""
        query = _query(
            preset,
            host_contains,
            path_contains,
            method_in,
            status_in,
            resource_class_in,
            min_priority_score,
            request_header_name,
            request_header_value_contains,
            response_header_name,
            response_header_value_contains,
            request_content_type,
            response_content_type,
            request_body_contains,
            response_body_contains,
            request_json_query,
            response_json_query,
            keyword_regex,
            None,
        )
        return await app.traffic.query(
            source="history",
            recording_path=recording_path,
            query=query,
            max_items=max_items,
            include_preview=include_body_preview,
            preview_chars=preview_chars,
            max_headers=max_headers,
            scan_limit=scan_limit,
            sort=sort,
        )

    async def group_capture_analysis(
        source: SourceParam,
        group_by: Annotated[GroupKey, Field(description="Dimension to aggregate by")],
        capture_id: OptStr = None,
        recording_path: OptStr = None,
        preset: PresetParam = "api_focus",
        host_contains: OptStr = None,
        path_contains: OptStr = None,
        method_in: list[str] | None = None,
        status_in: list[int] | None = None,
        since_seconds: OptInt = None,
        max_groups: int = 15,
    ) -> dict[str, Any]:
        """Aggregate traffic into hot spots (counts, errors, bytes) – the cheapest overview."""
        query = _query(
            preset, host_contains, path_contains, method_in, status_in, since_seconds=since_seconds
        )
        return await app.traffic.group(
            source=source,
            group_by=group_by,
            query=query,
            capture_id=capture_id,
            recording_path=recording_path,
            max_groups=max_groups,
        )

    async def get_capture_analysis_stats(
        source: SourceParam, capture_id: OptStr = None, recording_path: OptStr = None
    ) -> dict[str, Any]:
        """Class counts, status families, top hosts and time range for a capture or recording."""
        return await app.traffic.stats(
            source=source, capture_id=capture_id, recording_path=recording_path
        )

    async def get_traffic_entry_detail(
        entry_id: str,
        source: Annotated[
            Literal["live", "history"] | None, Field(description="Optional; inferred when omitted")
        ] = None,
        capture_id: OptStr = None,
        recording_path: OptStr = None,
        include_full_body: Annotated[
            bool,
            Field(description="Return bodies up to max_body_chars instead of 512-char previews"),
        ] = False,
        max_body_chars: int = 4096,
    ) -> dict[str, Any]:
        """Full headers, timing, TLS, trailers, 1xx responses and decoded bodies for ONE entry."""
        return await app.traffic.detail(
            entry_id,
            source=source,
            capture_id=capture_id,
            recording_path=recording_path,
            include_full_body=include_full_body,
            max_body_chars=max(256, min(max_body_chars, app.settings.max_detail_body_chars)),
        )

    async def get_traffic_entries(
        source: Annotated[
            Literal["live", "history", "reverse"],
            Field(
                description="live (capture_id), history (recording_path, default newest) or reverse (rcap- capture_id)"
            ),
        ],
        capture_id: OptStr = None,
        recording_path: OptStr = None,
        entry_ids: Annotated[
            list[str] | None,
            Field(description="Specific entries; omit to take every entry matching the filters"),
        ] = None,
        preset: PresetParam = "all_http",
        host_contains: OptStr = None,
        path_contains: OptStr = None,
        method_in: list[str] | None = None,
        status_in: list[int] | None = None,
        request_content_type: OptStr = None,
        response_content_type: OptStr = None,
        keyword_regex: OptStr = None,
        include_headers: bool = True,
        max_body_chars: Annotated[int, Field(description="Per body, in the inline result")] = 2000,
        max_entries: Annotated[
            int, Field(description="Page size for the inline result (max 100)")
        ] = 20,
        offset: int = 0,
        save_to_file: Annotated[
            bool,
            Field(
                description="Write ALL matching entries with full bodies (up to 1 MB each) to a .jsonl file instead"
            ),
        ] = False,
    ) -> dict[str, Any]:
        """Full records for specific entries or for every entry matching the filters: URL, decoded
        query parameters, request and response headers, and decoded bodies (JSON, form fields,
        multipart parts with uploaded files, gzip/br/zstd removed, charset fixed). Pages with
        offset/next_offset; save_to_file=true dumps everything to a JSON Lines file."""
        query = _query(
            preset,
            host_contains,
            path_contains,
            method_in,
            status_in,
            request_content_type=request_content_type,
            response_content_type=response_content_type,
            keyword_regex=keyword_regex,
        )
        return await app.traffic.entries(
            source=source,
            query=query,
            entry_ids=entry_ids,
            capture_id=capture_id,
            recording_path=recording_path,
            include_headers=include_headers,
            max_body_chars=max(64, min(max_body_chars, app.settings.max_detail_body_chars)),
            max_entries=max_entries,
            offset=offset,
            save_to_file=save_to_file,
            output_dir=app.settings.state_dir / "exports",
        )

    async def extract_entry_bodies(
        entry_id: str,
        source: Literal["live", "history", "reverse"] | None = None,
        capture_id: OptStr = None,
        recording_path: OptStr = None,
    ) -> dict[str, Any]:
        """Save one entry's decoded request and response bodies to files: images and other
        downloads, uploaded files (each multipart part separately), large JSON, WebSocket
        messages. Returns the file paths (open images with your file/vision tools)."""
        return await app.traffic.extract(
            entry_id,
            output_dir=app.settings.state_dir / "extracted",
            source=source,
            capture_id=capture_id,
            recording_path=recording_path,
        )

    register_tool(mcp, list_recordings, read_only=True)
    register_tool(mcp, get_recording_snapshot, read_only=True)
    register_tool(mcp, query_recorded_traffic, read_only=True)
    register_tool(mcp, analyze_recorded_traffic, read_only=True)
    register_tool(mcp, group_capture_analysis, read_only=True)
    register_tool(mcp, get_capture_analysis_stats, read_only=True)
    register_tool(mcp, get_traffic_entry_detail, read_only=True)
    register_tool(mcp, get_traffic_entries)  # save_to_file writes a file
    register_tool(mcp, extract_entry_bodies)


# =============================================================== reverse tools


def _register_reverse_tools(mcp: Any, app: App) -> None:
    rev = app.reverse

    def reverse_import_session(
        path: Annotated[
            str,
            Field(description="Session file: .chlsj .chlz .chls .xml .har (format auto-detected)"),
        ],
        label: OptStr = None,
    ) -> dict[str, Any]:
        """Import a session file into the reverse-analysis store; returns a reverse capture_id."""
        return rev.import_session(path, label=label)

    def reverse_list_captures(limit: int = 20) -> dict[str, Any]:
        """List reverse captures (imports and live sessions), newest first."""
        return rev.list_captures(limit)

    def reverse_delete_capture(capture_id: str) -> dict[str, Any]:
        """Delete a reverse capture with its entries, replays and findings."""
        return rev.delete_capture(capture_id)

    def reverse_query_entries(
        capture_id: str,
        host_contains: OptStr = None,
        path_contains: OptStr = None,
        method_in: list[str] | None = None,
        status_in: list[int] | None = None,
        errors_only: bool = False,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List entries of a reverse capture in order, with route-level filters and paging."""
        return rev.query_entries(
            capture_id,
            host_contains=host_contains,
            path_contains=path_contains,
            method_in=method_in,
            status_in=status_in,
            errors_only=errors_only,
            limit=limit,
            offset=offset,
        )

    def reverse_get_entry_detail(
        entry_id: str, include_body: bool = True, max_body_chars: int = 4096
    ) -> dict[str, Any]:
        """Full detail of one reverse entry, plus flattened request parameters and recent replays."""
        return rev.entry_detail(entry_id, include_body=include_body, max_body_chars=max_body_chars)

    def reverse_decode_entry_body(
        entry_id: str,
        side: Literal["request", "response"],
        descriptor_path: Annotated[
            OptStr, Field(description="protoc --descriptor_set_out file for named protobuf fields")
        ] = None,
        message_type: Annotated[
            OptStr, Field(description="Fully-qualified protobuf message, e.g. pkg.LoginReq")
        ] = None,
        max_chars: int = 8192,
    ) -> dict[str, Any]:
        """Decode a body: gzip/deflate/br/zstd, JSON, forms, multipart, gRPC frames and protobuf
        (schemaless by default, named with a descriptor)."""
        return rev.decode_body(
            entry_id,
            side,
            descriptor_path=descriptor_path,
            message_type=message_type,
            max_chars=max_chars,
        )

    async def reverse_replay_entry(
        entry_id: str,
        query_overrides: Annotated[
            dict[str, Any] | None, Field(description="{name: value}; null removes")
        ] = None,
        header_overrides: Annotated[
            dict[str, Any] | None, Field(description="{name: value}; null removes")
        ] = None,
        cookie_overrides: Annotated[
            dict[str, Any] | None, Field(description="{name: value}; null removes")
        ] = None,
        json_overrides: Annotated[
            dict[str, Any] | None,
            Field(description="{'data.user.id': 1, 'sign': null}; dot/bracket paths"),
        ] = None,
        form_overrides: dict[str, Any] | None = None,
        body_text_override: OptStr = None,
        method_override: OptStr = None,
        follow_redirects: bool = False,
        use_proxy: Annotated[
            bool, Field(description="Send through Charles so the replay shows up in the session")
        ] = False,
        verify_tls: Annotated[
            bool,
            Field(
                description="Set false when use_proxy=true and Charles' root cert is not trusted"
            ),
        ] = True,
    ) -> dict[str, Any]:
        """Re-send one stored request (optionally mutated) and compare with the original response,
        including app-level codes like {"code": 401, "msg": "签名错误"}. Sends real traffic."""
        mutation = {
            "query_overrides": query_overrides,
            "header_overrides": header_overrides,
            "cookie_overrides": cookie_overrides,
            "json_overrides": json_overrides,
            "form_overrides": form_overrides,
            "body_text_override": body_text_override,
            "method_override": method_override,
        }
        return await rev.replay(
            entry_id,
            {k: v for k, v in mutation.items() if v is not None},
            follow_redirects=follow_redirects,
            use_proxy=use_proxy,
            verify_tls=verify_tls,
        )

    def reverse_discover_signature_candidates(
        entry_ids: Annotated[
            list[str] | None,
            Field(
                description="2+ entries, ideally the same endpoint; one id compares it with its siblings"
            ),
        ] = None,
        capture_id: OptStr = None,
        host_contains: OptStr = None,
        path_contains: OptStr = None,
    ) -> dict[str, Any]:
        """Label request fields as signature / timestamp / nonce / static secret by comparing requests."""
        return rev.discover_signatures(
            entry_ids=entry_ids,
            capture_id=capture_id,
            host_contains=host_contains,
            path_contains=path_contains,
        )

    def reverse_build_mutation_plan(
        entry_id: str,
        workflow: Literal["signature", "login", "api"] = "signature",
        fields: Annotated[
            list[str] | None,
            Field(description="Explicit fields like query.sign, header.x-token, json.data.ts"),
        ] = None,
    ) -> dict[str, Any]:
        """Plan one-change-at-a-time replay variants (drop / tamper / stale timestamp / reuse old value)."""
        return rev.mutation_plan(entry_id, workflow=workflow, fields=fields)

    async def reverse_run_mutation_plan(
        entry_id: str,
        variants: Annotated[
            list[dict[str, Any]] | None,
            Field(description="Variants from reverse_build_mutation_plan; default builds one"),
        ] = None,
        fields: list[str] | None = None,
        workflow: Literal["signature", "login", "api"] = "signature",
        max_variants: int = 12,
        delay_ms: int = 300,
        use_proxy: bool = False,
        verify_tls: bool = True,
    ) -> dict[str, Any]:
        """Replay an unmodified control, then each variant, and report which fields the server
        actually enforces. Sends real traffic; stops early if the control already fails."""
        return await rev.run_mutation_plan(
            entry_id,
            variants=variants,
            fields=fields,
            workflow=workflow,
            max_variants=max_variants,
            delay_ms=delay_ms,
            use_proxy=use_proxy,
            verify_tls=verify_tls,
        )

    def reverse_list_findings(
        capture_id: OptStr = None,
        subject_id: OptStr = None,
        finding_type: OptStr = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List recorded findings (signature candidates, verified parameters, rejected replays)."""
        return rev.findings(
            capture_id=capture_id, subject_id=subject_id, finding_type=finding_type, limit=limit
        )

    async def reverse_charles_recording_status(live_session_id: OptStr = None) -> dict[str, Any]:
        """Charles recording state plus reverse live sessions."""
        return await rev.status(live_session_id)

    async def reverse_start_live_analysis(
        reset_session: Annotated[
            bool, Field(description="DESTRUCTIVE: clear Charles' session first. Only when asked.")
        ] = False,
        start_recording_if_stopped: bool = True,
    ) -> dict[str, Any]:
        """Start a reverse live session: new traffic is stored incrementally in one reverse capture."""
        return await rev.start_live(
            reset_session=reset_session, start_recording_if_stopped=start_recording_if_stopped
        )

    async def reverse_peek_live_entries(
        live_session_id: str,
        host_contains: OptStr = None,
        path_contains: OptStr = None,
        method_in: list[str] | None = None,
        status_in: list[int] | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """New entries of a reverse live session without advancing its cursor."""
        return await rev.live_items(
            live_session_id,
            advance=False,
            limit=limit,
            host_contains=host_contains,
            path_contains=path_contains,
            method_in=method_in,
            status_in=status_in,
        )

    async def reverse_read_live_entries(
        live_session_id: str,
        host_contains: OptStr = None,
        path_contains: OptStr = None,
        method_in: list[str] | None = None,
        status_in: list[int] | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """New entries of a reverse live session; advances its cursor."""
        return await rev.live_items(
            live_session_id,
            advance=True,
            limit=limit,
            host_contains=host_contains,
            path_contains=path_contains,
            method_in=method_in,
            status_in=status_in,
        )

    async def reverse_stop_live_analysis(
        live_session_id: str, restore_recording: bool = True
    ) -> dict[str, Any]:
        """Stop a reverse live session. Its capture stays in the store."""
        return await rev.stop_live(live_session_id, restore_recording=restore_recording)

    def _workflow_tool(name: str, workflow: str, doc: str) -> None:
        async def tool(
            live_session_id: str,
            host_contains: OptStr = None,
            path_keywords: Annotated[
                list[str] | None, Field(description="Override the built-in endpoint keywords")
            ] = None,
            advance: bool = True,
            decode_bodies: bool = True,
            descriptor_path: OptStr = None,
            message_type: OptStr = None,
            run_replay: Annotated[
                bool,
                Field(description="Also replay the selected request once (sends real traffic)"),
            ] = False,
            replay_use_proxy: bool = False,
            verify_tls: bool = True,
        ) -> dict[str, Any]:
            return await rev.run_workflow(
                workflow,
                live_session_id=live_session_id,
                host_contains=host_contains,
                path_keywords=path_keywords,
                advance=advance,
                decode_bodies=decode_bodies,
                descriptor_path=descriptor_path,
                message_type=message_type,
                run_replay=run_replay,
                replay_use_proxy=replay_use_proxy,
                verify_tls=verify_tls,
            )

        tool.__name__ = name
        register_tool(mcp, tool, name=name, description=doc, open_world=True)

    _workflow_tool(
        "reverse_analyze_live_login_flow",
        "login",
        "Find the login/auth request in new live traffic, decode it, compare signatures and plan mutations. "
        "Read `summary` and `next` first.",
    )
    _workflow_tool(
        "reverse_analyze_live_api_flow",
        "api",
        "Find the main API request in new live traffic, decode it and plan mutations.",
    )
    _workflow_tool(
        "reverse_analyze_live_signature_flow",
        "signature",
        "Find requests carrying signatures/timestamps/nonces in new live traffic and plan which to test.",
    )

    async def reverse_analyze_capture(
        capture_id: str,
        workflow: Literal["signature", "login", "api"] = "signature",
        host_contains: OptStr = None,
        path_keywords: list[str] | None = None,
        decode_bodies: bool = True,
        descriptor_path: OptStr = None,
        message_type: OptStr = None,
    ) -> dict[str, Any]:
        """Run the login / api / signature workflow over an imported reverse capture."""
        return await rev.run_workflow(
            workflow,
            capture_id=capture_id,
            host_contains=host_contains,
            path_keywords=path_keywords,
            decode_bodies=decode_bodies,
            descriptor_path=descriptor_path,
            message_type=message_type,
        )

    register_tool(mcp, reverse_import_session)
    register_tool(mcp, reverse_list_captures, read_only=True)
    register_tool(mcp, reverse_delete_capture, destructive=True)
    register_tool(mcp, reverse_query_entries, read_only=True)
    register_tool(mcp, reverse_get_entry_detail, read_only=True)
    register_tool(mcp, reverse_decode_entry_body, read_only=True)
    register_tool(mcp, reverse_replay_entry, open_world=True)
    register_tool(mcp, reverse_discover_signature_candidates)
    register_tool(mcp, reverse_build_mutation_plan, read_only=True)
    register_tool(mcp, reverse_run_mutation_plan, open_world=True)
    register_tool(mcp, reverse_list_findings, read_only=True)
    register_tool(mcp, reverse_charles_recording_status, read_only=True)
    register_tool(mcp, reverse_start_live_analysis)
    register_tool(mcp, reverse_peek_live_entries, read_only=True)
    register_tool(mcp, reverse_read_live_entries)
    register_tool(mcp, reverse_stop_live_analysis)
    register_tool(mcp, reverse_analyze_capture)
