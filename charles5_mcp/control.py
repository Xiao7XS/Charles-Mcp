"""Status, throttling, tool toggles, session export and config backup/restore."""

from __future__ import annotations

import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from charles5_mcp import TARGET_CHARLES_VERSION
from charles5_mcp.charles.client import EXPORT_ENDPOINTS, SELF_RECORDING_WARNING, CharlesClient
from charles5_mcp.config import Settings
from charles5_mcp.errors import CharlesMCPError
from charles5_mcp.session.loader import SUPPORTED_SUFFIXES, convert_file, run_charles_cli

EXPORT_FORMATS = tuple(EXPORT_ENDPOINTS)
CONVERT_OUTPUTS = ("chlz", "chls", "chlsx", "chlsj", "har", "trace", "xml", "csv")


def _version_tuple(version: str | None) -> tuple[int, ...] | None:
    if not version:
        return None
    parts = []
    for chunk in version.split("b")[0].split("."):
        if chunk.isdigit():
            parts.append(int(chunk))
    return tuple(parts) or None


def _safe_stem(name: str | None, prefix: str) -> str:
    stem = name or f"{prefix}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    stem = "".join(ch for ch in stem if ch.isalnum() or ch in "-_.").strip(".")
    return stem or prefix


def _unique(path: Path) -> Path:
    """``path`` or ``stem-2.ext``, ``stem-3.ext``... so nothing is overwritten."""
    if not path.exists():
        return path
    for n in range(2, 10_000):
        candidate = path.with_name(f"{path.stem}-{n}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise CharlesMCPError(f"too many files named {path.stem}")


_SIZE = re.compile(r"^\d+(\.\d+)?[kmgKMG]?$")


def _filter_args(
    *,
    include_hosts: list[str] | None,
    exclude_hosts: list[str] | None,
    include_mime: list[str] | None,
    exclude_mime: list[str] | None,
    include_methods: list[str] | None,
    exclude_methods: list[str] | None,
    max_response_size: str | None,
) -> list[str]:
    args: list[str] = []
    for flag, values in (
        ("--include-host", include_hosts),
        ("--exclude-host", exclude_hosts),
        ("--include-mime", include_mime),
        ("--exclude-mime", exclude_mime),
        ("--include-method", include_methods),
        ("--exclude-method", exclude_methods),
    ):
        for value in values or []:
            if value and value.strip():
                args += [flag, value.strip()]
    if max_response_size:
        size = max_response_size.strip()
        if not _SIZE.match(size):
            raise CharlesMCPError(
                f"invalid max_response_size `{max_response_size}`",
                hint="use bytes or k/m/g, e.g. 500k or 2m",
            )
        args += ["--max-response-size", size]
    return args


class ControlService:
    def __init__(self, settings: Settings, client: CharlesClient) -> None:
        self.settings = settings
        self.client = client

    async def status(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "config": self.settings.public_view(),
            "target_charles": TARGET_CHARLES_VERSION,
        }
        try:
            info = await self.client.info()
            result["connected"] = True
            result["charles_version"] = info.get("version")
            recording = await self.client.recording_status()
            result["recording"] = {True: "recording", False: "stopped", None: "unknown"}[recording]
            throttle = await self.client.throttling_status()
            result["throttling"] = "on" if throttle["active"] else "off"
        except CharlesMCPError as exc:
            result["connected"] = False
            result["error"] = str(exc)
            result["hint"] = exc.hint
            return result
        if self.client.records_control_requests:
            result["warning"] = SELF_RECORDING_WARNING
        if self.client.last_export_bytes:
            result["last_export_mb"] = round(self.client.last_export_bytes / 1_048_576, 2)
        if result["recording"] == "stopped":
            result["note"] = (
                "Charles is not recording: the Web Interface cannot export anything until "
                "recording starts (start_live_capture starts it, opening a new session)."
            )
        version = _version_tuple(result.get("charles_version"))
        target = _version_tuple(TARGET_CHARLES_VERSION)
        if version and target and version < target:
            result["version_note"] = (
                f"Charles {result['charles_version']} is older than {TARGET_CHARLES_VERSION}. Core "
                "features work; 5.2.x adds 1xx/Early-Hints recording, HTTP/2 fixes and the "
                "convert/filter CLI used by convert_session_file."
            )
        return result

    async def controls(self) -> dict[str, Any]:
        throttle = await self.client.throttling_status()
        tools = await self.client.tools_status()
        return {
            "throttling": {"active": throttle["active"], "presets": throttle["presets"]},
            "tools": tools,
            "note": "Rules for Map Remote, Rewrite, Breakpoints etc. are edited in Charles; "
            "this server switches the tools on and off.",
        }

    async def throttling(self, preset: str) -> dict[str, Any]:
        lowered = preset.strip().lower()
        if lowered in {"off", "deactivate", "disable", "none", "stop", ""}:
            await self.client.set_throttling(None)
            return {"throttling": "off"}
        name = await self.client.set_throttling(preset)
        status = await self.client.throttling_status()
        return {"throttling": "on" if status["active"] else "unknown", "preset": name}

    async def set_tool(self, tool: str, enabled: bool) -> dict[str, Any]:
        return await self.client.set_tool(tool, enabled)

    async def export_session(self, fmt: str = "chlsj", name: str | None = None) -> dict[str, Any]:
        if fmt not in EXPORT_FORMATS:
            raise CharlesMCPError(
                f"unsupported export format `{fmt}`", hint=f"one of {EXPORT_FORMATS}"
            )
        assert self.settings.recordings_dir is not None
        directory = Path(self.settings.recordings_dir)
        directory.mkdir(parents=True, exist_ok=True)
        data = await self.client.export_raw(fmt)
        target = _unique(directory / f"{_safe_stem(name, 'charles')}.{fmt}")
        tmp = target.with_suffix(target.suffix + ".part")
        tmp.write_bytes(data)
        tmp.replace(target)
        return {
            "recording_path": str(target),
            "format": fmt,
            "size_bytes": len(data),
            "next": "analyze_recorded_traffic(recording_path=...) or reverse_import_session(path=...)"
            if fmt != "csv"
            else "CSV is a summary table and cannot be analysed as a session; prefer chlsj or chlz.",
        }

    def convert_file(
        self,
        source: str,
        output_format: str,
        *,
        name: str | None = None,
        **filters: Any,
    ) -> dict[str, Any]:
        """Convert and/or filter a session file with the Charles 5.2 CLI."""
        if output_format not in CONVERT_OUTPUTS:
            raise CharlesMCPError(
                f"unsupported output format `{output_format}`", hint=f"one of {CONVERT_OUTPUTS}"
            )
        source_path = Path(source).expanduser()
        if not source_path.is_file():
            raise CharlesMCPError(f"file not found: {source}", hint="call list_recordings")
        if source_path.suffix.lower() not in SUPPORTED_SUFFIXES:
            raise CharlesMCPError(
                f"unsupported input type `{source_path.suffix}`",
                hint=f"supported: {', '.join(SUPPORTED_SUFFIXES)}",
            )
        assert self.settings.recordings_dir is not None
        directory = Path(self.settings.recordings_dir)
        directory.mkdir(parents=True, exist_ok=True)
        target = _unique(
            directory / f"{_safe_stem(name, source_path.stem + '-converted')}.{output_format}"
        )
        if target.resolve() == source_path.resolve():
            raise CharlesMCPError("output would overwrite the input; pass a different name")
        args = _filter_args(**filters)
        output = convert_file(self.settings.charles_cli_path, source_path, target, args)
        summary = next(
            (line for line in output.splitlines() if "transaction" in line.lower()), None
        )
        return {
            "recording_path": str(target),
            "format": output_format,
            "size_bytes": target.stat().st_size,
            "filters": args or None,
            "charles_output": summary,
        }

    def charles_cli_version(self) -> str:
        return run_charles_cli(self.settings.charles_cli_path, "--version")

    # ------------------------------------------------------------- backups

    def backup_config(self) -> dict[str, Any]:
        source = self.settings.charles_config_path
        if not source or not Path(source).is_file():
            return {
                "backed_up": False,
                "reason": "Charles config file not found (set CHARLES_CONFIG_PATH)",
            }
        target_dir = self.settings.backup_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / "charles.config"
        if target.is_file():
            # Keep the first backup: a later start may follow a session that
            # already changed Charles' settings.
            return {"backed_up": False, "reason": "existing backup kept", "path": str(target)}
        shutil.copy2(source, target)
        (target_dir / "SOURCE").write_text(source, encoding="utf-8")
        return {"backed_up": True, "path": str(target)}

    async def reset_environment(self, *, quit_charles: bool) -> dict[str, Any]:
        """Restore the backed-up Charles config. Saved recordings are never touched."""
        backup = self.settings.backup_dir / "charles.config"
        destination = self.settings.charles_config_path
        if not backup.is_file() or not destination:
            return {
                "restored": False,
                "reason": "No config backup exists. Backups are taken at startup when "
                "CHARLES_MANAGE_LIFECYCLE=true.",
            }
        try:
            await self.client.set_throttling(None)
        except CharlesMCPError:
            pass  # Charles may already be closed; restoring the file still works
        if quit_charles:
            # Charles rewrites its config on exit, so it must quit before restore.
            await self.client.quit()
        shutil.copy2(backup, destination)
        return {
            "restored": True,
            "config_path": destination,
            "charles_quit": quit_charles,
            "note": "Start Charles again to load the restored settings."
            if quit_charles
            else "Restart Charles to load the restored settings; Charles may overwrite them on exit if still running.",
        }
