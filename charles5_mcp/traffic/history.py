"""Saved recordings (session files on disk)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from charles5_mcp.config import Settings
from charles5_mcp.errors import NotFoundError, SessionFormatError
from charles5_mcp.session.loader import SUPPORTED_SUFFIXES, load_session_file
from charles5_mcp.session.model import Transaction

_CACHE_LIMIT = 6


@dataclass
class LoadedRecording:
    path: Path
    signature: tuple[float, int]
    transactions: list[Transaction]
    ids: list[str]
    index: dict[str, int]


class RecordingStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._cache: dict[str, LoadedRecording] = {}

    def directories(self) -> list[Path]:
        assert self.settings.recordings_dir is not None
        dirs = [Path(self.settings.recordings_dir)]
        dirs += [Path(d).expanduser() for d in self.settings.extra_recording_dirs]
        return [d for d in dirs if d.is_dir()]

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        files: list[Path] = []
        for directory in self.directories():
            files += [
                p
                for p in directory.iterdir()
                if p.is_file()
                and p.suffix.lower() in SUPPORTED_SUFFIXES
                and not p.name.startswith(".")
            ]
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return [
            {
                "recording_path": str(p),
                "name": p.name,
                "format": p.suffix.lower().lstrip("."),
                "size_bytes": p.stat().st_size,
                "modified": datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat(
                    timespec="seconds"
                ),
            }
            for p in files[:limit]
        ]

    def resolve(self, recording_path: str | None) -> Path:
        if not recording_path:
            recordings = self.list(limit=1)
            if not recordings:
                raise NotFoundError(
                    "no saved recordings found",
                    hint=(
                        f"Save a session into {self.settings.recordings_dir} (File > Save Session As), "
                        "call export_charles_session, or stop a live capture with persist=true."
                    ),
                )
            return Path(recordings[0]["recording_path"])
        candidate = Path(recording_path).expanduser()
        if not candidate.is_absolute():
            for directory in self.directories():
                if (directory / candidate).is_file():
                    candidate = directory / candidate
                    break
        if not candidate.is_file():
            raise NotFoundError(
                f"recording not found: {recording_path}", hint="call list_recordings"
            )
        if candidate.suffix.lower() not in SUPPORTED_SUFFIXES:
            raise SessionFormatError(
                f"unsupported file type `{candidate.suffix}`",
                hint=f"supported: {', '.join(SUPPORTED_SUFFIXES)}",
            )
        return candidate.resolve()

    def load(self, recording_path: str | None) -> LoadedRecording:
        path = self.resolve(recording_path)
        stat = path.stat()
        signature = (stat.st_mtime, stat.st_size)
        key = str(path)
        cached = self._cache.get(key)
        if cached and cached.signature == signature:
            return cached
        transactions = load_session_file(path, charles_cli=self.settings.charles_cli_path)
        prefix = hashlib.sha1(key.encode()).hexdigest()[:6]
        ids = [f"h{prefix}{txn.seq:05d}" for txn in transactions]
        loaded = LoadedRecording(
            path, signature, transactions, ids, {i: n for n, i in enumerate(ids)}
        )
        self._cache[key] = loaded
        while len(self._cache) > _CACHE_LIMIT:
            self._cache.pop(next(iter(self._cache)))
        return loaded

    def find_entry(self, entry_id: str) -> tuple[LoadedRecording, int] | None:
        for loaded in self._cache.values():
            position = loaded.index.get(entry_id)
            if position is not None:
                return loaded, position
        return None
