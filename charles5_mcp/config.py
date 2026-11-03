"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import glob
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value not in (None, "") else default


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    try:
        return int(value) if value not in (None, "") else default
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    try:
        return float(value) if value not in (None, "") else default
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value in (None, ""):
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_paths(name: str) -> list[str]:
    value = os.getenv(name)
    if not value:
        return []
    return [part for part in value.split(os.pathsep) if part.strip()]


def default_state_dir() -> Path:
    """Platform-appropriate directory for recordings, the reverse DB and backups."""
    override = os.getenv("CHARLES_STATE_DIR")
    if override:
        return Path(override).expanduser()
    home = Path.home()
    if sys.platform == "win32":
        base = os.getenv("LOCALAPPDATA")
        return Path(base) / "charles5-mcp" if base else home / "AppData" / "Local" / "charles5-mcp"
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "charles5-mcp"
    xdg = os.getenv("XDG_STATE_HOME")
    return Path(xdg) / "charles5-mcp" if xdg else home / ".local" / "state" / "charles5-mcp"


def detect_charles_cli() -> str | None:
    """Locate the Charles executable used for `charles convert` (native .chls files)."""
    override = os.getenv("CHARLES_CLI_PATH")
    candidates: list[Path] = [Path(override).expanduser()] if override else []
    if sys.platform == "darwin":
        candidates += [
            Path("/Applications/Charles.app/Contents/MacOS/Charles"),
            Path.home() / "Applications/Charles.app/Contents/MacOS/Charles",
        ]
    elif sys.platform == "win32":
        candidates += [
            Path("C:/Program Files/Charles/Charles.exe"),
            Path("C:/Program Files (x86)/Charles/Charles.exe"),
        ]
    else:
        candidates += [Path("/usr/bin/charles"), Path("/opt/charles/bin/charles")]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def detect_charles_config() -> str | None:
    """Locate Charles' own configuration file (used only for backup / restore)."""
    override = os.getenv("CHARLES_CONFIG_PATH")
    if override and Path(override).expanduser().is_file():
        return str(Path(override).expanduser())
    home = Path.home()
    patterns: list[str] = []
    if sys.platform == "darwin":
        patterns += [
            str(home / "Library/Preferences/com.xk72.charles.config"),
            str(home / "Library/Preferences/com.xk72.Charles.config"),
            str(home / "Library/Application Support/Charles/charles.config"),
        ]
    elif sys.platform == "win32":
        appdata = os.getenv("APPDATA", "")
        local = os.getenv("LOCALAPPDATA", "")
        if appdata:
            patterns.append(os.path.join(appdata, "Charles", "charles.config"))
        if local:
            patterns.append(
                os.path.join(local, "Packages", "XK72.Charles_*", "RoamingState", "charles.config")
            )
    else:
        xdg = os.getenv("XDG_CONFIG_HOME", str(home / ".config"))
        patterns += [os.path.join(xdg, "Charles", "charles.config")]
    patterns.append(str(home / ".charles.config"))
    for pattern in patterns:
        for match in sorted(glob.glob(pattern)):
            if Path(match).is_file():
                return match
    return None


@dataclass
class Settings:
    """All tunables. Construct with ``Settings.from_env()``; tests pass values directly."""

    charles_user: str = "admin"
    charles_pass: str = "123456"
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8888
    # Charles answers Web Interface requests for this virtual host when they
    # arrive through its own proxy port.
    control_host: str = "control.charles"
    request_timeout: float = 15.0

    state_dir: Path = field(default_factory=default_state_dir)
    recordings_dir: Path | None = None
    extra_recording_dirs: list[str] = field(default_factory=list)

    charles_cli_path: str | None = None
    charles_config_path: str | None = None
    manage_lifecycle: bool = False

    max_detail_body_chars: int = 16_384
    live_max_entries: int = 20_000
    replay_timeout: float = 20.0
    reverse_live_ttl_seconds: int = 1800
    reverse_max_query_limit: int = 200

    def __post_init__(self) -> None:
        self.state_dir = Path(self.state_dir).expanduser()
        if self.recordings_dir is None:
            self.recordings_dir = self.state_dir / "recordings"
        self.recordings_dir = Path(self.recordings_dir).expanduser()

    @classmethod
    def from_env(cls) -> Settings:
        recordings = os.getenv("CHARLES_RECORDINGS_DIR") or os.getenv("CHARLES_PACKAGE_DIR")
        return cls(
            charles_user=_env_str("CHARLES_USER", "admin"),
            charles_pass=_env_str("CHARLES_PASS", "123456"),
            proxy_host=_env_str("CHARLES_PROXY_HOST", "127.0.0.1"),
            proxy_port=_env_int("CHARLES_PROXY_PORT", 8888),
            request_timeout=_env_float("CHARLES_REQUEST_TIMEOUT", 15.0),
            state_dir=default_state_dir(),
            recordings_dir=Path(recordings) if recordings else None,
            extra_recording_dirs=_env_paths("CHARLES_EXTRA_RECORDING_DIRS"),
            charles_cli_path=detect_charles_cli(),
            charles_config_path=detect_charles_config(),
            manage_lifecycle=_env_bool("CHARLES_MANAGE_LIFECYCLE", False),
            max_detail_body_chars=_env_int("CHARLES_MAX_DETAIL_BODY_CHARS", 16_384),
            live_max_entries=_env_int("CHARLES_LIVE_MAX_ENTRIES", 20_000),
            replay_timeout=_env_float("CHARLES_REPLAY_TIMEOUT", 20.0),
            reverse_live_ttl_seconds=_env_int("CHARLES_REVERSE_LIVE_TTL_SECONDS", 1800),
            reverse_max_query_limit=_env_int("CHARLES_REVERSE_MAX_QUERY_LIMIT", 200),
        )

    @property
    def proxy_url(self) -> str:
        return f"http://{self.proxy_host}:{self.proxy_port}"

    @property
    def control_base_url(self) -> str:
        return f"http://{self.control_host}"

    @property
    def reverse_db_path(self) -> Path:
        return self.state_dir / "reverse.sqlite3"

    @property
    def backup_dir(self) -> Path:
        return self.state_dir / "backup"

    @property
    def scratch_dir(self) -> Path:
        return self.state_dir / "tmp"

    def ensure_dirs(self) -> None:
        for path in (self.state_dir, self.recordings_dir, self.scratch_dir):
            assert path is not None
            path.mkdir(parents=True, exist_ok=True)

    def warnings(self) -> list[str]:
        notes: list[str] = []
        if self.charles_user == "admin" and self.charles_pass == "123456":
            notes.append(
                "Using the default Web Interface credentials admin/123456; "
                "set CHARLES_USER / CHARLES_PASS to match your Charles settings."
            )
        if not self.charles_cli_path:
            notes.append(
                "Charles executable not found; binary .chls files cannot be converted. "
                "Set CHARLES_CLI_PATH or use .chlsj/.chlz/.xml/.har files."
            )
        return notes

    def public_view(self) -> dict[str, object]:
        return {
            "proxy_url": self.proxy_url,
            "control_base_url": self.control_base_url,
            "charles_user": self.charles_user,
            "recordings_dir": str(self.recordings_dir),
            "extra_recording_dirs": list(self.extra_recording_dirs),
            "state_dir": str(self.state_dir),
            "charles_cli_path": self.charles_cli_path,
            "charles_config_path": self.charles_config_path,
            "manage_lifecycle": self.manage_lifecycle,
        }
