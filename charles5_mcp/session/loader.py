"""Detect a session's format and load it, using the Charles CLI where needed.

Formats parsed natively: Charles JSON (.chlsj / Web Interface export-json),
Charles XML (.xml / .chlsx), HAR and the zip-based native session (.chlz).

Formats that need ``charles convert`` (Charles 5.2 CLI): the Java-serialised
Charles 4 session (.chls), HTTP trace (.trace), Fiddler archives (.saz) and
packet captures (.pcap). They are converted to .chlsj in a temporary
directory and then parsed like any JSON session.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import zipfile
import zlib
from pathlib import Path

from charles5_mcp.errors import SessionFormatError
from charles5_mcp.session import parsers
from charles5_mcp.session.model import Transaction

NATIVE_SUFFIXES = (".chlsj", ".chlz", ".xml", ".chlsx", ".har", ".json")
CLI_SUFFIXES = (".chls", ".trace", ".saz", ".pcap")
SUPPORTED_SUFFIXES = NATIVE_SUFFIXES + CLI_SUFFIXES

_ZIP_MAGIC = b"PK\x03\x04"
_EMPTY_ZIP_MAGIC = b"PK\x05\x06"  # Charles writes this for an empty session
_JAVA_SERIAL_MAGIC = b"\xac\xed"
_CLI_TIMEOUT_SECONDS = 300


def detect_format(data: bytes, suffix: str = "") -> str:
    """Return chlz, xml, har, chlsj, or ``cli`` for formats only Charles can read."""
    suffix = suffix.lower()
    if suffix in (".saz", ".pcap", ".trace"):
        return "cli"
    head = data[:64].lstrip(b"\xef\xbb\xbf \t\r\n")
    if data.startswith((_ZIP_MAGIC, _EMPTY_ZIP_MAGIC)):
        return "chlz"
    if data.startswith(_JAVA_SERIAL_MAGIC) or suffix == ".chls":
        return "cli"
    if head.startswith(b"<"):
        return "xml"
    if head.startswith((b"[", b"{")):
        probe = data[:4096]
        if suffix == ".har" or (b'"log"' in probe and b'"entries"' in probe):
            return "har"
        return "chlsj"
    raise SessionFormatError(
        "unrecognised session content",
        hint="Supported: " + ", ".join(SUPPORTED_SUFFIXES),
    )


def parse_bytes(
    data: bytes, *, suffix: str = "", charles_cli: str | None = None
) -> list[Transaction]:
    fmt = detect_format(data, suffix)
    if fmt == "chlz":
        return parsers.parse_native_zip(data)
    if fmt == "xml":
        return parsers.parse_charles_xml(data)
    if fmt in ("har", "chlsj"):
        payload = json.loads(data)
        if isinstance(payload, dict) and "log" in payload:
            return parsers.parse_har(payload)
        return parsers.parse_charles_json(payload)
    return _via_cli(data, suffix or ".chls", charles_cli)


def load_session_file(path: str | Path, *, charles_cli: str | None = None) -> list[Transaction]:
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise SessionFormatError(f"session file not found: {file_path}")
    data = file_path.read_bytes()
    if not data.strip():
        return []
    try:
        return parse_bytes(data, suffix=file_path.suffix, charles_cli=charles_cli)
    except SessionFormatError:
        raise
    except (ValueError, RecursionError, OverflowError, zipfile.BadZipFile, zlib.error) as exc:
        raise SessionFormatError(f"{file_path.name}: {type(exc).__name__}: {exc}") from exc


def run_charles_cli(charles_cli: str | None, *args: str) -> str:
    """Run a Charles CLI command (``convert``, ``filter``) and return its output."""
    if not charles_cli:
        raise SessionFormatError(
            "this needs the Charles executable (charles convert / filter)",
            hint="Set CHARLES_CLI_PATH, e.g. /Applications/Charles.app/Contents/MacOS/Charles",
        )
    try:
        result = subprocess.run(
            [charles_cli, *args],
            capture_output=True,
            text=True,
            timeout=_CLI_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SessionFormatError(f"charles {args[0]} failed to run: {exc}") from exc
    output = "\n".join(
        line
        for line in (result.stdout + "\n" + result.stderr).splitlines()
        if line.strip() and "JAVA_TOOL_OPTIONS" not in line and " WARNING " not in line
    )
    if result.returncode != 0:
        detail = output[-500:] or "no output"
        raise SessionFormatError(
            f"charles {args[0]} exited with {result.returncode}: {detail}",
            hint=None
            if "invalid" in detail.lower() or "unsupported" in detail.lower()
            else "Check the input file; if Charles shows a dialog, close it and retry.",
        )
    return output


def convert_file(
    charles_cli: str | None, source: Path, target: Path, filters: list[str] | None = None
) -> str:
    """``charles convert <source> <target> [filters]``; formats come from the suffixes."""
    output = run_charles_cli(charles_cli, "convert", str(source), str(target), *(filters or []))
    if not target.is_file():
        raise SessionFormatError(
            f"charles convert produced no output: {output[-300:] or 'unknown error'}",
            hint="Output formats: .chlz .chls .chlsx .chlsj .har .trace .xml .csv",
        )
    return output


def _via_cli(data: bytes, suffix: str, charles_cli: str | None) -> list[Transaction]:
    with tempfile.TemporaryDirectory(prefix="charles5-mcp-") as tmp:
        source = Path(tmp) / f"input{suffix}"
        target = Path(tmp) / "output.chlsj"
        source.write_bytes(data)
        convert_file(charles_cli, source, target)
        return parsers.parse_charles_json(target.read_bytes())
