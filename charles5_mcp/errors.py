"""Error types. Each carries an optional ``hint`` telling the agent what to do next."""

from __future__ import annotations


class CharlesMCPError(Exception):
    """Base error for this package."""

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


class CharlesUnavailableError(CharlesMCPError):
    """Charles could not be reached through its proxy port / Web Interface."""


class CharlesAuthError(CharlesMCPError):
    """The Web Interface rejected the configured credentials."""


class CharlesAPIError(CharlesMCPError):
    """A Web Interface call returned an unexpected status or payload."""


class CharlesNotRecordingError(CharlesAPIError):
    """Charles is not recording, so the Web Interface has no session to export."""


class SessionFormatError(CharlesMCPError):
    """A session file or export could not be parsed."""


class NotFoundError(CharlesMCPError):
    """A capture, entry, recording or session id does not exist."""


class StateConflictError(CharlesMCPError):
    """The requested operation conflicts with current runtime state."""
