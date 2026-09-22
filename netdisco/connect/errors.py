from __future__ import annotations


class ConnectError(Exception):
    """A connection problem the UI can explain. `code` drives the UI (e.g. 'otp_required')."""

    def __init__(self, code: str, message: str, extra: dict | None = None):
        super().__init__(message)
        self.code, self.message, self.extra = code, message, extra or {}
