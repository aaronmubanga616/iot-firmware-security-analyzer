"""Sanitized application errors that never contain firmware data or paths."""


class InspectionError(Exception):
    """An expected failure identified by a stable code and safe message."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
