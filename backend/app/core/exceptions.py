"""Typed application errors that render as RFC-7807-ish JSON problems."""

from __future__ import annotations

from typing import Any


class SilentShiftError(Exception):
    """Base class for every error the application raises deliberately."""

    status_code: int = 500
    code: str = "internal_error"
    message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message or self.message
        self.code = code or self.code
        self.status_code = status_code or self.status_code
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            payload["details"] = self.details
        return {"error": payload}


class NotFoundError(SilentShiftError):
    status_code = 404
    code = "not_found"
    message = "The requested resource does not exist."


class ConflictError(SilentShiftError):
    status_code = 409
    code = "conflict"
    message = "The resource is in a conflicting state."


class ValidationError(SilentShiftError):
    status_code = 422
    code = "validation_error"
    message = "The supplied payload failed validation."


class AuthenticationError(SilentShiftError):
    status_code = 401
    code = "unauthenticated"
    message = "Valid credentials are required."


class PermissionDeniedError(SilentShiftError):
    status_code = 403
    code = "permission_denied"
    message = "Your role does not permit this operation."


class RateLimitedError(SilentShiftError):
    status_code = 429
    code = "rate_limited"
    message = "Too many requests. Slow down."


class ServiceUnavailableError(SilentShiftError):
    status_code = 503
    code = "service_unavailable"
    message = "A dependency is unavailable."
