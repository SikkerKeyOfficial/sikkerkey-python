"""Typed exceptions for the SikkerKey SDK."""


class SikkerKeyError(Exception):
    """Base exception for all SikkerKey SDK errors."""
    pass


class ConfigurationError(SikkerKeyError):
    """Identity file missing, malformed, or private key not found."""
    pass


class ApiError(SikkerKeyError):
    """HTTP error from the SikkerKey API."""

    def __init__(self, message: str, http_status: int = 0):
        super().__init__(message)
        self.http_status = http_status


class AuthenticationError(ApiError):
    """401 — signature verification failed or machine unknown."""

    def __init__(self, message: str):
        super().__init__(message, 401)


class AccessDeniedError(ApiError):
    """403 — machine not approved, disabled, or no access grant."""

    def __init__(self, message: str):
        super().__init__(message, 403)


class NotFoundError(ApiError):
    """404 — secret or resource not found."""

    def __init__(self, message: str):
        super().__init__(message, 404)


class ConflictError(ApiError):
    """409 — conflict (e.g. cannot rotate dynamic secret)."""

    def __init__(self, message: str):
        super().__init__(message, 409)


class RateLimitedError(ApiError):
    """429 — too many requests."""

    def __init__(self, message: str):
        super().__init__(message, 429)


class ServerSealedError(ApiError):
    """503 — server is sealed, awaiting unseal."""

    def __init__(self, message: str):
        super().__init__(message, 503)


class SecretStructureError(SikkerKeyError):
    """Wrong secret type for the operation."""
    pass


class FieldNotFoundError(SikkerKeyError):
    """Field not found in a structured secret."""
    pass
