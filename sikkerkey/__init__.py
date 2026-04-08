"""
SikkerKey Python SDK — read secrets from a SikkerKey vault.

Quick start::

    from sikkerkey import SikkerKey

    sk = SikkerKey("vault_abc123")
    secret = sk.get_secret("sk_a1b2c3d4e5")

Structured secrets::

    fields = sk.get_fields("sk_db_prod")
    host = fields["host"]
    password = fields["password"]
"""

from sikkerkey.client import SikkerKey, SecretListItem
from sikkerkey.exceptions import (
    SikkerKeyError,
    ConfigurationError,
    ApiError,
    AuthenticationError,
    AccessDeniedError,
    NotFoundError,
    ConflictError,
    RateLimitedError,
    ServerSealedError,
    SecretStructureError,
    FieldNotFoundError,
)

__all__ = [
    "SikkerKey",
    "SecretListItem",
    "SikkerKeyError",
    "ConfigurationError",
    "ApiError",
    "AuthenticationError",
    "AccessDeniedError",
    "NotFoundError",
    "ConflictError",
    "RateLimitedError",
    "ServerSealedError",
    "SecretStructureError",
    "FieldNotFoundError",
]
