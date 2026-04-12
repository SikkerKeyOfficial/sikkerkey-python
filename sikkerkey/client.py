"""SikkerKey SDK client."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from sikkerkey.exceptions import (
    AccessDeniedError,
    ApiError,
    AuthenticationError,
    ConfigurationError,
    ConflictError,
    FieldNotFoundError,
    NotFoundError,
    RateLimitedError,
    SecretStructureError,
    ServerSealedError,
    SikkerKeyError,
)


@dataclass
class SecretListItem:
    """Secret metadata returned by list operations."""
    id: str
    name: str
    field_names: Optional[str] = None
    project_id: Optional[str] = None


class WatchStatus(Enum):
    """Status of a watched secret change."""
    CHANGED = "changed"
    DELETED = "deleted"
    ACCESS_DENIED = "access_denied"
    ERROR = "error"


@dataclass
class WatchEvent:
    """Event delivered to a watch callback."""
    secret_id: str
    status: WatchStatus
    value: Optional[str] = None
    fields: Optional[dict[str, str]] = None
    error: Optional[str] = None


_RETRYABLE_CODES = {429, 503}
_MAX_RETRIES = 3
_BACKOFF_SECONDS = [1.0, 2.0, 4.0]


class SikkerKey:
    """SikkerKey SDK client bound to a specific vault.

    Args:
        vault_or_path: A vault ID (e.g. ``"vault_abc123"``), a path to an
            ``identity.json`` file, or ``None`` to auto-detect.
    """

    def __init__(self, vault_or_path: Optional[str] = None):
        identity_file = _resolve_identity(vault_or_path)
        self._identity, self._private_key = _load_identity(identity_file)

        # Watch state
        self._watchers: dict[str, Callable[[WatchEvent], None]] = {}
        self._watchers_lock = threading.Lock()
        self._poll_interval: int = 15
        self._poll_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @property
    def machine_id(self) -> str:
        return self._identity["machineId"]

    @property
    def machine_name(self) -> str:
        return self._identity["machineName"]

    @property
    def vault_id(self) -> str:
        return self._identity.get("vaultId", "")

    @property
    def api_url(self) -> str:
        return self._identity["apiUrl"]

    # ── Read ──

    def get_secret(self, secret_id: str) -> str:
        """Fetch a secret value by ID."""
        body = self._request("GET", f"/v1/secret/{secret_id}")
        return json.loads(body)["value"]

    def get_fields(self, secret_id: str) -> dict[str, str]:
        """Fetch a structured secret as a dict of field names to values."""
        raw = self.get_secret(secret_id)
        try:
            fields = json.loads(raw)
            if not isinstance(fields, dict):
                raise ValueError
            return {k: str(v) for k, v in fields.items()}
        except (json.JSONDecodeError, ValueError):
            raise SecretStructureError(f"Secret {secret_id} is not a structured secret")

    def get_field(self, secret_id: str, field: str) -> str:
        """Fetch a single field from a structured secret."""
        fields = self.get_fields(secret_id)
        if field not in fields:
            raise FieldNotFoundError(
                f"Field '{field}' not found in secret {secret_id}. "
                f"Available: {', '.join(fields.keys())}"
            )
        return fields[field]

    # ── List ──

    def list_secrets(self) -> list[SecretListItem]:
        """List all secrets this machine can access."""
        body = self._request("GET", "/v1/secrets")
        return [_parse_secret_item(s) for s in json.loads(body)["secrets"]]

    def list_secrets_by_project(self, project_id: str) -> list[SecretListItem]:
        """List secrets in a specific project."""
        payload = json.dumps({"projectId": project_id})
        body = self._request("POST", "/v1/secrets/list", payload)
        return [_parse_secret_item(s) for s in json.loads(body)["secrets"]]

    # ── Export ──

    def export(self, project_id: Optional[str] = None) -> dict[str, str]:
        """Export all accessible secrets as a flat key-value map (single round trip).

        Structured secrets are flattened: ``SECRET_NAME_FIELD_NAME``.
        """
        payload = json.dumps({"projectId": project_id}) if project_id else None
        body = self._request("POST", "/v1/secrets/export", payload)
        entries = json.loads(body)["secrets"]
        result: dict[str, str] = {}
        for entry in entries:
            env_name = _to_env_name(entry["name"])
            if entry.get("fieldNames") is not None:
                try:
                    fields = json.loads(entry["value"])
                    if isinstance(fields, dict) and fields:
                        for k, v in fields.items():
                            result[f"{env_name}_{_to_env_name(k)}"] = str(v)
                        continue
                except (json.JSONDecodeError, TypeError):
                    pass
            result[env_name] = entry["value"]
        return result

    # ── Watch ──

    def watch(self, secret_id: str, callback: Callable[[WatchEvent], None]) -> None:
        """Register a callback to be invoked when a secret changes.

        Starts a background daemon thread on the first call. The thread polls
        the server at ``poll_interval`` seconds (default 15).

        Args:
            secret_id: The secret to watch.
            callback: Called with a :class:`WatchEvent` on every detected change.
        """
        with self._watchers_lock:
            self._watchers[secret_id] = callback
            if self._poll_thread is None or not self._poll_thread.is_alive():
                self._stop_event.clear()
                self._poll_thread = threading.Thread(
                    target=self._poll_loop, daemon=True
                )
                self._poll_thread.start()

    def unwatch(self, secret_id: str) -> None:
        """Remove a watch callback for a secret.

        If no watches remain, the polling thread is stopped.
        """
        with self._watchers_lock:
            self._watchers.pop(secret_id, None)
            if not self._watchers:
                self._stop_polling()

    def set_poll_interval(self, seconds: int) -> None:
        """Set the polling interval in seconds (minimum 10)."""
        self._poll_interval = max(seconds, 10)

    def close(self) -> None:
        """Stop polling and clear all watches."""
        with self._watchers_lock:
            self._watchers.clear()
            self._stop_polling()

    def _stop_polling(self) -> None:
        """Signal the poll thread to exit and wait for it."""
        self._stop_event.set()
        thread = self._poll_thread
        self._poll_thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)

    def _poll_loop(self) -> None:
        """Background loop that polls the server for secret changes."""
        while not self._stop_event.is_set():
            with self._watchers_lock:
                if not self._watchers:
                    return
                watched_ids = list(self._watchers.keys())

            try:
                payload = json.dumps({"watch": watched_ids})
                body = self._request("POST", "/v1/secrets/poll", payload)
                changes = json.loads(body).get("changes", {})
            except Exception:
                # Network/auth errors during poll are non-fatal; retry next cycle
                self._stop_event.wait(self._poll_interval)
                continue

            for secret_id, info in changes.items():
                status_str = info.get("status", "")

                with self._watchers_lock:
                    callback = self._watchers.get(secret_id)
                if callback is None:
                    continue

                if status_str == "changed":
                    self._handle_changed(secret_id, callback)
                elif status_str in ("deleted", "access_denied"):
                    status = (
                        WatchStatus.DELETED
                        if status_str == "deleted"
                        else WatchStatus.ACCESS_DENIED
                    )
                    event = WatchEvent(secret_id=secret_id, status=status)
                    self._fire_callback(callback, event)
                    with self._watchers_lock:
                        self._watchers.pop(secret_id, None)

            self._stop_event.wait(self._poll_interval)

    def _handle_changed(
        self,
        secret_id: str,
        callback: Callable[[WatchEvent], None],
    ) -> None:
        """Fetch the new value of a changed secret and fire the callback."""
        try:
            value = self.get_secret(secret_id)
        except Exception as exc:
            event = WatchEvent(
                secret_id=secret_id,
                status=WatchStatus.ERROR,
                error=str(exc),
            )
            self._fire_callback(callback, event)
            return

        fields: Optional[dict[str, str]] = None
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                fields = {k: str(v) for k, v in parsed.items()}
        except (json.JSONDecodeError, ValueError):
            pass

        event = WatchEvent(
            secret_id=secret_id,
            status=WatchStatus.CHANGED,
            value=value,
            fields=fields,
        )
        self._fire_callback(callback, event)

    @staticmethod
    def _fire_callback(
        callback: Callable[[WatchEvent], None], event: WatchEvent
    ) -> None:
        """Invoke a user callback, suppressing exceptions."""
        try:
            callback(event)
        except Exception:
            pass

    # ── List Vaults ──

    @staticmethod
    def list_vaults() -> list[str]:
        """List all vault IDs registered on this machine."""
        vaults_dir = Path(_get_vaults_dir())
        if not vaults_dir.is_dir():
            return []
        return [
            d.name
            for d in sorted(vaults_dir.iterdir())
            if d.is_dir() and (d / "identity.json").exists()
        ]

    # ── Internal ──

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[str] = None,
        expect_status: int = 200,
    ) -> str:
        last_error: Optional[SikkerKeyError] = None

        for attempt in range(_MAX_RETRIES + 1):
            if attempt > 0:
                idx = min(attempt - 1, len(_BACKOFF_SECONDS) - 1)
                time.sleep(_BACKOFF_SECONDS[idx])

            # Fresh nonce + timestamp per attempt (replay protection)
            timestamp = str(int(time.time()))
            nonce = base64.b64encode(secrets.token_bytes(16)).decode()
            body_hash = hashlib.sha256((body or "").encode()).hexdigest()
            sign_payload = f"{method}:{path}:{timestamp}:{nonce}:{body_hash}"
            signature = base64.b64encode(
                self._private_key.sign(sign_payload.encode())
            ).decode()

            url = self._identity["apiUrl"] + path
            data = body.encode() if body else None
            req = Request(url, data=data, method=method)
            req.add_header("X-Machine-Id", self._identity["machineId"])
            req.add_header("X-Timestamp", timestamp)
            req.add_header("X-Nonce", nonce)
            req.add_header("X-Signature", signature)
            if body is not None:
                req.add_header("Content-Type", "application/json")

            try:
                with urlopen(req, timeout=15) as resp:
                    response_body = resp.read().decode()
                    code = resp.status
            except URLError as e:
                if hasattr(e, "code"):
                    code = e.code  # type: ignore[union-attr]
                    response_body = e.read().decode() if hasattr(e, "read") else ""  # type: ignore[union-attr]
                else:
                    # Network error — retry
                    last_error = ApiError(f"Network error: {e.reason}", 0)
                    continue

            if code == expect_status:
                return response_body

            # Parse error message
            try:
                error_msg = json.loads(response_body).get("error", response_body)
            except (json.JSONDecodeError, AttributeError):
                error_msg = response_body or f"HTTP {code}"

            exception = _make_exception(code, error_msg)

            if code in _RETRYABLE_CODES and attempt < _MAX_RETRIES:
                last_error = exception
                continue

            raise exception

        raise last_error or ApiError(f"Request failed after {_MAX_RETRIES} retries", 0)


# ── Identity resolution ──

def _get_base_dir() -> str:
    return os.environ.get("SIKKERKEY_HOME", str(Path.home() / ".sikkerkey"))


def _get_vaults_dir() -> str:
    return os.path.join(_get_base_dir(), "vaults")


def _resolve_identity(vault_or_path: Optional[str]) -> str:
    if vault_or_path is not None:
        if vault_or_path.startswith("/") or "identity.json" in vault_or_path:
            return vault_or_path

        vault_id = vault_or_path if vault_or_path.startswith("vault_") else f"vault_{vault_or_path}"
        path = os.path.join(_get_vaults_dir(), vault_id, "identity.json")
        if os.path.exists(path):
            return path
        raise ConfigurationError(
            f"No identity found for vault '{vault_id}'. Expected: {path}. "
            "Run the bootstrap command first."
        )

    env_path = os.environ.get("SIKKERKEY_IDENTITY")
    if env_path:
        return env_path

    vaults_dir = _get_vaults_dir()
    if os.path.isdir(vaults_dir):
        found = [
            os.path.join(vaults_dir, d, "identity.json")
            for d in os.listdir(vaults_dir)
            if os.path.isdir(os.path.join(vaults_dir, d))
            and os.path.exists(os.path.join(vaults_dir, d, "identity.json"))
        ]
        if len(found) == 1:
            return found[0]
        if len(found) > 1:
            names = ", ".join(os.path.basename(os.path.dirname(f)) for f in found)
            raise ConfigurationError(
                f"Multiple vaults registered: {names}. "
                'Specify which vault to use: SikkerKey("vault_id")'
            )

    raise ConfigurationError(
        "No SikkerKey identity found. Run the bootstrap command first.\n"
        f"  Checked: {vaults_dir}/*/identity.json"
    )


def _load_identity(path: str) -> tuple[dict, Ed25519PrivateKey]:
    if not os.path.exists(path):
        raise ConfigurationError(f"Identity file not found: {path}. Run the bootstrap command first.")
    if not os.access(path, os.R_OK):
        raise ConfigurationError(f"Cannot read identity file: {path}. Check file permissions.")

    try:
        with open(path) as f:
            identity = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise ConfigurationError(f"Failed to parse identity file: {e}")

    api_url = identity.get("apiUrl", "")
    if not api_url.startswith("https://") and not api_url.startswith("http://localhost"):
        raise ConfigurationError(
            f"API URL must use HTTPS: {api_url}. Use http://localhost only for local development."
        )

    key_path = identity.get("privateKeyPath", "")
    if not os.path.exists(key_path):
        raise ConfigurationError(f"Private key not found: {key_path}")
    if not os.access(key_path, os.R_OK):
        raise ConfigurationError(f"Cannot read private key: {key_path}. Check file permissions.")

    try:
        with open(key_path, "rb") as f:
            private_key = load_pem_private_key(f.read(), password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ConfigurationError("Private key is not Ed25519")
    except Exception as e:
        raise ConfigurationError(f"Failed to load private key: {e}")

    return identity, private_key


# ── Helpers ──

def _parse_secret_item(data: dict) -> SecretListItem:
    return SecretListItem(
        id=data["id"],
        name=data["name"],
        field_names=data.get("fieldNames"),
        project_id=data.get("projectId"),
    )


def _make_exception(code: int, message: str) -> ApiError:
    if code == 401:
        return AuthenticationError(message)
    if code == 403:
        return AccessDeniedError(message)
    if code == 404:
        return NotFoundError(message)
    if code == 409:
        return ConflictError(message)
    if code == 429:
        return RateLimitedError(message)
    if code == 503:
        return ServerSealedError(message)
    return ApiError(message, code)


def _to_env_name(name: str) -> str:
    result = re.sub(r"[^A-Z0-9]", "_", name.upper())
    result = re.sub(r"_+", "_", result)
    return result.strip("_")
