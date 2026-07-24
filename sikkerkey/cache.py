"""On-disk fallback secret cache — the Python port of the .skc format defined by
the SikkerKey CLI. Files are byte-compatible with the CLI and the other SDKs: same
key derivation, AES-256-GCM sealing, AAD, envelope, and path, so a cache written by
one is readable by all.

Strictly opt-in (SikkerKey.enable_cache) and inert until then.

    key   = HKDF-SHA256(ikm = ed25519_seed, salt = vault_id, info = "sikkerkey-cache-v1")  -> 32 bytes
    entry = AES-256-GCM(key, nonce = random 12B, plaintext = {name,value,fieldNames} JSON,
                        aad = "sikkerkey-cache-v1\\0{vaultId}\\0{machineId}\\0{secretId}\\0{cachedAt}")
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_FORMAT_VERSION = 1
_KDF_INFO = "sikkerkey-cache-v1"
_FILE_EXT = ".skc"
# Guards the on-disk filename against traversal; real secret ids are sk_<alnum>.
_SAFE_SECRET_ID = re.compile(r"^[A-Za-z0-9_-]+$")


def _base_dir() -> str:
    # Mirrors the client's _get_base_dir so the cache lands beside the identity.
    return os.environ.get("SIKKERKEY_HOME", str(Path.home() / ".sikkerkey"))


def cache_dir(vault_id: str) -> str:
    return os.path.join(_base_dir(), "vaults", vault_id, "cache")


@dataclass
class CacheResult:
    secret_id: str
    name: str
    value: str
    field_names: Optional[str]
    cached_at: int  # epoch seconds


def derive_key(seed: bytes, vault_id: str) -> bytes:
    """Derive the 32-byte AES-256 cache key from the Ed25519 seed, bound to the vault."""
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=vault_id.encode("utf-8"),
        info=_KDF_INFO.encode("utf-8"),
    ).derive(seed)


class SecretCache:
    """Reads and writes encrypted per-secret .skc entries for one vault."""

    def __init__(self, vault_id: str, machine_id: str, key: bytes):
        self._vault_id = vault_id
        self._machine_id = machine_id
        self._key = key

    def store(self, secret_id: str, name: str, value: str, field_names: Optional[str]) -> None:
        if not _SAFE_SECRET_ID.match(secret_id):
            raise ValueError(f"refusing to cache unsafe secret id {secret_id!r}")
        cached_at = int(time.time())
        payload = {"value": value}
        if name:
            payload["name"] = name
        if field_names is not None:
            payload["fieldNames"] = field_names
        plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        nonce = secrets.token_bytes(12)
        ct = AESGCM(self._key).encrypt(nonce, plaintext, self._aad(secret_id, cached_at))
        envelope = json.dumps(
            {
                "v": _FORMAT_VERSION,
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ct": base64.b64encode(ct).decode("ascii"),
                "cachedAt": cached_at,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self._write_atomic(self._file_path(secret_id), envelope)

    def load(self, secret_id: str) -> Optional[CacheResult]:
        """Return the cached entry, or None on a miss. A decrypt failure (tampered,
        or from a different identity) raises."""
        if not _SAFE_SECRET_ID.match(secret_id):
            return None
        try:
            with open(self._file_path(secret_id), "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return None
        return self._decode(secret_id, data)

    def _decode(self, secret_id: str, data: bytes) -> Optional[CacheResult]:
        env = json.loads(data)
        if env.get("v") != _FORMAT_VERSION:
            return None  # a newer format wrote this; treat as a miss
        nonce = base64.b64decode(env["nonce"])
        ct = base64.b64decode(env["ct"])
        cached_at = int(env["cachedAt"])
        # Raises cryptography.exceptions.InvalidTag on a wrong key or tampered entry.
        plaintext = AESGCM(self._key).decrypt(nonce, ct, self._aad(secret_id, cached_at))
        p = json.loads(plaintext)
        return CacheResult(
            secret_id=secret_id,
            name=p.get("name", ""),
            value=str(p.get("value", "")),
            field_names=p.get("fieldNames"),
            cached_at=cached_at,
        )

    def _file_path(self, secret_id: str) -> str:
        return os.path.join(cache_dir(self._vault_id), secret_id + _FILE_EXT)

    def _aad(self, secret_id: str, cached_at: int) -> bytes:
        # domain || vault || machine || secret || timestamp, null-separated.
        return "\x00".join(
            [_KDF_INFO, self._vault_id, self._machine_id, secret_id, str(cached_at)]
        ).encode("utf-8")

    @staticmethod
    def _write_atomic(path: str, data: bytes) -> None:
        d = os.path.dirname(path)
        os.makedirs(d, mode=0o700, exist_ok=True)
        tmp = os.path.join(d, f".skc-{os.getpid()}-{secrets.token_hex(6)}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise


def clear_cache(vault_id: str) -> None:
    """Remove the entire cache directory for a vault."""
    import shutil

    shutil.rmtree(cache_dir(vault_id), ignore_errors=True)


def count_cache(vault_id: str) -> int:
    """How many secrets are currently cached for a vault."""
    try:
        return sum(1 for n in os.listdir(cache_dir(vault_id)) if n.endswith(_FILE_EXT))
    except FileNotFoundError:
        return 0
