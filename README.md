# SikkerKey Python SDK

The official Python SDK for [SikkerKey](https://sikkerkey.com). Read-only access to secrets using Ed25519 machine authentication.

## Installation

```bash
pip install sikkerkey
```

Requires Python 3.10+. Single dependency: `cryptography` (for Ed25519 signing).

## Quick Start

```python
from sikkerkey import SikkerKey

sk = SikkerKey("vault_abc123")
api_key = sk.get_secret("sk_stripe_key")
```

The SDK reads the machine identity from `~/.sikkerkey/vaults/<vault-id>/identity.json`, signs every request with the machine's Ed25519 private key, and returns the decrypted value.

## Client Creation

```python
# Explicit vault ID
sk = SikkerKey("vault_abc123")

# Direct path to identity file
sk = SikkerKey("/etc/sikkerkey/vaults/vault_abc123/identity.json")

# Auto-detect from SIKKERKEY_IDENTITY env or single vault on disk
sk = SikkerKey()
```

Raises `ConfigurationError` if the identity is missing, the key can't be loaded, or multiple vaults exist without a specified vault ID.

## Reading Secrets

### Single Value

```python
api_key = sk.get_secret("sk_stripe_prod")
```

### Structured (Multiple Fields)

```python
fields = sk.get_fields("sk_db_prod")
host = fields["host"]       # "db.example.com"
password = fields["password"]  # "hunter2"
```

Raises `SecretStructureError` if the secret value is not a JSON object.

### Single Field

```python
password = sk.get_field("sk_db_prod", "password")
```

Raises `FieldNotFoundError` if the field doesn't exist. The error message includes available field names.

## Listing Secrets

```python
# All secrets this machine can access
secrets = sk.list_secrets()
for s in secrets:
    print(f"{s.id}: {s.name}")

# Secrets in a specific project
secrets = sk.list_secrets_by_project("proj_production")
```

Each `SecretListItem` has `id`, `name`, `field_names` (None for single-value), and `project_id`.

## Export

```python
# All secrets as a flat dict
env = sk.export()
# {"API_KEY": "sk-live-...", "DB_CREDS_HOST": "db.example.com", "DB_CREDS_PASSWORD": "s3cret"}

# Scoped to a project
env = sk.export("proj_production")

# Inject into environment
import os
os.environ.update(sk.export())
```

Structured secrets are flattened: `SECRET_NAME_FIELD_NAME`.

## Multi-Vault

```python
prod = SikkerKey("vault_a1b2c3")
staging = SikkerKey("vault_x9y8z7")

prod_key = prod.get_secret("sk_api_key")
staging_key = staging.get_secret("sk_api_key")
```

### List Registered Vaults

```python
vaults = SikkerKey.list_vaults()
# ["vault_a1b2c3", "vault_x9y8z7"]
```

## Machine Info

```python
sk.machine_id    # "550e8400-e29b-41d4-a716-446655440000"
sk.machine_name  # "api-server-1"
sk.vault_id      # "vault_abc123"
sk.api_url       # "https://api.sikkerkey.com"
```

## Error Handling

```python
from sikkerkey import SikkerKey, NotFoundError, AccessDeniedError, AuthenticationError

try:
    secret = sk.get_secret("sk_nonexistent")
except NotFoundError:
    # Secret doesn't exist
except AccessDeniedError:
    # Machine not approved or no grant
except AuthenticationError:
    # Invalid signature or unknown machine
```

### Exception Hierarchy

```
SikkerKeyError
├── ConfigurationError      — identity file missing, bad key, invalid config
├── SecretStructureError    — secret is not a JSON object (get_fields)
├── FieldNotFoundError      — field not in structured secret (get_field)
└── ApiError                — HTTP error (has http_status attribute)
    ├── AuthenticationError — 401
    ├── AccessDeniedError   — 403
    ├── NotFoundError       — 404
    ├── ConflictError       — 409
    ├── RateLimitedError    — 429
    └── ServerSealedError   — 503
```

## Identity Resolution

1. **Explicit path** — starts with `/` or contains `identity.json`
2. **Vault ID** — looks up `~/.sikkerkey/vaults/{vault_id}/identity.json`
3. **`SIKKERKEY_IDENTITY` env** — path to identity file
4. **Auto-detect** — single vault on disk

The `vault_` prefix is added automatically if not present.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SIKKERKEY_IDENTITY` | Path to `identity.json` — overrides vault lookup |
| `SIKKERKEY_HOME` | Base config directory (default: `~/.sikkerkey`) |

## Retry Behavior

429 and 503 responses are retried up to 3 times with exponential backoff (1s, 2s, 4s). Each retry uses a fresh timestamp and nonce. Network errors are also retried.

## Authentication

Every request includes Ed25519-signed headers: `X-Machine-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature`. HTTPS enforced for non-localhost. 15-second timeout.

## Method Reference

| Method | Returns | Description |
|--------|---------|-------------|
| `SikkerKey(vault_or_path?)` | `SikkerKey` | Create client |
| `SikkerKey.list_vaults()` | `list[str]` | List registered vault IDs (static) |
| `get_secret(secret_id)` | `str` | Read a secret value |
| `get_fields(secret_id)` | `dict[str, str]` | Read structured secret |
| `get_field(secret_id, field)` | `str` | Read single field |
| `list_secrets()` | `list[SecretListItem]` | List all accessible secrets |
| `list_secrets_by_project(project_id)` | `list[SecretListItem]` | List secrets in a project |
| `export(project_id?)` | `dict[str, str]` | Export as env map |

## Dependencies

- `cryptography>=41.0` — Ed25519 key loading and signing

All other functionality uses Python stdlib: `urllib`, `json`, `hashlib`, `os`, `pathlib`.

## Documentation

- [SDK Overview](https://docs.sikkerkey.com/docs/sdk/overview)
- [Python SDK Reference](https://docs.sikkerkey.com/docs/sdk/python)
- [Machine Authentication](https://docs.sikkerkey.com/docs/machines/signatures)

## License

Proprietary. See [sikkerkey.com/terms](https://sikkerkey.com/terms) for details.
