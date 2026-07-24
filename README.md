# SikkerKey Python SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/sikkerkey)](https://pypi.org/project/sikkerkey/)
[![Python](https://img.shields.io/pypi/pyversions/sikkerkey)](https://pypi.org/project/sikkerkey/)

Use the official SikkerKey Python SDK to give a Python application read access to the secrets its machine is authorized to use.

The SDK can:

- Read standard and structured secrets.
- List the secrets available to a machine.
- Export accessible secrets as application-friendly key/value pairs.
- Monitor selected secrets for changes.
- Use persistent machine identities or memory-only ephemeral identities.
- Keep an optional encrypted fallback cache for temporary service or network outages.

After the client is initialized, every secret request is authenticated with the machine's Ed25519 identity. The SDK supports Python 3.10 or newer and uses `cryptography` for Ed25519 and encrypted-cache operations.

## Install the SDK

```bash
pip install sikkerkey
```

To install the version represented by this source:

```bash
pip install sikkerkey==1.3.0
```

## Read your first secret

```python
from sikkerkey import SikkerKey

sikker_key = SikkerKey("vault_abc123")
api_key = sikker_key.get_secret("sk_stripe_key")
```

The SDK loads the machine identity from:

```text
~/.sikkerkey/vaults/vault_abc123/identity.json
```

It signs the request with the machine's Ed25519 private key and returns the secret value as a `str`. Your application's access remains limited by the machine's configured access.

All SDK calls are synchronous. Run network operations in an executor when using them from an asynchronous application.

## Create a client

```python
# Select a registered vault.
by_vault = SikkerKey("vault_abc123")

# Load a specific identity file.
by_path = SikkerKey(
    "/etc/sikkerkey/vaults/vault_abc123/identity.json"
)

# Use SIKKERKEY_IDENTITY or auto-select the only registered vault.
automatically = SikkerKey()
```

When no argument is supplied, the SDK checks `SIKKERKEY_IDENTITY` first. If that variable is not set, it uses the only registered vault under `~/.sikkerkey/vaults/`.

If more than one vault is registered, select one explicitly. Missing identities, unreadable keys, invalid identity files, and ambiguous vault selection raise `ConfigurationError`.

The `vault_` prefix is added when a vault ID is supplied without it.

### Use a different identity directory

```bash
export SIKKERKEY_HOME=/var/lib/sikkerkey
```

The SDK will look under:

```text
/var/lib/sikkerkey/vaults/<vault-id>/identity.json
```

## Use an ephemeral identity

`bootstrap_in_memory` is designed for short-lived or read-only environments where an identity should not be stored on disk.

```python
import os

from sikkerkey import SikkerKey

sikker_key = SikkerKey.bootstrap_in_memory(
    os.environ["SIKKERKEY_VAULT_ID"],
    os.environ["SIKKERKEY_ENROLLMENT_TOKEN"],
)

database_url = sikker_key.get_secret(
    "sk_db_prod"
)
```

During bootstrap, the SDK:

1. Generates an Ed25519 key pair in memory.
2. Uses the enrollment token to register an ephemeral machine.
3. Keeps the private key inside the running Python process.
4. Returns a client ready to read the secrets allowed by the token's access policy.

Nothing is written to disk. The private key disappears when the process exits.

The enrollment token registers the machine; it does not read secrets itself. The resulting machine remains subject to the token's permitted scope, use limit, hostname rules, and machine lifetime. Reads raise `AuthenticationError` after the machine expires.

### Set the machine hostname and name

```python
sikker_key = SikkerKey.bootstrap_in_memory(
    vault_id,
    enrollment_token,
    hostname="worker-1",
    name="invoice-runner",
)
```

`hostname` defaults to the `HOSTNAME` environment variable and then to `serverless`. A name pattern configured on the enrollment token takes precedence over `name`.

For reliable ephemeral deployments:

- Set a machine lifetime long enough for the workload to finish.
- Allow enough token uses for expected cold starts and concurrency.
- Use a unique name pattern such as `worker-{uuid8}`.
- Ensure the vault's IP allowlist permits the workload's outbound address when an allowlist is enabled.

Each active ephemeral machine uses a machine slot until it expires.

## Read secrets

### Standard secrets

```python
api_key = sikker_key.get_secret(
    "sk_stripe_prod"
)
```

### Structured secrets

```python
database = sikker_key.get_fields(
    "sk_db_prod"
)

host = database["host"]
username = database["username"]
password = database["password"]
```

`get_fields` expects a JSON object and converts each property to a string. It raises `SecretStructureError` for another structure.

Use `get_field` when the application needs one field:

```python
password = sikker_key.get_field(
    "sk_db_prod",
    "password",
)
```

A missing field raises `FieldNotFoundError` with the available field names.

## Discover accessible secrets

```python
secrets = sikker_key.list_secrets()

for secret in secrets:
    print(f"{secret.id}: {secret.name}")
```

Limit the result to one project:

```python
production_secrets = (
    sikker_key.list_secrets_by_project(
        "proj_production"
    )
)
```

Each `SecretListItem` contains:

| Attribute | Type | Meaning |
|---|---|---|
| `id` | `str` | Secret ID used by read methods |
| `name` | `str` | Display name |
| `field_names` | `Optional[str]` | Optional structured-field metadata |
| `project_id` | `Optional[str]` | Owning project, when present |

Listing returns metadata, not secret values.

## Export secrets for application configuration

```python
configuration = sikker_key.export()
```

Limit the export to a project:

```python
production_configuration = (
    sikker_key.export("proj_production")
)
```

The returned `dict[str, str]` uses uppercase environment-style names. Structured secrets are expanded into one entry per field:

```text
API_KEY
DB_CREDENTIALS_HOST
DB_CREDENTIALS_USERNAME
DB_CREDENTIALS_PASSWORD
```

Apply the result to the current process when appropriate:

```python
import os

os.environ.update(configuration)
```

## Continue reads during temporary outages

The fallback cache is disabled by default:

```python
sikker_key = (
    SikkerKey("vault_abc123")
    .enable_cache()
)
```

After it is enabled, successful `get_secret` reads are stored under:

```text
~/.sikkerkey/vaults/<vault-id>/cache/
```

`get_fields` and `get_field` use `get_secret`, so their successful reads are cached too. Cache writes are best-effort and cannot turn a successful live read into a failure.

The SDK can return a cached value after a network failure, request timeout, or HTTP `502`, `503`, `504`, `520` through `527`, or `530`.

Authentication failures, revoked access, missing secrets, rate limits, and other authoritative responses are never replaced by cached values.

Entries use AES-256-GCM with a key derived from the machine's Ed25519 identity and vault ID. Tampered entries and entries belonging to another identity are rejected. The `.skc` format is compatible with other SikkerKey SDKs and the SikkerKey CLI.

### Limit cache age and observe fallback use

```python
sikker_key = SikkerKey(
    "vault_abc123"
).enable_cache(
    max_age=3600,
    on_fallback=lambda secret_id, cached_at: print(
        f"Using cached value for {secret_id} "
        f"from epoch {cached_at}"
    ),
)
```

`max_age` is measured in seconds and may be an `int` or `float`. Passing `None` means no automatic expiry. The callback is optional; fallback is otherwise silent.

The cache is intended for a host with a persistent, protected identity directory, not a memory-only identity that disappears with the process.

## Monitor secrets for changes

```python
from sikkerkey import WatchStatus


def handle_change(event):
    if event.status == WatchStatus.CHANGED:
        print(f"{event.secret_id} changed")
        print(event.fields)
    elif event.status == WatchStatus.DELETED:
        print(f"{event.secret_id} was deleted")
    elif event.status == WatchStatus.ACCESS_DENIED:
        print(
            f"Access to {event.secret_id} was removed"
        )
    elif event.status == WatchStatus.ERROR:
        print(
            f"Could not retrieve the update: {event.error}"
        )


sikker_key.watch(
    "sk_db_credentials",
    handle_change,
)
```

The SDK polls on a background daemon thread. It performs the first poll when the thread starts, then waits 15 seconds between cycles by default.

For changed secrets, `value` contains the complete new value and `fields` contains parsed structured fields when available. Deleted and inaccessible secrets are automatically removed from the watch list. A failed polling request is skipped and retried during the next cycle.

Callbacks run on the polling thread. Callback exceptions are contained by the SDK so they do not stop later polling; log and handle callback failures inside the callback when they matter to your application.

### Change or stop polling

```python
sikker_key.set_poll_interval(30)
sikker_key.unwatch("sk_db_credentials")
sikker_key.close()
```

The interval is measured in seconds and has a minimum of 10. `close` stops the polling thread and clears all callbacks, while leaving the client available for subsequent reads.

## Work with more than one vault

```python
production = SikkerKey("vault_production")
staging = SikkerKey("vault_staging")

production_key = production.get_secret(
    "sk_api_key"
)
staging_key = staging.get_secret(
    "sk_api_key"
)
```

List locally registered vault IDs:

```python
vault_ids = SikkerKey.list_vaults()
```

The returned list is sorted alphabetically.

## Inspect the active machine

```python
print(sikker_key.machine_id)
print(sikker_key.machine_name)
print(sikker_key.vault_id)
print(sikker_key.api_url)
```

| Property | Meaning |
|---|---|
| `machine_id` | Machine UUID assigned by SikkerKey |
| `machine_name` | Machine name assigned during provisioning or enrollment |
| `vault_id` | Vault associated with the identity |
| `api_url` | Service endpoint stored in the identity |

## Handle errors

```python
from sikkerkey import (
    AccessDeniedError,
    ApiError,
    AuthenticationError,
    ConfigurationError,
    NotFoundError,
    RateLimitedError,
)

try:
    value = sikker_key.get_secret("sk_example")
except NotFoundError as error:
    print(f"Secret not found: {error}")
except AccessDeniedError as error:
    print(f"Access denied: {error}")
except AuthenticationError as error:
    print(f"Authentication failed: {error}")
except RateLimitedError as error:
    print(f"Request remained rate-limited: {error}")
except ApiError as error:
    print(
        f"SikkerKey returned HTTP "
        f"{error.http_status}: {error}"
    )
except ConfigurationError as error:
    print(
        f"Machine identity could not be loaded: {error}"
    )
```

### Exception reference

| Exception | When it is used |
|---|---|
| `ConfigurationError` | Identity, key, vault-selection, or bootstrap configuration is invalid |
| `AuthenticationError` | HTTP `401` |
| `AccessDeniedError` | HTTP `403` |
| `NotFoundError` | HTTP `404` |
| `ConflictError` | HTTP `409` |
| `RateLimitedError` | HTTP `429` |
| `ServerSealedError` | HTTP `503` |
| `ApiError` | Another HTTP or network error; inspect `http_status` |
| `SecretStructureError` | `get_fields` or `get_field` received a non-object value |
| `FieldNotFoundError` | The requested structured field does not exist |

Network failures and request timeouts use `ApiError` with `http_status == 0`.

### Retries and timeout

Authenticated secret requests retry network failures and HTTP `429` or `503` responses up to three times. Retries wait 1, 2, and 4 seconds, and every attempt receives a fresh timestamp and nonce.

Each request has a 15-second timeout. Other HTTP responses are returned immediately as their matching exception.

## Feature-to-API reference

| What you want to do | SDK API | Result |
|---|---|---|
| Create a client from disk | `SikkerKey(vault_or_path?)` | `SikkerKey` |
| Create an ephemeral client | `SikkerKey.bootstrap_in_memory(vault_id, token, *, hostname?, name?)` | `SikkerKey` |
| List locally registered vaults | `SikkerKey.list_vaults()` | `list[str]` |
| Enable outage fallback | `enable_cache(max_age?, on_fallback?)` | The same `SikkerKey` client |
| Read a standard secret | `get_secret(secret_id)` | `str` |
| Read every structured field | `get_fields(secret_id)` | `dict[str, str]` |
| Read one structured field | `get_field(secret_id, field)` | `str` |
| List accessible secrets | `list_secrets()` | `list[SecretListItem]` |
| List accessible secrets in a project | `list_secrets_by_project(project_id)` | `list[SecretListItem]` |
| Export accessible values | `export(project_id?)` | `dict[str, str]` |
| Monitor a secret | `watch(secret_id, callback)` | `None` |
| Stop monitoring one secret | `unwatch(secret_id)` | `None` |
| Set the polling interval | `set_poll_interval(seconds)` | `None` |
| Stop all monitoring | `close()` | `None` |

## Runtime footprint

The SDK uses:

- `cryptography>=41.0` for Ed25519, AES-GCM, and HKDF.
- Python's standard `urllib` for HTTPS.
- Python's standard `json`, `threading`, `hashlib`, and filesystem modules.

## Documentation

- [SikkerKey documentation](https://docs.sikkerkey.com)
- [SDK overview](https://docs.sikkerkey.com/docs/sdk/overview)
- [Python SDK reference](https://docs.sikkerkey.com/docs/sdk/python)
- [Machine authentication](https://docs.sikkerkey.com/docs/machines/signatures)

## License

The SikkerKey Python SDK is available under the [MIT License](LICENSE).
