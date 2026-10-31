# Copied from AI-SOC: backend/services/collectors/credentials.py (decrypt side)
# merged with web_app/backend/app/services/connector_credentials.py (encrypt,
# hint, is_configured), since killchain runs both halves in one process.
# killchain change: when CONNECTOR_CREDENTIALS_KEY is unset, a key is generated
# once into <data>/connectors/.credentials_key and a warning is logged
# (hackathon convenience; set the env var for anything real).
"""Encryption of API-pull credentials stored on connector records.

Unlike webhook secrets (which the platform only ever needs to *verify*, so it
stores a hash), an API-pull connector needs the vendor credential in usable
form to call the vendor's API. It is therefore stored encrypted with Fernet
(AES-128-CBC + HMAC-SHA256) under `CONNECTOR_CREDENTIALS_KEY`.

The plaintext is never returned by any API. The UI sees a short hint only.

Key rotation: `CONNECTOR_CREDENTIALS_KEY` may hold several comma-separated
Fernet keys. The first encrypts; all of them are tried for decryption, so a new
key can be prepended, records re-saved, and the old key removed afterwards.

Generate a key with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any, Dict

from .config import connectors_dir

logger = logging.getLogger(__name__)

ENV_VAR = 'CONNECTOR_CREDENTIALS_KEY'
KEY_FILE = '.credentials_key'

_key_lock = threading.Lock()


class CredentialError(RuntimeError):
    """Credentials are missing, undecryptable, or the key is not configured."""


# The web app's name for the same error (siem_integrations.py catches it).
CredentialConfigError = CredentialError


def _file_key() -> str:
    """Read, or create once, the fallback key file. Only used without the env var."""
    path = connectors_dir() / KEY_FILE
    with _key_lock:
        if path.exists():
            return path.read_text(encoding='ascii').strip()
        from cryptography.fernet import Fernet

        path.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key().decode('ascii')
        tmp = path.with_suffix('.tmp')
        tmp.write_text(key + '\n', encoding='ascii')
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        logger.warning(
            '%s is not set; generated a credentials key in %s. API-pull credentials are '
            'encrypted with it. Set %s for a real deployment.', ENV_VAR, path, ENV_VAR,
        )
        return key


def _keys() -> list[str]:
    raw = (os.getenv(ENV_VAR) or '').strip()
    keys = [k.strip() for k in raw.split(',') if k.strip()]
    if not keys:
        try:
            keys = [_file_key()]
        except OSError as exc:
            raise CredentialError(
                f'{ENV_VAR} is not set and no key file could be written: {exc}'
            ) from exc
    return keys


def _fernet():
    from cryptography.fernet import Fernet, MultiFernet

    keys = _keys()
    try:
        return MultiFernet([Fernet(k.encode()) for k in keys])
    except Exception as exc:
        raise CredentialError(f'{ENV_VAR} is not a valid Fernet key: {exc}') from exc


def is_configured() -> bool:
    try:
        _fernet()
        return True
    except CredentialError:
        return False


def decrypt_credentials(token: str | None) -> Dict[str, Any]:
    if not token:
        raise CredentialError('Connector has no stored credentials.')
    from cryptography.fernet import InvalidToken

    try:
        plain = _fernet().decrypt(token.encode('ascii'))
    except InvalidToken as exc:
        raise CredentialError(
            'Stored credentials could not be decrypted -- the key has changed or '
            'the record was written with a different key.'
        ) from exc
    try:
        data = json.loads(plain.decode('utf-8'))
    except ValueError as exc:
        raise CredentialError('Stored credentials are corrupt.') from exc
    if not isinstance(data, dict):
        raise CredentialError('Stored credentials are corrupt.')
    return data


def encrypt_credentials(values: Dict[str, Any]) -> str:
    return _fernet().encrypt(json.dumps(values).encode('utf-8')).decode('ascii')


# ── Web-app API (connector_credentials.py) ───────────────────────────────────

def encrypt(values: dict[str, Any]) -> str:
    return encrypt_credentials(values)


def decrypt(token: str | None) -> dict[str, Any]:
    """Like decrypt_credentials, but no token means no credentials ({})."""
    if not token:
        return {}
    return decrypt_credentials(token)


def hint(values: dict[str, Any]) -> str:
    """Non-reversible display hint: field names plus the last 4 chars of the
    first secret, e.g. 'api_token ••••a1B2'."""
    if not values:
        return ''
    names = ', '.join(sorted(values))
    first = next((str(v) for v in values.values() if v), '')
    tail = first[-4:] if len(first) >= 12 else ''
    return f'{names} ••••{tail}' if tail else names
