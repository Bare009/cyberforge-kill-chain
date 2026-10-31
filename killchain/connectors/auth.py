# Copied from AI-SOC: backend/services/mtls/app/services/connector_auth.py
# killchain changes: the registry is the JSON store (store.py) instead of Mongo;
# mTLS mode is dropped (no client certificates here) and always fails; the
# last-seen/counter write is not throttled (a local file write is cheap) and the
# registry invalidates the lookup cache whenever it changes a connector. The
# bearer / X-SOAR-Token / HMAC scheme is unchanged.
"""Authentication for per-connector webhooks (`/ingest/webhook/{connector_id}`).

Reads the connector registry written by `registry.py`. Both sides must agree on
the document shape and on the secret hashing scheme (SHA-256 hex of the token).

Security posture
----------------
  * Every request must resolve to an enabled connector record.
  * `bearer`/`hmac` connectors must present a valid 256-bit secret.
  * Any other auth mode (including AI-SOC's `mtls`) is rejected.
  * There is deliberately no anonymous fallback.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from fastapi import HTTPException, Request, status

from .store import ConnectorStore, get_store

logger = logging.getLogger(__name__)

# Header names accepted for the shared secret. `Authorization: Bearer` is
# preferred, but several SIEM webhook UIs will not let you set that header, so a
# dedicated header is also accepted.
_TOKEN_HEADER = 'X-SOAR-Token'
_SIGNATURE_HEADER = 'X-SOAR-Signature'

# Registry lookups are cached briefly so a burst of alerts from one connector
# does not re-read the file per alert. registry.py invalidates on every change,
# so the TTL only matters for edits made outside the API.
_CACHE_TTL_SECONDS = 5.0

_cache: Dict[str, Tuple[float, Optional[Dict[str, Any]]]] = {}


def _unauthorized(detail: str) -> HTTPException:
    # Deliberately vague to the caller: a precise reason ("wrong secret" vs
    # "connector disabled") tells an attacker which half of the guess was right.
    logger.warning('Webhook auth rejected: %s', detail)
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Invalid or missing connector credentials.',
    )


def invalidate_cache(connector_id: str | None = None) -> None:
    if connector_id is None:
        _cache.clear()
    else:
        # Keys are '<store path>|<connector_id>'.
        for key in [k for k in _cache if k.endswith(f'|{connector_id}')]:
            _cache.pop(key, None)


def load_connector(store: Optional[ConnectorStore], connector_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a connector record, with a short-lived positive+negative cache."""
    store = store or get_store()
    key = f'{store.path}|{connector_id}'
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and (now - hit[0]) < _CACHE_TTL_SECONDS:
        return hit[1]
    try:
        doc = store.find_one({'connector_id': connector_id})
    except Exception as exc:
        # Fail closed: a broken registry file must not open the endpoint.
        logger.error('Connector lookup failed for %s: %s', connector_id, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Connector registry unavailable.',
        )
    _cache[key] = (now, doc)
    return doc


def _verify_bearer(request: Request, secret_hash: str) -> bool:
    supplied: Optional[str] = None

    auth = request.headers.get('Authorization') or ''
    if auth.lower().startswith('bearer '):
        supplied = auth[7:].strip()
    if not supplied:
        supplied = (request.headers.get(_TOKEN_HEADER) or '').strip()
    if not supplied:
        return False

    digest = hashlib.sha256(supplied.encode('utf-8')).hexdigest()
    return hmac.compare_digest(digest, secret_hash or '')


def _verify_hmac(request: Request, body: bytes, secret_hash: str) -> bool:
    """Verify `X-SOAR-Signature: sha256=<hex>` over the raw request body.

    The registry stores only sha256(token), never the token itself, so the HMAC
    key here is that stored hash. The sender therefore signs with
    sha256(their_token) as the key (hex string, UTF-8). That still binds the
    payload to a secret only the two parties know, and it means a registry dump
    does not reveal a token reusable on the bearer path.
    """
    header = (request.headers.get(_SIGNATURE_HEADER) or '').strip()
    if not header:
        return False
    if header.startswith('sha256='):
        header = header[7:].strip()
    if not header:
        return False

    expected = hmac.new(
        (secret_hash or '').encode('utf-8'), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected.lower(), header.lower())


def connector_transport(connector: Dict[str, Any]) -> str:
    """How a connector delivers alerts. Records with no field are webhook connectors."""
    return str(connector.get('transport') or 'webhook').lower()


async def authenticate_connector(
    *,
    store: Optional[ConnectorStore] = None,
    connector_id: str,
    request: Request,
    body: bytes,
    allowed_transports: frozenset[str] = frozenset({'webhook'}),
) -> Dict[str, Any]:
    """Resolve and authenticate a connector, or raise 401/503."""
    connector = load_connector(store, connector_id)
    if not connector:
        raise _unauthorized(f'unknown connector_id={connector_id!r}')

    if not connector.get('enabled', True):
        raise _unauthorized(f'connector {connector_id!r} is disabled')

    transport = connector_transport(connector)
    if transport not in allowed_transports:
        raise _unauthorized(
            f'connector {connector_id!r} uses transport {transport!r}, '
            f'not one of {sorted(allowed_transports)}'
        )

    mode = (connector.get('auth_mode') or '').lower()
    secret_hash = connector.get('secret_hash') or ''

    if mode == 'bearer':
        ok = _verify_bearer(request, secret_hash)
    elif mode == 'hmac':
        ok = _verify_hmac(request, body, secret_hash)
    else:
        # Includes 'mtls': killchain has no client-certificate layer.
        logger.error(
            'Connector %s has unsupported auth_mode %r; rejecting.', connector_id, mode
        )
        ok = False

    if not ok:
        raise _unauthorized(f'credential check failed for connector {connector_id!r} (mode={mode})')

    return connector


def touch_connector(store: Optional[ConnectorStore], connector_id: str, alert_count: int) -> None:
    """Record last-seen time and increment the received counter.

    Best-effort: a failure here must never fail an otherwise-accepted alert.
    """
    store = store or get_store()
    try:
        store.update_one(
            {'connector_id': connector_id},
            {
                '$set': {'last_seen_at': datetime.now(timezone.utc)},
                '$inc': {'alerts_received': int(alert_count)},
            },
        )
    except Exception as exc:
        logger.debug('touch_connector failed for %s: %s', connector_id, exc)
