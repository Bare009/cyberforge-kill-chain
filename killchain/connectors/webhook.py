# Copied from AI-SOC: backend/services/mtls/app/api/ingest/webhook.py and
# ingest_core.py (BatchIngestResponse, extract_alerts, ingest_many).
# killchain changes: path is /ingest/webhook/{connector_id} (no /api/v1); no
# client-certificate dependency; records go to the file sink (sink.py) instead
# of Mongo + Redis, so there is no 503-queue or 402-licence error; duplicates
# are skipped and reported. Status codes otherwise unchanged: 202, 400 bad
# JSON/shape, 401 auth, 413 body over 8 MiB or batch over 500.
"""
Per-connector webhook ingestion
================================
One dynamic endpoint serves every configured log source:

  POST /ingest/webhook/{connector_id}

`connector_id` identifies a record in the connector registry, created from
Settings -> SIEM Integrations. That record decides how the request is
authenticated (bearer token or HMAC signature).

Payload shapes accepted: a single JSON object, a JSON string (one raw log
line), a JSON array of objects and/or strings, or an object wrapping such an
array under a common envelope key (`alerts`, `events`, `records`, ...). See
`sink.split_batch`. Raw FortiGate lines found in the records are appended to
data/ingest/live.log for live mode.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from . import sink as raw_ingest
from .auth import authenticate_connector, touch_connector
from .store import get_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/ingest', tags=['webhook-ingestion'])

# Reject oversized bodies before parsing rather than after, so a hostile sender
# cannot force a large JSON parse.
MAX_BODY_BYTES = 8 * 1024 * 1024  # 8 MiB


class BatchIngestResponse(BaseModel):
    status: str = Field(..., description='accepted | failed')
    message: str
    source: str
    accepted: int = Field(..., description='Number of records accepted (duplicates excluded)')
    alert_ids: List[str] = Field(default_factory=list)
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # killchain additions
    duplicates: int = Field(0, description='Records skipped because this connector already sent them')
    lines_forwarded: int = Field(0, description='Raw log lines appended to data/ingest/live.log')
    not_analysable: int = Field(0, description='Records with no raw log line (stored, not analysed)')


def extract_alerts(body: Any) -> List[Any]:
    """Normalise any accepted body shape into a flat list of records (400 / 413 on failure)."""
    try:
        return raw_ingest.split_batch(body)
    except raw_ingest.BatchShapeError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
                if exc.too_large
                else status.HTTP_400_BAD_REQUEST
            ),
            detail=str(exc),
        ) from exc


@router.post(
    '/webhook/{connector_id}',
    response_model=BatchIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary='Ingest alerts from a configured log source',
    description=(
        'Customer-facing webhook. Authenticated per connector using the credential '
        'issued when the connection was created in Settings. Accepts a single JSON '
        'alert, an array of alerts, or an envelope object containing an array.'
    ),
)
async def ingest_via_webhook(connector_id: str, request: Request):
    store = get_store()

    # Raw bytes are needed before JSON parsing because HMAC is computed over the
    # exact body as sent -- re-serialising the parsed dict would change the bytes
    # and break the signature.
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f'Body too large ({len(body)} bytes, max {MAX_BODY_BYTES}).',
        )

    connector = await authenticate_connector(
        store=store, connector_id=connector_id, request=request, body=body,
    )

    try:
        parsed: Any = json.loads(body) if body else None
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'Invalid JSON body: {exc}',
        )

    if parsed is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Empty request body.',
        )

    alerts = extract_alerts(parsed)

    # The vendor is authoritative here: an operator explicitly created this
    # connector for this log source.
    vendor = str(connector.get('vendor') or 'unknown').lower()

    logger.info('Webhook ingest: connector=%s vendor=%s alerts=%d', connector_id, vendor, len(alerts))

    res = raw_ingest.get_sink().ingest_many(
        alerts, source=vendor, source_hint=vendor, connector=connector, transport='webhook',
    )

    touch_connector(store, connector_id, res.accepted)

    msg = f'{res.accepted} alert(s) accepted, {res.lines_forwarded} log line(s) forwarded to live mode'
    if res.duplicates:
        msg += f', {res.duplicates} duplicate(s) skipped'
    return BatchIngestResponse(
        status='accepted',
        message=msg,
        source=vendor,
        accepted=res.accepted,
        alert_ids=[str(a) for a in res.alert_ids],
        duplicates=res.duplicates,
        lines_forwarded=res.lines_forwarded,
        not_analysable=res.not_analysable,
    )


@router.get(
    '/webhook/{connector_id}/ping',
    summary='Connectivity check for a configured log source',
    description=(
        'Verifies credentials without ingesting anything. Useful when setting up a '
        'webhook in the sending SIEM.'
    ),
)
async def ping_webhook(connector_id: str, request: Request) -> Dict[str, Any]:
    connector = await authenticate_connector(
        store=get_store(), connector_id=connector_id, request=request, body=b'',
    )
    return {
        'status': 'ok',
        'connector_id': connector_id,
        'vendor': connector.get('vendor'),
        'name': connector.get('name'),
        'auth_mode': connector.get('auth_mode'),
    }
