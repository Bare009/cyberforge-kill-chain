# Copied from AI-SOC: web_app/backend/app/routes/settings.py (SIEM integration
# routes only). killchain changes: no auth / role guards / audit (killchain has
# no login); the Mongo session is the JSON store; GET /settings/siem-integrations
# merges with no observed Mongo stats; created_by is always null. The paths,
# request bodies and camelCase responses are unchanged.
"""Settings -> SIEM Integrations API (connector CRUD, secret rotation, poll now)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from . import registry as reg
from .config import ingest_public_base_url
from .store import get_store
from .vendors import public_catalog

router = APIRouter(prefix='/settings', tags=['settings'])


def _base_url(request: Request) -> str:
    return ingest_public_base_url(str(request.base_url))


def _bad_request(exc: reg.SiemIntegrationError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


class PullSettingsBody(BaseModel):
    config: dict[str, Any] | None = Field(
        default=None, description='Client settings; fields per GET /settings/siem-vendors pull.configFields.'
    )
    interval_seconds: int | None = Field(default=None, ge=60, le=86_400)


class CreateIntegrationBody(BaseModel):
    vendor: str = Field(..., description='Vendor id from GET /settings/siem-vendors')
    name: str = Field(..., description='Human label, e.g. "Prod cluster"')
    transport: str | None = Field(
        default=None, description='webhook | api_pull | syslog. Defaults to webhook.'
    )
    auth_mode: str | None = Field(
        default=None,
        description='webhook: hmac|bearer; syslog: source_ip. Defaults per transport.',
    )
    allowed_cn_pattern: str | None = Field(
        default=None, description='mTLS only (not supported in killchain).'
    )
    pull: PullSettingsBody | None = Field(default=None, description='api_pull only.')
    # Write-only: never echoed back by any endpoint.
    credentials: dict[str, str] | None = Field(default=None, description='api_pull only.')
    allowed_sources: list[str] | None = Field(
        default=None, description='syslog only: sender IPs / CIDR ranges.'
    )
    time_zone: str | None = Field(
        default=None,
        description='Zone of the source\'s offset-less timestamps: IANA name or "+05:30". Default UTC.',
    )
    silence_minutes: int | None = Field(
        default=None, description='Alert when silent this long. Omit/-1 = learned, 0 = off.'
    )


class UpdateIntegrationBody(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    allowed_cn_pattern: str | None = None
    pull: PullSettingsBody | None = None
    # Blank / omitted fields keep their stored value.
    credentials: dict[str, str] | None = None
    allowed_sources: list[str] | None = None
    # '' clears (UTC).
    time_zone: str | None = None
    # -1 = back to learned threshold, 0 = off.
    silence_minutes: int | None = None


@router.get('/siem-vendors')
async def siem_vendors(request: Request) -> dict:
    """Catalog of supported log sources, plus the platform's ingest addresses."""
    return {'vendors': public_catalog(), 'endpoints': reg.ingest_endpoints(_base_url(request))}


@router.get('/siem-integrations')
async def list_siem_integrations(request: Request) -> dict:
    """Configured connectors with their ingest counters."""
    integrations = await reg.list_integrations(get_store(), base_url=_base_url(request))
    rows = await reg.merge_with_observed_sources(integrations, [])
    return {'integrations': rows}


@router.post('/siem-integrations', status_code=status.HTTP_201_CREATED)
async def create_siem_integration(body: CreateIntegrationBody, request: Request) -> dict:
    """Create a connector. The response contains `secret` — shown only here.

    The plaintext secret is never persisted and cannot be retrieved later; if it
    is lost, rotate it. API-pull credentials are stored encrypted and are never
    returned.
    """
    try:
        return await reg.create_integration(
            get_store(),
            vendor=body.vendor,
            name=body.name,
            transport=body.transport,
            auth_mode=body.auth_mode,
            allowed_cn_pattern=body.allowed_cn_pattern,
            pull_config=body.pull.config if body.pull else None,
            pull_interval_seconds=body.pull.interval_seconds if body.pull else None,
            credentials=body.credentials,
            allowed_sources=body.allowed_sources,
            time_zone=body.time_zone,
            silence_minutes=body.silence_minutes,
            created_by=None,
            base_url=_base_url(request),
        )
    except reg.SiemIntegrationError as exc:
        raise _bad_request(exc) from exc


@router.patch('/siem-integrations/{connector_id}')
async def update_siem_integration(connector_id: str, body: UpdateIntegrationBody, request: Request) -> dict:
    try:
        return await reg.update_integration(
            get_store(),
            connector_id,
            name=body.name,
            enabled=body.enabled,
            allowed_cn_pattern=body.allowed_cn_pattern,
            pull_config=body.pull.config if body.pull else None,
            pull_interval_seconds=body.pull.interval_seconds if body.pull else None,
            credentials=body.credentials,
            allowed_sources=body.allowed_sources,
            time_zone=body.time_zone,
            silence_minutes=body.silence_minutes,
            base_url=_base_url(request),
        )
    except reg.SiemIntegrationError as exc:
        raise _bad_request(exc) from exc


@router.post('/siem-integrations/{connector_id}/rotate-secret')
async def rotate_siem_integration_secret(connector_id: str, request: Request) -> dict:
    """Issue a new secret. The previous one stops working immediately."""
    try:
        return await reg.rotate_secret(get_store(), connector_id, base_url=_base_url(request))
    except reg.SiemIntegrationError as exc:
        raise _bad_request(exc) from exc


@router.post('/siem-integrations/{connector_id}/poll-now')
async def poll_siem_integration_now(connector_id: str, request: Request) -> dict:
    """Run an API-pull connector on the poller's next tick (within seconds)."""
    try:
        return await reg.poll_now(get_store(), connector_id, base_url=_base_url(request))
    except reg.SiemIntegrationError as exc:
        raise _bad_request(exc) from exc


@router.get('/siem-integrations/{connector_id}/agents')
async def list_siem_integration_agents(connector_id: str) -> dict:
    """Forwarding agents that have sent a heartbeat for this connector (none in killchain)."""
    return {'agents': await reg.list_agents(get_store(), connector_id)}


@router.get('/syslog/unmatched-sources')
async def list_unmatched_syslog_sources() -> dict:
    """Addresses that sent syslog matching no enabled connection (dropped)."""
    return {'sources': await reg.list_unmatched_syslog_sources(get_store())}


@router.delete('/siem-integrations/{connector_id}', status_code=status.HTTP_204_NO_CONTENT,
               response_model=None)
async def delete_siem_integration(connector_id: str) -> None:
    """Remove a connector. Records already ingested through it are not touched."""
    try:
        await reg.delete_integration(get_store(), connector_id)
    except reg.SiemIntegrationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
