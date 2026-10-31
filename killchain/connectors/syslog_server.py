# Copied from AI-SOC: backend/services/collectors/syslog_server.py
# killchain changes: plain UDP/TCP only (the TLS listener and certificate-CN
# routing are removed); connectors come from the JSON store; messages go to the
# file sink (sink.py), with the message body set as `full_log` so a FortiGate
# key=value line reaches data/ingest/live.log intact; unmatched senders are kept
# in memory (unmatched_sources) instead of a Mongo collection; metrics,
# licensing and tenancy removed. Off unless KILLCHAIN_SYSLOG=1.
"""Syslog listener: UDP and TCP, feeding the sink.

Routing and authentication
--------------------------
Syslog has no application-level credential, so each message is attributed to
a `transport: syslog` connector by *where it came from*: the sender address
must fall inside one of the connector's `syslog.allowed_sources` CIDRs.
Longest prefix wins when connectors overlap.

Messages from senders that match no enabled connector are dropped -- nothing is
stored -- and the address is recorded (in memory) so an operator can see what
is knocking (typically a NAT address they did not expect). Plain UDP/TCP source
addresses can be spoofed on an untrusted network; keep the listener on a
trusted segment.

Framing (TCP): RFC 6587 octet counting (`LEN SP MSG`) and newline / NUL
delimited messages are both accepted, detected per message.

Back-pressure: messages go through a bounded queue to a pool of ingest
workers. When it is full, UDP datagrams are dropped (and counted) while TCP
readers simply wait, which pushes back on the sender through TCP flow control.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any, Dict, List, Optional, Tuple

from .config import CollectorSettings
from .sink import Sink, get_sink
from .store import ConnectorStore, get_store
from .syslog_parser import _parse_envelope, _to_text, parse_syslog

logger = logging.getLogger(__name__)

# RFC 6587 octet counting: "LEN SP <PRI>...". Requiring the '<' of the PRI
# keeps a newline-framed message that merely starts with a number
# ("2026 backup finished") from being misread as a length prefix.
_OCTET_RE = re.compile(rb'^(\d{1,6}) (?=<)')
_OCTET_PREFIX_RE = re.compile(rb'^\d{1,6} ?$')
_MAX_UNMATCHED_TRACKED = 1000
_COUNTER_FLUSH_SECONDS = 5

_TZ_OFFSET_RE = re.compile(r'^([+-])(\d{2}):(\d{2})$')

# Unmatched senders, shared with registry.list_unmatched_syslog_sources.
_unmatched: Dict[str, Dict[str, Any]] = {}
_unmatched_lock = threading.Lock()


def unmatched_sources(limit: int = 50) -> List[Dict[str, Any]]:
    with _unmatched_lock:
        rows = sorted(_unmatched.items(), key=lambda kv: kv[1]['last_seen_at'], reverse=True)[:limit]
    return [
        {
            'address': ip,
            'count': int(e['count']),
            'listener': e['listener'],
            'certCn': None,
            'firstSeenAt': e['first_seen_at'].isoformat(),
            'lastSeenAt': e['last_seen_at'].isoformat(),
        }
        for ip, e in rows
    ]


def resolve_timezone(value: Optional[str]) -> Optional[tzinfo]:
    """Connector time zone (registry.clean_time_zone output) -> tzinfo; None = UTC."""
    if not value:
        return None
    if value == 'UTC':
        return timezone.utc
    m = _TZ_OFFSET_RE.match(value)
    if m:
        delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
        return timezone(-delta if m.group(1) == '-' else delta)
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(value)
    except Exception:
        return None


def _peer_ip(addr: Any) -> str:
    if isinstance(addr, (tuple, list)) and addr:
        return str(addr[0])
    return str(addr or '')


def _normalise_ip(ip: str) -> Optional[ipaddress._BaseAddress]:
    try:
        parsed = ipaddress.ip_address(ip.split('%', 1)[0])
    except ValueError:
        return None
    mapped = getattr(parsed, 'ipv4_mapped', None)
    return mapped or parsed


# ── Connector routing ────────────────────────────────────────────────────────

class ConnectorRouter:
    """In-memory map of enabled syslog connectors, refreshed from the store."""

    def __init__(self, store: ConnectorStore) -> None:
        self.store = store
        self._by_net: List[Tuple[Any, Dict[str, Any]]] = []
        self.loaded_at = 0.0

    def refresh(self) -> None:
        docs = self.store.find({'transport': 'syslog', 'enabled': True})
        by_net: List[Tuple[Any, Dict[str, Any]]] = []
        for doc in docs:
            mode = str(doc.get('auth_mode') or 'source_ip').lower()
            if mode != 'source_ip':
                continue        # mTLS syslog is not supported in killchain
            for cidr in (doc.get('syslog') or {}).get('allowed_sources') or []:
                try:
                    by_net.append((ipaddress.ip_network(str(cidr).strip(), strict=False), doc))
                except ValueError:
                    logger.error('Bad CIDR %r on syslog connector %s', cidr, doc.get('connector_id'))
        by_net.sort(key=lambda t: t[0].prefixlen, reverse=True)
        self._by_net = by_net
        self.loaded_at = time.monotonic()

    def match_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        addr = _normalise_ip(ip)
        if addr is None:
            return None
        for net, doc in self._by_net:
            if addr.version == net.version and addr in net:
                return doc
        return None


# ── TCP framing ──────────────────────────────────────────────────────────────

class FrameError(ValueError):
    pass


def extract_frame(buf: bytearray, max_len: int) -> Optional[Tuple[bytes, int]]:
    """Pull one message off the front of `buf`.

    Returns (message, bytes_consumed), or None when more data is needed.
    Raises FrameError for an octet-counted frame longer than `max_len`.
    """
    if not buf:
        return None
    if buf[:1].isdigit():
        head = bytes(buf[:9])
        m = _OCTET_RE.match(head)
        if m:
            length = int(m.group(1))
            if length > max_len:
                raise FrameError(f'octet-counted frame of {length} bytes exceeds {max_len}')
            start = m.end()
            if len(buf) < start + length:
                return None
            return bytes(buf[start:start + length]), start + length
        if _OCTET_PREFIX_RE.match(head):
            return None  # "123" or "123 " -- could still become "123 <..."
    nl = buf.find(b'\n')
    nul = buf.find(b'\x00')
    ends = [i for i in (nl, nul) if i != -1]
    if not ends:
        return None
    end = min(ends)
    return bytes(buf[:end]).rstrip(b'\r'), end + 1


# ── Server ───────────────────────────────────────────────────────────────────

@dataclass
class _Message:
    connector: Dict[str, Any]
    data: bytes
    sender_ip: str
    listener: str
    received_at: datetime


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: 'SyslogServer') -> None:
        self.server = server

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.server.accept_datagram(data, _peer_ip(addr))


class SyslogServer:
    def __init__(
        self,
        store: Optional[ConnectorStore] = None,
        settings: Optional[CollectorSettings] = None,
        sink: Optional[Sink] = None,
    ) -> None:
        self.store = store or get_store()
        self.settings = settings or CollectorSettings()
        self.sink = sink or get_sink()
        self.router = ConnectorRouter(self.store)
        self.queue: asyncio.Queue[_Message] = asyncio.Queue(maxsize=self.settings.syslog_queue_size)
        self._tcp_connections = 0
        self._counts: Dict[str, int] = {}
        self._drops: Dict[str, int] = {}
        self._last_sender: Dict[str, str] = {}
        self._last_unmatched_log = 0.0
        self._servers: List[Any] = []
        self._transports: List[asyncio.BaseTransport] = []
        self.bound: Dict[str, Tuple[str, int]] = {}

    # ── Lifecycle ───────────────────────────────────────────────────────────

    async def start(self) -> List[asyncio.Task]:
        """Bind the listeners and start the workers. Returns the worker tasks."""
        self.router.refresh()
        loop = asyncio.get_running_loop()
        s = self.settings

        if s.syslog_udp_port >= 0:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UdpProtocol(self), local_addr=(s.syslog_bind, s.syslog_udp_port)
            )
            self._transports.append(transport)
            self.bound['udp'] = transport.get_extra_info('sockname')[:2]
            logger.info('Syslog UDP listening on %s:%d', *self.bound['udp'])

        if s.syslog_tcp_port >= 0:
            srv = await asyncio.start_server(
                lambda r, w: self._handle_stream(r, w, 'tcp'),
                host=s.syslog_bind, port=s.syslog_tcp_port,
                limit=s.syslog_max_message_bytes * 2,
            )
            self._servers.append(srv)
            self.bound['tcp'] = srv.sockets[0].getsockname()[:2]
            logger.info('Syslog TCP listening on %s:%d', *self.bound['tcp'])

        return [asyncio.create_task(self._worker(i)) for i in range(s.syslog_workers)]

    async def run(self, stop: asyncio.Event) -> None:
        workers = await self.start()
        housekeeping = asyncio.create_task(self._housekeeping(stop))
        try:
            await stop.wait()
        finally:
            await self.close(workers + [housekeeping])

    async def close(self, tasks: List[asyncio.Task]) -> None:
        for t in self._transports:
            t.close()
        for srv in self._servers:
            srv.close()
            await srv.wait_closed()
        # Give workers a moment to drain what was already accepted.
        try:
            await asyncio.wait_for(self.queue.join(), timeout=10)
        except asyncio.TimeoutError:
            logger.warning('Syslog shutdown with %d messages still queued', self.queue.qsize())
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.flush_counters()
        logger.info('Syslog listener stopped')

    async def _housekeeping(self, stop: asyncio.Event) -> None:
        last_refresh = time.monotonic()
        while not stop.is_set():
            await asyncio.sleep(_COUNTER_FLUSH_SECONDS)
            try:
                self.flush_counters()
            except Exception as exc:
                logger.debug('syslog counter flush failed: %s', exc)
            if time.monotonic() - last_refresh >= self.settings.syslog_router_refresh_seconds:
                try:
                    self.router.refresh()
                except Exception as exc:
                    logger.warning('syslog connector refresh failed: %s', exc)
                last_refresh = time.monotonic()

    # ── Intake ──────────────────────────────────────────────────────────────

    def _note_unmatched(self, ip: str, listener: str) -> None:
        now = datetime.now(timezone.utc)
        with _unmatched_lock:
            entry = _unmatched.get(ip)
            if entry is None:
                if len(_unmatched) >= _MAX_UNMATCHED_TRACKED:
                    return
                entry = _unmatched[ip] = {'count': 0, 'listener': listener, 'first_seen_at': now}
            entry['count'] += 1
            entry['last_seen_at'] = now
        mono = time.monotonic()
        if mono - self._last_unmatched_log > 60:
            self._last_unmatched_log = mono
            logger.warning('Dropping syslog from %s (%s): no enabled syslog connector allows this sender',
                           ip, listener)

    def accept_datagram(self, data: bytes, ip: str) -> None:
        connector = self.router.match_ip(ip)
        if connector is None:
            self._note_unmatched(ip, 'udp')
            return
        data = data[: self.settings.syslog_max_message_bytes]
        # Some relays pack several newline-separated messages into a datagram.
        parts = [data]
        if b'\n' in data.strip():
            lines = [ln for ln in data.split(b'\n') if ln.strip()]
            if len(lines) > 1 and all(ln.lstrip().startswith(b'<') for ln in lines):
                parts = lines
        now = datetime.now(timezone.utc)
        for part in parts:
            try:
                self.queue.put_nowait(_Message(connector, part, ip, 'udp', now))
            except asyncio.QueueFull:
                self._note_drop(connector['connector_id'])

    async def _handle_stream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, listener: str) -> None:
        ip = _peer_ip(writer.get_extra_info('peername'))
        if self._tcp_connections >= self.settings.syslog_max_tcp_connections:
            writer.close()
            return
        connector = self.router.match_ip(ip)
        if connector is None:
            self._note_unmatched(ip, listener)
            writer.close()
            return

        self._tcp_connections += 1
        max_len = self.settings.syslog_max_message_bytes
        buf = bytearray()
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(
                        reader.read(65536), timeout=self.settings.syslog_tcp_idle_timeout_seconds)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                buf += chunk
                while True:
                    try:
                        frame = extract_frame(buf, max_len)
                    except FrameError as exc:
                        logger.warning('Closing syslog %s connection from %s: %s', listener, ip, exc)
                        return
                    if frame is None:
                        break
                    msg, consumed = frame
                    del buf[:consumed]
                    if msg.strip():
                        await self._enqueue_stream(connector, msg, ip, listener)
                if len(buf) > max_len:
                    # A delimiter-less run longer than any legal message.
                    buf.clear()
            if buf.strip():
                await self._enqueue_stream(connector, bytes(buf), ip, listener)
        except ConnectionError as exc:
            logger.debug('syslog %s connection from %s ended: %s', listener, ip, exc)
        finally:
            self._tcp_connections -= 1
            try:
                writer.close()
            except Exception:
                pass

    async def _enqueue_stream(self, connector: Dict[str, Any], msg: bytes, ip: str, listener: str) -> None:
        # Blocking put: a full queue slows the reader, which applies TCP
        # back-pressure to the sender instead of dropping.
        await self.queue.put(_Message(connector, msg, ip, listener, datetime.now(timezone.utc)))

    # ── Workers ─────────────────────────────────────────────────────────────

    async def _worker(self, idx: int) -> None:
        while True:
            m = await self.queue.get()
            try:
                self.ingest(m)
            except Exception as exc:
                logger.error('syslog worker %d failed on message from %s: %s', idx, m.sender_ip, exc,
                             exc_info=True)
            finally:
                self.queue.task_done()

    def ingest(self, m: _Message) -> None:
        event = parse_syslog(
            m.data,
            sender_ip=m.sender_ip,
            received_at=m.received_at,
            assume_tz=resolve_timezone(m.connector.get('time_zone')),
        )
        # killchain: the message body without the syslog envelope is the raw
        # line live mode parses (a FortiGate sends key=value lines as the body).
        if isinstance(event, dict) and not event.get('full_log'):
            try:
                _, body = _parse_envelope(_to_text(m.data), m.received_at)
                if body.strip():
                    event['full_log'] = body.strip()
            except Exception:
                pass
        vendor = str(m.connector.get('vendor') or 'unknown').lower()
        cid = m.connector['connector_id']
        res = self.sink.ingest_many(
            [event],
            source=vendor,
            source_hint=vendor,
            connector=m.connector,
            transport='syslog',
            meta_extra={'sender_ip': m.sender_ip, 'listener': m.listener},
        )
        self._counts[cid] = self._counts.get(cid, 0) + res.accepted
        self._last_sender[cid] = m.sender_ip

    def _note_drop(self, connector_id: str) -> None:
        """A message from a known connector was lost before reaching the sink."""
        self._drops[connector_id] = self._drops.get(connector_id, 0) + 1

    def flush_counters(self) -> None:
        counts, self._counts = self._counts, {}
        senders, self._last_sender = self._last_sender, {}
        drops, self._drops = self._drops, {}
        now = datetime.now(timezone.utc)
        for cid, n in drops.items():
            try:
                self.store.update_one(
                    {'connector_id': cid},
                    {
                        '$set': {'syslog_state.last_drop_at': now},
                        '$inc': {'syslog_state.dropped_total': n},
                    },
                )
            except Exception:
                self._drops[cid] = self._drops.get(cid, 0) + n
        for cid, n in counts.items():
            try:
                self.store.update_one(
                    {'connector_id': cid},
                    {
                        '$set': {
                            'last_seen_at': now,
                            'syslog_state.last_message_at': now,
                            'syslog_state.last_sender_ip': senders.get(cid),
                        },
                        '$inc': {'alerts_received': n},
                    },
                )
            except Exception as exc:
                self._counts[cid] = self._counts.get(cid, 0) + n
                logger.debug('syslog counter flush for %s failed: %s', cid, exc)


async def run_syslog(stop: asyncio.Event) -> None:
    """Entry point used by poller.connectors_lifespan when KILLCHAIN_SYSLOG=1."""
    try:
        await SyslogServer().run(stop)
    except OSError as exc:
        logger.error('Syslog listener could not start: %s', exc)
