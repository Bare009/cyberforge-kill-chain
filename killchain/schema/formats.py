"""Input formats: detection on the first bytes, record decoding, and readers that keep line numbers and offsets.

Formats
  fortigate  FortiGate key=value lines (the existing fast parser handles them, nothing here)
  ndjson     one JSON object per line
  json       a JSON array of objects, an object holding arrays of objects ({"data": [...]}, {"value": [...]}),
             or pretty-printed objects one after another
  csv        delimited text with a header line (comma, tab, semicolon or pipe)
  kv         other key=value lines (Check Point, Sophos, Fortinet variants; also key:"value")
  syslog     RFC 5424 / 3164 lines, with CEF, LEEF, JSON or key=value payloads (connectors/syslog_parser.py)
  xml        Windows event XML (<Event>...</Event> records)

Every reader yields (record, line, byte_offset, raw) with `line` 1-based and `byte_offset` the byte where
the record starts, so evidence can seek to it. A JSON record's line is the line its opening brace is on.
"""

from __future__ import annotations

import csv
import gzip
import io
import mmap
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ..parser import arrowutil as au

HEAD_BYTES = 1 << 20
SAMPLE_LINES = 200
LINE_FORMATS = ("ndjson", "kv", "syslog")
Record = Dict[str, Any]

FG_PREFIX = b"date="
_SYSLOG_RE = re.compile(rb"^(?:<\d{1,3}>\d? ?|[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d |"
                        rb"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\S* \S+ )")
_CEF_RE = re.compile(rb"CEF:\s?\d+\|")
_LEEF_RE = re.compile(rb"LEEF:\s?\d(?:\.\d)?\|")
KV_RE = re.compile(r'([A-Za-z_][\w.\-]*)=("(?:[^"\\]|\\.)*"|\'[^\']*\'|[^\s]*)|([A-Za-z_][\w.\-]*):"((?:[^"\\]|\\.)*)"')
_KV_BYTES_RE = re.compile(rb'[A-Za-z_][\w.\-]*=(?:"(?:[^"\\]|\\.)*"|[^\s]*)|[A-Za-z_][\w.\-]*:"(?:[^"\\]|\\.)*"')
_JSON_TOKEN = re.compile(rb'"(?:[^"\\]|\\.)*"|[{}\[\]]')
_XML_EVENT = re.compile(rb"<Event[\s>].*?</Event>", re.S)
_XML_TAG = re.compile(r"^\{[^}]*\}")


@dataclass
class Detected:
    format: str                       # see module docstring, or "unknown"
    delimiter: Optional[str] = None   # csv
    compressed: Optional[str] = None  # gzip | zip
    payload: Optional[str] = None     # syslog: cef | leef | json | kv | text
    shares: Dict[str, float] = field(default_factory=dict)

    @property
    def label(self) -> str:
        s = self.format + (f"/{self.payload}" if self.payload else "")
        return s + (f" ({self.compressed})" if self.compressed else "")


# ── detection ────────────────────────────────────────────────────────────────

def _lines(head: bytes, n: int = SAMPLE_LINES) -> List[bytes]:
    out = []
    for raw in head.split(b"\n")[:-1] if b"\n" in head else [head]:
        raw = raw.rstrip(b"\r")
        if raw.strip():
            out.append(raw.lstrip(b"\xef\xbb\xbf"))
        if len(out) >= n:
            break
    return out


def kv_share(raw: bytes) -> float:
    """Share of a line's bytes covered by key=value pairs (with at least 3 pairs)."""
    pairs = _KV_BYTES_RE.findall(raw)
    if len(pairs) < 3:
        return 0.0
    return min(1.0, (sum(len(p) for p in pairs) + len(pairs)) / max(len(raw), 1))


def _is_json_obj(raw: bytes) -> bool:
    try:
        return isinstance(au.loads(raw), dict)
    except ValueError:
        return False


def _wraps_records(raw: bytes) -> bool:
    try:
        obj = au.loads(raw)
    except ValueError:
        return False
    return isinstance(obj, dict) and any(isinstance(v, list) and v and all(isinstance(x, dict) for x in v)
                                         for v in obj.values())


def _csv_dialect(lines: List[bytes]) -> Optional[str]:
    text = [l.decode("utf-8", "replace") for l in lines[:50]]
    if len(text) < 2:
        return None
    best = None
    for d in (",", "\t", ";", "|"):
        rows = list(csv.reader(text, delimiter=d))
        n = len(rows[0])
        if n < 3:
            continue
        same = sum(len(r) == n for r in rows[1:]) / max(len(rows) - 1, 1)
        header = rows[0]
        wordy = sum(bool(re.match(r"^[A-Za-z_@#\"][\w .\-/#()@:\"]*$", h.strip())) for h in header) / n
        if same >= 0.9 and wordy >= 0.8 and (best is None or n > best[1]):
            best = (d, n)
    return best[0] if best else None


def detect_bytes(head: bytes) -> Detected:
    body = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if not body:
        return Detected("unknown")
    if body[:1] == b"[":
        return Detected("json")
    if body[:1] == b"<" and (body.startswith(b"<?xml") or body.startswith(b"<Event") or b"<Event" in body[:4096]) \
            and not _SYSLOG_RE.match(body):
        return Detected("xml")
    lines = _lines(head)
    n = len(lines) or 1
    fg = sum(l.startswith(FG_PREFIX) or l.lstrip(b" \t").startswith(FG_PREFIX) for l in lines) / n
    if fg >= 0.5:
        return Detected("fortigate", shares={"fortigate": fg})
    if body[:1] == b"{":
        js = sum(l[:1] == b"{" and _is_json_obj(l) for l in lines) / n
        if js >= 0.8 and len(lines) == 1 and _wraps_records(lines[0]):
            return Detected("json")          # one object holding the records: {"value": [{...}, ...]}
        if js >= 0.8:
            return Detected("ndjson", shares={"json": js})
        return Detected("json")
    cef = sum(bool(_CEF_RE.search(l)) for l in lines) / n
    leef = sum(bool(_LEEF_RE.search(l)) for l in lines) / n
    sysl = sum(bool(_SYSLOG_RE.match(l)) for l in lines) / n
    kv = sum(kv_share(l) >= 0.6 for l in lines) / n
    shares = {"cef": cef, "leef": leef, "syslog": sysl, "kv": kv}
    if cef >= 0.5:
        return Detected("syslog", payload="cef", shares=shares)
    if leef >= 0.5:
        return Detected("syslog", payload="leef", shares=shares)
    if sysl >= 0.5:
        return Detected("syslog", payload="kv" if kv >= 0.5 else "text", shares=shares)
    if kv >= 0.5:
        return Detected("kv", shares=shares)
    d = _csv_dialect(lines)
    if d:
        return Detected("csv", delimiter=d, shares=shares)
    return Detected("unknown", shares=shares)


def read_head(path: Path, n: int = HEAD_BYTES) -> Tuple[bytes, Optional[str]]:
    with open(path, "rb") as f:
        head = f.read(n)
    if head[:2] == b"\x1f\x8b":
        with gzip.open(path, "rb") as g:
            return g.read(n), "gzip"
    if head[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(path) as z:
                names = [i for i in z.infolist() if not i.is_dir()]
                if names:
                    with z.open(max(names, key=lambda i: i.file_size)) as g:
                        return g.read(n), "zip"
        except zipfile.BadZipFile:
            pass
    return head, None


def detect_file(path: Path) -> Detected:
    head, comp = read_head(Path(path))
    d = detect_bytes(head)
    d.compressed = comp
    return d


def is_fortigate(path: Path) -> bool:
    """True when the pipeline should use the FortiGate parser: FortiGate lines, or nothing we recognise
    (the FortiGate parser then reports the lines as rejected, as before)."""
    d = detect_file(path)
    return d.compressed is None and d.format in ("fortigate", "unknown")


def decompress(path: Path, out_dir: Path) -> Path:
    """gzip/zip input -> a plain copy under out_dir (the parsers need seekable byte offsets)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    head, comp = read_head(path, 4)
    if comp == "gzip":
        dst = out_dir / (path.name[:-3] if path.name.endswith(".gz") else path.name + ".out")
        with gzip.open(path, "rb") as g, open(dst, "wb") as f:
            while True:
                b = g.read(16 << 20)
                if not b:
                    break
                f.write(b)
        return dst
    with zipfile.ZipFile(path) as z:
        info = max((i for i in z.infolist() if not i.is_dir()), key=lambda i: i.file_size)
        dst = out_dir / Path(info.filename).name
        with z.open(info) as g, open(dst, "wb") as f:
            while True:
                b = g.read(16 << 20)
                if not b:
                    break
                f.write(b)
        return dst


# ── record decoding ──────────────────────────────────────────────────────────

def flatten(obj: Dict[str, Any], prefix: str = "", out: Optional[Record] = None) -> Record:
    """Nested objects -> dotted keys. A list of objects is flattened too: each key gets the values of
    every element joined by "," (first-seen order, no repeats), so `Entities: [{Type: ip, Address: x},
    {Type: account, Name: y}]` gives Entities.Type = "ip,account", Entities.Address = "x",
    Entities.Name = "y". Lists of plain values stay lists (joined when a column is built)."""
    if out is None:
        out = {}
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            if v:
                flatten(v, key + ".", out)
        elif isinstance(v, list) and v and any(isinstance(x, dict) for x in v):
            merged: Dict[str, List[Any]] = {}
            for x in v:
                if isinstance(x, dict):
                    for kk, vv in flatten(x).items():
                        vals = merged.setdefault(kk, [])
                        for item in (vv if isinstance(vv, list) else [vv]):
                            if item is not None and item != "" and item not in vals:
                                vals.append(item)
            for kk, vals in merged.items():
                out[f"{key}.{kk}"] = vals[0] if len(vals) == 1 else (",".join(map(str, vals)) if vals else None)
        else:
            out[key] = v
    return out


def strip_wrappers(rec: Record, wrappers: Tuple[str, ...]) -> Record:
    if not wrappers:
        return rec
    out: Record = {}
    for k, v in rec.items():
        for w in wrappers:
            if k.startswith(w):
                k2 = k[len(w):]
                if k2 and k2 not in rec:
                    k = k2
                break
        out[k] = v
    return out


def _unq(v: str) -> str:
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
        if '\\"' in v:
            v = v.replace('\\"', '"')
    return v


def parse_kv(text: str) -> Record:
    out: Record = {}
    for m in KV_RE.finditer(text):
        if m.group(1) is not None:
            out.setdefault(m.group(1), _unq(m.group(2)))
        else:
            out.setdefault(m.group(3), m.group(4).replace('\\"', '"'))
    return out


def looks_kv(text: Any) -> bool:
    return isinstance(text, str) and kv_share(text.encode("utf-8", "replace")) >= 0.6


class Decoder:
    """Bytes of one line -> a flat record, or (None, reason)."""

    def __init__(self, fmt: str, wrappers: Tuple[str, ...] = (), patterns: Optional[List[Dict[str, Any]]] = None,
                 expand: Tuple[str, ...] = ()):
        self.fmt = fmt
        self.wrappers = wrappers
        self._roots = {w.split(".")[0] for w in wrappers}
        self.patterns = [(p["name"], re.compile(p["regex"]), p.get("set") or {}) for p in (patterns or [])]
        self.expand = expand

    def line(self, raw: bytes) -> Tuple[Optional[Record], str]:
        if self.fmt == "ndjson":
            if raw[:1] != b"{":
                return None, "not_json"
            try:
                obj = au.loads(raw)
            except ValueError:
                return None, "bad_json"
            if not isinstance(obj, dict):
                return None, "bad_json"
            return self.finish(flatten(obj), wrapped=bool(self._roots and not self._roots.isdisjoint(obj))), ""
        text = raw.decode("utf-8", "replace")
        if self.fmt == "kv":
            rec = parse_kv(text)
            return (self.finish(rec), "") if len(rec) >= 2 else (None, "unknown_format")
        if self.fmt == "syslog":
            return self.finish(self.syslog(text)), ""
        raise ValueError(f"not a line format: {self.fmt}")

    def syslog(self, text: str) -> Record:
        from ..connectors.syslog_parser import parse_syslog

        ev = parse_syslog(text)
        fmt = (ev.get("syslog") or ev.get("_syslog") or {}).get("payload_format")
        msg = ev.get("message")
        for k in ("raw_syslog", "title", "name", "description"):
            ev.pop(k, None)
        rec = flatten(ev)
        if fmt == "text" and isinstance(msg, str):
            if looks_kv(msg):
                for k, v in parse_kv(msg).items():
                    rec.setdefault(k, v)
            else:
                self.match_patterns(msg, rec)
        return rec

    def match_patterns(self, msg: str, rec: Record) -> None:
        for name, rx, fixed in self.patterns:
            m = rx.search(msg)
            if m:
                rec["parsed._pattern"] = name
                for k, v in m.groupdict().items():
                    if v is not None:
                        rec["parsed." + k] = v
                for k, v in fixed.items():
                    rec.setdefault("parsed." + k, v)
                return

    def finish(self, rec: Record, wrapped: Optional[bool] = None) -> Record:
        """wrapped: whether the record has an envelope key (None: not known, check every key)."""
        if self.wrappers and wrapped is not False:
            rec = strip_wrappers(rec, self.wrappers)
        for f in self.expand:
            v = rec.get(f)
            if isinstance(v, str):
                if _CEF_RE.search(v.encode("utf-8", "replace")) or _LEEF_RE.search(v.encode("utf-8", "replace")):
                    for k, x in flatten(_payload_record(v)).items():
                        rec.setdefault(k, x)
                elif looks_kv(v):
                    for k, x in parse_kv(v).items():
                        rec.setdefault(k, x)
        return rec


def _payload_record(text: str) -> Record:
    from ..connectors.syslog_parser import parse_syslog

    ev = parse_syslog(text)
    for k in ("raw_syslog", "title", "name", "description", "syslog", "_syslog"):
        ev.pop(k, None)
    return ev


# ── whole-file readers (also used for samples) ───────────────────────────────

def iter_lines(path: Path, start: int = 0, end: Optional[int] = None, first_line: int = 1
               ) -> Iterator[Tuple[bytes, int, int]]:
    """(raw line without newline, line number, byte offset) from start (a line start) to end."""
    with open(path, "rb") as f:
        f.seek(start)
        pos, n = start, first_line
        for raw in f:
            if end is not None and pos >= end:
                break
            length = len(raw)
            line = raw.rstrip(b"\n").rstrip(b"\r")
            yield line, n, pos
            pos += length
            n += 1


def iter_csv(path: Path, delimiter: str, start_line: int = 1) -> Iterator[Tuple[Record, int, int, bytes]]:
    """Rows as {header: value}. Quoted fields may span lines; a row's line is its first physical line."""
    offsets: List[int] = []
    raws: List[bytes] = []

    def physical() -> Iterator[str]:
        with open(path, "rb") as f:
            pos = 0
            for raw in f:
                offsets.append(pos)
                raws.append(raw)
                pos += len(raw)
                if len(offsets) > 4096:          # keep only what the current row can still need
                    del offsets[:2048]
                    del raws[:2048]
                    base[0] += 2048
                yield raw.decode("utf-8", "replace").lstrip("\ufeff") if pos == len(raw) else raw.decode("utf-8", "replace")

    base = [0]
    reader = csv.reader(physical(), delimiter=delimiter)
    header: Optional[List[str]] = None
    prev = 0
    for row in reader:
        first = prev + 1                  # 1-based physical line of this row
        prev = reader.line_num
        if header is None:
            header = [h.strip() for h in row]
            continue
        if not row or (len(row) == 1 and not row[0].strip()):
            continue
        i = first - 1 - base[0]
        off = offsets[i] if 0 <= i < len(offsets) else -1
        raw = raws[i] if 0 <= i < len(raws) else b""
        rec = {h: (v if v != "" else None) for h, v in zip(header, row) if h}
        yield rec, first, off, raw


def csv_header(path: Path, delimiter: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        return [h.strip().lstrip("\ufeff") for h in next(csv.reader(f, delimiter=delimiter), [])]


def iter_json_doc(path: Path, limit: Optional[int] = None) -> Iterator[Tuple[Record, int, int, bytes]]:
    """Records of a JSON document: objects in a top-level array, objects in arrays directly under a top-level
    object, or top-level objects one after another (a top-level object without such arrays is one record)."""
    size = Path(path).stat().st_size
    if size == 0:
        return
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        stack: List[int] = []           # b'{' or b'[' as ints
        rec_start: Optional[int] = None
        rec_depth = 0
        top_obj_start: Optional[int] = None
        top_has_records = False
        newlines_at = 0
        line_no = 1
        count = 0
        for m in _JSON_TOKEN.finditer(mm):
            tok = m.group()
            c = tok[0]
            if c == 0x22:   # string
                continue
            pos = m.start()
            if c in (0x7B, 0x5B):   # { [
                if c == 0x7B and rec_start is None:
                    parent = stack[-1] if stack else None
                    if not stack:
                        top_obj_start = pos
                        top_has_records = False
                    elif parent == 0x5B and (len(stack) == 1 or (len(stack) == 2 and stack[0] == 0x7B)):
                        rec_start, rec_depth = pos, len(stack)
                        if len(stack) == 2:
                            top_has_records = True
                stack.append(c)
                continue
            if not stack:
                continue
            stack.pop()
            if rec_start is not None and len(stack) == rec_depth and c == 0x7D:
                raw = mm[rec_start:pos + 1]
                line_no += mm[newlines_at:rec_start].count(b"\n") if rec_start >= newlines_at else 0
                newlines_at = rec_start
                try:
                    obj = au.loads(raw)
                except ValueError:
                    obj = None
                if isinstance(obj, dict):
                    yield flatten(obj), line_no, rec_start, bytes(raw[:4096])
                    count += 1
                    if limit and count >= limit:
                        return
                rec_start = None
            elif not stack and c == 0x7D and top_obj_start is not None and not top_has_records:
                raw = mm[top_obj_start:pos + 1]
                line_no += mm[newlines_at:top_obj_start].count(b"\n")
                newlines_at = top_obj_start
                try:
                    obj = au.loads(raw)
                except ValueError:
                    obj = None
                if isinstance(obj, dict):
                    yield flatten(obj), line_no, top_obj_start, bytes(raw[:4096])
                    count += 1
                    if limit and count >= limit:
                        return
                top_obj_start = None


def _xml_flat(raw: bytes) -> Optional[Record]:
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None
    rec: Record = {}
    for part in root:
        pname = _XML_TAG.sub("", part.tag)
        for el in part.iter():
            tag = _XML_TAG.sub("", el.tag)
            if el is part:
                continue
            if tag == "Data":
                name = el.attrib.get("Name")
                key = f"{pname}.{name}" if name else f"{pname}.Data"
                if key in rec and not name:
                    rec[key] = f"{rec[key]},{(el.text or '').strip()}"
                else:
                    rec[key] = (el.text or "").strip() or None
            else:
                txt = (el.text or "").strip()
                if txt:
                    rec[f"{pname}.{tag}"] = txt
                for a, v in el.attrib.items():
                    rec[f"{pname}.{tag}.{_XML_TAG.sub('', a)}"] = v
    return rec


def iter_xml(path: Path, limit: Optional[int] = None) -> Iterator[Tuple[Record, int, int, bytes]]:
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        line_no, seen = 1, 0
        count = 0
        for m in _XML_EVENT.finditer(mm):
            line_no += mm[seen:m.start()].count(b"\n")
            seen = m.start()
            rec = _xml_flat(m.group())
            if rec:
                yield rec, line_no, m.start(), bytes(m.group()[:4096])
                count += 1
                if limit and count >= limit:
                    return


def mid_offset(path: Path) -> int:
    """A line start near the middle of the file."""
    size = Path(path).stat().st_size
    with open(path, "rb") as f:
        f.seek(size // 2)
        f.readline()
        return f.tell()


def count_lines_before(path: Path, offset: int) -> int:
    n = 0
    with open(path, "rb") as f:
        left = offset
        while left > 0:
            b = f.read(min(16 << 20, left))
            if not b:
                break
            n += b.count(b"\n")
            left -= len(b)
    return n


def sample_records(path: Path, det: Detected, n: int, decoder: Optional[Decoder] = None
                   ) -> Tuple[List[Tuple[Record, int, int]], Dict[str, int]]:
    """Up to n records from the start and n from the middle (line and CSV formats), or the first 2n
    (JSON documents and XML). Returns ([(record, line, offset)], rejected reasons)."""
    path = Path(path)
    rejected: Dict[str, int] = {}
    out: List[Tuple[Record, int, int]] = []
    if det.format in LINE_FORMATS:
        dec = decoder or Decoder(det.format)
        size = path.stat().st_size
        mid = mid_offset(path) if size > 4 * HEAD_BYTES else None
        starts = [(0, 1)]
        if mid:
            starts.append((mid, 1 + count_lines_before(path, mid)))
        for start, first in starts:
            got = 0
            for raw, ln, off in iter_lines(path, start, None, first):
                if not raw.strip():
                    continue
                rec, why = dec.line(raw)
                if rec is None:
                    rejected[why] = rejected.get(why, 0) + 1
                    if sum(rejected.values()) > 50 * n:
                        break
                    continue
                out.append((rec, ln, off))
                got += 1
                if got >= n:
                    break
        return out, rejected
    if det.format == "csv":
        got = 0
        for rec, ln, off, _ in iter_csv(path, det.delimiter or ","):
            out.append((rec, ln, off))
            got += 1
            if got >= n:
                break
        size = path.stat().st_size
        mid = mid_offset(path) if size > 4 * HEAD_BYTES else None
        if mid and out and mid > out[-1][2]:
            header = csv_header(path, det.delimiter or ",")
            first = 1 + count_lines_before(path, mid)
            got = 0
            for raw, ln, off in iter_lines(path, mid, None, first):
                if not raw.strip():
                    continue
                row = next(csv.reader([raw.decode("utf-8", "replace")], delimiter=det.delimiter or ","), [])
                if len(row) != len(header):      # a row split by a quoted newline: skip it in the sample
                    rejected["csv_columns"] = rejected.get("csv_columns", 0) + 1
                    continue
                out.append(({h: (v if v != "" else None) for h, v in zip(header, row) if h}, ln, off))
                got += 1
                if got >= n:
                    break
        return out, rejected
    it = iter_json_doc(path, 2 * n) if det.format == "json" else iter_xml(path, 2 * n)
    for rec, ln, off, _ in it:
        out.append((rec, ln, off))
    return out, rejected
