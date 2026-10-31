"""Follow one growing log file: appends, rotation, truncation, and a checkpoint to resume from.

Adapted from `FileTailer` in AI-SOC agent/soar_agent.py, cut down to one file and no thread:
the live engine calls poll() once per tick. Each poll opens the file, reads what is new in
256 KB chunks and closes it again, so the file is never held open between polls (on Windows
an open file cannot be rotated by rename).

poll() returns complete lines only, as (raw bytes without the newline, 1-based line number,
0-based byte offset). An unfinished last line is held back until its newline arrives; a line
that grows past max_line_bytes without a newline is emitted truncated, as AI-SOC does.

Rotation: the inode changed (os.stat().st_ino; NTFS sets it), or the first line's fingerprint
changed (covers copy-truncate and file systems that report inode 0). Truncation: the file is
now shorter than the offset read. Either way the tailer reads the new file from byte 0, line 1,
and the poll result has reset=True.

The checkpoint records the end of the last complete line plus where the caller's window
starts, so a restart backfills the window and then continues; the caller saves it only after
the lines up to `offset` have been processed (AI-SOC: checkpoint after spooling).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from ..parser.worker import count_newlines

CHUNK = 256 * 1024
FINGERPRINT_BYTES = 256

Line = Tuple[bytes, int, int]


@dataclass
class TailResult:
    lines: List[Line] = field(default_factory=list)
    reset: bool = False
    reason: Optional[str] = None        # rotated | truncated
    size: int = 0
    offset: int = 0
    status: str = "ok"                  # ok | waiting (file missing)


def _fingerprint(path: Path) -> Optional[str]:
    """blake2b-8 of the first complete line (up to 256 bytes); None while there is no complete line."""
    try:
        with open(path, "rb") as f:
            head = f.read(FINGERPRINT_BYTES + 1)
    except OSError:
        return None
    nl = head.find(b"\n")
    if nl < 0:
        if len(head) <= FINGERPRINT_BYTES:
            return None
        nl = FINGERPRINT_BYTES
    return hashlib.blake2b(head[:min(nl, FINGERPRINT_BYTES)], digest_size=8).hexdigest()


class FileTailer:
    def __init__(self, path: Union[str, Path], max_line_bytes: int = 1 << 20,
                 max_backfill_bytes: int = 256 << 20) -> None:
        self.path = Path(path)
        self.max_line_bytes = max_line_bytes
        self.max_backfill_bytes = max_backfill_bytes
        self.inode = 0
        self.fp: Optional[str] = None
        self.offset = 0                 # end of the last complete line handed out
        self.line = 1                   # number of the next line
        self.partial_len = 0            # bytes of an unfinished last line already seen
        self.status = "starting"
        self._pending_reset: Optional[str] = None

    # -- start
    def _stat(self) -> Optional[os.stat_result]:
        try:
            return os.stat(self.path)
        except OSError:
            return None

    def start(self, checkpoint: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Pick where to read from. Returns {mode: resume | start | tail, backfill_from: (offset, line)}.

        resume: the checkpoint matches the file (same inode and fingerprint, offset not past the end);
                the first poll returns the lines from the checkpoint's window start, then new ones.
        start:  no usable checkpoint; read from byte 0.
        tail:   the file is bigger than max_backfill_bytes; start at the first line after size - max.
        """
        st = self._stat()
        self.inode = int(getattr(st, "st_ino", 0) or 0) if st else 0
        self.fp = _fingerprint(self.path) if st else None
        size = st.st_size if st else 0
        ck = checkpoint or {}
        ok = (st is not None and ck.get("path") in (None, str(self.path.resolve()))
              and int(ck.get("offset", -1)) >= 0 and int(ck["offset"]) <= size
              and ck.get("fingerprint") == self.fp
              and (not self.inode or not ck.get("inode") or int(ck["inode"]) == self.inode))
        if ok:
            start = int(ck.get("window_offset", ck["offset"]))
            line = int(ck.get("window_line", ck.get("line", 1)))
            if start > int(ck["offset"]) or start < 0:
                start, line = int(ck["offset"]), int(ck.get("line", 1))
            mode = "resume"
        elif size > self.max_backfill_bytes:
            start = self._line_start(size - self.max_backfill_bytes, size)
            line = 1 + count_newlines((str(self.path), 0, start))
            mode = "tail"
        else:
            start, line, mode = 0, 1, "start"
        self.offset, self.line, self.partial_len = start, line, 0
        return {"mode": mode, "backfill_from": (start, line)}

    def _line_start(self, pos: int, size: int) -> int:
        """Smallest offset >= pos that starts a line."""
        if pos <= 0:
            return 0
        with open(self.path, "rb") as f:
            f.seek(pos - 1)
            scanned = pos - 1
            while True:
                buf = f.read(1 << 20)
                if not buf:
                    return size
                i = buf.find(b"\n")
                if i >= 0:
                    return scanned + i + 1
                scanned += len(buf)

    # -- poll
    def poll(self) -> TailResult:
        st = self._stat()
        if st is None:
            self.status = "waiting"
            return TailResult(size=0, offset=self.offset, status="waiting")
        self.status = "ok"
        inode = int(getattr(st, "st_ino", 0) or 0)
        res = TailResult(size=st.st_size, offset=self.offset)
        reason = None
        if self.inode and inode and inode != self.inode:
            reason = "rotated"
        elif st.st_size < self.offset + self.partial_len or st.st_size < self.offset:
            reason = "truncated"
        else:
            fp = _fingerprint(self.path)
            if self.fp is not None and fp != self.fp:
                reason = "rotated"
            elif self.fp is None:
                self.fp = fp
        if reason:
            self.inode, self.fp = inode, _fingerprint(self.path)
            self.offset, self.line, self.partial_len = 0, 1, 0
            res.reset, res.reason = True, reason
        elif not self.inode:
            self.inode = inode
        if st.st_size > self.offset:
            res.lines = self._read(st.st_size)
            if self.fp is None:
                self.fp = _fingerprint(self.path)
        res.offset = self.offset
        return res

    def _read(self, size: int) -> List[Line]:
        out: List[Line] = []
        pos = self.offset
        partial = b""
        with open(self.path, "rb") as f:
            f.seek(pos)
            left = size - pos
            while left > 0:
                chunk = f.read(min(CHUNK, left))
                if not chunk:
                    break
                left -= len(chunk)
                data = partial + chunk if partial else chunk
                parts = data.split(b"\n")
                partial = parts.pop()
                for raw in parts:
                    out.append((raw[:self.max_line_bytes], self.line, pos))
                    pos += len(raw) + 1
                    self.line += 1
                if len(partial) > self.max_line_bytes:
                    # a line that never ends: hand it out truncated and skip to the next newline
                    out.append((partial[:self.max_line_bytes], self.line, pos))
                    self.line += 1
                    pos += len(partial)
                    partial = b""
                    skip = self._skip_to_newline(f, left)
                    pos += skip
                    left -= skip
        self.offset = pos
        self.partial_len = len(partial)
        return out

    @staticmethod
    def _skip_to_newline(f, left: int) -> int:
        """Bytes consumed up to and including the next newline (or all that is left)."""
        used = 0
        while left - used > 0:
            buf = f.read(min(CHUNK, left - used))
            if not buf:
                break
            i = buf.find(b"\n")
            if i >= 0:
                used += i + 1
                f.seek(f.tell() - (len(buf) - i - 1))
                return used
            used += len(buf)
        return used

    # -- checkpoint
    def checkpoint(self, window_offset: Optional[int] = None, window_line: Optional[int] = None) -> Dict[str, Any]:
        return {"path": str(self.path.resolve()), "inode": self.inode, "fingerprint": self.fp,
                "offset": self.offset, "line": self.line,
                "window_offset": self.offset if window_offset is None else int(window_offset),
                "window_line": self.line if window_line is None else int(window_line)}

    def state(self) -> Dict[str, Any]:
        return {"path": str(self.path), "status": self.status, "offset": self.offset, "line": self.line,
                "inode": self.inode, "fingerprint": self.fp}
