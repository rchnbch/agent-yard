"""Durable, append-only event log with an opaque cursor.

One JSON object per line: {"seq", "ts", "job", "type", "data"}. ``seq`` is
strictly increasing from 1. The cursor handed to clients is ``"c<seq>"``
for the last event they have seen; ``read_since`` returns everything after
it, so HQ can catch up after the laptop was closed.

Appends take an exclusive flock and fsync before returning, so an event the
daemon reported as written survives a crash or reboot.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from dataclasses import dataclass
from typing import Iterator

EVENT_TYPES = frozenset({
    "job.created", "job.running", "job.status", "job.attention", "job.finished",
    "job.failed", "job.killed", "job.cleanup", "approval.pending", "approval.decided",
    "approval.auto", "host.warning",
})


class CursorError(ValueError):
    pass


def parse_cursor(cursor: str | None) -> int:
    if cursor in (None, "", "c0"):
        return 0
    if not isinstance(cursor, str) or not cursor.startswith("c") or not cursor[1:].isdigit():
        raise CursorError(f"invalid cursor: {cursor!r}")
    return int(cursor[1:])


def make_cursor(seq: int) -> str:
    return f"c{seq}"


@dataclass
class EventLog:
    path: str

    def _last_seq(self, fh) -> int:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        if size == 0:
            return 0
        # Read backwards until the last complete line.
        block = 4096
        pos = size
        buf = b""
        while pos > 0:
            step = min(block, pos)
            pos -= step
            fh.seek(pos)
            buf = fh.read(step) + buf
            lines = buf.rstrip(b"\n").split(b"\n")
            if len(lines) > 1 or pos == 0:
                for raw in reversed(lines):
                    if raw.strip():
                        try:
                            return int(json.loads(raw)["seq"])
                        except (ValueError, KeyError):
                            # A torn final line from a crash: skip it.
                            continue
                return 0
        return 0

    def append(self, etype: str, job: str | None = None, data: dict | None = None,
               ts: float | None = None) -> dict:
        if etype not in EVENT_TYPES:
            raise ValueError(f"unknown event type: {etype}")
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o640)
        with os.fdopen(fd, "r+b") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                seq = self._last_seq(fh) + 1
                event = {"seq": seq, "ts": round(ts if ts is not None else time.time(), 3),
                         "job": job, "type": etype, "data": data or {}}
                line = json.dumps(event, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                fh.seek(0, os.SEEK_END)
                # A torn previous line (crash mid-write) must not glue onto ours.
                if fh.tell() > 0:
                    fh.seek(-1, os.SEEK_END)
                    if fh.read(1) != b"\n":
                        line = b"\n" + line
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)
        return event

    def iter_events(self) -> Iterator[dict]:
        try:
            fh = open(self.path, "rb")
        except FileNotFoundError:
            return
        with fh:
            fcntl.flock(fh, fcntl.LOCK_SH)
            try:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        yield json.loads(raw)
                    except ValueError:
                        continue
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def read_since(self, cursor: str | None, limit: int = 1000, job: str | None = None) -> dict:
        after = parse_cursor(cursor)
        if limit <= 0:
            raise ValueError("limit must be positive")
        events = []
        last = after
        more = False
        for ev in self.iter_events():
            if ev["seq"] <= after:
                continue
            if len(events) >= limit:
                more = True
                break
            last = ev["seq"]
            if job is None or ev.get("job") == job:
                events.append(ev)
        return {"events": events, "cursor": make_cursor(last), "more": more}
