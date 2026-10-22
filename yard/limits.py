"""Per-job limits: parsing and enforcement decisions (pure functions)."""

from __future__ import annotations

import re
from dataclasses import dataclass

DEFAULT_TIMEOUT_S = 4 * 3600
DEFAULT_IDLE_S = 30 * 60
DEFAULT_DISK_BYTES = 20 * 1024**3
MAX_TIMEOUT_S = 7 * 24 * 3600
MIN_DISK_BYTES = 512 * 1024**2

_DUR_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_SIZE = re.compile(r"^(\d+(?:\.\d+)?)([KMGT]?)(?:i?B?)$", re.IGNORECASE)
_SIZE_UNITS = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
_CPU = re.compile(r"^\s*(\d+(?:\.\d+)?|\d+m)\s*$")


class LimitError(ValueError):
    pass


def parse_duration(text: str) -> int:
    """'4h', '30m', '90s', '1h30m' or plain seconds ('120') -> seconds."""
    t = re.sub(r"\s+", "", text or "")
    if re.fullmatch(r"\d+", t):
        total = int(t)
    elif re.fullmatch(r"(?:\d+[smhd])+", t):
        total = sum(int(n) * _DUR_UNITS[u] for n, u in re.findall(r"(\d+)([smhd])", t))
    else:
        raise LimitError(f"invalid duration: {text!r}")
    if total <= 0:
        raise LimitError("duration must be positive")
    return total


def parse_size(text: str) -> int:
    """'20G', '20Gi', '20GB', '512M', '1024' (bytes) -> bytes, binary units."""
    m = _SIZE.match(re.sub(r"\s+", "", text or ""))
    if not m:
        raise LimitError(f"invalid size: {text!r}")
    value = int(float(m.group(1)) * _SIZE_UNITS[m.group(2).upper()])
    if value <= 0:
        raise LimitError("size must be positive")
    return value


def validate_cpu(text: str) -> str:
    if not _CPU.match(text or ""):
        raise LimitError(f"invalid cpu value: {text!r} (examples: 2, 0.5, 500m)")
    return text.strip()


def validate_memory(text: str) -> str:
    parse_size(text)
    return text.strip()


@dataclass(frozen=True)
class Limits:
    timeout_s: int = DEFAULT_TIMEOUT_S
    idle_s: int = DEFAULT_IDLE_S
    disk_bytes: int = DEFAULT_DISK_BYTES
    cpu: str | None = None
    memory: str | None = None

    def __post_init__(self) -> None:
        if not 0 < self.timeout_s <= MAX_TIMEOUT_S:
            raise LimitError(f"timeout must be within (0, {MAX_TIMEOUT_S}] seconds")
        if self.idle_s <= 0:
            raise LimitError("idle timeout must be positive")
        if self.disk_bytes < MIN_DISK_BYTES:
            raise LimitError(f"disk quota must be at least {MIN_DISK_BYTES} bytes")

    def to_dict(self) -> dict:
        return {"timeout_s": self.timeout_s, "idle_s": self.idle_s,
                "disk_bytes": self.disk_bytes, "cpu": self.cpu, "memory": self.memory}

    @classmethod
    def from_dict(cls, d: dict) -> "Limits":
        return cls(timeout_s=int(d["timeout_s"]), idle_s=int(d["idle_s"]),
                   disk_bytes=int(d["disk_bytes"]), cpu=d.get("cpu"), memory=d.get("memory"))


def effective_resources(limits: Limits, host_cpus: int, host_memory_bytes: int) -> tuple[str, str]:
    """CPU and memory values to pass to OpenShell.

    The Podman driver applies 2 CPUs / 4 GiB when a request sets nothing.
    Alex chose "no caps by default", so an unset value becomes the whole host.
    """
    cpu = limits.cpu or str(max(1, host_cpus))
    memory = limits.memory or f"{max(1, host_memory_bytes // 1024**2)}Mi"
    return cpu, memory


def check_limits(limits: Limits, now: float, started_at: float, last_output_at: float) -> str | None:
    """Return a kill reason ('timeout' or 'idle') or None."""
    if now - started_at >= limits.timeout_s:
        return "timeout"
    if now - last_output_at >= limits.idle_s:
        return "idle"
    return None
