"""Per-job disk quota through the root helper (host/libexec/yard-quota).

Rootless Podman cannot enforce overlay ``size=`` (containers/storage needs
quotactl and mknod privileges; see docs/SPIKES.md). Instead the Podman
user's storage lives on an XFS filesystem mounted with ``prjquota`` and a
small root-owned helper, callable via one sudoers rule, puts the job's
writable layer and workspace volume into an XFS project with a hard block
limit. The helper re-derives every path from Podman itself, so the caller
can only name a sandbox, never a directory.
"""

from __future__ import annotations

import json
import re
import subprocess
from typing import Callable, Sequence

NAME_RE = re.compile(r"^yard-[a-z0-9-]{4,60}$")

Run = Callable[[Sequence[str]], subprocess.CompletedProcess]


class QuotaError(RuntimeError):
    pass


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True, check=False, timeout=120)


def apply(helper: str, sandbox: str, job_id: str, limit_bytes: int, run: Run = _run) -> dict:
    if not NAME_RE.match(sandbox):
        raise QuotaError(f"refusing quota for unexpected sandbox name {sandbox!r}")
    if limit_bytes <= 0:
        raise QuotaError("quota must be positive")
    p = run(["sudo", "-n", helper, "apply", sandbox, job_id, str(limit_bytes)])
    if p.returncode != 0:
        raise QuotaError(f"quota helper failed ({p.returncode}): {(p.stderr or p.stdout).strip()[:500]}")
    try:
        return json.loads(p.stdout)
    except ValueError:
        raise QuotaError(f"quota helper returned non-JSON: {p.stdout[:200]!r}") from None


def release(helper: str, job_id: str, run: Run = _run) -> None:
    run(["sudo", "-n", helper, "release", job_id])


def check(helper: str, run: Run = _run) -> dict:
    p = run(["sudo", "-n", helper, "check"])
    if p.returncode != 0:
        raise QuotaError((p.stderr or p.stdout).strip()[:500] or "quota helper check failed")
    return json.loads(p.stdout)
