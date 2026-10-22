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

JOB_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,38}[a-z0-9]$")

Run = Callable[[Sequence[str]], subprocess.CompletedProcess]


class QuotaError(RuntimeError):
    pass


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True, check=False, timeout=120)


def apply(helper: str, job_id: str, limit_bytes: int, run: Run = _run) -> dict:
    """The helper derives the sandbox name and directories from the job id."""
    if not JOB_RE.match(job_id):
        raise QuotaError(f"refusing quota for unexpected job id {job_id!r}")
    if limit_bytes <= 0:
        raise QuotaError("quota must be positive")
    p = run(["sudo", "-n", helper, "apply", job_id, str(limit_bytes)])
    if p.returncode != 0:
        raise QuotaError(f"quota helper failed ({p.returncode}): {(p.stderr or p.stdout).strip()[:500]}")
    try:
        return json.loads(p.stdout)
    except ValueError:
        raise QuotaError(f"quota helper returned non-JSON: {p.stdout[:200]!r}") from None


def release(helper: str, job_id: str, run: Run = _run) -> None:
    run(["sudo", "-n", helper, "release", job_id])


def podman_user_denied(helper: str, pod_user: str = "yard-pod", run: Run = _run) -> tuple[bool, str]:
    """Selftest: as the Podman user, invoking the helper through sudo must fail.

    Uses the one sudoers rule that lets ``yard`` run exactly
    ``sudo -n -- <helper> check`` as the Podman user.
    """
    p = run(["sudo", "-n", "-u", pod_user, "--", "/usr/bin/sudo", "-n", "--", helper, "check"])
    out = (p.stderr + p.stdout).strip()[:300]
    return p.returncode != 0 and '"ok": true' not in p.stdout, f"rc={p.returncode} {out}"


def check(helper: str, run: Run = _run) -> dict:
    p = run(["sudo", "-n", helper, "check"])
    if p.returncode != 0:
        raise QuotaError((p.stderr or p.stdout).strip()[:500] or "quota helper check failed")
    return json.loads(p.stdout)
