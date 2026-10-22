"""Job records on the host: one JSON file per job, written atomically."""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field

ACTIVE_STATES = ("creating", "running", "finishing")
TERMINAL_STATES = ("finished", "failed", "killed")


@dataclass
class Job:
    id: str
    repo: str
    title: str
    egress: str
    branch: str
    read_repos: list[str]
    limits: dict
    env_project: str | None
    state: str = "creating"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    ended_at: float | None = None
    last_output_at: float | None = None
    last_output_size: int = 0
    status_lines: int = 0
    last_status: dict | None = None
    sandbox: str = ""
    default_branch: str = ""
    image: str = ""
    profiles: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    tokens: dict = field(default_factory=dict)  # provider -> {installation_id, repos, expires_at}
    token_refreshed_at: float | None = None
    end_reason: str | None = None
    exit_code: int | None = None
    pr_url: str | None = None
    selftest: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return self.state in ACTIVE_STATES

    def public(self) -> dict:
        d = asdict(self)
        d.pop("tokens", None)
        d["tokens"] = {k: {kk: vv for kk, vv in v.items() if kk != "token"}
                       for k, v in self.tokens.items()}
        return d


def new_job_id(now: float | None = None) -> str:
    t = time.gmtime(now if now is not None else time.time())
    return f"j{time.strftime('%Y%m%d', t)}-{secrets.token_hex(3)}"


class JobStore:
    def __init__(self, jobs_dir: str):
        self.dir = jobs_dir
        os.makedirs(self.dir, mode=0o750, exist_ok=True)

    def _path(self, job_id: str) -> str:
        if not job_id or "/" in job_id or job_id.startswith("."):
            raise ValueError(f"invalid job id: {job_id!r}")
        return os.path.join(self.dir, f"{job_id}.json")

    def job_dir(self, job_id: str) -> str:
        d = os.path.join(self.dir, job_id)
        os.makedirs(d, mode=0o750, exist_ok=True)
        return d

    @contextmanager
    def lock(self):
        """Serialize job creation/updates between the CLI and yardd."""
        fd = os.open(os.path.join(self.dir, ".lock"), os.O_RDWR | os.O_CREAT, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def exists(self, job_id: str) -> bool:
        return os.path.exists(self._path(job_id))

    def save(self, job: Job) -> None:
        path = self._path(job.id)
        tmp = f"{path}.tmp.{os.getpid()}"
        with open(tmp, "w") as fh:
            json.dump(asdict(job), fh, indent=1, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)

    def load(self, job_id: str) -> Job:
        with open(self._path(job_id)) as fh:
            data = json.load(fh)
        return Job(**data)

    def all(self) -> list[Job]:
        jobs = []
        for name in sorted(os.listdir(self.dir)):
            if name.endswith(".json") and not name.startswith("."):
                try:
                    jobs.append(self.load(name[:-5]))
                except (ValueError, OSError, TypeError):
                    continue
        return sorted(jobs, key=lambda j: j.created_at)

    def active(self) -> list[Job]:
        return [j for j in self.all() if j.active]
