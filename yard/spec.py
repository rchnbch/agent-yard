"""Job spec parsing.

A spec is a Markdown file: the task for the worker, used verbatim as the
prompt body. It may start with a front-matter block of flat ``key: value``
lines between ``---`` fences that sets job options; command-line flags win
over front matter. Example::

    ---
    repo: rchnbch/example
    egress: deny
    read_repos: rchnbch/lib-a, rchnbch/lib-b
    timeout: 2h
    ---
    # Add a health check endpoint
    ...
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import limits as L
from .policy import PolicyError, validate_repo

MAX_SPEC_BYTES = 200 * 1024
JOB_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,38}[a-z0-9]$")
BRANCH_RE = re.compile(r"^(?!/)(?!.*//)(?!.*\.\.)(?!.*@\{)[A-Za-z0-9._/-]{1,200}(?<![./])$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")

FRONT_MATTER_KEYS = {"repo", "branch", "egress", "read_repos", "timeout", "idle", "disk",
                     "cpu", "memory", "env_project", "job_id"}


class SpecError(ValueError):
    pass


@dataclass(frozen=True)
class JobRequest:
    repo: str
    spec_text: str
    title: str
    branch: str | None = None
    job_id: str | None = None
    egress: str = "open"
    read_repos: tuple[str, ...] = ()
    limits: L.Limits = field(default_factory=L.Limits)
    env_project: str | None = None

    def to_dict(self) -> dict:
        return {"repo": self.repo, "title": self.title, "branch": self.branch,
                "job_id": self.job_id, "egress": self.egress,
                "read_repos": list(self.read_repos), "limits": self.limits.to_dict(),
                "env_project": self.env_project}


def split_front_matter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end < 0:
        raise SpecError("front matter starts with '---' but has no closing '---'")
    meta: dict[str, str] = {}
    for n, line in enumerate(text[4:end].splitlines(), start=2):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            raise SpecError(f"front matter line {n}: expected 'key: value'")
        key, value = line.split(":", 1)
        key = key.strip()
        if key not in FRONT_MATTER_KEYS:
            raise SpecError(f"front matter line {n}: unknown key {key!r}")
        if key in meta:
            raise SpecError(f"front matter line {n}: duplicate key {key!r}")
        meta[key] = value.strip()
    return meta, text[end + 5:]


def spec_title(body: str) -> str:
    for line in body.splitlines():
        m = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if m:
            return m.group(1)[:200]
    for line in body.splitlines():
        if line.strip():
            return line.strip()[:200]
    return "(untitled)"


def _list(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(v.strip() for v in value.split(",") if v.strip())


def parse_job(spec_bytes: bytes, overrides: dict | None = None) -> JobRequest:
    """Build a JobRequest from spec file bytes plus CLI overrides (None = unset)."""
    if len(spec_bytes) > MAX_SPEC_BYTES:
        raise SpecError(f"spec is {len(spec_bytes)} bytes; the limit is {MAX_SPEC_BYTES}")
    try:
        text = spec_bytes.decode("utf-8")
    except UnicodeDecodeError as err:
        raise SpecError(f"spec is not UTF-8: {err}") from None
    if "\x00" in text:
        raise SpecError("spec contains a NUL byte")
    text = text.replace("\r\n", "\n")
    meta, body = split_front_matter(text)
    if not body.strip():
        raise SpecError("spec body is empty")
    opts = dict(meta)
    for k, v in (overrides or {}).items():
        if v is not None:
            opts[k] = v

    repo = opts.get("repo")
    if not repo:
        raise SpecError("no target repo: pass --repo or set 'repo:' in the spec front matter")
    try:
        validate_repo(repo)
        read_repos = opts.get("read_repos")
        read = _list(read_repos) if isinstance(read_repos, str) or read_repos is None else tuple(read_repos)
        for r in read:
            validate_repo(r)
    except PolicyError as err:
        raise SpecError(str(err)) from None
    if any(r.lower() == repo.lower() for r in read):
        raise SpecError("read_repos must not include the target repo")
    if len({r.lower() for r in read}) != len(read):
        raise SpecError("read_repos contains duplicates")

    egress = opts.get("egress", "open")
    if egress not in ("open", "deny"):
        raise SpecError(f"egress must be 'open' or 'deny', not {egress!r}")
    branch = opts.get("branch") or None
    if branch is not None and not BRANCH_RE.match(branch):
        raise SpecError(f"invalid branch name: {branch!r}")
    job_id = opts.get("job_id") or None
    if job_id is not None and not JOB_ID_RE.match(job_id):
        raise SpecError("job id must be 4-40 chars of a-z, 0-9 and '-', not starting or ending with '-'")
    project = opts.get("env_project") or None
    if project is not None and not PROJECT_RE.match(project):
        raise SpecError(f"invalid project name: {project!r}")

    try:
        lim = L.Limits(
            timeout_s=L.parse_duration(opts["timeout"]) if opts.get("timeout") else L.DEFAULT_TIMEOUT_S,
            idle_s=L.parse_duration(opts["idle"]) if opts.get("idle") else L.DEFAULT_IDLE_S,
            disk_bytes=L.parse_size(opts["disk"]) if opts.get("disk") else L.DEFAULT_DISK_BYTES,
            cpu=L.validate_cpu(opts["cpu"]) if opts.get("cpu") else None,
            memory=L.validate_memory(opts["memory"]) if opts.get("memory") else None,
        )
    except L.LimitError as err:
        raise SpecError(str(err)) from None

    return JobRequest(repo=repo, spec_text=body, title=spec_title(body), branch=branch,
                      job_id=job_id, egress=egress, read_repos=read, limits=lim,
                      env_project=project)
