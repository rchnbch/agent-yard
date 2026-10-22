"""Host-side implementation of every ``yard`` command.

Runs as the gateway user on the yard host. The laptop CLI reaches it over
SSH on the tailnet (see docs/DESIGN.md, "Transport"); yardd (daemon.py) runs
the same code on a timer. All external effects go through injected
adapters so the orchestration logic is unit-testable.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from typing import Callable

from . import images, limits as L, policy as P, prove, quota, worker
from .config import HostConfig
from .events import EventLog
from .github import (CHECK_PERMISSIONS, READ_PERMISSIONS, WRITE_PERMISSIONS, GitHubApp,
                     GitHubError, download_tarball)
from .openshell import OpenShell, OpenShellError
from .spec import JobRequest, SpecError
from .state import Job, JobStore, new_job_id
from .yamlout import dumps as yaml_dumps

TOKEN_REFRESH_S = 40 * 60
READY_TIMEOUT_S = 900
SANDBOX_PREFIX = "y-"
MAX_SANDBOX_NAME = 19  # OpenShell routable-name limit


class YardError(RuntimeError):
    """A refusal or failure reported to the caller (exit code 1)."""


@dataclass
class Deps:
    openshell: OpenShell
    github: GitHubApp | None
    engine: images.Podman
    quota_apply: Callable[[str, int], dict]
    quota_release: Callable[[str], None]
    host_resources: Callable[[], tuple[int, int]]
    clock: Callable[[], float] = time.time
    prove_checks: Callable = prove.job_checks


def host_resources() -> tuple[int, int]:
    cpus = os.cpu_count() or 1
    with open("/proc/meminfo") as fh:
        for line in fh:
            if line.startswith("MemTotal:"):
                return cpus, int(line.split()[1]) * 1024
    return cpus, 4 * 1024**3


def default_deps(cfg: HostConfig) -> Deps:
    gh = None
    if cfg.github_app_id and os.path.exists(cfg.github_private_key):
        gh = GitHubApp(cfg.github_app_id, cfg.github_private_key)
    engine_cmd = ["podman", "--url", cfg.podman_url] if cfg.engine == "podman" else ["docker"]
    return Deps(
        openshell=OpenShell(gateway=cfg.openshell_gateway),
        github=gh,
        engine=images.Podman(engine_cmd),
        quota_apply=lambda job, n: quota.apply(cfg.quota_helper, job, n),
        quota_release=lambda job: quota.release(cfg.quota_helper, job),
        host_resources=host_resources,
    )


def _write_private(path: str, data: str | bytes, mode: int = 0o600) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data.encode() if isinstance(data, str) else data)


class Yard:
    def __init__(self, cfg: HostConfig, deps: Deps | None = None):
        self.cfg = cfg
        self.deps = deps or default_deps(cfg)
        self.jobs = JobStore(cfg.jobs_dir)
        self.events = EventLog(cfg.events_path)

    # ------------------------------------------------------------ helpers
    def _gh(self) -> GitHubApp:
        if self.deps.github is None:
            raise YardError("GitHub App is not configured: set [github] app_id and run "
                            "'yard secrets set github-app-key'")
        return self.deps.github

    def _token_file(self, job_id: str) -> str:
        return self.cfg.secret_path(os.path.join("jobs", f"{job_id}.json"))

    def _load_tokens(self, job_id: str) -> dict:
        try:
            with open(self._token_file(job_id)) as fh:
                return json.load(fh)
        except FileNotFoundError:
            return {}

    def _save_tokens(self, job_id: str, tokens: dict) -> None:
        _write_private(self._token_file(job_id), json.dumps(tokens))

    def _claude_token(self) -> str:
        path = self.cfg.secret_path("claude-oauth-token")
        try:
            with open(path) as fh:
                tok = fh.read().strip()
        except FileNotFoundError:
            raise YardError("Claude token missing: run 'claude setup-token' on the laptop, then "
                            "'yard secrets set claude-oauth-token'") from None
        if not tok:
            raise YardError("Claude token file is empty")
        return tok

    def _emit(self, etype: str, job: Job | None, **data) -> dict:
        return self.events.append(etype, job.id if job else None, data)

    def _job(self, job_id: str) -> Job:
        if not self.jobs.exists(job_id):
            raise YardError(f"no such job: {job_id}")
        return self.jobs.load(job_id)

    # ------------------------------------------------------------ run
    def run(self, req: JobRequest, main_command: list[str] | None = None,
            selftest: bool = False, extra_uploads: list[tuple[str, str]] | None = None) -> Job:
        gh = self._gh()
        claude_token = self._claude_token()
        project = None
        if req.env_project:
            project = self.cfg.projects.get(req.env_project)
            if project is None:
                raise YardError(f"unknown env project {req.env_project!r} (see [projects] in yard.toml)")
        with self.jobs.lock():
            if len(self.jobs.active()) >= self.cfg.max_jobs:
                raise YardError(f"concurrency cap reached ({self.cfg.max_jobs} active jobs)")
            job_id = req.job_id or new_job_id(self.deps.clock())
            if self.jobs.exists(job_id):
                raise YardError(f"job id {job_id} already exists")
            branch = req.branch or f"yard/{job_id}"
            job = Job(id=job_id, repo=req.repo, title=req.title, egress=req.egress,
                      branch=branch, read_repos=list(req.read_repos),
                      limits=req.limits.to_dict(), env_project=req.env_project,
                      sandbox=sandbox_name(job_id), selftest=selftest,
                      created_at=self.deps.clock())
            self.jobs.save(job)
        self._emit("job.created", job, repo=job.repo, title=job.title, egress=job.egress,
                   branch=job.branch, read_repos=job.read_repos, limits=job.limits)
        try:
            self._start(job, req, gh, claude_token, project, main_command, extra_uploads or [])
        except Exception as err:  # noqa: BLE001 - every failure must clean up
            job.errors.append(str(err)[:2000])
            self._finish(job, "failed", f"start failed: {err}")
            if isinstance(err, (YardError, SpecError, GitHubError, OpenShellError,
                                images.ImageError, quota.QuotaError, P.PolicyError)):
                raise YardError(f"job {job.id} failed to start: {err}") from None
            raise
        return job

    def _start(self, job: Job, req: JobRequest, gh: GitHubApp, claude_token: str, project,
               main_command, extra_uploads) -> None:
        jdir = self.jobs.job_dir(job.id)
        tokens: dict = {}

        # 1. Host-side prep token: canonical name, default branch, protection, tarball.
        inst = gh.installation_for(job.repo)
        prep = gh.mint(inst, [job.repo], {**CHECK_PERMISSIONS, "contents": "read"})
        try:
            meta = gh.canonical_repo(prep.token, job.repo)
            job.repo = meta["full_name"]
            job.default_branch = meta["default_branch"]
            if job.branch == job.default_branch:
                raise YardError(f"branch {job.branch!r} is the default branch; workers never push there")
            evidence = gh.push_protection(prep.token, job.repo, job.default_branch,
                                          self.cfg.github_app_slug)
            if not evidence["blocks_direct_push"]:
                raise YardError(f"{job.repo}: default branch {job.default_branch!r} has no branch "
                                "protection or ruleset that blocks direct pushes by the yard App; "
                                f"refusing (evidence: {json.dumps(evidence)})")
            with tempfile.TemporaryDirectory(dir=jdir) as tmp:
                tarball = os.path.join(tmp, "repo.tar.gz")
                download_tarball(gh, prep.token, job.repo, job.default_branch, tarball)
                root = images.safe_extract(tarball, os.path.join(tmp, "src"))
                img = images.resolve_image(self.deps.engine, self.cfg.base_image, root, job.repo)
        finally:
            gh.revoke(prep.token)
        job.image = img["image"]

        # 2. Per-job tokens: write on the target, read on read_repos (per installation).
        write_tok = gh.mint(inst, [job.repo], WRITE_PERMISSIONS)
        tokens[P.provider_name(job.id, "ghw")] = {"token": write_tok.token, **write_tok.redacted(),
                                                  "permissions_req": WRITE_PERMISSIONS,
                                                  "env": "GITHUB_TOKEN"}
        groups: dict[int, list[str]] = {}
        for r in job.read_repos:
            groups.setdefault(gh.installation_for(r), []).append(r)
        read_groups = []
        read_env = {}
        for idx, (rinst, repos) in enumerate(sorted(groups.items())):
            rt = gh.mint(rinst, repos, READ_PERMISSIONS)
            name = P.provider_name(job.id, "ghr", idx)
            tokens[name] = {"token": rt.token, **rt.redacted(), "permissions_req": READ_PERMISSIONS,
                            "env": f"YARD_GH_READ_TOKEN_{idx}"}
            read_groups.append(rt.repositories)
            for r in rt.repositories:
                read_env[r] = f"YARD_GH_READ_TOKEN_{idx}"
        job.read_repos = [r for g in read_groups for r in g]
        self._save_tokens(job.id, tokens)
        with open(os.path.join(jdir, "token-hashes.json"), "w") as fh:
            # sha256 of each real token, for the selftest's cross-check only.
            json.dump([hashlib.sha256(t["token"].encode()).hexdigest() for t in tokens.values()], fh)
        job.tokens = {k: {kk: vv for kk, vv in v.items() if kk != "token"} for k, v in tokens.items()}
        job.token_refreshed_at = self.deps.clock()
        self.jobs.save(job)

        # 3. Policy + provider profiles, proven before anything is created.
        services = tuple(self.cfg.services[s] for s in (project.services if project else ()))
        net = P.JobNetwork(job_id=job.id, repo=job.repo, egress=job.egress,
                           read_repos=tuple(job.read_repos),
                           registries=tuple(project.registries) if project else (),
                           services=services)
        ctx = P.PolicyContext()
        base = P.render_sandbox_policy(net, ctx)
        gh_profiles = P.job_profiles(P.JobNetwork(job_id=job.id, repo=job.repo, egress=job.egress,
                                                  read_repos=tuple(job.read_repos)), read_groups, ctx)
        attached = [(p["id"], p) for p in gh_profiles]
        for svc in services:
            attached.append((project_provider_name(project.name, svc.id), P.service_profile(svc, P.public_ipv4())))
        checks = self.deps.prove_checks(base, attached, job.egress)
        with open(os.path.join(jdir, "prover.json"), "w") as fh:
            json.dump([c.to_dict() for c in checks], fh, indent=1)
        failed = [c for c in checks if not c.ok]
        if failed:
            raise YardError("policy proof failed: " + "; ".join(f"{c.name}: {c.result} {c.detail or ''}"
                                                                for c in failed))
        policy_path = os.path.join(jdir, "policy.yaml")
        with open(policy_path, "w") as fh:
            fh.write(yaml_dumps(base))

        os_ = self.deps.openshell
        for prof in gh_profiles:
            path = os.path.join(jdir, f"profile-{prof['id']}.yaml")
            with open(path, "w") as fh:
                fh.write(yaml_dumps(prof))
            os_.profile_import(path)
            job.profiles.append(prof["id"])
            self.jobs.save(job)
        for prof in gh_profiles:
            pname = prof["id"]
            os_.provider_create(pname, prof["id"], {tokens[pname]["env"]: tokens[pname]["token"]})
            job.providers.append(pname)
            self.jobs.save(job)
        project_providers = []
        for svc in services:
            name = project_provider_name(project.name, svc.id)
            if not os_.provider_exists(name):
                raise YardError(f"project secret {svc.env_var} for {project.name!r} is not set: "
                                f"yard secrets set --project {project.name} {svc.env_var}")
            project_providers.append(name)

        # 4. Worker files.
        # Uploaded as a directory named .yard into /sandbox (upload keeps the name).
        updir = os.path.join(jdir, "upload", ".yard")
        os.makedirs(updir, exist_ok=True)
        with open(os.path.join(updir, "prompt.md"), "w") as fh:
            fh.write(worker.render_prompt(job.id, job.repo, job.branch, job.default_branch,
                                          job.egress, job.read_repos, req.spec_text))
        with open(os.path.join(updir, "job.json"), "w") as fh:
            json.dump(worker.job_file(job.id, job.repo, job.branch, job.default_branch, read_env), fh)
        for local, name in extra_uploads:
            shutil.copy(local, os.path.join(updir, name))

        # 5. Sandbox.
        lim = L.Limits.from_dict(job.limits)
        cpu, memory = L.effective_resources(lim, *self.deps.host_resources())
        os_.sandbox_create(
            name=job.sandbox, image=job.image, policy_path=policy_path,
            providers=job.providers + project_providers,
            command=worker.gated(main_command or worker.main_command()),
            cpu=cpu, memory=memory,
            env_from={"CLAUDE_CODE_OAUTH_TOKEN": claude_token},
            labels={"agent-yard.job": job.id},
            approval_mode="auto" if job.egress == "open" else "manual",
        )
        self._wait_ready(job)
        os_.sandbox_upload(job.sandbox, updir, os.path.dirname(worker.YARD_DIR))
        # Quota before the go signal: the workload writes nothing until then.
        q = self.deps.quota_apply(job.id, lim.disk_bytes)
        res = os_.sandbox_exec(job.sandbox, ["/bin/sh", "-c",
                                             f"test -s {worker.JOB_FILE} && touch {worker.GO_FILE}"])
        if res.returncode != 0:
            raise YardError(f"could not hand job files to the sandbox: {res.stderr.strip()[:300]}")
        now = self.deps.clock()
        job.state = "running"
        job.started_at = now
        job.last_output_at = now
        self.jobs.save(job)
        self._emit("job.running", job, sandbox=job.sandbox, image=job.image, quota=q,
                   prover=[c.to_dict() for c in checks], default_branch=job.default_branch)

    def _wait_ready(self, job: Job) -> None:
        deadline = self.deps.clock() + READY_TIMEOUT_S
        while True:
            sb = self.deps.openshell.sandbox_get(job.sandbox)
            phase = (sb or {}).get("phase")
            if phase == "Ready":
                return
            if phase in ("Error", "Failed") or (sb and sb.get("exit_code") is not None):
                raise YardError(f"sandbox {job.sandbox} failed to start: phase={phase} "
                                f"conditions={(sb or {}).get('conditions')}")
            if self.deps.clock() > deadline:
                raise YardError(f"sandbox {job.sandbox} not ready after {READY_TIMEOUT_S}s (phase={phase})")
            time.sleep(3)

    # ------------------------------------------------------------ teardown
    def _harvest(self, job: Job) -> None:
        """Copy /sandbox/.yard out of the (possibly exited) workload container."""
        jdir = self.jobs.job_dir(job.id)
        dest = os.path.join(jdir, "final")
        if os.path.exists(dest):
            return
        cid = self.deps.engine.workload_container(job.sandbox)
        if cid and self.deps.engine.copy_out(cid, worker.YARD_DIR, dest):
            try:
                with open(os.path.join(dest, "status.jsonl"), errors="replace") as fh:
                    self._ingest_status(job, fh.read())
            except FileNotFoundError:
                pass

    def _finish(self, job: Job, state: str, reason: str) -> None:
        if job.state in ("finished", "failed", "killed"):
            return
        job.state = "finishing"
        job.end_reason = reason
        self.jobs.save(job)
        os_ = self.deps.openshell
        try:
            self._harvest(job)
        except Exception as err:  # noqa: BLE001
            job.errors.append(f"harvest: {err}")
        if job.sandbox:
            res = os_.sandbox_delete(job.sandbox)
            if res.returncode != 0 and "not found" not in (res.stderr + res.stdout).lower():
                job.errors.append(f"sandbox delete: {res.stderr.strip()[:300]}")
        tokens = self._load_tokens(job.id)
        revoked = []
        for name, t in tokens.items():
            try:
                self._gh().revoke(t["token"])
                revoked.append(name)
            except Exception as err:  # noqa: BLE001
                job.errors.append(f"revoke {name}: {err}")
        for name in job.providers:
            os_.provider_delete(name)
        for pid in job.profiles:
            os_.profile_delete(pid)
        try:
            os.unlink(self._token_file(job.id))
        except FileNotFoundError:
            pass
        try:
            self.deps.quota_release(job.id)
        except Exception as err:  # noqa: BLE001
            job.errors.append(f"quota release: {err}")
        job.state = state
        job.ended_at = self.deps.clock()
        self.jobs.save(job)
        etype = {"finished": "job.finished", "failed": "job.failed", "killed": "job.killed"}[state]
        self._emit(etype, job, reason=reason, exit_code=job.exit_code, pr_url=job.pr_url,
                   revoked_tokens=revoked, errors=job.errors[-5:],
                   last_status=job.last_status)

    # ------------------------------------------------------------ polling
    def _ingest_status(self, job: Job, raw: str) -> None:
        entries, total = worker.parse_status_lines(raw, job.status_lines)
        for e in entries:
            job.last_status = e
            pr = worker.find_pr_url(e["note"], job.repo)
            if pr:
                job.pr_url = pr
            self._emit("job.status", job, **e)
            if e["attn"]:
                self._emit("job.attention", job, note=e["note"], source="worker")
        job.status_lines = total
        self.jobs.save(job)

    def poll_job(self, job: Job) -> None:
        os_ = self.deps.openshell
        now = self.deps.clock()
        sb = os_.sandbox_get(job.sandbox)
        if sb is None:
            self._finish(job, "failed", "sandbox disappeared")
            return
        if sb.get("exit_code") is not None or sb.get("phase") in ("Error", "Failed"):
            job.exit_code = sb.get("exit_code")
            # Read the final status lines (written after the last poll) before
            # deciding the terminal state.
            try:
                self._harvest(job)
            except Exception as err:  # noqa: BLE001
                job.errors.append(f"harvest: {err}")
            ok = job.exit_code == 0 and (job.last_status or {}).get("status") != "failed"
            self._finish(job, "finished" if ok else "failed", f"main process exited ({job.exit_code})")
            return
        res = os_.sandbox_exec(job.sandbox, ["/bin/sh", "-c",
                               f"cat {worker.STATUS_FILE} 2>/dev/null; "
                               f"printf '\\n@@YARD-LOGSIZE@@ %s\\n' \"$(stat -c %s {worker.AGENT_LOG} 2>/dev/null || echo 0)\""])
        if res.returncode == 0 and "@@YARD-LOGSIZE@@" in res.stdout:
            body, _, tail = res.stdout.rpartition("\n@@YARD-LOGSIZE@@ ")
            try:
                size = int(tail.strip().split()[0])
            except (ValueError, IndexError):
                size = job.last_output_size
            if size != job.last_output_size:
                job.last_output_size = size
                job.last_output_at = now
            # No terminator added: an unterminated last line is still being
            # written and must stay unparsed until the next poll.
            self._ingest_status(job, body)
        lim = L.Limits.from_dict(job.limits)
        reason = L.check_limits(lim, now, job.started_at or now, job.last_output_at or now)
        if reason:
            self._emit("job.attention", job, note=f"killing job: {reason} limit reached", source="yard")
            self._finish(job, "killed", reason)
            return
        if now - (job.token_refreshed_at or now) >= TOKEN_REFRESH_S:
            self._refresh_tokens(job)
        self._poll_approvals(job)

    def _refresh_tokens(self, job: Job) -> None:
        gh = self._gh()
        tokens = self._load_tokens(job.id)
        for name, t in tokens.items():
            new = gh.mint(int(t["installation_id"]), t["repositories"], t["permissions_req"])
            self.deps.openshell.provider_update(name, {t["env"]: new.token})
            old = t["token"]
            tokens[name] = {**t, "token": new.token, "expires_at": new.expires_at}
            self._save_tokens(job.id, tokens)
            try:
                gh.revoke(old)
            except GitHubError as err:
                job.errors.append(f"revoke old {name}: {err}")
        job.token_refreshed_at = self.deps.clock()
        self.jobs.save(job)

    def _job_allowlist(self, job: Job) -> set[str]:
        """Hosts a deny-mode proposal may be auto-approved for: the project's
        registries only. Credentialed hosts (GitHub, service hosts) and
        Anthropic always go to Alex, so an auto-approved rule can never
        change what a credential can do."""
        if job.env_project and job.env_project in self.cfg.projects:
            return set(self.cfg.projects[job.env_project].registries)
        return set()

    def _poll_approvals(self, job: Job) -> None:
        pending = self.deps.openshell.pending_rules(job.sandbox)
        jdir = self.jobs.job_dir(job.id)
        seen_path = os.path.join(jdir, "seen-chunks.json")
        try:
            with open(seen_path) as fh:
                seen = set(json.load(fh))
        except FileNotFoundError:
            seen = set()
        allow = self._job_allowlist(job)
        for rule in pending:
            if rule.chunk_id in seen:
                continue
            seen.add(rule.chunk_id)
            auto, why = self._auto_decision(job, rule, allow)
            if auto:
                self.deps.openshell.rule_approve(job.sandbox, rule.chunk_id)
                self._emit("approval.auto", job, proposal=f"{job.id}:{rule.chunk_id}",
                           rule=rule.to_dict(), why=why)
            else:
                self._emit("approval.pending", job, proposal=f"{job.id}:{rule.chunk_id}",
                           rule=rule.to_dict(), why=why)
                self._emit("job.attention", job, source="yard",
                           note=f"proposal {job.id}:{rule.chunk_id} waits for review: {why}")
        with open(seen_path, "w") as fh:
            json.dump(sorted(seen), fh)

    def _auto_decision(self, job: Job, rule, allow: set[str]) -> tuple[bool, str]:
        """Deny mode only: approve iff OpenShell found nothing AND the rule
        only reaches hosts already on this job's allowlist."""
        if job.egress != "deny":
            return False, "open mode: OpenShell auto-approval declined it (flagged)"
        if not rule.prover_clean:
            return False, f"OpenShell risk check: {rule.prover or 'no verdict'}"
        if rule.security.strip():
            return False, f"flagged destination: {rule.security}"
        if not rule.endpoints:
            return False, "could not parse endpoints"
        for ep in rule.endpoints:
            if ep.get("host") not in allow or ep.get("port") != 443:
                return False, f"{ep.get('host')}:{ep.get('port')} is not one of this job's registries"
        return True, "prover-clean and only reaches this job's registries"

    # ------------------------------------------------------------ commands
    def status(self, job_id: str | None = None) -> dict:
        if job_id:
            return {"job": self._job(job_id).public()}
        return {"jobs": [j.public() for j in self.jobs.all()]}

    def kill(self, job_id: str) -> dict:
        job = self._job(job_id)
        if not job.active:
            return {"job": job.public(), "changed": False}
        self._finish(job, "killed", "killed by request")
        return {"job": job.public(), "changed": True}

    def logs(self, job_id: str, tail_bytes: int = 200_000) -> str:
        job = self._job(job_id)
        final = os.path.join(self.jobs.job_dir(job.id), "final", "agent.log")
        if not job.active and os.path.exists(final):
            with open(final, "rb") as fh:
                fh.seek(max(0, os.path.getsize(final) - tail_bytes))
                return fh.read().decode(errors="replace")
        if not job.active:
            return ""
        res = self.deps.openshell.sandbox_exec(job.sandbox, ["tail", "-c", str(tail_bytes), worker.AGENT_LOG])
        return res.stdout

    def events_since(self, cursor: str | None, limit: int = 1000, job: str | None = None) -> dict:
        return self.events.read_since(cursor, limit=limit, job=job)

    def approvals(self) -> dict:
        out = []
        for job in self.jobs.active():
            if job.state != "running":
                continue
            for rule in self.deps.openshell.pending_rules(job.sandbox):
                out.append({"proposal": f"{job.id}:{rule.chunk_id}", "job": job.id, **rule.to_dict()})
        return {"approvals": out}

    def decide(self, proposal: str, approve: bool, reason: str | None) -> dict:
        job_id, _, chunk = proposal.partition(":")
        if not chunk:
            raise YardError("proposal ids look like <job-id>:<chunk-id> (see 'yard approvals')")
        job = self._job(job_id)
        if not job.active:
            raise YardError(f"job {job_id} is not running")
        if approve:
            self.deps.openshell.rule_approve(job.sandbox, chunk)
        else:
            self.deps.openshell.rule_reject(job.sandbox, chunk, reason or "rejected by Alex")
        self._emit("approval.decided", job, proposal=proposal, approved=approve, reason=reason)
        return {"proposal": proposal, "approved": approve}

    def tick(self) -> bool:
        """One yardd iteration over every running job, plus orphan cleanup.

        Only one ticker runs at a time (yardd, or selftest's wait loop); a
        concurrent call returns False without doing anything."""
        fd = os.open(os.path.join(self.jobs.dir, ".tick.lock"), os.O_RDWR | os.O_CREAT, 0o640)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            self._tick()
            return True
        finally:
            os.close(fd)

    def _tick(self) -> None:
        for job in self.jobs.active():
            try:
                if job.state == "running":
                    self.poll_job(job)
                elif job.state == "finishing":
                    st = "killed" if job.end_reason in ("timeout", "idle", "killed by request") else "failed"
                    job.state = "running"
                    self._finish(job, st, job.end_reason or "recovered unfinished teardown")
                elif job.state == "creating" and self.deps.clock() - job.created_at > READY_TIMEOUT_S + 600:
                    self._finish(job, "failed", "stuck in creating (yard restarted mid-start?)")
            except Exception as err:  # noqa: BLE001 - one bad job must not stop the loop
                self._emit("host.warning", job, error=str(err)[:1000], where="tick")
        self.reap_orphans()

    def reap_orphans(self) -> list[str]:
        known = {j.sandbox for j in self.jobs.active()}
        reaped = []
        try:
            boxes = self.deps.openshell.sandbox_list()
        except Exception:  # noqa: BLE001
            return reaped
        for sb in boxes:
            name = sb.get("name", "")
            if name.startswith(SANDBOX_PREFIX) and name not in known:
                self.deps.openshell.sandbox_delete(name)
                reaped.append(name)
                self._emit("job.cleanup", None, sandbox=name, reason="orphan sandbox deleted")
        return reaped


def sandbox_name(job_id: str) -> str:
    name = f"{SANDBOX_PREFIX}{job_id}"
    if len(name) <= MAX_SANDBOX_NAME:
        return name
    return f"{SANDBOX_PREFIX}{hashlib.sha256(job_id.encode()).hexdigest()[:12]}"


def project_provider_name(project: str, service: str) -> str:
    return f"proj-{project}-{service}"
