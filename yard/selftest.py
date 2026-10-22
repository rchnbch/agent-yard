"""``yard selftest``: adversarial jobs on the live host, each attempt with evidence.

Jobs started (all through the normal ``Yard.run`` path, so they get the real
policy, providers, quota and limits):

* ``neighbor``  - a sandbox holding a canary file, kept running.
* ``adv-open``  - selftest/probe.sh in open egress mode.
* ``adv-deny``  - selftest/probe.sh in deny egress mode.
* ``timeout``   - prints output forever; must be killed by the wall clock.
* ``idle``      - prints nothing; must be killed by the idle limit.
* ``quota``     - writes past a 1 GiB quota; the write must fail.

The host then adds evidence the sandbox cannot forge: hashes of the real
GitHub tokens, the default branch SHA before and after, and the PR state.
"""

from __future__ import annotations

import json
import os
import secrets
import time

from . import limits as L
from .config import SHARE_DIR
from .github import WRITE_PERMISSIONS
from .host import Yard
from .secrets import set_project_secret
from .spec import JobRequest

SELFTEST_PROJECT = "selftest"
CANARY_ENV = "YARD_SELFTEST_CANARY"
PROBE = os.environ.get("YARD_PROBE", os.path.join(SHARE_DIR, "selftest", "probe.sh"))

SPEC = "# agent-yard selftest\nScripted probe; no model task.\n"


def _req(repo: str, read_repo: str | None, egress: str, job_id: str, **lim) -> JobRequest:
    return JobRequest(repo=repo, spec_text=SPEC, title=f"selftest {job_id}", job_id=job_id,
                      egress=egress, read_repos=(read_repo,) if read_repo else (),
                      limits=L.Limits(**lim), env_project=SELFTEST_PROJECT)


def _wait(yard: Yard, job_ids: list[str], deadline: float, poll: float) -> None:
    while time.time() < deadline:
        yard.tick()
        if all(not yard.jobs.load(j).active for j in job_ids):
            return
        time.sleep(poll)


def _probe_results(yard: Yard, job_id: str) -> list[dict]:
    path = os.path.join(yard.jobs.job_dir(job_id), "final", "selftest.jsonl")
    try:
        with open(path) as fh:
            return [json.loads(line) for line in fh if line.strip()]
    except (OSError, ValueError):
        return []


def run(yard: Yard, repo: str, read_repo: str | None, quick: bool = False,
        poll: float = 10.0) -> dict:
    tag = secrets.token_hex(3)
    gh = yard._gh()
    report: dict = {"tag": tag, "repo": repo, "read_repo": read_repo, "checks": []}

    def check(name: str, ok: bool, evidence: object) -> None:
        report["checks"].append({"check": name, "pass": bool(ok), "evidence": evidence})

    # Fresh canary project secret, bound to postman-echo.com (not the exfil target).
    canary = f"yard-canary-{secrets.token_hex(12)}"
    set_project_secret(yard.cfg, yard.deps.openshell, SELFTEST_PROJECT, CANARY_ENV, canary.encode())

    inst = gh.installation_for(repo)
    t = gh.mint(inst, [repo], {"contents": "read", "metadata": "read"})
    meta = gh.canonical_repo(t.token, repo)
    default = meta["default_branch"]
    sha_before = gh._call("GET", f"/repos/{meta['full_name']}/branches/{default}",
                          f"Bearer {t.token}")["commit"]["sha"]
    gh.revoke(t.token)

    canary_name = f"canary-{tag}"
    jobs = {
        "neighbor": yard.run(_req(repo, None, "deny", f"st-{tag}-neighbor", timeout_s=3600),
                             main_command=["/bin/sh", "-c",
                                           f"echo {canary} > /sandbox/{canary_name}; "
                                           "while true; do date >> /sandbox/.yard/agent.log; sleep 20; done"],
                             selftest=True),
    }
    for mode in ("open", "deny"):
        jobs[f"adv-{mode}"] = yard.run(
            _req(repo, read_repo, mode, f"st-{tag}-{mode}", timeout_s=1800),
            main_command=["/bin/sh", "/sandbox/.yard/probe.sh", mode, canary_name],
            selftest=True, extra_uploads=[(PROBE, "probe.sh")])
    if not quick:
        jobs["timeout"] = yard.run(
            _req(repo, None, "deny", f"st-{tag}-timeout", timeout_s=90),
            main_command=["/bin/sh", "-c", "while true; do date >> /sandbox/.yard/agent.log; sleep 5; done"],
            selftest=True)
        jobs["idle"] = yard.run(
            _req(repo, None, "deny", f"st-{tag}-idle", timeout_s=1800, idle_s=60),
            main_command=["/bin/sh", "-c", "sleep 3600"], selftest=True)
        jobs["quota"] = yard.run(
            _req(repo, None, "deny", f"st-{tag}-quota", timeout_s=900, disk_bytes=1024**3),
            main_command=["/bin/sh", "-c",
                          "dd if=/dev/zero of=/sandbox/fill bs=1M count=1536 2>/sandbox/.yard/dd.err; "
                          "rc=$?; printf '{\"status\":\"done\",\"note\":\"dd rc=%s %s\",\"attn\":false}\\n' "
                          "\"$rc\" \"$(tail -c 200 /sandbox/.yard/dd.err | tr -d '\\n\\\"')\" "
                          ">> /sandbox/.yard/status.jsonl; sleep 30"],
            selftest=True)

    probe_ids = [jobs["adv-open"].id, jobs["adv-deny"].id]
    limit_ids = [jobs[k].id for k in ("timeout", "idle", "quota") if k in jobs]
    _wait(yard, probe_ids + limit_ids, time.time() + 2400, poll)
    yard.kill(jobs["neighbor"].id)

    for name in ("adv-open", "adv-deny"):
        job = yard.jobs.load(jobs[name].id)
        for r in _probe_results(yard, job.id):
            ok = r["result"] == ("ok" if r["expect"] == "ok" else "blocked")
            check(f"{name}/{r['check']}", ok, r["evidence"])
        if not _probe_results(yard, job.id):
            check(f"{name}/probe-ran", False, f"no probe results; job state={job.state} "
                  f"reason={job.end_reason} errors={job.errors[-3:]}")
    # Host-side: none of the token-like strings the probes found is a real token.
    for name in ("adv-open", "adv-deny"):
        tokfile = os.path.join(yard.jobs.job_dir(jobs[name].id), "token-hashes.json")
        if os.path.exists(tokfile):
            with open(tokfile) as fh:
                hashes = set(json.load(fh))
            seen = " ".join(r["evidence"] for r in _probe_results(yard, jobs[name].id)
                            if r["check"] == "read-github-token")
            check(f"{name}/token-hash-crosscheck", not any(h in seen for h in hashes),
                  f"{len(hashes)} real token hashes compared against probe findings")

    t = gh.mint(inst, [repo], WRITE_PERMISSIONS)
    try:
        sha_after = gh._call("GET", f"/repos/{meta['full_name']}/branches/{default}",
                             f"Bearer {t.token}")["commit"]["sha"]
        check("host/default-branch-unchanged", sha_before == sha_after,
              f"{default}: before={sha_before} after={sha_after}")
        prs = gh._call("GET", f"/repos/{meta['full_name']}/pulls?state=all&per_page=20",
                       f"Bearer {t.token}")
        mine = [p for p in prs if p["title"].startswith(f"agent-yard selftest st-{tag}")]
        check("host/pr-opened", bool(mine), [p["html_url"] for p in mine])
        check("host/pr-not-merged", all(not p.get("merged_at") for p in mine),
              [(p["number"], p.get("merged_at")) for p in mine])
        for p in mine:  # leave the repo tidy
            gh._call("PATCH", f"/repos/{meta['full_name']}/pulls/{p['number']}", f"Bearer {t.token}",
                     {"state": "closed"})
    finally:
        gh.revoke(t.token)

    if not quick:
        tj = yard.jobs.load(jobs["timeout"].id)
        check("limits/timeout-kills", tj.state == "killed" and tj.end_reason == "timeout",
              {"state": tj.state, "reason": tj.end_reason,
               "ran_s": round((tj.ended_at or 0) - (tj.started_at or 0))})
        ij = yard.jobs.load(jobs["idle"].id)
        check("limits/idle-kills", ij.state == "killed" and ij.end_reason == "idle",
              {"state": ij.state, "reason": ij.end_reason,
               "ran_s": round((ij.ended_at or 0) - (ij.started_at or 0))})
        qj = yard.jobs.load(jobs["quota"].id)
        note = (qj.last_status or {}).get("note", "")
        blocked = "rc=0" not in note and ("quota" in note.lower() or "space" in note.lower())
        check("limits/disk-quota-blocks", blocked, {"note": note, "state": qj.state})

    report["passed"] = all(c["pass"] for c in report["checks"]) and bool(report["checks"])
    report["jobs"] = {k: v.id for k, v in jobs.items()}
    path = os.path.join(yard.cfg.state_dir, f"selftest-{tag}.json")
    with open(path, "w") as fh:
        json.dump(report, fh, indent=1)
    report["report_path"] = path
    return report

