#!/usr/bin/env python3
"""Local end-to-end run of a trivial job against a REAL OpenShell gateway.

Real: OpenShell gateway + sandbox (Docker or Podman driver), policy
rendering, openshell-prover checks, per-job provider profile import,
provider creation, sandbox create/poll/exec, status ingestion, event log,
harvest, teardown, orphan reaping.

Stubbed (and reported as such): the GitHub App (no App exists in a dev
environment: tokens are random strings, the protection gate answers "protected"),
the repository tarball (an empty repo, so the base image is used) and the
XFS disk-quota helper. The Claude token is a dummy, so the trivial job does
not call claude; it writes status lines and checks its placeholders.

Usage: python3 tests/e2e/local_e2e.py [--engine docker|podman]
Requires: a running gateway registered as "openshell", base image
localhost/agent-yard/base:latest, openshell-prover on PATH.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tarfile
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from yard import host as H  # noqa: E402
from yard import images  # noqa: E402
from yard.config import HostConfig, load_services  # noqa: E402
from yard.github import InstallationToken  # noqa: E402
from yard.limits import Limits  # noqa: E402
from yard.openshell import OpenShell  # noqa: E402
from yard.spec import JobRequest  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class StubGitHub:
    """Stands in for the GitHub App. Records every call."""

    def __init__(self):
        self.calls = []
        self.revoked = []

    def installation_for(self, repo):
        self.calls.append(("installation_for", repo))
        return 1

    def mint(self, inst, repos, perms):
        self.calls.append(("mint", tuple(repos), tuple(sorted(perms.items()))))
        return InstallationToken(f"ghs_e2eSTUB{secrets.token_hex(16)}", "2099-01-01T00:00:00Z", inst,
                                 sorted(repos), dict(perms))

    def revoke(self, token):
        self.revoked.append(token[:12])

    def canonical_repo(self, token, repo):
        return {"full_name": repo, "default_branch": "main"}

    def push_protection(self, token, repo, branch, slug):
        return {"branch": branch, "blocks_direct_push": True, "stub": True}


def fake_tarball(app, token, repo, ref, dest):
    with tempfile.TemporaryDirectory() as d:
        top = os.path.join(d, "owner-repo-abc123")
        os.makedirs(top)
        with open(os.path.join(top, "README.md"), "w") as fh:
            fh.write("e2e\n")
        with tarfile.open(dest, "w:gz") as tf:
            tf.add(top, arcname="owner-repo-abc123")


TRIVIAL = r'''
S=/sandbox/.yard/status.jsonl
echo '{"status":"working","note":"trivial e2e job started","attn":false}' >> $S
case "$GITHUB_TOKEN" in openshell:resolve:*) ph=placeholder ;; *) ph=REAL-VALUE-LEAKED ;; esac
case "$YARD_GH_READ_TOKEN_0" in openshell:resolve:*) rph=placeholder ;; *) rph=REAL-VALUE-LEAKED ;; esac
echo "{\"status\":\"working\",\"note\":\"GITHUB_TOKEN is $ph, read token is $rph\",\"attn\":false}" >> $S
code=$(curl -s -o /dev/null -m 15 -w '%{http_code}' https://api.github.com/repos/octocat/Hello-World)
echo "{\"status\":\"working\",\"note\":\"api.github.com via curl: HTTP $code\",\"attn\":false}" >> $S
m=$(curl -s -m 15 -X PUT -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/e2e-owner/e2e-repo/pulls/1/merge | head -c 120 | tr -d '"\n')
echo "{\"status\":\"working\",\"note\":\"merge attempt: $m\",\"attn\":false}" >> $S
x=$(curl -s -m 15 -H "Authorization: Bearer $GITHUB_TOKEN" https://httpbin.org/anything/x | grep -o 'ghs_e2eSTUB' | head -1)
echo "{\"status\":\"working\",\"note\":\"token at non-GitHub host: ${x:-not resolved}\",\"attn\":true}" >> $S
for i in 1 2 3; do date >> /sandbox/.yard/agent.log; sleep 5; done
echo '{"status":"done","note":"trivial job done","attn":false}' >> $S
sleep 25
'''


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="docker", choices=("docker", "podman"))
    ap.add_argument("--state", default=None)
    args = ap.parse_args()
    state = args.state or tempfile.mkdtemp(prefix="yard-e2e-")
    cfg = HostConfig(state_dir=os.path.join(state, "state"), secrets_dir=os.path.join(state, "secrets"),
                     engine=args.engine, base_image="localhost/agent-yard/base:latest",
                     github_app_id="e2e", github_app_slug="e2e", poll_seconds=5,
                     services=load_services(os.path.join(ROOT, "providers", "services.toml")))
    os.makedirs(cfg.secrets_dir, exist_ok=True)
    H._write_private(cfg.secret_path("claude-oauth-token"), "e2e-dummy-token-not-real\n")
    gh = StubGitHub()
    H.download_tarball = fake_tarball
    engine_cmd = ["docker"] if args.engine == "docker" else ["podman", "--url", cfg.podman_url]
    deps = H.Deps(openshell=OpenShell(gateway="openshell"), github=gh,
                  engine=images.Podman(engine_cmd),
                  quota_apply=lambda job, n: {"stub": True, "limit_bytes": n},
                  quota_release=lambda job: None, host_resources=H.host_resources)
    yard = H.Yard(cfg, deps)
    req = JobRequest(repo="e2e-owner/e2e-repo", spec_text="# trivial e2e job\n", title="trivial e2e job",
                     egress="open", read_repos=("e2e-owner/e2e-lib",), limits=Limits(timeout_s=600))
    t0 = time.time()
    job = yard.run(req, main_command=["/bin/sh", "-c", TRIVIAL])
    print(f"started {job.id} in {time.time() - t0:.1f}s; sandbox {job.sandbox}; image {job.image}")
    deadline = time.time() + 300
    while time.time() < deadline and yard.jobs.load(job.id).active:
        yard.tick()
        time.sleep(5)
    job = yard.jobs.load(job.id)
    events = yard.events_since(None)["events"]
    print(json.dumps({"state": job.state, "end_reason": job.end_reason, "exit_code": job.exit_code,
                      "errors": job.errors, "revoked": gh.revoked,
                      "sandbox_still_exists": deps.openshell.sandbox_get(job.sandbox) is not None},
                     indent=1))
    for ev in events:
        print(ev["seq"], ev["type"], json.dumps(ev["data"], default=str)[:220])
    with open(os.path.join(yard.jobs.job_dir(job.id), "prover.json")) as fh:
        print("prover:", [(c["name"], c["result"]) for c in json.load(fh)])
    ok = job.state == "finished" and not deps.openshell.sandbox_get(job.sandbox)
    print("STUBBED: GitHub App, repo tarball, disk quota helper, Claude token")
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
