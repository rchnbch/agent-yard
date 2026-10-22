"""Orchestration tests with fake OpenShell / GitHub / engine adapters."""

import json
import os
import tempfile
import unittest

from yard import host as H
from yard.config import HostConfig, Project
from yard.github import InstallationToken
from yard.limits import Limits
from yard.openshell import PendingRule, Result
from yard.policy import ServiceProfile
from yard.prove import Check
from yard.spec import JobRequest


class FakeOS:
    def __init__(self):
        self.calls = []
        self.sandboxes = {}
        self.pending = []
        self.files = {}
        self.providers = set()

    def _c(self, *a):
        self.calls.append(a)

    def profile_import(self, path):
        self._c("profile_import", os.path.basename(path))

    def profile_delete(self, pid):
        self._c("profile_delete", pid)

    def provider_create(self, name, ptype, creds):
        self._c("provider_create", name, ptype, tuple(creds))
        self.providers.add(name)

    def provider_update(self, name, creds):
        self._c("provider_update", name, tuple(creds))

    def provider_delete(self, name):
        self._c("provider_delete", name)

    def provider_exists(self, name):
        return name in self.providers

    def sandbox_create(self, **kw):
        self._c("sandbox_create", kw)
        self.sandboxes[kw["name"]] = {"phase": "Ready", "exit_code": None, "conditions": []}
        return Result(0, "", "")

    def sandbox_get(self, name):
        return self.sandboxes.get(name)

    def sandbox_list(self):
        return [{"name": n} for n in self.sandboxes]

    def sandbox_upload(self, name, local, dest):
        self._c("sandbox_upload", name, os.path.basename(local), dest)

    def sandbox_exec(self, name, command, timeout=30):
        self._c("sandbox_exec", name)
        if "@@YARD-LOGSIZE@@" in command[-1]:
            return Result(0, self.files.get("status", "") + f"\n@@YARD-LOGSIZE@@ {self.files.get('size', 0)}\n", "")
        return Result(0, "", "")

    def sandbox_delete(self, name):
        self._c("sandbox_delete", name)
        self.sandboxes.pop(name, None)
        return Result(0, "", "")

    def pending_rules(self, sandbox):
        return list(self.pending)

    def rule_approve(self, sandbox, chunk):
        self._c("rule_approve", chunk)

    def rule_reject(self, sandbox, chunk, reason):
        self._c("rule_reject", chunk, reason)


class FakeGH:
    def __init__(self, protected=True):
        self.protected = protected
        self.minted = []
        self.revoked = []

    def installation_for(self, repo):
        return 7 if repo.startswith("o/") else 9

    def mint(self, inst, repos, perms):
        tok = InstallationToken(f"ghs_fake{len(self.minted)}", "2099-01-01T00:00:00Z", inst, sorted(repos), perms)
        self.minted.append((inst, tuple(repos), dict(perms)))
        return tok

    def revoke(self, token):
        self.revoked.append(token)

    def canonical_repo(self, token, repo):
        return {"full_name": repo, "default_branch": "main"}

    def push_protection(self, token, repo, branch, slug):
        return {"blocks_direct_push": self.protected}


class FakeEngine:
    def workload_container(self, name):
        return None

    def copy_out(self, cid, path, dest):
        return False


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def ok_checks(base, attached, egress):
    return [Check("network/" + egress, "b", "within_boundary", None)]


class HostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        svc = ServiceProfile(id="openrouter", env_var="OPENROUTER_API_KEY", hosts=("openrouter.ai",))
        self.cfg = HostConfig(state_dir=os.path.join(d, "state"), secrets_dir=os.path.join(d, "sec"),
                              github_app_id="1", github_app_slug="yard", max_jobs=2,
                              projects={"p": Project("p", ("openrouter",), ("pypi.org",))},
                              services={"openrouter": svc})
        H._write_private(self.cfg.secret_path("claude-oauth-token"), "sk-ant-oat-test\n")
        self.os = FakeOS()
        self.gh = FakeGH()
        self.clock = Clock()
        self.quota = []
        self.deps = H.Deps(openshell=self.os, github=self.gh, engine=FakeEngine(),
                           quota_apply=lambda sb, j, n: (self.quota.append((sb, n)), self.os.calls.append(("quota", sb)))
                           and {"ok": True},
                           quota_release=lambda j: self.quota.append(("release", j)),
                           host_resources=lambda: (8, 16 * 1024**3), clock=self.clock,
                           prove_checks=ok_checks)
        H.download_tarball = self._tarball
        H.images.resolve_image = lambda engine, base, root, repo: {"image": base, "source": "base", "hash": "x"}
        self.yard = H.Yard(self.cfg, self.deps)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _tarball(app, token, repo, ref, dest):
        import tarfile
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "top"))
            with tarfile.open(dest, "w:gz") as tf:
                tf.add(os.path.join(d, "top"), arcname="top")

    def req(self, **kw):
        base = dict(repo="o/app", spec_text="# Do it\n", title="Do it", read_repos=("o/lib", "x/ext"),
                    limits=Limits(timeout_s=600, idle_s=120))
        base.update(kw)
        return JobRequest(**base)

    def test_run_happy_path(self):
        self.os.providers.add("proj-p-openrouter")
        job = self.yard.run(self.req(env_project="p"))
        self.assertEqual(job.state, "running")
        self.assertEqual(job.sandbox, f"y-{job.id}")
        create = next(c[1] for c in self.os.calls if c[0] == "sandbox_create")
        self.assertEqual(create["env_from"], {"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat-test"})
        self.assertEqual(create["approval_mode"], "auto")
        self.assertEqual((create["cpu"], create["memory"]), ("8", "16384Mi"))
        self.assertIn("proj-p-openrouter", create["providers"])
        # read repos split per installation -> two read providers
        self.assertEqual(sorted(job.providers), [f"yard-{job.id}-ghr0", f"yard-{job.id}-ghr1",
                                                  f"yard-{job.id}-ghw"])
        # prep token revoked before the job starts; tokens never on argv
        self.assertIn("ghs_fake0", self.gh.revoked)
        flat = json.dumps(self.os.calls, default=str)
        self.assertNotIn("ghs_fake1", flat)
        self.assertNotIn("sk-ant-oat-test", json.dumps([c for c in self.os.calls if c[0] != "sandbox_create"], default=str))
        types = [e["type"] for e in self.yard.events_since(None)["events"]]
        self.assertEqual(types[:2], ["job.created", "job.running"])
        self.assertEqual(self.quota[0][1], 20 * 1024**3)
        # upload, then quota, then the go signal (first exec)
        order = [c[0] for c in self.os.calls]
        self.assertLess(order.index("sandbox_upload"), order.index("quota"))
        self.assertLess(order.index("quota"), order.index("sandbox_exec"))

    def test_unprotected_repo_refused_and_cleaned(self):
        self.gh.protected = False
        with self.assertRaises(H.YardError) as cm:
            self.yard.run(self.req())
        self.assertIn("branch protection", str(cm.exception))
        self.assertFalse(any(c[0] == "sandbox_create" for c in self.os.calls))
        job = self.yard.jobs.all()[0]
        self.assertEqual(job.state, "failed")
        self.assertIn("ghs_fake0", self.gh.revoked)

    def test_missing_project_secret_refused(self):
        self.os.providers.clear()
        with self.assertRaises(H.YardError):
            self.yard.run(self.req(env_project="p"))
        job = self.yard.jobs.all()[0]
        self.assertEqual(job.state, "failed")
        # minted job tokens revoked, providers deleted
        self.assertTrue(set(self.gh.revoked) >= {"ghs_fake1", "ghs_fake2", "ghs_fake3"})
        self.assertTrue(any(c[0] == "provider_delete" for c in self.os.calls))

    def test_failed_proof_refused(self):
        self.deps.prove_checks = lambda b, a, e: [Check("network/open", "b", "exceeds_boundary", "x")]
        with self.assertRaises(H.YardError) as cm:
            self.yard.run(self.req(read_repos=()))
        self.assertIn("policy proof failed", str(cm.exception))
        self.assertFalse(any(c[0] == "sandbox_create" for c in self.os.calls))

    def test_concurrency_cap(self):
        self.yard.run(self.req(read_repos=()))
        self.yard.run(self.req(read_repos=()))
        with self.assertRaises(H.YardError):
            self.yard.run(self.req(read_repos=()))

    def test_status_events_and_finish(self):
        self.os.providers.add("proj-p-openrouter")
        job = self.yard.run(self.req(read_repos=()))
        self.os.files["status"] = ('{"status":"working","note":"hi","attn":false}\n'
                                   '{"status":"done","note":"https://github.com/o/app/pull/3","attn":true}\n')
        self.os.files["size"] = 10
        self.yard.tick()
        job = self.yard.jobs.load(job.id)
        self.assertEqual(job.pr_url, "https://github.com/o/app/pull/3")
        self.os.sandboxes[job.sandbox]["exit_code"] = 0
        self.yard.tick()
        job = self.yard.jobs.load(job.id)
        self.assertEqual(job.state, "finished")
        evs = [e["type"] for e in self.yard.events_since(None)["events"]]
        self.assertIn("job.attention", evs)
        self.assertEqual(evs[-1], "job.finished")
        self.assertNotIn(job.sandbox, self.os.sandboxes)
        self.assertIn(("release", job.id), self.quota)
        self.assertFalse(os.path.exists(self.yard._token_file(job.id)))

    def test_timeout_and_idle_kill(self):
        a = self.yard.run(self.req(read_repos=(), limits=Limits(timeout_s=600, idle_s=120)))
        self.clock.t += 121
        self.yard.tick()
        a = self.yard.jobs.load(a.id)
        self.assertEqual((a.state, a.end_reason), ("killed", "idle"))
        b = self.yard.run(self.req(read_repos=(), limits=Limits(timeout_s=300, idle_s=10_000)))
        for _ in range(4):
            self.clock.t += 80
            self.os.files["size"] = self.os.files.get("size", 0) + 1
            self.yard.tick()
        b = self.yard.jobs.load(b.id)
        self.assertEqual((b.state, b.end_reason), ("killed", "timeout"))

    def test_output_resets_idle(self):
        a = self.yard.run(self.req(read_repos=(), limits=Limits(timeout_s=6000, idle_s=120)))
        for i in range(5):
            self.clock.t += 100
            self.os.files["size"] = i + 1
            self.yard.tick()
        self.assertEqual(self.yard.jobs.load(a.id).state, "running")

    def test_token_refresh(self):
        job = self.yard.run(self.req(read_repos=("o/lib",), limits=Limits(timeout_s=7200, idle_s=7200)))
        self.clock.t += H.TOKEN_REFRESH_S + 1
        self.os.files["size"] = 5
        self.yard.tick()
        updates = [c for c in self.os.calls if c[0] == "provider_update"]
        self.assertEqual(sorted(u[1] for u in updates), [f"yard-{job.id}-ghr0", f"yard-{job.id}-ghw"])
        self.assertIn(("GITHUB_TOKEN",), [u[2] for u in updates])

    def test_deny_mode_auto_approval_rules(self):
        self.os.providers.add("proj-p-openrouter")
        job = self.yard.run(self.req(read_repos=(), egress="deny", env_project="p"))
        mk = lambda cid, host, prover="prover: no new findings", sec="": PendingRule(
            cid, "r", ["/usr/bin/python3"], [{"host": host, "port": 443, "kind": "L4"}], prover, "", sec)
        self.os.pending = [mk("c1", "pypi.org"), mk("c2", "api.github.com"),
                           mk("c3", "pypi.org", "prover: capability_expansion"),
                           mk("c4", "pypi.org", sec="wildcard host")]
        self.os.files["size"] = 1
        self.yard.tick()
        approved = [c[1] for c in self.os.calls if c[0] == "rule_approve"]
        self.assertEqual(approved, ["c1"])
        evs = self.yard.events_since(None)["events"]
        pending = [e["data"]["proposal"] for e in evs if e["type"] == "approval.pending"]
        self.assertEqual(pending, [f"{job.id}:c2", f"{job.id}:c3", f"{job.id}:c4"])
        # seen once only
        self.yard.tick()
        self.assertEqual(len([e for e in self.yard.events_since(None)["events"]
                              if e["type"] == "approval.pending"]), 3)
        self.yard.decide(f"{job.id}:c2", False, "no")
        self.assertIn(("rule_reject", "c2", "no"), self.os.calls)

    def test_kill_and_orphans(self):
        job = self.yard.run(self.req(read_repos=()))
        self.os.sandboxes["y-stray"] = {"phase": "Ready", "exit_code": None}
        self.os.sandboxes["unrelated"] = {"phase": "Ready", "exit_code": None}
        self.yard.tick()
        self.assertNotIn("y-stray", self.os.sandboxes)
        self.assertIn("unrelated", self.os.sandboxes)
        res = self.yard.kill(job.id)
        self.assertTrue(res["changed"])
        self.assertEqual(self.yard.jobs.load(job.id).state, "killed")

    def test_long_job_id_gets_short_sandbox_name(self):
        self.assertLessEqual(len(H.sandbox_name("a" * 40)), 19)
        self.assertEqual(H.sandbox_name("j20261022-abcdef"), "y-j20261022-abcdef")
