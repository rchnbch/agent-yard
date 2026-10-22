import ipaddress
import json
import os
import shutil
import unittest

from yard import policy as P
from yard import yamlout

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SVC = P.ServiceProfile(id="openrouter", env_var="OPENROUTER_API_KEY", hosts=("openrouter.ai",))


def job(egress="open", read=("o/lib",), regs=("pypi.org", "files.pythonhosted.org")):
    return P.JobNetwork(job_id="j1", repo="o/app", egress=egress, read_repos=read,
                        registries=regs, services=(SVC,))


def rules_for_host(pol, host):
    out = []
    for name, rule in pol["network_policies"].items():
        for ep in rule["endpoints"]:
            if ep["host"] == host:
                out.append((name, ep, [b["path"] for b in rule["binaries"]]))
    return out


class PublicIpTests(unittest.TestCase):
    def test_excludes_private_tailnet_metadata(self):
        nets = [ipaddress.ip_network(n) for n in P.public_ipv4()]
        for addr in ("10.1.2.3", "100.100.100.100", "127.0.0.1", "169.254.169.254", "0.1.2.3", "239.1.1.1"):
            ip = ipaddress.ip_address(addr)
            self.assertFalse(any(ip in n for n in nets), addr)
        for addr in ("1.1.1.1", "140.82.112.3", "8.8.8.8"):
            ip = ipaddress.ip_address(addr)
            self.assertTrue(any(ip in n for n in nets), addr)

    def test_budget_fits_prover(self):
        # 4096 IP ranges across candidate + boundary (docs/SPIKES.md).
        self.assertLessEqual(len(P.public_ipv4()), 40)


class RenderTests(unittest.TestCase):
    def test_open_template(self):
        pol = P.render_sandbox_policy(job("open"), P.PolicyContext())
        rules = pol["network_policies"]
        self.assertEqual(set(rules), {"anthropic", "open_egress", "github_api_guard"})
        self.assertEqual(pol["landlock"]["compatibility"], "hard_requirement")
        hosts = {ep["host"] for ep in rules["open_egress"]["endpoints"]}
        self.assertIn("**.*.com", hosts)
        self.assertIn("github.com", hosts)
        self.assertIn("pypi.org", hosts)
        self.assertNotIn("files.pythonhosted.org", hosts)  # covered by **.*.org
        guard = rules["github_api_guard"]["endpoints"][0]
        self.assertEqual(guard["host"], "api.github.com")
        self.assertIn({"method": "PUT", "path": "/**"}, guard["deny_rules"])
        self.assertIn({"method": "POST", "path": "/repos/o/app/merges"}, guard["deny_rules"])
        self.assertEqual([b["path"] for b in rules["anthropic"]["binaries"]], [P.BIN_CLAUDE])

    def test_deny_template_is_allowlist(self):
        pol = P.render_sandbox_policy(job("deny"), P.PolicyContext())
        rules = pol["network_policies"]
        self.assertEqual(set(rules), {"anthropic", "registries"})
        hosts = sorted(ep["host"] for ep in rules["registries"]["endpoints"])
        self.assertEqual(hosts, ["files.pythonhosted.org", "pypi.org"])
        self.assertTrue(all(ep["access"] == "read-only" for ep in rules["registries"]["endpoints"]))
        self.assertFalse(any("*" in ep["host"] for r in rules.values() for ep in r["endpoints"]))

    def test_every_endpoint_inspected_with_identical_allowed_ips(self):
        for eg in ("open", "deny"):
            base = P.render_sandbox_policy(job(eg), P.PolicyContext())
            profs = P.job_profiles(job(eg), [["o/lib"]], P.PolicyContext())
            eff = P.compose_effective(base, [(p["id"], p) for p in profs])
            ips = {json.dumps(ep["allowed_ips"]) for r in eff["network_policies"].values()
                   for ep in r["endpoints"]}
            self.assertEqual(len(ips), 1, eg)
            for r in eff["network_policies"].values():
                for ep in r["endpoints"]:
                    self.assertEqual((ep["protocol"], ep["enforcement"]), ("rest", "enforce"))

    def test_write_profile_scoped_to_target(self):
        profs = P.job_profiles(job(), [["o/lib"]], P.PolicyContext())
        w = profs[0]
        self.assertEqual(w["id"], "yard-j1-ghw")
        self.assertEqual(w["credentials"][0]["env_vars"], ["GITHUB_TOKEN", "GH_TOKEN"])
        self.assertTrue(w["credentials"][0]["stable_placeholder"])
        paths = sorted((e["host"], e["path"]) for e in w["endpoints"])
        self.assertEqual(paths, [("api.github.com", "/repos/o/app/**"), ("github.com", "/o/app.git/**")])
        git = next(e for e in w["endpoints"] if e["host"] == "github.com")
        self.assertIn({"allow": {"method": "POST", "path": "/o/app.git/git-receive-pack"}}, git["rules"])
        api = next(e for e in w["endpoints"] if e["host"] == "api.github.com")
        self.assertIn({"method": "PUT", "path": "/**"}, api["deny_rules"])

    def test_read_profile_cannot_push(self):
        profs = P.job_profiles(job(), [["o/lib"]], P.PolicyContext())
        r = profs[1]
        self.assertEqual(r["credentials"][0]["env_vars"], ["YARD_GH_READ_TOKEN_0"])
        for e in r["endpoints"]:
            if e["host"] == "github.com":
                methods = {(x["allow"]["method"], x["allow"]["path"]) for x in e["rules"]}
                self.assertNotIn(("POST", "/o/lib.git/git-receive-pack"), methods)
            else:
                self.assertEqual(e["access"], "read-only")

    def test_read_groups_must_partition(self):
        with self.assertRaises(P.PolicyError):
            P.job_profiles(job(), [["o/other"]], P.PolicyContext())

    def test_credential_surface_any_binary(self):
        profs = P.job_profiles(job(), [["o/lib"]], P.PolicyContext())
        surf = P.credential_surface([(p["id"], p) for p in profs[:1]])
        rule = next(iter(surf["network_policies"].values()))
        self.assertEqual(rule["binaries"], [{"path": "/**"}])

    def test_validation(self):
        for bad in ("noslash", "a/b/c", "a/..", "a/b.git", "-a/b"):
            with self.subTest(bad=bad), self.assertRaises(P.PolicyError):
                P.validate_repo(bad)
        with self.assertRaises(P.PolicyError):
            P.JobNetwork(job_id="j", repo="o/a", read_repos=("O/A",))
        with self.assertRaises(P.PolicyError):
            P.JobNetwork(job_id="j", repo="o/a", egress="sideways")
        with self.assertRaises(P.PolicyError):
            P.JobNetwork(job_id="j", repo="o/a", registries=("*.evil.com",))

    def test_compose_mirrors_openshell_keys(self):
        profs = P.job_profiles(job(), [["o/lib"]], P.PolicyContext())
        eff = P.compose_effective({"version": 1, "network_policies": {}}, [("yard-j1-ghw", profs[0])])
        self.assertIn("_provider_yard_j1_ghw", eff["network_policies"])


class YamlTests(unittest.TestCase):
    def test_round_trip_through_json_semantics(self):
        doc = {"a": [1, {"b": "x: y", "c": []}], "d": {}, "e": True, "f": None, "g": "-"}
        text = yamlout.dumps(doc)
        self.assertIn('b: "x: y"', text)
        self.assertIn("c: []", text)


if os.environ.get("YARD_REQUIRE_PROVER") == "1" and not shutil.which("openshell-prover"):
    raise RuntimeError("YARD_REQUIRE_PROVER=1 but openshell-prover is not on PATH")


@unittest.skipUnless(shutil.which("openshell-prover"), "openshell-prover not installed")
class ProverTests(unittest.TestCase):
    """The acceptance proofs. CI installs the pinned prover and runs these."""

    def test_templates_within_boundaries_and_mutants_fail(self):
        from yard import prove
        svcs = (SVC, P.ServiceProfile(id="typesafe", env_var="TYPESAFE_API_KEY", hosts=("api.typesafe.ai",)))
        for eg in ("open", "deny"):
            j = P.JobNetwork(job_id="ci", repo="example-owner/example-repo", egress=eg,
                             read_repos=("example-owner/example-lib",),
                             registries=("pypi.org", "files.pythonhosted.org"), services=svcs)
            base = P.render_sandbox_policy(j, P.PolicyContext())
            att = [(p["id"], p) for p in P.job_profiles(j, [["example-owner/example-lib"]], P.PolicyContext())]
            for c in prove.job_checks(base, att, eg):
                with self.subTest(template=eg, check=c.name):
                    self.assertEqual(c.result, "within_boundary", c.detail)
            for name, cand, b in prove.mutants(base, att, eg):
                with self.subTest(template=eg, mutant=name):
                    result, detail = prove.run_check(cand, os.path.join(prove.BOUNDARY_DIR, b), timeout="30s")
                    self.assertNotEqual(result, "within_boundary", f"{name} must not prove: {detail}")
