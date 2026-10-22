import json
import unittest

from yard import worker
from yard.openshell import parse_rule_get

RULE_GET = """Network Rules:  (version 1, 2 chunks)

  Chunk: ad5bae53-f621-49a0-b168-20a963a4a707
  Status: pending
  Rule: allow_postman_echo_com_443
  Binary: /usr/bin/curl
  Confidence: 65%
  Rationale: Allow curl to connect to postman-echo.com:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 3fcd0a526279
  Endpoints: postman-echo.com:443 [L4]
  Binaries: /usr/bin/curl

  Chunk: 11111111-2222-3333-4444-555555555555
  Status: pending
  Rule: allow_db
  Prover: prover: credential_reach_expansion
  Security: private address
  Endpoints: db.internal:5432 [L4], api.github.com:443 [REST]
  Binaries: /usr/bin/python3.13, /usr/bin/curl
"""


class StatusTests(unittest.TestCase):
    def test_parse_incremental(self):
        raw = ('{"status":"working","note":"a","attn":false}\n'
               '{"status":"done","note":"PR https://github.com/o/app/pull/7","attn":true}\n'
               '{"status":"wor')
        entries, total = worker.parse_status_lines(raw, 0)
        self.assertEqual(total, 2)
        self.assertEqual([e["status"] for e in entries], ["working", "done"])
        self.assertTrue(entries[1]["attn"])
        again, total2 = worker.parse_status_lines(raw, 2)
        self.assertEqual((again, total2), ([], 2))

    def test_hostile_lines(self):
        raw = "not json\n[1]\n" + json.dumps({"status": "pwned", "note": "x\x1b[31m" + "y" * 5000}) + "\n\n"
        entries, total = worker.parse_status_lines(raw, 0)
        self.assertEqual(total, 4)
        self.assertEqual([e["status"] for e in entries], ["invalid"] * 4)
        self.assertNotIn("\x1b", entries[2]["note"])
        self.assertLessEqual(len(entries[2]["note"]), worker.MAX_NOTE)

    def test_pr_url_must_match_repo(self):
        self.assertEqual(worker.find_pr_url("see https://github.com/o/app/pull/7 ok", "O/App"),
                         "https://github.com/o/app/pull/7")
        self.assertIsNone(worker.find_pr_url("https://github.com/evil/app/pull/1", "o/app"))


class CommandTests(unittest.TestCase):
    def test_main_is_claude_never_bare(self):
        cmd = worker.main_command()
        self.assertEqual(cmd[:2], ["/bin/sh", "-c"])
        self.assertIn("exec /usr/local/bin/claude -p", cmd[2])
        self.assertNotIn("--bare", cmd[2])

    def test_gate_execs_command(self):
        g = worker.gated(["/bin/echo", "hi"])
        self.assertEqual(g[:2], ["/bin/sh", "-c"])
        self.assertIn('exec "$@"', g[2])
        self.assertEqual(g[3:], ["yard-gate", "/bin/echo", "hi"])

    def test_prompt_and_job_file(self):
        p = worker.render_prompt("j1", "o/app", "yard/j1", "main", "deny", ["o/lib"], "# Do X\n")
        self.assertIn("git clone https://github.com/o/app.git", p)
        self.assertIn("never merge", p)
        self.assertIn("o/lib", p)
        self.assertIn("# Do X", p)
        jf = worker.job_file("j1", "o/app", "yard/j1", "main", {"o/lib": "YARD_GH_READ_TOKEN_0"})
        self.assertEqual(jf["credentials"], [{"path": "o/app.git", "env": "GITHUB_TOKEN"},
                                             {"path": "o/lib.git", "env": "YARD_GH_READ_TOKEN_0"}])


class RuleParseTests(unittest.TestCase):
    def test_parse(self):
        rules = parse_rule_get(RULE_GET)
        self.assertEqual(len(rules), 2)
        a, b = rules
        self.assertTrue(a.prover_clean)
        self.assertEqual(a.endpoints, [{"host": "postman-echo.com", "port": 443, "kind": "L4"}])
        self.assertFalse(b.prover_clean)
        self.assertEqual(b.security, "private address")
        self.assertEqual([e["host"] for e in b.endpoints], ["db.internal", "api.github.com"])
        self.assertEqual(b.binaries, ["/usr/bin/python3.13", "/usr/bin/curl"])
