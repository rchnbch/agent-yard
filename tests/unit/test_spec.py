import unittest

from yard import limits as L
from yard.spec import SpecError, parse_job, split_front_matter, spec_title


class SpecTests(unittest.TestCase):
    def test_minimal_with_cli_repo(self):
        req = parse_job(b"# Add health check\nDo it.\n", {"repo": "rchnbch/app"})
        self.assertEqual(req.repo, "rchnbch/app")
        self.assertEqual(req.title, "Add health check")
        self.assertEqual(req.egress, "open")
        self.assertEqual(req.read_repos, ())
        self.assertEqual(req.limits.timeout_s, 4 * 3600)
        self.assertEqual(req.limits.idle_s, 30 * 60)
        self.assertEqual(req.limits.disk_bytes, 20 * 1024**3)
        self.assertIsNone(req.limits.cpu)

    def test_front_matter_and_cli_override(self):
        spec = (b"---\nrepo: a/b\negress: deny\nread_repos: a/c, a/d\ntimeout: 2h\n---\n"
                b"# T\nbody\n")
        req = parse_job(spec, {"timeout": "30m", "egress": None})
        self.assertEqual(req.egress, "deny")
        self.assertEqual(req.read_repos, ("a/c", "a/d"))
        self.assertEqual(req.limits.timeout_s, 1800)
        self.assertEqual(req.spec_text, "# T\nbody\n")

    def test_rejections(self):
        bad = [
            (b"# x\n", {}),                                             # no repo
            (b"   \n", {"repo": "a/b"}),                                # empty body
            (b"---\nrepo: a/b\nnope: 1\n---\nx", {}),                   # unknown key
            (b"---\nrepo: a/b\n", {}),                                  # unterminated
            (b"x", {"repo": "a/b", "egress": "maybe"}),
            (b"x", {"repo": "../etc"}),
            (b"x", {"repo": "a/b", "read_repos": "a/b"}),               # target in read
            (b"x", {"repo": "a/b", "read_repos": "a/c,a/c"}),
            (b"x", {"repo": "a/b", "branch": "../main"}),
            (b"x", {"repo": "a/b", "job_id": "UPPER"}),
            (b"x", {"repo": "a/b", "timeout": "forever"}),
            (b"x", {"repo": "a/b", "disk": "1M"}),                       # below minimum
            (b"\xff\xfe", {"repo": "a/b"}),
            (b"a\x00b", {"repo": "a/b"}),
            (b"x" * (200 * 1024 + 1), {"repo": "a/b"}),
        ]
        for data, opts in bad:
            with self.subTest(data=data[:30], opts=opts):
                with self.assertRaises(SpecError):
                    parse_job(data, opts)

    def test_cpu_memory_flags(self):
        req = parse_job(b"x", {"repo": "a/b", "cpu": "2", "memory": "8Gi"})
        self.assertEqual((req.limits.cpu, req.limits.memory), ("2", "8Gi"))

    def test_title_fallback(self):
        self.assertEqual(spec_title("no heading here\nmore"), "no heading here")
        self.assertEqual(split_front_matter("plain"), ({}, "plain"))


class LimitTests(unittest.TestCase):
    def test_durations(self):
        self.assertEqual(L.parse_duration("4h"), 14400)
        self.assertEqual(L.parse_duration("1h30m"), 5400)
        self.assertEqual(L.parse_duration("90"), 90)
        for bad in ("", "0", "4x", "h", "-1h", "1.5h"):
            with self.subTest(bad=bad), self.assertRaises(L.LimitError):
                L.parse_duration(bad)

    def test_sizes(self):
        self.assertEqual(L.parse_size("20G"), 20 * 1024**3)
        self.assertEqual(L.parse_size("20Gi"), 20 * 1024**3)
        self.assertEqual(L.parse_size("512M"), 512 * 1024**2)
        self.assertEqual(L.parse_size("1.5GB"), int(1.5 * 1024**3))
        for bad in ("", "G", "-1G", "1Q"):
            with self.subTest(bad=bad), self.assertRaises(L.LimitError):
                L.parse_size(bad)

    def test_check_limits(self):
        lim = L.Limits(timeout_s=100, idle_s=30)
        self.assertIsNone(L.check_limits(lim, now=50, started_at=0, last_output_at=40))
        self.assertEqual(L.check_limits(lim, now=100, started_at=0, last_output_at=99), "timeout")
        self.assertEqual(L.check_limits(lim, now=80, started_at=0, last_output_at=50), "idle")

    def test_no_caps_by_default_means_whole_host(self):
        cpu, mem = L.effective_resources(L.Limits(), host_cpus=8, host_memory_bytes=32 * 1024**3)
        self.assertEqual((cpu, mem), ("8", f"{32 * 1024}Mi"))
        cpu, mem = L.effective_resources(L.Limits(cpu="2", memory="4Gi"), 8, 32 * 1024**3)
        self.assertEqual((cpu, mem), ("2", "4Gi"))

    def test_limit_bounds(self):
        with self.assertRaises(L.LimitError):
            L.Limits(timeout_s=0)
        with self.assertRaises(L.LimitError):
            L.Limits(timeout_s=8 * 86400)
        self.assertEqual(L.Limits.from_dict(L.Limits().to_dict()), L.Limits())
