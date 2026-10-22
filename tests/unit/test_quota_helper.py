import os
import subprocess
import unittest

from yard import quota

HELPER = os.path.join(os.path.dirname(__file__), "..", "..", "host", "libexec", "yard-quota")


def run(env_user=None, *args):
    env = {"PATH": os.environ["PATH"]}
    if env_user is not None:
        env["SUDO_USER"] = env_user
    return subprocess.run(["bash", HELPER, *args], capture_output=True, text=True, env=env, check=False)


class QuotaHelperRefusals(unittest.TestCase):
    """The root helper must refuse every caller but `yard` and every bad argument.

    Runs the real script. As non-root it refuses at the root check; as root
    (this test never uses sudo) it refuses because SUDO_USER is not `yard`.
    """

    def test_refuses_podman_user_and_unset_caller(self):
        for caller in (None, "yard-pod", "root", "alex"):
            with self.subTest(caller=caller):
                p = run(caller, "check")
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('"ok": false', p.stdout)

    @unittest.skipUnless(os.geteuid() == 0, "argument checks run after the root check")
    def test_refuses_bad_arguments_as_yard(self):
        for args in (("apply", "../../etc", "1073741824"), ("apply", "job1", "12"),
                     ("apply", "job1", "1e9"), ("apply", "job1"), ("release", "a b"),
                     ("frobnicate",), ("apply", "-rf", "1073741824")):
            with self.subTest(args=args):
                p = run("yard", *args)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('"ok": false', p.stdout)

    def test_python_side_validates_job_id(self):
        with self.assertRaises(quota.QuotaError):
            quota.apply("/nonexistent", "../x", 1 << 30, run=lambda a: None)
