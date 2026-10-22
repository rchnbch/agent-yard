"""``yard doctor``: every host precondition, each reported ok/fail with evidence."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess

from . import quota
from .config import HostConfig
from .events import EventLog

PINNED_OPENSHELL = re.compile(r"^openshell 0\.1\.\d+$")


def _sh(argv: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as err:
        return 127, str(err)


def run_checks(cfg: HostConfig) -> list[dict]:
    checks: list[dict] = []

    def add(name: str, ok: bool, detail: str, required: bool = True) -> None:
        checks.append({"check": name, "ok": bool(ok), "required": required, "detail": detail[:500]})

    add("os", os.path.exists("/etc/debian_version"),
        f"{platform.platform()}; debian_version="
        f"{open('/etc/debian_version').read().strip() if os.path.exists('/etc/debian_version') else 'n/a'}")
    try:
        lsm = open("/sys/kernel/security/lsm").read().strip()
    except OSError as err:
        lsm = f"unreadable: {err}"
    add("landlock-lsm", "landlock" in lsm, f"lsm={lsm}")
    add("cgroup-v2", os.path.exists("/sys/fs/cgroup/cgroup.controllers"), "unified cgroup hierarchy")

    rc, out = _sh(["openshell", "--version"])
    add("openshell-version", rc == 0 and bool(PINNED_OPENSHELL.match(out.strip())),
        f"{out or 'not installed'} (pinned stable 0.1.x)")
    rc, out = _sh(["openshell-prover", "--version"])
    add("openshell-prover", rc == 0, out or "not installed")
    gw = ["--gateway", cfg.openshell_gateway] if cfg.openshell_gateway else []
    rc, out = _sh(["openshell", *gw, "--color", "never", "status"], timeout=30)
    add("gateway-connected", rc == 0 and "Connected" in out, out.replace("\n", " | "))

    gwcfg = os.path.expanduser("~/.config/openshell/gateway.toml")
    text = open(gwcfg).read() if os.path.exists(gwcfg) else ""
    add("gateway-driver-podman", re.search(r'compute_driver\s*=\s*"podman"', text) is not None
        or cfg.engine == "docker", f"{gwcfg}: compute_driver must be \"podman\"")
    genv = os.path.expanduser("~/.config/openshell/gateway.env")
    envtext = open(genv).read() if os.path.exists(genv) else ""
    add("telemetry-off", re.search(r"^OPENSHELL_TELEMETRY_ENABLED=false$", envtext, re.M) is not None,
        f"{genv} must set OPENSHELL_TELEMETRY_ENABLED=false")

    rc, out = _sh(["podman", "--url", cfg.podman_url, "info", "--format",
                   "{{.Host.Security.Rootless}} {{.Version.Version}} {{.Host.CgroupsVersion}}"])
    parts = out.split()
    add("podman-rootless-5", rc == 0 and len(parts) == 3 and parts[0] == "true"
        and parts[1].startswith("5.") and parts[2] == "v2", f"rootless/version/cgroups: {out}")
    rc, out = _sh(["podman", "--url", cfg.podman_url, "image", "inspect", "--format",
                   "{{index .Config.Labels \"org.agent-yard.base\"}}", cfg.base_image])
    add("base-image", rc == 0 and bool(out.strip()), f"{cfg.base_image}: {out or 'missing'}")

    try:
        q = quota.check(cfg.quota_helper)
        add("disk-quota", bool(q.get("ok")), str(q))
    except Exception as err:  # noqa: BLE001
        add("disk-quota", False, f"{err}")

    for name, file in (("secret-claude-token", "claude-oauth-token"),
                       ("secret-github-app-key", "github-app.pem")):
        path = cfg.secret_path(file)
        ok = os.path.exists(path) and (os.stat(path).st_mode & 0o077) == 0
        add(name, ok, f"{path} present with mode 0600" if ok else f"{path} missing or group/world-readable")
    add("github-app-config", bool(cfg.github_app_id and cfg.github_app_slug),
        f"app_id={cfg.github_app_id or '-'} app_slug={cfg.github_app_slug or '-'}")
    if cfg.github_app_id and os.path.exists(cfg.github_private_key):
        try:
            from .github import GitHubApp
            app = GitHubApp(cfg.github_app_id, cfg.github_private_key)
            info = app._app("GET", "/app")
            perms = info.get("permissions", {})
            want = {"contents": "write", "pull_requests": "write", "administration": "read",
                    "metadata": "read"}
            missing = {k: v for k, v in want.items() if perms.get(k) not in (v, "write")}
            add("github-app-auth", not missing, f"slug={info.get('slug')} permissions={perms}"
                + (f" missing={missing}" if missing else ""))
        except Exception as err:  # noqa: BLE001
            add("github-app-auth", False, str(err))

    try:
        EventLog(cfg.events_path)
        os.makedirs(cfg.state_dir, exist_ok=True)
        probe = os.path.join(cfg.state_dir, ".doctor")
        open(probe, "w").close()
        os.unlink(probe)
        add("state-writable", True, cfg.state_dir)
    except OSError as err:
        add("state-writable", False, str(err))

    rc, out = _sh(["systemctl", "is-active", "yardd.service"])
    add("yardd-running", out.strip() == "active", out)
    rc, out = _sh(["sudo", "-n", "/usr/sbin/nft", "list", "table", "inet", "agent_yard"])
    add("nftables-sandbox-egress", rc == 0 and "agent_yard" in out,
        "inet agent_yard table drops private ranges for the Podman user" if rc == 0 else out)
    rc, out = _sh(["tailscale", "status", "--json"])
    add("tailscale-up", rc == 0 and '"BackendState": "Running"' in out, "tailscale status" if rc == 0 else out)
    rc, out = _sh(["ss", "-Hltn"])
    public = [ln for ln in out.splitlines() if re.search(r"\s(0\.0\.0\.0|\[::\]|\*):(?!22\s)", ln)]
    add("no-public-listeners", rc == 0 and not public,
        "only sshd may listen on all addresses (Hetzner firewall blocks it)"
        if not public else f"listening on all addresses: {public}")
    add("openshell-cli", shutil.which("openshell") is not None, shutil.which("openshell") or "missing")
    return checks
