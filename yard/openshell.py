"""Thin adapter over the ``openshell`` CLI (pinned 0.1.x).

Every call goes through ``Runner`` so tests can substitute a fake. Secrets
are only ever passed through the child's environment (``--credential KEY``
and ``--env-from KEY`` read the value from there), never on argv.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Callable, Sequence

Runner = Callable[[Sequence[str], dict | None, bytes | None, float | None], "Result"]


@dataclass
class Result:
    returncode: int
    stdout: str
    stderr: str


class OpenShellError(RuntimeError):
    pass


def subprocess_runner(argv: Sequence[str], env: dict | None, stdin: bytes | None,
                      timeout: float | None) -> Result:
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        proc = subprocess.run(list(argv), input=stdin, capture_output=True, env=full_env,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return Result(124, "", f"timed out after {timeout}s: {argv[:3]}")
    return Result(proc.returncode, proc.stdout.decode(errors="replace"),
                  proc.stderr.decode(errors="replace"))


ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


@dataclass
class PendingRule:
    chunk_id: str
    rule: str
    binaries: list[str]
    endpoints: list[dict]
    prover: str
    rationale: str
    security: str

    @property
    def prover_clean(self) -> bool:
        return self.prover.strip().lower() in ("prover: no new findings", "no new findings")

    def to_dict(self) -> dict:
        return {"chunk_id": self.chunk_id, "rule": self.rule, "binaries": self.binaries,
                "endpoints": self.endpoints, "prover": self.prover,
                "rationale": self.rationale, "security": self.security,
                "prover_clean": self.prover_clean}


def parse_rule_get(text: str) -> list[PendingRule]:
    """Parse ``openshell rule get <sb> --status pending`` text output (0.1.5)."""
    rules: list[PendingRule] = []
    cur: dict | None = None
    for raw in ANSI.sub("", text).splitlines():
        line = raw.strip()
        if line.startswith("Chunk:"):
            if cur:
                rules.append(_mk(cur))
            cur = {"chunk": line.split(":", 1)[1].strip()}
            continue
        if cur is None or ":" not in line:
            continue
        key, value = line.split(":", 1)
        cur[key.strip().lower()] = value.strip()
    if cur:
        rules.append(_mk(cur))
    return rules


def _parse_endpoint(token: str) -> dict:
    m = re.match(r"^(?P<host>[^\s:]+):(?P<port>\d+)(?:\s*\[(?P<kind>[^\]]+)\])?$", token.strip())
    if not m:
        return {"raw": token.strip()}
    return {"host": m.group("host").lower(), "port": int(m.group("port")),
            "kind": (m.group("kind") or "").strip()}


def _mk(d: dict) -> PendingRule:
    eps = [_parse_endpoint(t) for t in re.split(r",\s*", d.get("endpoints", "")) if t.strip()]
    bins = [b.strip() for b in re.split(r",\s*", d.get("binaries", d.get("binary", ""))) if b.strip()]
    return PendingRule(chunk_id=d["chunk"], rule=d.get("rule", ""), binaries=bins, endpoints=eps,
                       prover=d.get("prover", ""), rationale=d.get("rationale", ""),
                       security=d.get("security", ""))


class OpenShell:
    def __init__(self, binary: str = "openshell", gateway: str | None = None,
                 runner: Runner = subprocess_runner):
        self.binary = binary
        self.gateway = gateway
        self.runner = runner

    def _run(self, args: Sequence[str], env: dict | None = None, stdin: bytes | None = None,
             timeout: float | None = 120, check: bool = True) -> Result:
        argv = [self.binary]
        if self.gateway:
            argv += ["--gateway", self.gateway]
        argv += ["--color", "never", *args]
        res = self.runner(argv, env, stdin, timeout)
        if check and res.returncode != 0:
            raise OpenShellError(f"openshell {' '.join(args[:3])} failed ({res.returncode}): "
                                 f"{ANSI.sub('', res.stderr or res.stdout).strip()[:800]}")
        return res

    # gateway
    def status(self) -> Result:
        return self._run(["status"], check=False, timeout=30)

    # profiles and providers
    def profile_import(self, path: str) -> None:
        self._run(["profile", "import", "-f", path])

    def profile_delete(self, profile_id: str) -> None:
        self._run(["profile", "delete", profile_id], check=False)

    def provider_create(self, name: str, ptype: str, credentials: dict[str, str]) -> None:
        args = ["provider", "create", "--name", name, "--type", ptype]
        for key in credentials:
            args += ["--credential", key]
        self._run(args, env=credentials)

    def provider_update(self, name: str, credentials: dict[str, str]) -> None:
        args = ["provider", "update", name]
        for key in credentials:
            args += ["--credential", key]
        self._run(args, env=credentials)

    def provider_delete(self, name: str) -> None:
        self._run(["provider", "delete", name], check=False)

    def provider_exists(self, name: str) -> bool:
        return self._run(["provider", "get", name], check=False, timeout=30).returncode == 0

    # sandboxes
    def sandbox_create(self, name: str, image: str, policy_path: str, providers: list[str],
                       uploads: list[tuple[str, str]], command: list[str], cpu: str, memory: str,
                       env_from: dict[str, str], labels: dict[str, str], approval_mode: str,
                       driver_config: dict | None = None) -> Result:
        args = ["sandbox", "create", "--name", name, "--from", image, "--policy", policy_path,
                "--detach", "--no-auto-providers", "--no-tty", "--cpu", cpu, "--memory", memory,
                "--approval-mode", approval_mode, "--no-git-ignore", "--restart-policy", "never"]
        for p in providers:
            args += ["--provider", p]
        for local, remote in uploads:
            args += ["--upload", f"{local}:{remote}"]
        for key in env_from:
            args += ["--env-from", key]
        for k, v in labels.items():
            args += ["--label", f"{k}={v}"]
        if driver_config:
            args += ["--driver-config-json", json.dumps(driver_config, separators=(",", ":"))]
        args += ["--", *command]
        return self._run(args, env=env_from, timeout=900)

    def sandbox_get(self, name: str) -> dict | None:
        res = self._run(["sandbox", "get", name, "-o", "json"], check=False, timeout=30)
        if res.returncode != 0:
            if "not found" in (res.stderr + res.stdout).lower():
                return None
            raise OpenShellError(f"sandbox get {name}: {res.stderr.strip()[:300]}")
        return json.loads(res.stdout)

    def sandbox_list(self) -> list[dict]:
        res = self._run(["sandbox", "list", "-o", "json"], timeout=30)
        data = json.loads(res.stdout or "[]")
        return data if isinstance(data, list) else data.get("sandboxes", [])

    def sandbox_exec(self, name: str, command: list[str], timeout: int = 30) -> Result:
        return self._run(["sandbox", "exec", name, "--no-tty", "--no-login-shell",
                          "--timeout", str(timeout), "--", *command],
                         check=False, timeout=timeout + 15)

    def sandbox_download(self, name: str, path: str, dest: str) -> Result:
        return self._run(["sandbox", "download", name, path, dest], check=False, timeout=300)

    def sandbox_delete(self, name: str) -> Result:
        return self._run(["sandbox", "delete", name], check=False, timeout=120)

    def policy_full(self, name: str) -> str:
        res = self._run(["policy", "get", name, "--full"], timeout=30)
        text = ANSI.sub("", res.stdout)
        return text.split("\n---\n", 1)[1] if "\n---\n" in text else text

    def settings_set(self, sandbox: str, key: str, value: str) -> None:
        self._run(["settings", "set", sandbox, "--key", key, "--value", value])

    # policy advisor
    def pending_rules(self, sandbox: str) -> list[PendingRule]:
        res = self._run(["rule", "get", sandbox, "--status", "pending"], timeout=30)
        return parse_rule_get(res.stdout)

    def rule_approve(self, sandbox: str, chunk_id: str) -> None:
        self._run(["rule", "approve", sandbox, "--chunk-id", chunk_id])

    def rule_reject(self, sandbox: str, chunk_id: str, reason: str) -> None:
        self._run(["rule", "reject", sandbox, "--chunk-id", chunk_id, "--reason", reason])
