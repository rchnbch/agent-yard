"""GitHub App: per-job installation tokens and the branch-protection gate.

Stdlib only. The App JWT is signed with ``openssl`` so the host needs no
Python crypto package; the private key never leaves the gateway user's
secrets directory and is never passed on a command line.
"""

from __future__ import annotations

import base64
import json
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

API = "https://api.github.com"
WRITE_PERMISSIONS = {"contents": "write", "pull_requests": "write", "metadata": "read"}
READ_PERMISSIONS = {"contents": "read", "metadata": "read"}
# Host-side only, never injected: read branch protection / rulesets.
CHECK_PERMISSIONS = {"administration": "read", "metadata": "read"}
# Ruleset rule types that stop a direct push to the branch.
BLOCKING_RULE_TYPES = {"pull_request", "update"}


class GitHubError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def app_jwt(app_id: str, key_path: str, now: int | None = None,
            signer: Callable[[bytes, str], bytes] | None = None) -> str:
    """RS256 JWT for the App, valid 9 minutes (GitHub allows at most 10)."""
    now = int(time.time()) if now is None else now
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(app_id)},
                                 separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = (signer or _openssl_sign)(signing_input, key_path)
    return f"{header}.{payload}.{_b64url(sig)}"


def _openssl_sign(data: bytes, key_path: str) -> bytes:
    proc = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key_path],
                          input=data, capture_output=True, check=False)
    if proc.returncode != 0:
        raise GitHubError(f"openssl signing failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


Transport = Callable[[str, str, dict, bytes | None], tuple[int, bytes]]


def urllib_transport(method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


@dataclass
class InstallationToken:
    token: str
    expires_at: str
    installation_id: int
    repositories: list[str]
    permissions: dict

    def redacted(self) -> dict:
        return {"expires_at": self.expires_at, "installation_id": self.installation_id,
                "repositories": self.repositories, "permissions": self.permissions}


class GitHubApp:
    def __init__(self, app_id: str, key_path: str, transport: Transport = urllib_transport,
                 jwt_factory: Callable[[], str] | None = None):
        self.app_id = app_id
        self.key_path = key_path
        self.transport = transport
        self._jwt_factory = jwt_factory or (lambda: app_jwt(app_id, key_path))

    def _call(self, method: str, path: str, auth: str, body: dict | None = None,
              ok: tuple[int, ...] = (200,)) -> dict | list | None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "agent-yard",
            "Authorization": auth,
        }
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        status, raw = self.transport(method, API + path, headers, data)
        if status not in ok:
            msg = raw.decode(errors="replace")[:300]
            raise GitHubError(f"{method} {path} -> HTTP {status}: {msg}", status)
        if not raw:
            return None
        return json.loads(raw)

    def _app(self, method: str, path: str, body: dict | None = None, ok=(200,)):
        return self._call(method, path, f"Bearer {self._jwt_factory()}", body, ok)

    def installation_for(self, repo: str) -> int:
        owner, name = repo.split("/", 1)
        data = self._app("GET", f"/repos/{_q(owner)}/{_q(name)}/installation")
        return int(data["id"])

    def mint(self, installation_id: int, repos: list[str], permissions: dict) -> InstallationToken:
        names = sorted({r.split("/", 1)[1] for r in repos})
        data = self._app("POST", f"/app/installations/{installation_id}/access_tokens",
                         {"repositories": names, "permissions": permissions}, ok=(201,))
        granted = data.get("permissions", {})
        for k, v in permissions.items():
            if granted.get(k) != v:
                raise GitHubError(f"installation token lacks {k}:{v} (got {granted.get(k)!r}); "
                                  "check the App's permissions and installation")
        got = sorted(r["full_name"] for r in data.get("repositories", []))
        if [g.lower() for g in got] != sorted(r.lower() for r in repos):
            raise GitHubError(f"installation token covers {got}, expected {sorted(repos)}")
        return InstallationToken(data["token"], data["expires_at"], installation_id, got, granted)

    def revoke(self, token: str) -> None:
        # 204 on success; 401 means it is already invalid, which is the goal.
        self._call("DELETE", "/installation/token", f"Bearer {token}", ok=(204, 401))

    def canonical_repo(self, token: str, repo: str) -> dict:
        owner, name = repo.split("/", 1)
        return self._call("GET", f"/repos/{_q(owner)}/{_q(name)}", f"Bearer {token}")

    def push_protection(self, check_token: str, repo: str, branch: str, app_slug: str) -> dict:
        """Does ``branch`` block direct pushes by this App? Returns evidence."""
        owner, name = repo.split("/", 1)
        auth = f"Bearer {check_token}"
        o, n, b = _q(owner), _q(name), _q(branch)
        evidence: dict = {"branch": branch, "rulesets": [], "classic": None}
        blocked = False
        rules = self._call("GET", f"/repos/{o}/{n}/rules/branches/{b}", auth)
        ruleset_ids = sorted({r.get("ruleset_id") for r in rules or [] if r.get("type") in BLOCKING_RULE_TYPES})
        for rid in ruleset_ids:
            rs = self._call("GET", f"/repos/{o}/{n}/rulesets/{rid}", auth)
            bypass = rs.get("current_user_can_bypass", "never")
            types = sorted({r["type"] for r in rules if r.get("ruleset_id") == rid})
            entry = {"id": rid, "name": rs.get("name"), "enforcement": rs.get("enforcement"),
                     "rule_types": types, "current_user_can_bypass": bypass}
            evidence["rulesets"].append(entry)
            if rs.get("enforcement") == "active" and bypass == "never":
                blocked = True
        try:
            prot = self._call("GET", f"/repos/{o}/{n}/branches/{b}/protection", auth)
        except GitHubError as err:
            if err.status != 404:
                raise
            prot = None
        if prot:
            prr = prot.get("required_pull_request_reviews")
            apps = [a.get("slug") for a in
                    ((prr or {}).get("bypass_pull_request_allowances") or {}).get("apps", [])]
            push_apps = [a.get("slug") for a in (prot.get("restrictions") or {}).get("apps", [])]
            evidence["classic"] = {"requires_pull_request": prr is not None,
                                   "app_can_bypass_pr": app_slug in apps,
                                   "push_restrictions": prot.get("restrictions") is not None,
                                   "app_in_push_allowlist": app_slug in push_apps}
            if prr is not None and app_slug not in apps:
                blocked = True
            if prot.get("restrictions") is not None and app_slug not in push_apps:
                blocked = True
        evidence["blocks_direct_push"] = blocked
        return evidence


def _q(part: str) -> str:
    return urllib.parse.quote(part, safe="")


def download_tarball(app: GitHubApp, token: str, repo: str, ref: str, dest: str,
                     max_bytes: int = 512 * 1024**2) -> None:
    """Fetch the repo at ``ref`` as a tarball (host side, prep token)."""
    owner, name = repo.split("/", 1)
    url = f"{API}/repos/{_q(owner)}/{_q(name)}/tarball/{_q(ref)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}",
                                               "Accept": "application/vnd.github+json",
                                               "User-Agent": "agent-yard"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as fh:
        total = 0
        for chunk in iter(lambda: resp.read(1 << 20), b""):
            total += len(chunk)
            if total > max_bytes:
                raise GitHubError(f"repository tarball exceeds {max_bytes} bytes")
            fh.write(chunk)
