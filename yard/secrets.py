"""``yard secrets``: push secrets to the host after boot, never via user-data.

Values arrive on stdin (over SSH from the laptop) and land either in files
readable only by the gateway user, or in the OpenShell gateway's encrypted
provider store (project secrets). Values are never echoed or logged.
"""

from __future__ import annotations

import os
import re
import tempfile

from . import policy as P
from .config import HostConfig
from .host import _write_private, project_provider_name
from .openshell import OpenShell, OpenShellError
from .yamlout import dumps as yaml_dumps

FILE_SECRETS = {
    "claude-oauth-token": "Claude subscription token from 'claude setup-token'",
    "github-app-key": "GitHub App private key (PEM)",
    "tailscale-authkey": "Tailscale auth key (consumed by host/bootstrap)",
}
FILE_NAMES = {"claude-oauth-token": "claude-oauth-token", "github-app-key": "github-app.pem",
              "tailscale-authkey": "tailscale-authkey"}


class SecretError(ValueError):
    pass


def _validate(name: str, value: bytes) -> bytes:
    if not value.strip():
        raise SecretError("empty secret on stdin")
    if len(value) > 64 * 1024:
        raise SecretError("secret is larger than 64 KiB")
    if name == "github-app-key" and b"PRIVATE KEY-----" not in value:
        raise SecretError("github-app-key must be a PEM private key")
    if name == "claude-oauth-token":
        tok = value.strip()
        if b"\n" in tok or not re.fullmatch(rb"[A-Za-z0-9_\-.]+", tok):
            raise SecretError("claude-oauth-token must be a single token line")
        return tok + b"\n"
    return value


def set_file_secret(cfg: HostConfig, name: str, value: bytes) -> dict:
    if name not in FILE_SECRETS:
        raise SecretError(f"unknown secret {name!r}; known: {', '.join(FILE_SECRETS)} "
                          "(project secrets use --project)")
    _write_private(cfg.secret_path(FILE_NAMES[name]), _validate(name, value))
    return {"secret": name, "stored": True}


def set_project_secret(cfg: HostConfig, os_: OpenShell, project: str, env_var: str, value: bytes) -> dict:
    proj = cfg.projects.get(project)
    if proj is None:
        raise SecretError(f"unknown project {project!r}; add [projects.{project}] to yard.toml")
    svc = next((cfg.services[s] for s in proj.services if cfg.services[s].env_var == env_var), None)
    if svc is None:
        raise SecretError(f"project {project!r} has no service using {env_var}; "
                          f"services: {', '.join(proj.services) or '(none)'}")
    secret = value.decode("utf-8", errors="strict").strip()
    if not secret or "\n" in secret:
        raise SecretError("project secret must be one non-empty line")
    profile = P.service_profile(svc, P.public_ipv4())
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(yaml_dumps(profile))
        path = fh.name
    try:
        try:
            os_.profile_import(path)
        except OpenShellError as err:
            if "exist" not in str(err).lower():
                raise
    finally:
        os.unlink(path)
    name = project_provider_name(project, svc.id)
    if os_.provider_exists(name):
        os_.provider_update(name, {env_var: secret})
        action = "updated"
    else:
        os_.provider_create(name, svc.id, {env_var: secret})
        action = "created"
    return {"secret": env_var, "project": project, "provider": name, "action": action}


def list_secrets(cfg: HostConfig) -> dict:
    files = {n: os.path.exists(cfg.secret_path(FILE_NAMES[n])) for n in FILE_SECRETS}
    return {"files": files, "projects": {p: list(v.services) for p, v in cfg.projects.items()}}
