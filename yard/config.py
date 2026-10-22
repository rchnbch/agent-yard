"""Configuration: the laptop's host list and the host's own settings (TOML)."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field

from .policy import ServiceProfile, validate_host

LAPTOP_CONFIG = os.path.expanduser(os.environ.get("YARD_CONFIG", "~/.config/agent-yard/config.toml"))
HOST_CONFIG = os.environ.get("YARD_HOST_CONFIG", "/etc/agent-yard/yard.toml")
SHARE_DIR = os.environ.get("YARD_SHARE_DIR", "/usr/local/share/agent-yard")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class RemoteHost:
    """A yard host as the laptop sees it. v1 uses exactly one."""

    name: str
    ssh: str  # e.g. "yard@yard1" (a Tailscale MagicDNS name)
    ssh_options: tuple[str, ...] = ()


def load_laptop(path: str = LAPTOP_CONFIG) -> tuple[RemoteHost, ...]:
    if not os.path.exists(path):
        raise ConfigError(f"no laptop config at {path}; see README 'Quick start'")
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    hosts = []
    for name, h in (data.get("hosts") or {}).items():
        if "ssh" not in h:
            raise ConfigError(f"hosts.{name}: 'ssh' is required")
        hosts.append(RemoteHost(name, h["ssh"], tuple(h.get("ssh_options", ()))))
    if not hosts:
        raise ConfigError(f"{path}: define at least one [hosts.<name>] table")
    return tuple(hosts)


@dataclass(frozen=True)
class Project:
    name: str
    services: tuple[str, ...] = ()
    registries: tuple[str, ...] = ()


@dataclass(frozen=True)
class HostConfig:
    name: str = "yard1"
    state_dir: str = "/var/lib/agent-yard/state"
    secrets_dir: str = "/var/lib/agent-yard/secrets"
    max_jobs: int = 5
    base_image: str = "localhost/agent-yard/base:latest"
    podman_url: str = "unix:///run/agent-yard/podman/podman.sock"
    engine: str = "podman"  # "docker" only for the local test setup
    quota_helper: str = "/usr/local/libexec/agent-yard/yard-quota"
    openshell_gateway: str | None = "openshell"
    poll_seconds: int = 15
    github_app_id: str = ""
    github_app_slug: str = ""
    github_private_key: str = "/var/lib/agent-yard/secrets/github-app.pem"
    projects: dict[str, Project] = field(default_factory=dict)
    services: dict[str, ServiceProfile] = field(default_factory=dict)

    @property
    def events_path(self) -> str:
        return os.path.join(self.state_dir, "events.jsonl")

    @property
    def jobs_dir(self) -> str:
        return os.path.join(self.state_dir, "jobs")

    def secret_path(self, name: str) -> str:
        return os.path.join(self.secrets_dir, name)


def load_services(path: str) -> dict[str, ServiceProfile]:
    """Project-secret service catalog (providers/services.toml)."""
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    out = {}
    for sid, s in (data.get("services") or {}).items():
        try:
            hosts = tuple(validate_host(h) for h in s["hosts"])
            env_var = s["env_var"]
        except KeyError as err:
            raise ConfigError(f"services.{sid}: missing {err}") from None
        if not env_var.replace("_", "").isalnum() or not env_var.isupper():
            raise ConfigError(f"services.{sid}: env_var must be UPPER_SNAKE_CASE")
        out[sid] = ServiceProfile(id=sid, env_var=env_var, hosts=hosts,
                                  auth_style=s.get("auth_style", "bearer"),
                                  header_name=s.get("header_name", "authorization"),
                                  access=s.get("access", "read-write"))
    return out


def load_host(path: str = HOST_CONFIG, services_path: str | None = None) -> HostConfig:
    data: dict = {}
    if os.path.exists(path):
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    h = data.get("host", {})
    gh = data.get("github", {})
    services_path = services_path or os.path.join(SHARE_DIR, "providers", "services.toml")
    services = load_services(services_path) if os.path.exists(services_path) else {}
    projects = {}
    for name, p in (data.get("projects") or {}).items():
        svc = tuple(p.get("services", ()))
        for s in svc:
            if s not in services:
                raise ConfigError(f"projects.{name}: unknown service {s!r}")
        regs = tuple(validate_host(r) for r in p.get("registries", ()))
        projects[name] = Project(name, svc, regs)
    kwargs = {k: h[k] for k in ("name", "state_dir", "secrets_dir", "max_jobs", "base_image",
                                "podman_url", "engine", "quota_helper", "openshell_gateway",
                                "poll_seconds") if k in h}
    cfg = HostConfig(github_app_id=str(gh.get("app_id", "")),
                     github_app_slug=gh.get("app_slug", ""),
                     github_private_key=gh.get("private_key", HostConfig.github_private_key),
                     projects=projects, services=services, **kwargs)
    if cfg.engine not in ("podman", "docker"):
        raise ConfigError("host.engine must be 'podman' or 'docker'")
    if not 1 <= cfg.max_jobs <= 50:
        raise ConfigError("host.max_jobs must be between 1 and 50")
    return cfg
