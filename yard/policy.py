"""Render per-job OpenShell sandbox policies and provider profiles.

Two egress templates exist:

* ``open``: any binary may reach public HTTP(S) hosts, written as
  ``**.*.<tld>`` wildcards for a TLD list plus an explicit apex-host list
  (OpenShell forbids TLD wildcards such as ``*.com``). Every endpoint is
  L7-inspected (``protocol: rest``) so that deny rules on credentialed hosts
  take precedence over the broad allow (see docs/SPIKES.md, "guard rules").
* ``deny``: an allowlist of Anthropic, GitHub (through the GitHub provider
  rules only) and the project's registries.

Credentials never appear in a policy. GitHub tokens and project secrets are
OpenShell providers; their profiles' endpoints define where OpenShell will
resolve each placeholder. ``credential_surface`` renders those endpoints as a
policy so the prover can check where credentials can go.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable

# Paths of client binaries in the yard base image (images/base/Dockerfile).
# OpenShell matches the real executable path, or any ancestor process.
BIN_GIT = "/usr/bin/git"
BIN_GH = "/usr/bin/gh"
BIN_CLAUDE = "/usr/local/bin/claude"
BIN_CURL = "/usr/bin/curl"
BIN_ANY = "/**"

GITHUB_HOSTS = ("github.com", "api.github.com")
ANTHROPIC_HOST = "api.anthropic.com"

# Merging must never be reachable by the agent, on every template (branch
# protection enforces the same on GitHub's side). A merge is
# ``PUT /repos/{o}/{r}/pulls/{n}/merge``; no worker task needs PUT on the
# REST API (content goes through git push), so every PUT is denied. The
# branch-merge API ``POST /repos/{o}/{r}/merges`` is denied per repository.
# Literal paths keep the deny rules decidable by openshell-prover; glob
# segments such as ``/repos/*/*/pulls/*/merge`` make it time out.


def github_api_deny(repos: Iterable[str]) -> list[dict]:
    rules = [{"method": "PUT", "path": "/**"}]
    rules += [{"method": "POST", "path": f"/repos/{r}/merges"} for r in repos]
    return rules


# Ranges excluded from every endpoint's allowed_ips (OpenShell itself always
# blocks loopback and link-local). 10.0.0.0/8 covers Hetzner private networks
# and 100.64.0.0/10 the tailnet. The list is short on purpose: every CIDR is
# repeated on every endpoint (the prover needs identical allowed_ips on
# overlapping endpoints) and openshell-prover caps candidate + boundary at
# 4096 IP ranges in total. 172.16.0.0/12, 192.168.0.0/16 and the host's own
# public addresses are dropped for the sandbox user by host nftables
# (host/nftables-yard.conf), which is enforced in the kernel either way.
EXCLUDED_V4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/3",
)

DEFAULT_OPEN_TLDS = (
    "com", "org", "net", "io", "dev", "ai", "app", "co", "sh", "me", "rs",
    "so", "gg", "xyz", "cloud", "tech", "info", "edu", "gov", "us", "uk",
    "de", "eu", "ch",
)

# Two-label hosts cannot be covered by a wildcard; list the ones dev tooling
# hits first. Any other apex host is reached through OpenShell's own drafted
# rule for the blocked connection, auto-approved in open mode (it carries no
# credential), at the cost of one failed first attempt.
DEFAULT_APEX_HOSTS = (
    "github.com", "pypi.org", "npmjs.org", "npmjs.com", "crates.io", "go.dev",
    "golang.org", "rubygems.org", "nodejs.org", "python.org", "docker.io",
    "ghcr.io", "quay.io", "openrouter.ai",
)

OPEN_PORTS = (80, 443)

REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class PolicyError(ValueError):
    pass


def public_ipv4(extra_excluded: Iterable[str] = ()) -> list[str]:
    """Public IPv4 space as a sorted list of CIDRs, minus exclusions."""
    excluded = [ipaddress.ip_network(n) for n in (*EXCLUDED_V4, *extra_excluded)]
    nets = [ipaddress.ip_network("0.0.0.0/0")]
    for ex in excluded:
        if ex.version != 4:
            raise PolicyError(f"only IPv4 exclusions are supported: {ex}")
        nxt = []
        for net in nets:
            if not net.overlaps(ex):
                nxt.append(net)
            elif ex.subnet_of(net):
                nxt.extend(net.address_exclude(ex))
            # net inside ex: dropped entirely
        nets = nxt
    return [str(n) for n in sorted(ipaddress.collapse_addresses(nets))]


def validate_repo(repo: str) -> str:
    if not REPO_RE.match(repo) or ".." in repo or repo.endswith(".git"):
        raise PolicyError(f"invalid repository name: {repo!r} (want owner/name)")
    return repo


def validate_host(host: str) -> str:
    if not HOST_RE.match(host):
        raise PolicyError(f"invalid host name: {host!r}")
    return host


@dataclass(frozen=True)
class ServiceProfile:
    """A project secret provider type (providers/*.yaml in this repo)."""

    id: str
    env_var: str
    hosts: tuple[str, ...]
    auth_style: str = "bearer"
    header_name: str = "authorization"
    access: str = "read-write"
    binaries: tuple[str, ...] = (BIN_ANY,)


@dataclass(frozen=True)
class PolicyContext:
    """Host-level inputs shared by every job."""

    extra_excluded_v4: tuple[str, ...] = ()
    open_tlds: tuple[str, ...] = DEFAULT_OPEN_TLDS
    apex_hosts: tuple[str, ...] = DEFAULT_APEX_HOSTS


@dataclass(frozen=True)
class JobNetwork:
    """The parts of a job that shape its policy."""

    job_id: str
    repo: str
    egress: str = "open"
    read_repos: tuple[str, ...] = ()
    registries: tuple[str, ...] = ()
    services: tuple[ServiceProfile, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.egress not in ("open", "deny"):
            raise PolicyError(f"egress must be open or deny, not {self.egress!r}")
        validate_repo(self.repo)
        for r in self.read_repos:
            validate_repo(r)
            if r.lower() == self.repo.lower():
                raise PolicyError("read_repos must not contain the target repo")
        for h in self.registries:
            validate_host(h)


def _ep(host: str, ips: list[str], **kw) -> dict:
    ep = {"host": host}
    if "ports" in kw:
        ep["ports"] = list(kw.pop("ports"))
    else:
        ep["port"] = kw.pop("port", 443)
    path = kw.pop("path", None)
    if path:
        ep["path"] = path
    ep["protocol"] = "rest"
    ep["enforcement"] = "enforce"
    ep.update(kw)
    ep["allowed_ips"] = list(ips)
    return ep


def _bins(paths: Iterable[str]) -> list[dict]:
    return [{"path": p} for p in paths]


def provider_name(job_id: str, kind: str, idx: int | None = None) -> str:
    base = f"yard-{job_id}-{kind}"
    return base if idx is None else f"{base}{idx}"


def github_write_profile(job: JobNetwork, ips: list[str]) -> dict:
    """Write token: contents + pull requests on the target repo only."""
    o_r = job.repo
    return {
        "id": provider_name(job.job_id, "ghw"),
        "display_name": f"GitHub write {o_r}",
        "description": f"agent-yard job {job.job_id}: write access to {o_r}",
        "category": "source_control",
        "credentials": [{
            "name": "token",
            "description": "GitHub App installation token (write, target repo)",
            "env_vars": ["GITHUB_TOKEN", "GH_TOKEN"],
            "required": True,
            "auth_style": "bearer",
            "header_name": "authorization",
        }],
        "endpoints": [
            _ep("github.com", ips, path=f"/{o_r}.git/**", rules=[
                {"allow": {"method": "GET", "path": f"/{o_r}.git/info/refs"}},
                {"allow": {"method": "POST", "path": f"/{o_r}.git/git-upload-pack"}},
                {"allow": {"method": "POST", "path": f"/{o_r}.git/git-receive-pack"}},
            ]),
            _ep("api.github.com", ips, path=f"/repos/{o_r}/**", access="read-write",
                deny_rules=github_api_deny([o_r])),
        ],
        "binaries": [BIN_GIT, BIN_GH, BIN_CURL],
    }


def github_read_profile(job: JobNetwork, idx: int, repos: list[str], ips: list[str]) -> dict:
    """Read token: contents read on read_repos only (one per installation)."""
    endpoints = []
    for o_r in repos:
        endpoints.append(_ep("github.com", ips, path=f"/{o_r}.git/**", rules=[
            {"allow": {"method": "GET", "path": f"/{o_r}.git/info/refs"}},
            {"allow": {"method": "POST", "path": f"/{o_r}.git/git-upload-pack"}},
        ]))
        endpoints.append(_ep("api.github.com", ips, path=f"/repos/{o_r}/**", access="read-only"))
    return {
        "id": provider_name(job.job_id, "ghr", idx),
        "display_name": f"GitHub read {idx}",
        "description": f"agent-yard job {job.job_id}: read access to {', '.join(repos)}",
        "category": "source_control",
        "credentials": [{
            "name": "token",
            "description": "GitHub App installation token (read-only, read_repos)",
            "env_vars": [f"YARD_GH_READ_TOKEN_{idx}"],
            "required": True,
            "auth_style": "bearer",
            "header_name": "authorization",
        }],
        "endpoints": endpoints,
        "binaries": [BIN_GIT, BIN_GH, BIN_CURL],
    }


def service_profile(svc: ServiceProfile, ips: list[str]) -> dict:
    for h in svc.hosts:
        validate_host(h)
    return {
        "id": svc.id,
        "display_name": svc.id,
        "description": f"agent-yard project secret for {', '.join(svc.hosts)}",
        "category": "other",
        "credentials": [{
            "name": "secret",
            "description": f"{svc.env_var} for {', '.join(svc.hosts)}",
            "env_vars": [svc.env_var],
            "required": True,
            "auth_style": svc.auth_style,
            "header_name": svc.header_name,
        }],
        "endpoints": [_ep(h, ips, access=svc.access) for h in svc.hosts],
        "binaries": list(svc.binaries),
    }


def job_profiles(job: JobNetwork, read_groups: list[list[str]], ctx: PolicyContext) -> list[dict]:
    """Per-job GitHub profiles plus the project's service profiles.

    ``read_groups`` partitions ``job.read_repos`` by GitHub App installation,
    since one installation token covers one installation.
    """
    ips = public_ipv4(ctx.extra_excluded_v4)
    grouped = sorted(r.lower() for g in read_groups for r in g)
    if grouped != sorted(r.lower() for r in job.read_repos):
        raise PolicyError("read_groups must partition read_repos exactly")
    profiles = [github_write_profile(job, ips)]
    for idx, group in enumerate(read_groups):
        profiles.append(github_read_profile(job, idx, group, ips))
    profiles.extend(service_profile(s, ips) for s in job.services)
    return profiles


def _filesystem() -> dict:
    return {
        "include_workdir": True,
        "read_only": ["/usr", "/lib", "/etc", "/bin", "/proc", "/dev/urandom", "/var/log", "/opt"],
        "read_write": ["/tmp", "/dev/null", "/var/tmp"],
    }


def covered_by_open_wildcards(host: str, ctx: PolicyContext) -> bool:
    labels = host.split(".")
    return len(labels) >= 3 and labels[-1] in ctx.open_tlds


def render_sandbox_policy(job: JobNetwork, ctx: PolicyContext) -> dict:
    """The base sandbox policy (providers add their ``_provider_*`` rules)."""
    ips = public_ipv4(ctx.extra_excluded_v4)
    rules: dict[str, dict] = {
        "anthropic": {
            "endpoints": [_ep(ANTHROPIC_HOST, ips, access="read-write")],
            "binaries": _bins([BIN_CLAUDE]),
        },
    }
    if job.egress == "open":
        hosts = [f"**.*.{tld}" for tld in ctx.open_tlds] + list(ctx.apex_hosts)
        for h in job.registries:
            if h not in hosts and not covered_by_open_wildcards(h, ctx):
                hosts.append(h)
        rules["open_egress"] = {
            "endpoints": [_ep(h, ips, ports=OPEN_PORTS, access="full") for h in hosts],
            "binaries": _bins([BIN_ANY]),
        }
        # Guard: the open rule also matches api.github.com, and OpenShell
        # resolves a provider placeholder for any binary at its bound
        # endpoint (docs/SPIKES.md). Deny rules take precedence over every
        # matching allow, so the merge endpoints stay unreachable whichever
        # rule admitted the connection. github.com needs no guard: a push
        # there is what the job may do anyway, and main is protected.
        rules["github_api_guard"] = {
            "endpoints": [_ep("api.github.com", ips, ports=OPEN_PORTS, access="full",
                              deny_rules=github_api_deny([job.repo, *job.read_repos]))],
            "binaries": _bins([BIN_ANY]),
        }
    else:
        if job.registries:
            rules["registries"] = {
                "endpoints": [_ep(h, ips, access="read-only") for h in job.registries],
                "binaries": _bins([BIN_ANY]),
            }
    return {
        "version": 1,
        "filesystem_policy": _filesystem(),
        "landlock": {"compatibility": "hard_requirement"},
        "process": {"run_as_user": "1000", "run_as_group": "1000"},
        "network_policies": rules,
    }


def _provider_rule_key(name: str) -> str:
    return "_provider_" + re.sub(r"[^A-Za-z0-9]", "_", name)


def compose_effective(base: dict, attached: list[tuple[str, dict]]) -> dict:
    """Mirror OpenShell's just-in-time composition of base + provider rules.

    ``attached`` is a list of (provider instance name, profile). OpenShell
    concatenates a ``_provider_<name>`` rule per attached provider whose
    endpoints and binaries come from the profile.
    """
    out = {k: v for k, v in base.items() if k != "network_policies"}
    rules = dict(base.get("network_policies", {}))
    for name, profile in attached:
        key = _provider_rule_key(name)
        rules[key] = {
            "name": key,
            "endpoints": [dict(e) for e in profile["endpoints"]],
            "binaries": _bins(profile["binaries"]),
        }
    out["network_policies"] = rules
    return out


def credential_surface(attached: list[tuple[str, dict]]) -> dict:
    """Only the endpoints where provider credentials can be resolved.

    Binaries are widened to ``/**`` because OpenShell resolves static
    placeholders by endpoint, not by binary (verified in docs/SPIKES.md).
    """
    rules = {}
    for name, profile in attached:
        key = _provider_rule_key(name)
        rules[key] = {
            "endpoints": [dict(e) for e in profile["endpoints"]],
            "binaries": _bins([BIN_ANY]),
        }
    return {"version": 1, "network_policies": rules}
