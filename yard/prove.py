"""Run openshell-prover boundary checks for a job's rendered policy.

Three properties, per egress template:

1. network: the composed effective policy (base + provider rules) is within
   ``network-<mode>.yaml``. That boundary denies every PUT on
   api.github.com, which contains the PR merge endpoint, and in deny mode
   lists only the allowlisted hosts.
2. GitHub credentials: the endpoints where each GitHub provider's token can
   be resolved are within ``credential-github.yaml`` (github.com and
   api.github.com only, no PUT).
3. Every other credential: each service provider's endpoints are within its
   own ``credential-<service>.yaml``.

Only ``within_boundary`` passes; every other prover result is a failure.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from . import policy as P
from . import yamlout

BOUNDARY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "policies", "boundaries")


@dataclass
class Check:
    name: str
    boundary: str
    result: str
    detail: str | None

    @property
    def ok(self) -> bool:
        return self.result == "within_boundary"

    def to_dict(self) -> dict:
        return {"name": self.name, "boundary": os.path.basename(self.boundary),
                "result": self.result, "detail": self.detail, "ok": self.ok}


def prover_binary() -> str:
    found = shutil.which("openshell-prover")
    if not found:
        raise FileNotFoundError("openshell-prover not found on PATH")
    return found


def run_check(candidate: dict, boundary: str, timeout: str = "60s") -> tuple[str, str | None]:
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "candidate.yaml")
        with open(path, "w") as fh:
            fh.write(yamlout.dumps(candidate))
        proc = subprocess.run(
            [prover_binary(), "check", path, "--boundary", boundary, "--output", "json",
             "--timeout", timeout],
            capture_output=True, text=True, check=False,
        )
    try:
        out = json.loads(proc.stdout)
    except ValueError:
        return "error", (proc.stderr or proc.stdout).strip()[:500]
    detail = out.get("reason")
    if out.get("counterexample"):
        detail = json.dumps(out["counterexample"], sort_keys=True)
    return out.get("result", "error"), detail


def credential_kind(provider_name: str, profile: dict) -> str:
    if profile["id"].startswith("yard-") and ("-ghw" in profile["id"] or "-ghr" in profile["id"]):
        return "github"
    return profile["id"]


def job_checks(base: dict, attached: list[tuple[str, dict]], egress: str,
               boundary_dir: str = BOUNDARY_DIR) -> list[Check]:
    checks = []
    eff = P.compose_effective(base, attached)
    b = os.path.join(boundary_dir, f"network-{egress}.yaml")
    checks.append(Check(f"network/{egress}", b, *run_check(eff, b)))
    for name, profile in attached:
        kind = credential_kind(name, profile)
        b = os.path.join(boundary_dir, f"credential-{kind}.yaml")
        if not os.path.exists(b):
            checks.append(Check(f"credential/{name}", b, "error",
                                f"no boundary file for credential kind {kind!r}"))
            continue
        checks.append(Check(f"credential/{name}", b,
                            *run_check(P.credential_surface([(name, profile)]), b)))
    return checks


# --- negative controls (CI): each mutant must NOT be within its boundary ----

def mutants(base: dict, attached: list[tuple[str, dict]], egress: str) -> list[tuple[str, dict, str]]:
    """(name, candidate, boundary-file-name) triples that must fail."""
    out = []
    # 1. Allow the merge endpoint: drop every deny rule.
    b2 = copy.deepcopy(base)
    att2 = copy.deepcopy(attached)
    for rule in [*b2["network_policies"].values(), *[{"endpoints": p["endpoints"]} for _, p in att2]]:
        for ep in rule["endpoints"]:
            ep.pop("deny_rules", None)
    out.append(("merge-endpoint-allowed", P.compose_effective(b2, att2), f"network-{egress}.yaml"))
    # 2. GitHub write token bound to a non-GitHub host.
    name, prof = next((n, p) for n, p in attached if "-ghw" in p["id"])
    prof2 = copy.deepcopy(prof)
    leak = copy.deepcopy(prof2["endpoints"][-1])
    leak.pop("path", None)
    leak.pop("deny_rules", None)
    leak["host"] = "exfil.example.net"
    prof2["endpoints"].append(leak)
    out.append(("github-token-to-other-host", P.credential_surface([(name, prof2)]),
                "credential-github.yaml"))
    # 3. A service secret bound to a second host.
    for sname, sprof in attached:
        if sprof["id"].startswith("yard-"):
            continue
        sp2 = copy.deepcopy(sprof)
        leak = copy.deepcopy(sp2["endpoints"][0])
        leak["host"] = "exfil.example.net"
        sp2["endpoints"].append(leak)
        out.append((f"{sprof['id']}-secret-to-other-host", P.credential_surface([(sname, sp2)]),
                    f"credential-{sprof['id']}.yaml"))
        break
    # 4. Deny mode: a non-allowlisted host for any binary.
    if egress == "deny":
        b3 = copy.deepcopy(base)
        ips = P.public_ipv4()
        b3["network_policies"]["exfil"] = {
            "endpoints": [P._ep("exfil.example.net", ips, access="full")],
            "binaries": [{"path": P.BIN_ANY}],
        }
        out.append(("deny-mode-extra-host", P.compose_effective(b3, attached), "network-deny.yaml"))
    return out
