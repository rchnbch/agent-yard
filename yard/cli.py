"""``yard``: the stable CLI HQ calls. See docs/CLI.md for the contract.

On the laptop every command is forwarded over SSH (Tailscale) to the host,
where ``yard --local ...`` runs it. ``--json`` output is one JSON object on
stdout; errors are ``{"ok": false, "error": "..."}`` with a non-zero exit:
1 refused or failed, 2 usage error, 3 checks failed (doctor, selftest).
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import subprocess
import sys
import time

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_CHECKS = 0, 1, 2, 3
CLI_VERSION = "1"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="yard", description="agent-yard: OpenShell sandbox jobs for HQ")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--host", help="host name from the laptop config (default: the only one)")
    p.add_argument("--local", action="store_true", help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="start a job; returns once its sandbox is running")
    r.add_argument("--repo")
    r.add_argument("--branch")
    r.add_argument("--spec", required=True, help="Markdown spec file ('-' for stdin)")
    r.add_argument("--job-id")
    r.add_argument("--egress", choices=("open", "deny"))
    r.add_argument("--read-repos", help="comma-separated owner/name list")
    r.add_argument("--timeout", help="wall clock, e.g. 4h (default 4h)")
    r.add_argument("--idle", help="idle kill after no agent output, e.g. 30m (default 30m)")
    r.add_argument("--disk", help="disk quota, e.g. 20G (default 20G)")
    r.add_argument("--cpu")
    r.add_argument("--memory")
    r.add_argument("--env-project")

    s = sub.add_parser("status", help="one job, or all jobs")
    s.add_argument("id", nargs="?")
    lg = sub.add_parser("logs", help="agent output (stream-json) of a job")
    lg.add_argument("id")
    lg.add_argument("--follow", action="store_true")
    e = sub.add_parser("events", help="durable event log since a cursor")
    e.add_argument("--since", default=None, help="cursor from a previous call (default: start)")
    e.add_argument("--limit", type=int, default=1000)
    e.add_argument("--job")
    k = sub.add_parser("kill", help="stop a job now (tokens revoked, sandbox deleted)")
    k.add_argument("id")
    sub.add_parser("approvals", help="pending policy proposals")
    for verb in ("approve", "reject"):
        a = sub.add_parser(verb, help=f"{verb} a policy proposal")
        a.add_argument("proposal")
        a.add_argument("--reason")
    sub.add_parser("doctor", help="check every host precondition")
    st = sub.add_parser("selftest", help="adversarial self-test on the live host")
    st.add_argument("--repo", required=True, help="test repo with a protected default branch")
    st.add_argument("--read-repo", help="second test repo used as read_repos")
    st.add_argument("--quick", action="store_true", help="skip the limit jobs")
    sec = sub.add_parser("secrets", help="push secrets to the host (value on stdin)")
    secsub = sec.add_subparsers(dest="secrets_cmd", required=True)
    ss = secsub.add_parser("set")
    ss.add_argument("name", help="claude-oauth-token | github-app-key | tailscale-authkey | ENV_VAR")
    ss.add_argument("--project", help="store ENV_VAR as a project secret (OpenShell provider)")
    secsub.add_parser("list")
    sub.add_parser("version")
    return p


# ---------------------------------------------------------------- output

def emit(args, payload: dict, human: str | None = None, code: int = EXIT_OK) -> int:
    if args.json:
        print(json.dumps({"ok": code == EXIT_OK, **payload}, sort_keys=True, default=str))
    else:
        print(human if human is not None else json.dumps(payload, indent=2, default=str))
    return code


def fail(args, message: str, code: int = EXIT_FAIL) -> int:
    if args.json:
        print(json.dumps({"ok": False, "error": message}))
    else:
        print(f"yard: {message}", file=sys.stderr)
    return code


def _job_line(j: dict) -> str:
    st = (j.get("last_status") or {}).get("status", "-")
    return f"{j['id']:<22} {j['state']:<10} {st:<12} {j['egress']:<5} {j['repo']}  {j.get('pr_url') or ''}"


# ---------------------------------------------------------------- remote

def remote(args, argv: list[str]) -> int:
    from .config import ConfigError, load_laptop
    try:
        hosts = load_laptop()
    except ConfigError as err:
        return fail(args, str(err), EXIT_USAGE)
    if args.host:
        match = [h for h in hosts if h.name == args.host]
        if not match:
            return fail(args, f"unknown host {args.host!r}", EXIT_USAGE)
        host = match[0]
    elif len(hosts) == 1:
        host = hosts[0]
    else:
        return fail(args, "several hosts configured; pass --host", EXIT_USAGE)

    fwd: list[str] = []
    skip = False
    for a in argv:
        if skip:
            skip = False
        elif a == "--host":
            skip = True
        elif not a.startswith("--host="):
            fwd.append(a)
    stdin_data = None
    if args.cmd == "run" and args.spec != "-":
        try:
            with open(args.spec, "rb") as fh:
                stdin_data = fh.read()
        except OSError as err:
            return fail(args, f"cannot read spec: {err}", EXIT_USAGE)
        for n, a in enumerate(fwd):
            if a == "--spec":
                fwd[n + 1] = "-"
            elif a.startswith("--spec="):
                fwd[n] = "--spec=-"
    elif args.cmd == "run":
        stdin_data = sys.stdin.buffer.read()
    elif args.cmd == "secrets" and args.secrets_cmd == "set":
        if sys.stdin.isatty():
            stdin_data = getpass.getpass(f"value for {args.name} (input hidden): ").encode()
        else:
            stdin_data = sys.stdin.buffer.read()
    remote_cmd = shlex.join(["yard", "--local", *fwd])
    ssh = ["ssh", "-o", "BatchMode=yes", *host.ssh_options, host.ssh, "--", remote_cmd]
    proc = subprocess.run(ssh, input=stdin_data, check=False,
                          stdin=None if stdin_data is not None else subprocess.DEVNULL)
    if proc.returncode == 255:
        return fail(args, f"ssh to {host.ssh} failed (is Tailscale up?)", EXIT_FAIL)
    return proc.returncode


# ---------------------------------------------------------------- local (host)

def local(args) -> int:
    from .config import ConfigError, load_host
    from .host import Yard, YardError
    from .spec import SpecError, parse_job

    try:
        cfg = load_host()
    except ConfigError as err:
        return fail(args, f"host config: {err}", EXIT_USAGE)

    if args.cmd == "version":
        return emit(args, {"cli": CLI_VERSION}, f"yard CLI contract v{CLI_VERSION}")
    if args.cmd == "doctor":
        from .doctor import run_checks
        checks = run_checks(cfg)
        ok = all(c["ok"] for c in checks if c["required"])
        human = "\n".join(f"{'ok  ' if c['ok'] else 'FAIL'} {c['check']:<26} {c['detail']}" for c in checks)
        return emit(args, {"checks": checks, "all_green": ok}, human, EXIT_OK if ok else EXIT_CHECKS)

    yard = Yard(cfg)
    try:
        if args.cmd == "run":
            data = sys.stdin.buffer.read() if args.spec == "-" else open(args.spec, "rb").read()
            req = parse_job(data, {
                "repo": args.repo, "branch": args.branch, "job_id": args.job_id,
                "egress": args.egress, "read_repos": args.read_repos, "timeout": args.timeout,
                "idle": args.idle, "disk": args.disk, "cpu": args.cpu, "memory": args.memory,
                "env_project": args.env_project,
            })
            job = yard.run(req)
            return emit(args, {"job_id": job.id, "job": job.public()}, job.id)
        if args.cmd == "status":
            res = yard.status(args.id)
            if args.id:
                return emit(args, res, json.dumps(res["job"], indent=2, default=str))
            return emit(args, res, "\n".join(_job_line(j) for j in res["jobs"]) or "(no jobs)")
        if args.cmd == "logs":
            if not args.follow:
                out = yard.logs(args.id)
                return emit(args, {"job_id": args.id, "log": out}, out)
            seen = 0
            while True:
                out = yard.logs(args.id, tail_bytes=10_000_000)
                if len(out) > seen:
                    sys.stdout.write(out[seen:])
                    sys.stdout.flush()
                    seen = len(out)
                if not yard.jobs.load(args.id).active:
                    return EXIT_OK
                time.sleep(3)
        if args.cmd == "events":
            res = yard.events_since(args.since, args.limit, args.job)
            human = "\n".join(f"{e['seq']:>6} {e['type']:<17} {e.get('job') or '-':<22} "
                              f"{json.dumps(e['data'], default=str)[:160]}" for e in res["events"])
            return emit(args, res, (human + "\n" if human else "") + f"cursor: {res['cursor']}")
        if args.cmd == "kill":
            res = yard.kill(args.id)
            return emit(args, res, f"{args.id}: {res['job']['state']}")
        if args.cmd == "approvals":
            res = yard.approvals()
            human = "\n".join(f"{a['proposal']}  {a['rule']}  {a['endpoints']}  {a['prover']}"
                              for a in res["approvals"]) or "(none pending)"
            return emit(args, res, human)
        if args.cmd in ("approve", "reject"):
            res = yard.decide(args.proposal, args.cmd == "approve", args.reason)
            return emit(args, res, f"{args.proposal}: {'approved' if res['approved'] else 'rejected'}")
        if args.cmd == "selftest":
            from . import selftest
            rep = selftest.run(yard, args.repo, args.read_repo, quick=args.quick)
            human = "\n".join(f"{'PASS' if c['pass'] else 'FAIL'} {c['check']:<44} "
                              f"{json.dumps(c['evidence'], default=str)[:200]}" for c in rep["checks"])
            return emit(args, rep, human + f"\nreport: {rep['report_path']}",
                        EXIT_OK if rep["passed"] else EXIT_CHECKS)
        if args.cmd == "secrets":
            from . import secrets as S
            if args.secrets_cmd == "list":
                return emit(args, S.list_secrets(cfg))
            value = sys.stdin.buffer.read()
            if args.project:
                res = S.set_project_secret(cfg, yard.deps.openshell, args.project, args.name, value)
            else:
                res = S.set_file_secret(cfg, args.name, value)
            return emit(args, res, f"stored {args.name}")
    except (YardError, SpecError) as err:
        return fail(args, str(err))
    except Exception as err:  # noqa: BLE001
        from .secrets import SecretError
        if isinstance(err, SecretError):
            return fail(args, str(err))
        raise
    return fail(args, f"unhandled command {args.cmd}", EXIT_USAGE)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as err:
        return EXIT_USAGE if err.code else EXIT_OK
    if args.local or os.environ.get("YARD_LOCAL") == "1":
        return local(args)
    return remote(args, argv)


if __name__ == "__main__":
    sys.exit(main())
