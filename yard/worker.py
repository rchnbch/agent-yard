"""What runs inside the sandbox: the worker prompt, job.json and the status file.

The worker reports by appending JSON lines to ``/sandbox/.yard/status.jsonl``
with the same fields as ``hq report``: ``status``, ``note``, ``attn``.
yardd reads the file through ``openshell sandbox exec``; there is no network
path from the sandbox to the host. Everything read back is untrusted.
"""

from __future__ import annotations

import json
import re
import shlex

YARD_DIR = "/sandbox/.yard"
STATUS_FILE = f"{YARD_DIR}/status.jsonl"
AGENT_LOG = f"{YARD_DIR}/agent.log"
PROMPT_FILE = f"{YARD_DIR}/prompt.md"
JOB_FILE = f"{YARD_DIR}/job.json"
WORK_DIR = "/sandbox/work"

STATUSES = ("queued", "working", "blocked", "needs-review", "done", "failed")
MAX_NOTE = 2000
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

PROMPT_TEMPLATE = """\
You are an agent-yard worker: headless, in an ephemeral OpenShell sandbox that is
deleted when you exit. Job id: {job_id}.

## Rules (enforced outside your control; do not try to work around them)
- Clone the target repo with: git clone https://github.com/{repo}.git {work_dir}
  Git credentials are pre-configured. Environment variables hold placeholders, not
  tokens; never print, inspect or copy them.
- Work on the branch `{branch}`, created from `{default_branch}`. Never push to
  `{default_branch}` and never merge a pull request (both are blocked).
- Commit in small, logical steps and push with `git push -u origin {branch}`.
  Unpushed work is lost when the job ends.
- Open exactly ONE pull request into `{default_branch}` with the REST API (GraphQL
  and `gh pr create` are blocked):
    gh api -X POST repos/{repo}/pulls -f title='<title>' -f head='{branch}' \\
      -f base='{default_branch}' -f body='<summary, how you tested, open questions>'
{read_repos_block}- Network egress mode: {egress}. {egress_note}
- Report progress by appending one JSON object per line to {status_file}:
    {{"status": "working", "note": "short progress note", "attn": false}}
  status is one of: {statuses}. Set "attn": true only when a human must act.
  Write a line when you start, at each milestone, and a final line with status
  "done" (put the PR URL in note) or "failed" (say why).

## Task
{spec}
"""

EGRESS_NOTES = {
    "open": "Public HTTP(S) hosts are reachable. A first request to an unlisted "
            "apex domain may be blocked once while a rule is auto-approved; retry it.",
    "deny": "Only Anthropic, GitHub (via git/gh/curl) and the project's registries are "
            "reachable. If you need another host, request it through the policy advisor "
            "(/etc/openshell/skills/policy_advisor.md) and continue with other work while "
            "a human reviews it.",
}


def render_prompt(job_id: str, repo: str, branch: str, default_branch: str, egress: str,
                  read_repos: list[str], spec: str) -> str:
    if read_repos:
        listing = ", ".join(read_repos)
        block = (f"- Read-only reference repos: {listing}. Clone them with "
                 "git clone https://github.com/<owner>/<name>.git; pushing to them is impossible.\n")
    else:
        block = ""
    return PROMPT_TEMPLATE.format(job_id=job_id, repo=repo, branch=branch,
                                  default_branch=default_branch, egress=egress,
                                  egress_note=EGRESS_NOTES[egress], read_repos_block=block,
                                  status_file=STATUS_FILE, statuses=", ".join(STATUSES),
                                  work_dir=WORK_DIR, spec=spec.strip())


def job_file(job_id: str, repo: str, branch: str, default_branch: str,
             read_env: dict[str, str]) -> dict:
    """Read by the git credential helper in the base image (yard-git-credential)."""
    return {
        "job_id": job_id,
        "repo": repo,
        "branch": branch,
        "default_branch": default_branch,
        "credentials": [{"path": f"{repo}.git", "env": "GITHUB_TOKEN"}]
                       + [{"path": f"{r}.git", "env": env} for r, env in sorted(read_env.items())],
    }


def main_command(model: str | None = None) -> list[str]:
    """The sandbox's main process: the unmodified claude binary, headless.

    ``exec`` replaces the shell, so claude itself is the main process. Never
    ``--bare``: it ignores CLAUDE_CODE_OAUTH_TOKEN.
    """
    claude = ["/usr/local/bin/claude", "-p", '"$(cat ' + PROMPT_FILE + ')"',
              "--output-format", "stream-json", "--verbose",
              "--permission-mode", "bypassPermissions"]
    if model:
        claude += ["--model", shlex.quote(model)]
    script = f"cd /sandbox && exec {' '.join(claude)} >>{AGENT_LOG} 2>&1"
    return ["/bin/sh", "-c", script]


def _clean(text: object, limit: int) -> str:
    s = _CTRL.sub("", str(text))
    return s[:limit]


def parse_status_lines(raw: str, already_seen: int) -> tuple[list[dict], int]:
    """Parse status.jsonl; return (new valid entries, total complete lines).

    Malformed lines are reported as {"status": "invalid"} so a confused or
    hostile worker cannot hide progress or forge structure.
    """
    # The last element is either "" (file ends with a newline) or a line the
    # worker is still writing; both are left for the next poll.
    complete = raw.split("\n")[:-1]
    out = []
    for line in complete[already_seen:]:
        if not line.strip():
            out.append({"status": "invalid", "note": "empty line", "attn": False})
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            out.append({"status": "invalid", "note": _clean(line, 200), "attn": False})
            continue
        if not isinstance(obj, dict):
            out.append({"status": "invalid", "note": "not an object", "attn": False})
            continue
        status = obj.get("status")
        if status not in STATUSES:
            status = "invalid"
        attn = obj.get("attn", False)
        out.append({
            "status": status,
            "note": _clean(obj.get("note", ""), MAX_NOTE),
            "attn": attn if isinstance(attn, bool) else bool(_clean(attn, 200)),
        })
    return out, len(complete)


PR_URL_RE = re.compile(r"https://github\.com/([A-Za-z0-9-]+/[A-Za-z0-9._-]+)/pull/(\d+)")


def find_pr_url(note: str, repo: str) -> str | None:
    for m in PR_URL_RE.finditer(note or ""):
        if m.group(1).lower() == repo.lower():
            return m.group(0)
    return None
