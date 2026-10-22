# `yard` CLI contract (v1)

HQ depends on this; changes need a version bump (`yard version`). Every
command accepts `--json`: exactly one JSON object on stdout, always with
`"ok"`. Errors: `{"ok": false, "error": "..."}` and a non-zero exit.

Exit codes: `0` ok, `1` refused or failed, `2` usage/config error,
`3` checks failed (`doctor`, `selftest`).

| Command | Result (`--json`) |
|---|---|
| `yard run --repo O/R --spec FILE [--branch B] [--job-id ID] [--egress open\|deny] [--read-repos a/b,c/d] [--timeout 4h] [--idle 30m] [--disk 20G] [--cpu N --memory M] [--env-project NAME]` | `{"job_id", "job"}`; returns once the sandbox runs and the worker has started |
| `yard status [ID]` | `{"job"}` or `{"jobs": [...]}` |
| `yard logs ID [--follow]` | `{"job_id", "log"}` (claude stream-json); `--follow` streams raw text until the job ends |
| `yard events [--since CURSOR] [--limit N] [--job ID]` | `{"events": [...], "cursor", "more"}`; pass `cursor` back as `--since` |
| `yard kill ID` | `{"job", "changed"}` |
| `yard approvals` | `{"approvals": [{"proposal": "<job>:<chunk>", ...}]}` |
| `yard approve\|reject PROPOSAL [--reason TEXT]` | `{"proposal", "approved"}` |
| `yard doctor` | `{"checks": [...], "all_green"}` |
| `yard selftest --repo O/R [--read-repo O/R2] [--quick]` | `{"checks": [...], "passed", "report_path"}` |
| `yard secrets set NAME [--project P]` (value on stdin) / `yard secrets list` | never echoes values |
| `yard version` | `{"cli": "1"}` |

Spec files may carry front matter (`repo`, `branch`, `egress`, `read_repos`,
`timeout`, `idle`, `disk`, `cpu`, `memory`, `env_project`, `job_id`); flags win.

## Events

`{"seq", "ts", "job", "type", "data"}`, append-only, `seq` strictly increasing.

| type | data |
|---|---|
| `job.created` | repo, title, egress, branch, read_repos, limits |
| `job.running` | sandbox, image, quota, prover results, default_branch |
| `job.status` | status, note, attn (from the worker; **untrusted text**) |
| `job.attention` | note, source (`worker` or `yard`) |
| `approval.pending` / `approval.auto` / `approval.decided` | proposal, rule, why / approved, reason |
| `job.finished` / `job.failed` / `job.killed` | reason, exit_code, pr_url, revoked_tokens, errors, last_status |
| `job.cleanup` | orphan sandbox deleted |
| `host.warning` | error, where |

Worker status values: `queued, working, blocked, needs-review, done, failed`
(anything else is recorded as `invalid`).
