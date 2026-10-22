
# agent-yard v1: OpenShell sandbox host for HQ's cloud workers

## Goal
Build **agent-yard**: the infrastructure that runs HQ's cloud jobs on a single Hetzner host
Alex owns, with each job in its own ephemeral NVIDIA OpenShell sandbox, kernel-enforced
filesystem/process confinement, policy-controlled egress, and credentials the agent never
holds (except the Claude token, see below). It exposes one stable CLI (`yard`) that HQ will
call from Alex's laptop over Tailscale. v1 is done when the repo can take a fresh Debian 13
box to a working yard, run a job end to end, and prove its security guarantees with a
self-test suite Alex runs on the live host.

## Context

### Decisions already made with Alex (2026-10-21 grill session; do not re-litigate, ask HQ)
- **Role:** backend for agent-hq, not a replacement. HQ keeps specs, ledger, routing.
  agent-yard owns hosts, sandboxes, policies, credentials, job lifecycle.
- **Compute:** ONE fixed host (option C). No autoscaling in v1. Concurrency cap 5 jobs.
  Target ~8 vCPU / 16-32 GB amd64. Code must not assume a single host forever (host is a
  config entry), but do not build multi-host.
- **Host OS / runtime:** Debian 13, **rootless Podman 5.x** as the OpenShell compute
  driver. The gateway runs as a different unprivileged user from the Podman user that owns
  sandboxes, so a container escape does not land on the gateway's secrets. Docker is the
  documented fallback only if rootless Podman fails a hard requirement; report it, don't
  silently switch.
- **Jobs are ephemeral:** one sandbox per job, created at dispatch, deleted at the end
  (`--no-keep` semantics). Repo cloned fresh inside the sandbox; unpushed work does not exist.
- **Dev env:** per-project Dockerfile at `.openshell/Dockerfile` in the target repo (fall
  back to `.devcontainer/Dockerfile`, then to the base image), `FROM` a shared base image
  this repo builds (Debian, claude CLI, git, gh, curl, jq, common build tools). Built on
  the host, cached by content hash. Services (e.g. Postgres) start from the image
  entrypoint inside the sandbox.
- **Claude auth:** Alex's Max subscription via `claude setup-token`. The token is set as
  `CLAUDE_CODE_OAUTH_TOKEN` in the sandbox env (Alex chose the documented env-var path over
  proxy injection on purpose). Images must not contain `ANTHROPIC_API_KEY` or
  `ANTHROPIC_AUTH_TOKEN` (they outrank the OAuth token), and workers must never run with
  `--bare` (it ignores the token). The token cannot use Remote Control, so workers cannot
  `SendMessage` HQ; reporting goes through yard (below).
- **GitHub:** a private GitHub App on Alex's account. Per job, yard mints installation
  tokens: write (contents, pull requests) on the target repo only; read-only on repos listed
  in the job's `read_repos` (empty by default). Tokens are injected by OpenShell providers;
  the agent sees placeholders. Revoke tokens at job end.
- **No push to main / no merge:** enforced by GitHub, not by prompts. `yard run` refuses a
  target repo whose default branch lacks a branch protection rule or ruleset that blocks
  direct pushes. The network policy also denies the PR merge endpoint.
- **Egress:** open internet by default; `--egress deny` switches to an allowlist
  (Anthropic, GitHub, plus the project's registries). Credentialed endpoints are scoped per
  binary in both modes. In deny mode the policy advisor is ON: prover-clean proposals
  auto-approve; flagged proposals wait for Alex (surfaced as an attention event, approved
  with `yard approve`).
- **Project secrets** (.env-style values): OpenShell providers, stored in the gateway per
  project, injected only into requests to that service's hosts. Ship provider profiles
  for the services in Alex's current projects as examples (at least OpenRouter and
  TypeSafe `api.typesafe.ai`); document how to add one.
- **Limits per job:** wall-clock timeout (default 4h, per-job override), idle kill (no
  agent output for 30 min), disk quota (default 20 GB). No CPU/memory caps by default
  (Alex's choice); support `--cpu/--memory` as optional per-job flags.
- **Access:** host has no public inbound ports (Hetzner firewall denies all inbound;
  admin and HQ traffic only over Tailscale). OpenShell telemetry off.

### Interfaces
- **CLI contract (HQ depends on this; keep it stable and machine-readable with `--json`):**
  - `yard run --repo owner/name [--branch B] --spec FILE [--job-id ID] [--egress open|deny]
    [--read-repos a/b,c/d] [--timeout 4h] [--cpu N --memory M] [--env-project NAME]` →
    prints job id, returns once the sandbox is running.
  - `yard status [ID]`, `yard logs ID [--follow]`, `yard events [--since CURSOR]`,
    `yard kill ID`, `yard approvals`, `yard approve|reject PROPOSAL [--reason]`,
    `yard doctor`, `yard selftest`.
  - The CLI runs on the laptop and talks to the host over Tailscale (SSH or a small
    authenticated API on the tailnet address; your call, justify it in docs/DESIGN.md).
- **Worker reporting without a network hole:** the worker inside the sandbox writes status
  to a file (e.g. `/sandbox/.yard/status.jsonl`, same fields as `hq report`: status, note,
  attn). A host-side daemon polls it via OpenShell exec, plus sandbox lifecycle state,
  and appends to a durable event log on the host. `yard events` serves it with a cursor so
  HQ can catch up after the laptop was closed. Do not open a sandbox→host network path
  for reporting.
- **Worker prompt:** the sandbox's main process is `claude -p` (headless, unmodified
  binary) with the job spec as prompt, instructed to open a PR and write status lines.
  Do not use `--bare`.

### Provisioning
- `infra/`: OpenTofu with the `hcloud` provider for the server, firewall and SSH key
  (server type, location as variables; do not hard-code a price-dependent type). Hetzner
  repriced in June 2026 and some lines are unavailable; Alex picks the type at apply time.
- `host/bootstrap`: idempotent, works on ANY Debian 13 box reachable over SSH (so a Hetzner
  dedicated server also works). Installs Tailscale, Podman, OpenShell (pinned stable
  0.1.x release, checksum-verified), creates the users, gateway config, systemd units.
- **No secrets in cloud-init user-data** (Hetzner's metadata service serves it). Secrets
  (Claude token, GitHub App key, project secrets, Tailscale key) are pushed after boot
  over SSH/Tailscale by `yard secrets set ...` into files readable only by the gateway user.

### OpenShell facts (verified from NVIDIA/OpenShell main @ d223943, 2026-10-21)
- Gateway + per-sandbox supervisor (trusted) + sandbox (untrusted). Landlock (filesystem,
  fixed at start), seccomp, non-root, no capabilities. Workload container has
  `network=none`; all TCP/DNS goes through the supervisor and the policy. Loopback and
  link-local are always blocked (covers Hetzner metadata 169.254.169.254).
- Network rules: per host/port, per binary, HTTP method/path; hot-reloadable. Providers
  inject credentials only toward approved endpoints. Policy advisor + `openshell-prover`.
- `openshell sandbox create --from IMG --no-keep --detach -- CMD`; `sandbox exec`,
  `upload`, `download`; `--driver-config-json` for Podman mounts/limits.
- Reference provider profiles: `providers/claude-code.yaml`, `providers/github.yaml` in the
  OpenShell repo. The claude-code profile expects an API key; we do not use it for auth.
- Docs: https://docs.nvidia.com/openshell/latest/ (read them; don't trust this summary).

### Known risks: spike these first, before building on them
1. OpenShell gateway + rootless Podman driver on Debian 13 (Podman 5.x) passes its
   Landlock/seccomp qualification.
2. Two GitHub tokens (write on target, read on others) injected correctly by path on the
   same hosts (`github.com`, `api.github.com`). **Fallback if not possible:** host clones
   `read_repos` and uploads them read-only into the sandbox; only the write token is
   injected.
3. Per-sandbox disk quota under rootless Podman (overlay `size=` needs xfs pquota).
   If it can't be enforced, stop and report options; do not ship an advisory quota.
4. Revocation path for a `setup-token` token (Alex needs it for monthly rotation).
   Document what exists; if nothing does, say so plainly.

### Things only Alex can do (list them in README "Before you start")
Hetzner account + API token; Tailscale tailnet + auth key; create the GitHub App
(the repo provides a manifest and step-by-step instructions) and install it on the target
repos; run `claude setup-token`; add branch protection on target repos.

## Acceptance criteria
Verifiable by the worker (in the cloud session):
- [ ] Repo `rchnbch/agent-yard` with README (what/why, before-you-start checklist, quick
      start), `docs/DESIGN.md` (architecture, trust boundaries, each decision above and
      why), `docs/THREAT-MODEL.md` (what each guarantee covers and does NOT cover,
      including: Claude token readable by the agent and exfiltratable under open egress;
      shared kernel between jobs; host holds all other secrets).
- [ ] `yard` CLI implementing the contract above with `--json`; unit tests for spec
      parsing, policy rendering, event log/cursor, limits; one test command (`make test`)
      that passes.
- [ ] Policy templates `open` and `deny` rendered per job; `openshell-prover` runs in CI
      against a boundary file and proves for both: GitHub credentials reach only GitHub
      hosts, the merge endpoint is denied, no credential reaches a non-approved host.
- [ ] `tofu validate` and `shellcheck` pass in CI (GitHub Actions), plus `make test`.
- [ ] Base image Dockerfile builds in CI.
- [ ] If the cloud session can run Podman or Docker with OpenShell: a local end-to-end run
      of a trivial job. If it can't, say so in the report; do not claim it.

Verified by Alex on the live host (the worker ships the tooling and a checklist):
- [ ] `host/bootstrap` takes a fresh Debian 13 box to `yard doctor` all green.
- [ ] `yard run` on a test repo produces a PR; the job appears in `yard events`.
- [ ] `yard selftest` runs an adversarial job that tries, and must FAIL, to: read the
      GitHub token or a project secret from env/files; push to `main`; merge its PR; write
      to a `read_repos` repo; read another running sandbox's files; reach
      169.254.169.254; in deny mode, reach a non-allowlisted host. Each attempt is
      reported pass/fail with evidence. Plus positive checks: claude can reach
      api.anthropic.com, the PR opens.
- [ ] Timeout, idle kill and disk quota each demonstrably kill or block a job in selftest.

## Out of scope
- Autoscaling, multi-host, Kubernetes, MicroVM driver.
- The agent-hq side (`hq dispatch --where yard`); a follow-up HQ job builds it on the
  CLI contract.
- Telegram/phone notifications for approvals (follow-up; comms-bridge from j006).
- Persistent per-agent dev environments; GPU; Codex or other engines.
- Usage-spike canary for the Claude token (open question for a follow-up).
- Provisioning real infra or spending money from the cloud session; never put real
  secrets in the repo.

