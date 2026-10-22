# agent-yard design (v1)

agent-yard runs HQ's cloud jobs on one host Alex owns. Each job gets its own
ephemeral NVIDIA OpenShell sandbox, kernel-enforced confinement,
policy-controlled egress and credentials the agent never holds (except the
Claude token). HQ drives it through one CLI, `yard`. The contract is
[SPEC.md](SPEC.md); the spikes behind the choices below are in
[SPIKES.md](SPIKES.md); guarantees and their limits are in
[THREAT-MODEL.md](THREAT-MODEL.md).

## Architecture

```
laptop (HQ)                         yard host (Debian 13, Hetzner, no public inbound)
-----------                         ----------------------------------------------------
yard CLI ──ssh over Tailscale──▶ user `yard` (gateway user)
                                   ├─ yard --local <cmd>        (yard/host.py)
                                   ├─ yardd (system unit)       (yard/daemon.py, every 15 s)
                                   ├─ openshell-gateway (user unit, 127.0.0.1:17670, TLS)
                                   │     └─ Podman driver ──▶ /run/agent-yard/podman/podman.sock
                                   ├─ secrets: ~/state, /var/lib/agent-yard/secrets (0700)
                                   └─ sudo: yard-quota only
                                 user `yard-pod` (rootless Podman 5, owns all containers)
                                   └─ per job: workload container (network=none, Landlock,
                                      seccomp, uid 1000, no caps) + supervisor container
                                      (host network, policy proxy, provider credentials)
                                 XFS store /var/lib/agent-yard/containers (prjquota)
                                 nftables table inet agent_yard (egress fence for yard-pod)
GitHub ◀── installation tokens (minted/revoked per job by yard, via the App)
```

### Job lifecycle (`yard run` → yardd)

1. Parse the spec (Markdown; optional front matter; flags win), check the
   concurrency cap (5).
2. Host-only **prep token** (target repo, `administration:read` +
   `contents:read`): canonical name, default branch, **branch-protection
   gate** (an active ruleset with a `pull_request` or `update` rule the App
   cannot bypass, or classic protection requiring PRs without an App bypass;
   otherwise refuse and print the evidence), repo tarball for the dev image.
   Revoked before step 3.
3. **Dev image**: `.openshell/Dockerfile`, else `.devcontainer/Dockerfile`,
   else the base image. Tag = SHA-256 of the build context + base image ID, so
   builds are cached by content. The image must carry the base label, a
   non-root user, and no `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` /
   `CLAUDE_CODE_OAUTH_TOKEN` in its env.
4. **Job tokens**: write (target only) and read (read_repos, one per App
   installation). Stored only in the gateway user's secrets dir.
5. **Policy**: render the sandbox policy (open or deny template) and per-job
   provider profiles, then run the prover checks (below). Any result other
   than `within_boundary` aborts the job before anything is created.
6. Import the per-job profiles, create providers (token passed via the child
   environment, never argv), create the sandbox with
   `CLAUDE_CODE_OAUTH_TOKEN` via `--env-from`, approval mode `auto` (open) or
   `manual` (deny), and CPU/memory = the whole host unless `--cpu/--memory`.
7. When Ready: upload `.yard/` (prompt, job.json), apply the disk quota, then
   signal the gated main process, which `exec`s
   `claude -p "$(cat prompt.md)" --output-format stream-json --verbose
   --permission-mode bypassPermissions` (never `--bare`). Return the job id.
8. **yardd**, every 15 s per job: one `sandbox exec` reads
   `status.jsonl` and the size of `agent.log`; new lines become `job.status`
   / `job.attention` events; log growth resets the idle clock; the wall clock
   and idle limits kill; tokens are re-minted every 40 min and swapped in
   place (`stable_placeholder`); pending policy proposals are handled.
9. **End** (main process exited, killed, or failed): harvest `.yard/` from the
   stopped container (`podman cp`), delete the sandbox, revoke all tokens at
   GitHub, delete providers and per-job profiles, release the quota, write the
   final event. Orphaned `y-*` sandboxes are deleted on every tick.

### Policies and proofs

Every endpoint is L7-inspected (`protocol: rest`, `enforcement: enforce`)
and carries the same public-IPv4 `allowed_ips` (34 CIDRs; no RFC 1918 10/8,
CGNAT/tailnet 100.64/10, loopback, link-local, multicast).

| Rule | open | deny |
|---|---|---|
| `anthropic`: api.anthropic.com, binary `/usr/local/bin/claude` | yes | yes |
| `open_egress`: `**.*.<24 TLDs>` + apex list, ports 80/443, any binary, full access | yes | no |
| `github_api_guard`: api.github.com, any binary, deny `PUT /**` and `POST /repos/{r}/merges` | yes | no |
| `registries`: project registries, any binary, read-only | no | yes |
| `_provider_<job>-ghw`: target repo paths, git/gh/curl | yes | yes |
| `_provider_<job>-ghr<n>`: read_repos paths, no receive-pack, read-only API | yes | yes |
| `_provider_proj-<p>-<svc>`: the service's hosts | if `--env-project` | same |

Checks, per job at run time and in CI for a sample job
(`yard/prove.py`, boundaries in `policies/boundaries/`):

1. composed effective policy ⊆ `network-<mode>.yaml` (no PUT on api.github.com,
   which contains the PR merge endpoint; deny mode lists only allowlisted hosts);
2. each GitHub provider's credential endpoints ⊆ `credential-github.yaml`
   (github.com + api.github.com);
3. each service provider's endpoints ⊆ its own `credential-<id>.yaml`.

The boundaries are written by `policies/boundaries/make_boundaries.py`, which
deliberately does not import yard, so a renderer bug cannot move the
boundary. CI also checks negative controls (mutants that allow the merge,
send a token to another host, or add a host in deny mode must fail).

## Decisions from the 2026-10-21 grill session, and how v1 implements them

| Decision | Implementation | Why this way |
|---|---|---|
| Backend for agent-hq, not a replacement | yard owns hosts, sandboxes, policies, credentials, job lifecycle; HQ keeps specs/ledger/routing and talks to `yard` only | keeps the CLI the single integration point |
| One fixed host, cap 5, host is a config entry | laptop config `[hosts.<name>]`; host config `max_jobs = 5`; no multi-host code | spec |
| Debian 13 + rootless Podman 5; gateway user ≠ Podman user | `yard` runs the gateway/yardd/secrets; `yard-pod` runs rootless Podman with an API socket in `/run/agent-yard/podman` (group `yard-podsock`) | an escape from a container lands on `yard-pod` or a subordinate UID, which cannot read `yard`'s home (gateway TLS/JWT keys, App key, Claude token, job tokens) |
| Docker only as a reported fallback | bootstrap fails on Podman ≠ 5.x; doctor reports; the code supports `engine = "docker"` but nothing switches automatically | spec |
| Ephemeral jobs, fresh clone | one sandbox per job, deleted at the end by yard (`--no-keep` semantics; harvest first); the worker clones inside | `--no-keep` would delete the sandbox before the final status could be read |
| Per-project Dockerfile, shared base, content-hash cache | `yard/images.py`, `images/base/Dockerfile` | spec |
| Claude via `CLAUDE_CODE_OAUTH_TOKEN` env, no `--bare`, no API-key vars | `--env-from`, image env check, prompt runs `claude -p` | Alex chose the env path; consequences in THREAT-MODEL |
| GitHub App, per-job tokens, placeholders, revoke at end | `yard/github.py`, per-job provider profiles, revocation in teardown | spec; refresh added because tokens live 1 h |
| No push to main / no merge enforced by GitHub + policy | branch-protection gate in `yard run`; `PUT /**` denied on api.github.com in every template; GraphQL never receives a credential | spec; prover limits (see below) |
| Egress open by default, `--egress deny` allowlist, per-binary credentialed endpoints | templates above; provider rules list git/gh/curl | spec |
| Advisor ON in deny mode; prover-clean auto-approve; flagged waits for Alex | gateway-wide `agent_policy_proposals_enabled=true`; deny sandboxes `manual` + yardd auto-approves only OpenShell-clean proposals whose hosts are all among the project's registries; everything else → `approval.pending` + `job.attention`, `yard approve/reject` | OpenShell's own auto mode would approve any new public host (see Disagreements) |
| Project secrets as providers per project, examples for OpenRouter and TypeSafe | `providers/services.toml`, `yard secrets set --project`, provider `proj-<p>-<svc>` | spec |
| Limits: 4 h, idle 30 min, disk 20 GB, no CPU/mem caps | `yard/limits.py`, yardd, `yard-quota` | spec; see Disagreements for the Podman default caps |
| No public inbound, Tailscale only, telemetry off | Hetzner firewall with no inbound rules; `OPENSHELL_TELEMETRY_ENABLED=false`; doctor checks listeners | spec |
| No secrets in cloud-init; push after boot | user-data is a marker file only; Tailscale key on bootstrap's stdin; `yard secrets set` over SSH | Hetzner metadata serves user-data |

### Transport: SSH over Tailscale (instead of an HTTP API)

`yard` on the laptop runs `ssh yard@<tailnet-name> yard --local <args>` with
the spec and secrets on stdin. Reasons: no new listening service and no new
auth scheme to get right; SSH keys plus Tailscale ACLs are already Alex's
access model; output and exit codes pass through unchanged, including
`logs --follow` streaming. Cost: one SSH handshake per call (~0.3 s), which
is fine for HQ's call rate. If HQ ever needs high-frequency polling, an
authenticated API on the tailnet address can wrap the same `Yard` class.

### Worker reporting without a network hole

The worker appends `{"status", "note", "attn"}` lines to
`/sandbox/.yard/status.jsonl`. yardd reads it with `openshell sandbox exec`
(gateway → supervisor channel, no sandbox→host path). Events are appended to
`/var/lib/agent-yard/state/events.jsonl` (flock + fsync, monotonic `seq`);
`yard events --since c<seq>` returns everything after the cursor and the next
cursor, so HQ catches up after the laptop was closed. Worker text is
untrusted: control characters are stripped, notes are capped, invalid lines
become `status: invalid`.

## Disagreements between the spec's summary and primary sources

1. **"Open internet" cannot be one rule.** OpenShell rejects TLD wildcards
   and gives hostless rules no DNS. Open egress = `**.*.<tld>` for 24 TLDs +
   ~14 apex hosts + OpenShell's auto-approved drafts for other apex hosts
   (first request fails, retry works). Ports 80/443, HTTP(S) only.
2. **Credentials resolve per endpoint, not per binary.** The spec's "scoped
   per binary" holds for network access, but OpenShell's roadmap states that
   static placeholder resolution is endpoint-scoped. Under the broad open
   rule any binary can use the GitHub token *at GitHub*; the guard rule
   denies the merge endpoint for every binary. Tokens still cannot leave the
   bound endpoints.
3. **"prover-clean proposals auto-approve" conflicts with deny mode.**
   OpenShell's auto mode approves new public hosts that carry no
   credential. yard narrows it: in deny mode it approves only clean proposals
   whose hosts are the project's registries (e.g. another binary that needs
   pypi.org); credentialed hosts and everything else wait for Alex. Alex can widen this later.
4. **Podman driver caps CPU/memory at 2/4 GiB by default.** yard passes the
   host's totals unless `--cpu/--memory` are set.
5. **Disk quota needs root.** See SPIKES risk 3; a root helper with a single
   sudoers rule applies XFS project quotas.
6. **GraphQL is unprovable.** openshell-prover does not model GraphQL, so no
   credential reaches `/graphql`; workers open PRs with
   `gh api -X POST repos/{o}/{r}/pulls` and push content with git.
7. **`--no-keep`** would delete the sandbox before the last status could be
   read, and `--upload` cannot be combined with a command; yard implements
   the same semantics itself (gated start, harvest, delete).
8. **The `claude-code.yaml` reference profile** expects an API key; yard does
   not use it (Claude auth is the env var).

## Docker fallback (not active)

If rootless Podman fails a hard requirement on the live host (qualification,
socket split, quota), the fallback is the Docker driver with a rootless or
userns-remapped daemon owned by a third user. Changes needed: gateway TOML
`compute_driver = "docker"`, `engine = "docker"` in yard.toml, an equivalent
quota mechanism (overlay2 `size=` needs XFS pquota and works for rootful
Docker), and the nftables UID set. This needs Alex's decision; it is not
automatic.

## Not built (out of scope for v1)

Autoscaling, multi-host, Kubernetes, MicroVM; the HQ side; phone
notifications; persistent environments; GPU; non-Claude engines; a
token-usage canary.
