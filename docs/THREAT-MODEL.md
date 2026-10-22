# agent-yard threat model (v1)

**Adversary:** the agent inside a job sandbox: a model following a hostile
spec, a prompt injection from a dependency, README or web page, or a
compromised tool in the dev image. It has arbitrary code execution as uid
1000 inside its sandbox for up to the job's wall clock.

**Assets:** GitHub write access (the target repo's default branch and other
repos), project secrets, the Claude subscription token, the host and its
other secrets, other jobs' work, Alex's tailnet and laptop.

Each guarantee below says what enforces it, what it covers, and what it does
**not** cover. "Proved" means openshell-prover checks it in CI and on every
`yard run`; "selftest" means `yard selftest` attacks it on the live host.

## Guarantees

### G1. The agent cannot read the GitHub tokens or project secrets
- *Enforced by:* OpenShell providers. The sandbox env holds
  `openshell:resolve:env:...` placeholders; the supervisor substitutes the
  real value in outbound requests (verified in SPIKES: placeholders only,
  `credential_endpoint_mismatch` elsewhere). Real values live in the gateway's
  encrypted store and the gateway user's 0600 files. Selftest:
  `read-github-token`, `read-project-secret`, host-side hash cross-check.
- *Does not cover:* use of the credential **through** its bound endpoint.
  Any binary in the sandbox can make authenticated requests to GitHub for
  the target repo with the write token's permissions (contents and pull
  requests), and read the read_repos. That is the job's purpose. A
  compromised agent can push arbitrary branches, open and comment on PRs,
  delete non-protected branches of the target repo, and read
  everything the read token can read.

### G2. Credentials reach only their approved hosts
- *Enforced by:* static credential endpoint binding (profile endpoints:
  github.com `/{o}/{r}.git/**`, api.github.com `/repos/{o}/{r}/**`, service
  hosts). **Proved:** each credential surface ⊆ its credential boundary;
  mutants that bind a token to another host fail the proof. Selftest:
  `exfil-github-token-elsewhere`, `exfil-project-secret-elsewhere`.
- *Does not cover:* the **Claude token** (G7); data the agent fetched with
  a credential and then sends elsewhere under open egress (it can read the
  target repo and read_repos, then upload their contents to any public host;
  deny mode limits this to the allowlist); placeholder strings themselves
  (worthless outside the sandbox).

### G3. No push to the default branch, no merge
- *Enforced by:* GitHub: `yard run` refuses a target repo whose default
  branch lacks an active ruleset or classic protection that blocks the App's
  direct pushes. Network policy: every template denies `PUT /**` on
  api.github.com (the merge endpoint is `PUT /repos/{o}/{r}/pulls/{n}/merge`)
  and `POST /repos/{o}/{r}/merges`, for every binary; GraphQL never receives
  a credential, so `mergePullRequest` and auto-merge are unauthenticated.
  **Proved** (and a merge-allowing mutant fails). Selftest:
  `push-default-branch`, `merge-pr-gh`, `merge-pr-curl`, `merge-pr-graphql`,
  host-side `default-branch-unchanged` and `pr-not-merged`.
- *Does not cover:* a human merging a bad PR; branch protection that Alex
  later weakens (yard checks at job start, not continuously); other
  protected-branch bypasses granted to the App (keep the App out of bypass
  lists; `yard run` refuses when the ruleset says the App can bypass).

### G4. read_repos are read-only
- *Enforced by:* the read token is minted with `contents:read` only (GitHub
  rejects writes), and the read profile has no `git-receive-pack` rule and a
  read-only API preset. Selftest: `write-read-repo`.
- *Does not cover:* repos readable through the target repo itself (e.g.
  submodules with public URLs).

### G5. Filesystem and process confinement; jobs cannot see each other
- *Enforced by:* OpenShell: Landlock (`hard_requirement`), seccomp, non-root
  uid 1000, no capabilities, separate PID/mount/network namespaces per
  container, `network=none` workloads, private `/.openshell`. Each job has its
  own containers and workspace volume. Selftest: `read-neighbor-sandbox`.
- *Does not cover:* **a shared kernel.** All jobs and the host share one
  Linux kernel; a kernel exploit (or a Landlock/seccomp/OpenShell bug) breaks
  every boundary at once. MicroVM isolation is out of scope for v1. Jobs also
  run under the same Podman user (by default the same mapped UIDs), so an
  escape from one container to the Podman user reaches all running jobs.

### G6. A container escape does not reach the gateway's secrets
- *Enforced by:* user separation. Containers run under `yard-pod`; the
  gateway, yardd, the App key, the Claude token and job tokens belong to
  `yard` (home 0700, secrets 0600). nftables limits `yard-pod`'s network.
- *Does not cover:* **the host holds all other secrets.** An escape to root,
  or to `yard`, yields the GitHub App private key (it can mint tokens for
  every repo the App is installed on), the Claude token, all project secrets
  in the gateway store and the gateway's mTLS keys. Running workloads'
  provider credentials are also present in the supervisor containers
  (Podman secrets under `yard-pod`), so an escape to `yard-pod` yields the
  current jobs' GitHub tokens (≤ 1 h validity, scoped to their repos) and
  project secrets.

### G7. The Claude token: what is and is not protected
- *Alex's decision:* `CLAUDE_CODE_OAUTH_TOKEN` is a plain env var, not a
  provider.
- *Consequence:* **the agent can read the Claude token** (`env`,
  `/proc/self/environ`) and, **under open egress, exfiltrate it** to any
  public HTTP(S) host. In deny mode it can only send it to allowlisted hosts
  (Anthropic, GitHub, project registries) or through an approved proposal.
- *Blast radius:* the token "can only make model requests" (docs), so a
  thief gets Alex's Max-subscription usage for up to a year. **No documented
  revocation path exists** (SPIKES risk 4); rotation stops new jobs from
  using it but does not invalidate a stolen copy. A usage-spike canary is a
  follow-up (out of scope).
- *Mitigations in v1:* deny mode for untrusted specs; never print the token
  in yard logs or events; images may not set competing auth vars.

### G8. No reachable cloud metadata, tailnet or host services
- *Enforced by:* OpenShell always blocks loopback and link-local
  (169.254.169.254); every endpoint's `allowed_ips` excludes 10/8, 100.64/10
  (tailnet) and multicast; host nftables drops `yard-pod` traffic to all
  private ranges, `tailscale0`, the host's own addresses and loopback except
  the gateway port and DNS. Selftest: `reach-metadata`.
- *Does not cover:* public services reachable on the internet.

### G9. Deny mode blocks non-allowlisted hosts
- *Enforced by:* the deny template (allowlist only; **proved**, and a mutant
  with an extra host fails), policy advisor in manual mode with yardd only
  auto-approving clean proposals for the project's registries. Selftest:
  `deny-mode-non-allowlisted` (also after 45 s, to catch an auto-approval).
- *Does not cover:* exfiltration through allowlisted hosts (e.g. writing data
  into a PR or a branch on GitHub, a package registry upload if a registry
  allows unauthenticated writes; registries are read-only in policy),
  DNS-based channels through the supervisor's resolver, and proposals Alex
  approves.

### G10. Limits: wall clock, idle, disk
- *Enforced by:* yardd kills on timeout (default 4 h) and on no agent output
  for 30 min; XFS project quota (default 20 GB) on the job's writable layer
  and volumes, applied before the worker starts. Selftest: `limits/*`.
- *Does not cover:* CPU and memory (no caps by default, Alex's choice: one
  job can starve the others; `--cpu/--memory` exist), PIDs beyond OpenShell's
  default 2048, network bandwidth, Claude usage, and kills that happen up to
  one poll interval (15 s) late. If yardd is down, limits are not enforced
  until it restarts.

### G11. Reporting is untrusted
Worker status lines (and therefore events, PR URLs, attention notes) are
written by the agent. yard strips control characters and caps lengths, and
only accepts PR URLs for the job's own repo, but **HQ must treat event text
as untrusted input** (it can contain prompt injection aimed at HQ).

## Out of scope / accepted for v1

- Supply chain of the base image (Debian, Claude Code binary verified against
  Anthropic's manifest, OpenShell checksum-pinned) and of project Dockerfiles:
  **project images build on the host as `yard-pod` with network access and
  without OpenShell confinement.** A malicious Dockerfile in a target repo
  runs code there (bounded by `yard-pod`'s rights and nftables).
- Alex's laptop and SSH keys: whoever can SSH to `yard@host` controls yard.
- Denial of service by a job against the host or other jobs.
