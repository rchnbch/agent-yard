# Live-host checklist (Alex)

Things the cloud session could not verify. Each step names the command and
what "pass" looks like. Report failures with the output; several have a
documented fallback in DESIGN.md or SPIKES.md.

## 0. Before you start
Do the README "Before you start" list (Hetzner token, tailnet + auth key,
GitHub App, `claude setup-token`, branch protection on target repos).

## 1. Provision and bootstrap → `yard doctor` all green
1. `cd infra && cp terraform.tfvars.example terraform.tfvars`, pick
   `server_type`/`location`, set `admin_ssh_cidrs = ["<your-ip>/32"]`,
   `export HCLOUD_TOKEN=...`, `tofu init && tofu apply`.
2. `rsync -a --delete --exclude .git ./ root@<ipv4>:/opt/agent-yard/`
3. `ssh root@<ipv4> YARD_STORAGE_DEVICE=<store_device output> /opt/agent-yard/host/bootstrap --tailscale-authkey-stdin < tskey.txt`
4. Set `admin_ssh_cidrs = []`, `tofu apply` (no inbound left). From now on use
   the Tailscale name.
5. Edit `/etc/agent-yard/yard.toml` (`[github] app_id`, `app_slug`).
6. From the laptop: `yard secrets set claude-oauth-token` (paste),
   `yard secrets set github-app-key < key.pem`.
7. `yard doctor` → every line `ok`. Pay attention to:
   - `podman-rootless-5`, `landlock-lsm`, `cgroup-v2`
   - `disk-quota` (XFS prjquota mounted and enforcing)
   - `gateway-connected`, `telemetry-off`, `nftables-sandbox-egress`
   - `no-public-listeners`

## 2. Risk 1: qualification under rootless Podman
`yard selftest --quick --repo <test-repo>` creates sandboxes. If they fail to
start, `journalctl --user -M yard@ -u openshell-gateway` and
`openshell logs <sandbox>` show the denied primitive. Do **not** add
capabilities or disable seccomp; report it (Docker fallback is a decision).
Also confirm the supervisor reaches the gateway with the split users (the CA
copy at `/etc/agent-yard/gateway-ca.crt`, SPIKES item 8).

## 3. Selftest (adversarial)
`yard selftest --repo <owner>/<test-repo> --read-repo <owner>/<other-test-repo>`
(both repos have the App installed; the first has a protected default branch).
Expect every line `PASS`; the JSON report path is printed. It covers: reading
the GitHub token / project secret from env and files, placeholder exfil to
another host, push to the default branch, merging the PR (gh, curl, GraphQL),
writing to the read repo, a neighbor sandbox's canary file, 169.254.169.254,
deny-mode non-allowlisted host (also after 45 s), claude reaching
api.anthropic.com, the PR opening, the default branch SHA unchanged, the PR
unmerged; plus `limits/timeout-kills`, `limits/idle-kills`,
`limits/disk-quota-blocks`. Takes ~15 minutes.

Things to look at by hand once:
- `sudo nft list table inet agent_yard` shows the Podman user's UID and
  subordinate range. If supervisors run under a UID outside that set (check
  `ps -o uid,cmd -C openshell-supervisor`), the fence does not apply: report it.
- `sudo xfs_quota -x -c 'report -p -h' /var/lib/agent-yard/containers` during
  a job shows its project with the limit.

## 4. A real job → PR + events
`yard run --repo <owner>/<test-repo> --spec examples/hello-spec.md`
then `yard events --since c0` until `job.finished`; the PR URL is in the last
`job.status` and in `yard status <id>`.

## 5. Claude token revocation (SPIKES risk 4)
Check claude.ai account settings for a list of authorized Claude Code tokens
and whether removing one invalidates it (`curl` with the old token after
removal). Write the answer into docs/SPIKES.md.
