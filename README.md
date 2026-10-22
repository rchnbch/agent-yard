# agent-yard

OpenShell sandbox host for HQ's cloud workers: every HQ job runs in its own
ephemeral [NVIDIA OpenShell](https://docs.nvidia.com/openshell/latest/)
sandbox on one Hetzner box Alex owns, with kernel-enforced filesystem and
process confinement, policy-controlled egress, and GitHub/project credentials
the agent never holds. HQ drives it with one stable CLI, `yard`, over
Tailscale.

**Why:** HQ's workers need to clone, build, test and open PRs with real
credentials, unattended. agent-yard gives each job exactly the access it
needs (write to one repo, read a few, reach the internet or an allowlist),
proves the network policy with `openshell-prover` before the job starts,
enforces "no push to main, no merge" on GitHub's side and in the policy, and
tears everything down (tokens revoked) when the job ends.

- Contract: [docs/SPEC.md](docs/SPEC.md) · CLI: [docs/CLI.md](docs/CLI.md)
- Design and decisions: [docs/DESIGN.md](docs/DESIGN.md)
- What is and is not protected: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)
- Risk spikes and findings: [docs/SPIKES.md](docs/SPIKES.md)
- Live-host verification: [docs/LIVE-CHECKLIST.md](docs/LIVE-CHECKLIST.md)

## Before you start (only Alex can do these)

- [ ] **Hetzner Cloud** account and an API token (`HCLOUD_TOKEN`), and a
      choice of server type/location at apply time (~8 vCPU, 16-32 GB, amd64).
- [ ] **Tailscale** tailnet and a (pre-approved, preferably single-use) auth key
      for the host; the laptop on the same tailnet.
- [ ] **GitHub App**: create it from the manifest and install it on the target
      repos and any `read_repos` repos: [github-app/README.md](github-app/README.md).
- [ ] **Claude token**: run `claude setup-token` (Max subscription) and keep the
      token ready to paste once.
- [ ] **Branch protection** on every target repo's default branch: a ruleset
      (or classic protection) that requires a pull request and does not let
      the App bypass it. `yard run` refuses repos without it.
- [ ] Optional: project secrets (OpenRouter, TypeSafe keys) per project.

## Quick start

1. **Laptop:** Python ≥ 3.11 and `ssh`.
   ```sh
   git clone https://github.com/rchnbch/agent-yard && cd agent-yard
   ln -s "$PWD/bin/yard" ~/.local/bin/yard
   mkdir -p ~/.config/agent-yard
   printf '[hosts.yard1]\nssh = "yard@yard1"\n' > ~/.config/agent-yard/config.toml
   ```
2. **Server** (or skip and use any Debian 13 box you can SSH to):
   ```sh
   cd infra && cp terraform.tfvars.example terraform.tfvars   # edit it
   export HCLOUD_TOKEN=...      # never committed
   tofu init && tofu apply      # admin_ssh_cidrs = ["<your-ip>/32"] for now
   ```
3. **Bootstrap** (idempotent; Tailscale key on stdin, never in cloud-init):
   ```sh
   rsync -a --delete --exclude .git ./ root@<ipv4>:/opt/agent-yard/
   ssh root@<ipv4> YARD_STORAGE_DEVICE=<tofu output store_device> \
     /opt/agent-yard/host/bootstrap --tailscale-authkey-stdin < tskey.txt
   ```
   Then set `admin_ssh_cidrs = []` and `tofu apply` again: no inbound ports.
4. **Configure** `/etc/agent-yard/yard.toml` on the host (`[github] app_id`,
   `app_slug`; projects and their services).
5. **Secrets** from the laptop, over Tailscale:
   ```sh
   yard secrets set claude-oauth-token            # paste; input hidden
   yard secrets set github-app-key < app.private-key.pem
   yard secrets set --project myproj OPENROUTER_API_KEY
   ```
6. **Check and prove:**
   ```sh
   yard doctor                                   # everything ok
   yard selftest --repo rchnbch/yard-test --read-repo rchnbch/yard-test-lib
   ```
7. **Run a job:**
   ```sh
   yard --json run --repo rchnbch/yard-test --spec examples/hello-spec.md
   yard events --since c0          # job.running ... job.status ... job.finished
   yard logs <job-id> --follow
   ```

## Repository map

| Path | What |
|---|---|
| `yard/` | the CLI and host code (stdlib-only Python) |
| `policies/boundaries/` | operator-owned prover boundaries + their generator |
| `providers/services.toml` | project-secret services (OpenRouter, TypeSafe, selftest canary); how to add one is in the file |
| `images/base/` | shared base image: Debian, Claude Code, git, gh, curl, jq, build tools |
| `host/` | bootstrap, systemd units, quota helper, nftables, sudoers, config template |
| `infra/` | OpenTofu: server, deny-all firewall, SSH key, volume |
| `github-app/` | App manifest and setup steps |
| `selftest/probe.sh` | the adversarial probe run inside selftest sandboxes |
| `tests/` | `make test` unit tests (incl. prover proofs), local e2e harness |

## Development

```sh
make test          # unit tests; prover proofs run when openshell-prover is on PATH
make shellcheck
make tofu-validate
make e2e           # local end-to-end against a running OpenShell gateway (see tests/e2e)
```

CI (GitHub Actions) runs `make test` with the pinned `openshell-prover`,
shellcheck, `tofu validate`, and the base image build.
