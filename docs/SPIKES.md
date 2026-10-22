# Spikes: the spec's known risks, and what else surfaced

Environment for every result below: the j026 cloud session (Ubuntu 24.04
container in a Firecracker VM, kernel 6.18.44, Landlock ABI 7, **cgroups v1
hybrid**, root, Docker 29.9.1, no Podman, TLS-intercepting egress proxy).
OpenShell **v0.1.5** (stable, released 2026-10-20) from the checksum-verified
`openshell_0.1.5-1_amd64.deb`, source read at `NVIDIA/OpenShell` main
(132c582, 2026-10-22; the spec cites d223943, also present in history).

"Verified" means run here with the output quoted. "From source" means read in
OpenShell or containers/storage code, not executed. "Needs live host" means
it can only be shown on the Debian 13 box and is in
[LIVE-CHECKLIST.md](LIVE-CHECKLIST.md).

## Risk 1: gateway + rootless Podman driver on Debian 13 passes Landlock/seccomp qualification

**Status: partly verified; the Podman/Debian 13 combination needs the live host.**

- Verified (Docker driver): a gateway with `compute_driver = "docker"` started
  sandboxes that passed qualification. Sandbox log:
  `Isolation boundary enforcement confirmed backend=openshell-sandbox`; inside,
  `uid=1000`, `cat /etc/shadow: Permission denied`,
  `ls /.openshell: Permission denied`, seccomp `Seccomp: 2`.
- Not testable here: Podman is not installed, Ubuntu 24.04 ships Podman 4.9,
  and this VM is cgroups v1 (the Podman driver requires v2). I did not
  install a non-distro Podman 5 into a cgroups v1 VM: a pass there would not
  predict Debian 13 and a failure would not be informative.
- From source/docs: Debian 13 ships kernel 6.12 (Landlock ABI ≥ 3 is the
  requirement; 6.12 has ABI 6), cgroups v2 by default, and Podman 5.4. The
  Podman driver drops all capabilities, keeps the runtime-default seccomp
  profile and installs nested user-notification filters; it requires an
  active rootless socket. Nothing found that is specific to Debian.
- Stop rule: bootstrap fails closed on Podman ≠ 5.x, cgroups ≠ v2 or
  Landlock missing, and `yard doctor` reports it. If qualification fails on
  the live host, the documented fallback is Docker (DESIGN.md), which needs
  Alex's decision; yard does not switch silently.

## Risk 2: two GitHub tokens injected correctly by path on the same hosts

**Status: verified, works. No fallback needed.**

Two provider profiles bound to the same host with different `path` selectors
(`httpbin.org/anything/a/**` and `/anything/b/**`, tokens `real-secret-AAA`
and `real-secret-BBB`, echo service reflecting headers):

```
== path /anything/a with token A    "Authorization": "Bearer real-secret-AAA"   http=200
== path /anything/b with token B    "Authorization": "Bearer real-secret-BBB"   http=200
== path /anything/a with token B    {"error":"credential_endpoint_mismatch",...} http=403
== path /anything/b with token A    {"error":"credential_endpoint_mismatch",...} http=403
== basic A on a   "Authorization": "Basic eC1hY2Nlc3MtdG9rZW46cmVhbC1zZWNyZXQtQUFB"  (= x-access-token:real-secret-AAA)
== basic A on b   {"error":"credential_endpoint_mismatch",...}
== gh-style "Authorization: token <placeholder>"   "Authorization": "token real-secret-AAA"
```

So yard renders one per-job profile for the write token (target repo paths
`/{o}/{r}.git/**` on github.com, `/repos/{o}/{r}/**` on api.github.com) and
one per installation for read tokens (read_repos paths, no
`git-receive-pack`). The agent's env holds only placeholders; a credential
helper in the base image picks the right placeholder per repo path.

Also verified: **`stable_placeholder: true`** keeps one placeholder across
`provider update` (resolved `gen-one`, then `gen-two` after the update, same
placeholder string). This matters because installation tokens live 1 hour
and jobs up to 4: yardd refreshes tokens in place every 40 minutes.

## Risk 3: per-sandbox disk quota under rootless Podman

**Status: overlay `size=` cannot be enforced rootless (from source). Shipped
alternative: XFS project quotas applied by a narrow root helper. Kernel-
enforced, not advisory, but unverified here. Needs Alex's sign-off and the
live host.**

- From source (containers/storage `drivers/overlay/overlay.go`,
  `drivers/quota/projectquota_supported.go`): `--storage-opt size` requires
  `quota.NewControl`, which creates a block device node (`mknod`) and calls
  `quotactl(Q_XSETQLIM)`; both need privileges a rootless user does not
  have, so `projectQuotaSupported` stays false and the option is rejected
  ("--storage-opt is supported only for overlay over xfs with 'pquota'").
  The OpenShell Podman driver has no disk-size setting at all.
- Options considered:
  1. **XFS project quota set by root (shipped).** The Podman user's storage
     (graphroot and volumes) lives on an XFS filesystem mounted `prjquota`
     (a Hetzner volume, or a loop file). `host/libexec/yard-quota`, run via
     one sudoers rule, looks the sandbox up in Podman itself, refuses any
     directory outside the store, and puts the workload's writable layer and
     its volumes into one XFS project with a hard limit. yard applies it
     after the sandbox is up but **before the worker starts** (the main
     process waits on a go file), and `yard run` fails closed if the helper
     fails. Cost: a root-owned helper, a dedicated XFS filesystem.
  2. Per-UID user quotas with `userns=auto` (each sandbox gets distinct host
     UIDs). Also kernel-enforced, but depends on UID-range allocation and
     still needs root to set quotas. Not chosen.
  3. One filesystem for all Podman storage: caps the total, not per job. Not
     a per-job quota; rejected.
  4. Rootful Podman: would make overlay `size=` work but contradicts the
     rootless decision; rejected.
- Could not run here: this kernel reports `XFS (loop0): quota support not
  available in this kernel` when mounting with `prjquota`.
- The selftest's `limits/disk-quota-blocks` job writes 1.5 GiB into a 1 GiB
  quota and must see the write fail.

## Risk 4: revocation path for a `claude setup-token` token

**Status: no documented revocation path exists. Said plainly.**

- Official docs (code.claude.com/docs/en/authentication, read 2026-10-22):
  `claude setup-token` "generate[s] a one-year OAuth token"; it "does not
  save the token anywhere"; it "can only make model requests". Nothing about
  listing or revoking it.
- `claude setup-token` has no list/revoke options; a feature request for
  `--list`/`--revoke` (anthropics/claude-code#48373) was auto-closed as a
  duplicate of #22995 without a maintainer response.
- Community reports mention a token list on claude.ai settings; I could not
  verify that from a primary source. **Alex should check claude.ai account
  settings for a "Claude Code" entry and whether removing it revokes the
  token** (LIVE-CHECKLIST item).
- What yard supports: monthly rotation = run `claude setup-token`,
  `yard secrets set claude-oauth-token`; new jobs use the new token
  immediately. The old token stays valid until it expires (1 year) or is
  revoked by whatever mechanism Alex finds. THREAT-MODEL.md treats the token
  as exfiltratable under open egress for that reason.

## Other findings that changed the design (source disagrees with the spec summary)

1. **No literal "open internet" rule.** OpenShell rejects TLD wildcards
   (`*.com`), and hostless `allowed_ips` endpoints never get DNS
   (`DENIED github.com [reason:policy_dns_ineligible]`). Open egress is
   `**.*.<tld>` for 24 common TLDs plus a list of apex hosts (verified:
   `www.example.com 200`, `docs.python.org 200`, apex `postman-echo.com`
   blocked until listed). Other apex hosts are reached through OpenShell's
   own drafted rule for the blocked connection, auto-approved in open mode.
2. **Credentials resolve for any binary at the bound endpoint.** With a broad
   open rule, `curl` (not in the provider's binaries) got the real token
   injected at the provider host and bypassed the provider's method rules
   and deny rules: `curl POST /anything/w/x ... "Bearer real-secret-WWW"
   http=200`, including on a path the provider denied. The token still only
   went to the bound host. Fix, verified: an L7 guard rule for every binary
   on api.github.com with the merge deny rules; `curl POST` and the denied
   path then return `403 policy_denied`, reads still work. Consequence: the
   open template is fully L7-inspected (`protocol: rest`), so open egress is
   HTTP(S) only.
3. **openshell-prover limits shaped the policy.** It cannot model GraphQL
   (GitHub GraphQL is not reachable with a credential; PRs are opened over
   REST), overlapping L4 and REST endpoints ("inspection selection is not
   modeled"), numeric-looking wildcards like `**.*.*`, or exact+wildcard
   hosts on one port unless both carry identical `allowed_ips`. It caps
   candidate + boundary at 4096 IP ranges, so `allowed_ips` is a 34-CIDR
   public-IPv4 list and the host's own IPs and RFC 1918 172/192 ranges are
   dropped by host nftables instead. Multi-`*` deny paths such as
   `/repos/*/*/pulls/*/merge` made counterexample search time out; the
   merge deny is `PUT /**` on api.github.com (merge is a PUT; workers
   push content with git) plus a literal `POST /repos/{o}/{r}/merges`.
4. **Policy advisor auto-approval approves new public hosts.** OpenShell's
   `auto` mode approves any proposal without prover findings, including a
   new public host with no credential. That would defeat deny mode. Deny-mode
   sandboxes therefore use `manual` mode, and yardd auto-approves only
   proposals that OpenShell found clean AND that only reach the project's
   registries;
   everything else becomes an attention event for `yard approve`.
5. **Podman driver defaults to 2 CPU / 4 GiB** when a request sets nothing
   (`DEFAULT_CPU_QUOTA`, `DEFAULT_MEMORY_LIMIT` in the driver). To honor
   "no CPU/memory caps by default", yard passes the whole host's CPUs and
   memory unless `--cpu/--memory` are given.
6. **`sandbox create` cannot combine `--upload` with a command**, and an
   exited sandbox can no longer be exec'd into or downloaded from. yard
   starts the main process as a short wait loop, uploads `.yard/`, applies
   the quota, then signals; the loop `exec`s claude, which is then the main
   process. Final status lines are harvested with `podman cp` from the
   stopped workload container before deletion.
7. **Sandbox names are limited to 19 characters** (`MAX_ROUTABLE_NAME_LEN`);
   yard names sandboxes `y-<job-id>` or a hash for long ids.
8. **Split users need a readable gateway CA.** The Podman driver bind-mounts
   the gateway CA into supervisors from the gateway host; the Podman user
   cannot read the gateway user's home, so bootstrap publishes the (public)
   CA certificate at `/etc/agent-yard/gateway-ca.crt` and sets
   `guest_tls_ca`. Needs the live host to confirm.
9. `openshell sandbox upload` needs an `ssh` client on the host (bootstrap
   installs openssh-client).

## Local end-to-end run

`python3 tests/e2e/local_e2e.py` (Docker driver, real gateway 0.1.5, real
sandbox, real policy and per-job profiles, real prover). **Stubbed:** GitHub
App (fake tokens, protection gate answers "protected"), repo tarball, XFS
quota helper, Claude token (so the trivial job does not call claude).
Result: `RESULT: PASS`; events show placeholders only, `PUT .../merge` denied
with `policy_denied`, the write token not resolved at httpbin.org, status
lines and an attention event ingested, job finished, sandbox deleted, three
tokens passed to revoke. This does not prove the Podman driver, real GitHub
behavior or claude.
