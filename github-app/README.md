# The agent-yard GitHub App (Alex does this once)

yard never uses a personal token. A private GitHub App on Alex's account mints
installation tokens per job:

| Token | Scope | Lifetime | Where it goes |
|---|---|---|---|
| prep | `administration:read`, `contents:read` on the target repo | revoked after job setup | host only: reads branch protection and the repo tarball (dev image) |
| write | `contents:write`, `pull_requests:write` on the target repo only | 1 h, refreshed every 40 min, revoked at job end | OpenShell provider; agent sees a placeholder |
| read | `contents:read` on the job's `read_repos` (one per installation) | same | OpenShell provider; agent sees a placeholder |

No webhooks, no events, no `workflows` permission (an agent cannot edit CI),
no `administration:write` (an agent cannot loosen branch protection).

## Steps

1. **Create the App.** Open `github-app/create-app.html` in a browser while
   logged in to GitHub, change the name if needed, submit, review, and
   confirm. (Manual alternative: Settings → Developer settings → GitHub Apps →
   New GitHub App with the permissions in `manifest.json`, webhook off, "Only
   on this account".)
2. **Note the App ID and slug** from the App's settings page. Put them in
   `/etc/agent-yard/yard.toml` on the host (`[github] app_id`, `app_slug`).
3. **Generate a private key** (App settings → Private keys) and push it to the
   host without it touching disk elsewhere:
   `yard secrets set github-app-key < ~/Downloads/agent-yard-*.private-key.pem`
   then delete the downloaded file.
4. **Install the App** on the target repos and on the repos used as
   `read_repos` (App settings → Install App → only select repositories).
5. **Protect each target repo's default branch** so direct pushes are refused:
   a ruleset (Settings → Rules → Rulesets) targeting the default branch with
   "Require a pull request before merging" (1 approval) and without the App in
   the bypass list, or classic branch protection with "Require a pull request".
   `yard run` refuses repos where this is missing and prints its evidence.
6. Run `yard doctor`; the `github-app-auth` line shows the App's permissions.

Rotate the key: generate a new one, `yard secrets set github-app-key`, delete
the old key in the App settings.
