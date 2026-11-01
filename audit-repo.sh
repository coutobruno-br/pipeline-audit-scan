#!/usr/bin/env bash
# Pipeline Audit Kit — audit-repo.sh
#
# Scans one repository for CI/CD findings and prints them with the check IDs
# used in the guide, the checklist and the scorecard.
#
#   audit-repo.sh [path] [--warn-only] [--no-color]
#
# Exit codes: 0 no FAIL findings (or --warn-only), 1 FAIL findings, 2 usage error.
# Requires: bash 3.2+, grep, sed, awk, find. Works on Linux and macOS.

set -euo pipefail

VERSION="1.0.1"
REPO="."
WARN_ONLY=0
COLOR=1
[ -t 1 ] || COLOR=0

usage() {
  cat <<'EOF'
Usage: audit-repo.sh [path] [--warn-only] [--no-color]

Scans a repository for CI/CD findings: unpinned actions (SEC-01), token
permissions (SEC-02), static cloud keys (SEC-03), scanners (SEC-04), dangerous
triggers and script injection (SEC-06), reproducible builds (SRC-02), feedback
speed (SRC-03), reusable workflows (SRC-06), direct cluster changes from CI
(DEP-01), committed secrets (DEP-06) and code ownership (FLO-03).

Options:
  --warn-only   Always exit 0 (report only).
  --no-color    Plain output.
  -h, --help    Show this help.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --warn-only) WARN_ONLY=1 ;;
    --no-color) COLOR=0 ;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) REPO="$1" ;;
  esac
  shift
done

[ -d "$REPO" ] || { echo "not a directory: $REPO" >&2; exit 2; }
cd "$REPO"

if [ "$COLOR" = 1 ]; then
  RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; DIM=$'\033[2m'; BLD=$'\033[1m'; RST=$'\033[0m'
else
  RED=""; YEL=""; GRN=""; DIM=""; BLD=""; RST=""
fi

# Counters live in files: several checks run inside pipelines (subshells).
fail() { echo x >>"$TMP/n_fail"; printf '%s[FAIL]%s %-7s %s\n' "$RED" "$RST" "$1" "$2"; }
warn() { echo x >>"$TMP/n_warn"; printf '%s[WARN]%s %-7s %s\n' "$YEL" "$RST" "$1" "$2"; }
pass() { echo x >>"$TMP/n_pass"; printf '%s[PASS]%s %-7s %s\n' "$GRN" "$RST" "$1" "$2"; }
count() { if [ -f "$TMP/$1" ]; then wc -l <"$TMP/$1" | tr -d ' '; else echo 0; fi; }
section() { printf '\n%s%s%s\n' "$BLD" "$1" "$RST"; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Files to inspect. Prefer git's view of the repo (tracked files only).
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git ls-files >"$TMP/files"
else
  find . -type f -not -path './.git/*' -not -path '*/node_modules/*' -not -path '*/vendor/*' \
    | sed 's#^\./##' >"$TMP/files"
fi

grep -E '^\.github/workflows/[^/]+\.ya?ml$' "$TMP/files" | sort >"$TMP/wf" || true
WF_COUNT=$(wc -l <"$TMP/wf" | tr -d ' ')

printf '%sPipeline Audit Kit%s audit-repo.sh v%s  %s%s%s\n' "$BLD" "$RST" "$VERSION" "$DIM" "$(pwd)" "$RST"
printf '%s%s workflow file(s) found%s\n' "$DIM" "$WF_COUNT" "$RST"
[ "$WF_COUNT" -gt 0 ] || warn CI "no GitHub Actions workflows in .github/workflows; workflow checks skipped"

# grep across all workflow files, safe for any file name.
wfgrep() { tr '\n' '\0' <"$TMP/wf" | xargs -0 grep "$@" 2>/dev/null; }

# Print the trigger names of a workflow (the keys directly under "on:").
triggers() {
  awk '
    /^on:[[:space:]]*\[/ { gsub(/^on:[[:space:]]*\[|\][[:space:]]*$|[[:space:]]/, ""); n = split($0, t, ","); for (i = 1; i <= n; i++) print t[i]; exit }
    /^on:[[:space:]]*[A-Za-z_]/ { sub(/^on:[[:space:]]*/, ""); sub(/[[:space:]#].*$/, ""); print; exit }
    /^on:[[:space:]]*(#.*)?$/ { inon = 1; next }
    inon && /^[^[:space:]#]/ { exit }
    inon && /^[[:space:]]+[A-Za-z_]+:/ {
      match($0, /^[[:space:]]+/); ind = RLENGTH
      if (base == 0) base = ind
      if (ind == base) { k = $0; sub(/^[[:space:]]+/, "", k); sub(/:.*$/, "", k); print k }
    }
  ' "$1"
}

# Strip a trailing YAML comment and surrounding quotes from a value.
clean() { sed -e 's/[[:space:]]#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e "s/^[\"']//" -e "s/[\"']\$//"; }

# Print "<line> run" or "<line> script" for every line of a workflow that is code:
# a run: or script: line, and every line of its block scalar (run: | ... / script: |).
# Values under with:, env: and other keys are data, not code.
codelines() {
  awk '
    { match($0, /^[[:space:]]*/); ind = RLENGTH }
    inblk && $0 !~ /^[[:space:]]*$/ && ind <= keycol { inblk = 0 }
    inblk { print NR, kind; next }
    /^[[:space:]]*(-[[:space:]]+)?(run|script):/ {
      match($0, /^[[:space:]]*(-[[:space:]]+)?/); keycol = RLENGTH
      kind = ($0 ~ /^[[:space:]]*(-[[:space:]]+)?run:/) ? "run" : "script"
      print NR, kind
      if ($0 ~ /:[[:space:]]*[|>][-+0-9]*[[:space:]]*(#.*)?$/) inblk = 1
    }
  ' "$1"
}

# ---------------------------------------------------------------------------
section "Supply chain and secrets"

# SEC-01: every remote action and reusable workflow pinned to a 40-char commit SHA.
pinned=0
while IFS= read -r f; do
  grep -nE '^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*' "$f" 2>/dev/null | while IFS= read -r hit; do
    line=${hit%%:*}
    value=$(printf '%s' "${hit#*:}" | sed -E 's/^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*//' | clean)
    case "$value" in
      ./* | docker://*) continue ;;
    esac
    case "$value" in
      *@*) ref=${value##*@} ;;
      *) ref="" ;;
    esac
    if printf '%s' "$ref" | grep -qE '^[0-9a-f]{40}$'; then
      echo x >>"$TMP/pinned"
    else
      echo "$f:$line $value" >>"$TMP/unpinned"
    fi
  done || true
done <"$TMP/wf"
[ -f "$TMP/pinned" ] && pinned=$(wc -l <"$TMP/pinned" | tr -d ' ')
if [ -f "$TMP/unpinned" ]; then
  while IFS= read -r u; do
    fail SEC-01 "${u%% *}: not pinned to a commit SHA: ${u#* }"
  done <"$TMP/unpinned"
elif [ "$WF_COUNT" -gt 0 ]; then
  pass SEC-01 "all $pinned remote action reference(s) pinned to a commit SHA"
fi

# SEC-02: least-privilege GITHUB_TOKEN.
while IFS= read -r f; do
  if [ "$(triggers "$f" | tr '\n' ' ')" = "workflow_call " ]; then
    pass SEC-02 "$f: reusable workflow, inherits the caller's permissions"
    continue
  fi
  if grep -qE 'permissions:[[:space:]]*write-all' "$f"; then
    fail SEC-02 "$f: permissions: write-all"
  elif grep -qE '^permissions:' "$f"; then
    pass SEC-02 "$f: top-level permissions declared"
  elif grep -qE '^[[:space:]]+permissions:' "$f"; then
    warn SEC-02 "$f: permissions only at job level; add a read-only top-level default"
  else
    fail SEC-02 "$f: no permissions block; the token gets the organization default"
  fi
done <"$TMP/wf"

# SEC-03: no long-lived cloud credentials in CI.
static=0
while IFS= read -r f; do
  if grep -nE 'AWS_SECRET_ACCESS_KEY|aws-secret-access-key|GCP_SA_KEY|GOOGLE_CREDENTIALS|credentials_json|AZURE_CLIENT_SECRET|ARM_CLIENT_SECRET' "$f" >"$TMP/keys" 2>/dev/null; then
    while IFS= read -r k; do
      text=${k#*:}
      # A value read from another step or env (e.g. the short-lived session that an
      # OIDC login step outputs) is not a stored key; only secrets and literals are.
      # shellcheck disable=SC2016 # literal GitHub expression syntax, not a shell variable
      if printf '%s' "$text" | grep -q '\${{' && ! printf '%s' "$text" | grep -q 'secrets\.'; then
        continue
      fi
      static=1
      fail SEC-03 "$f:${k%%:*}: static cloud credential; use OIDC federation"
    done <"$TMP/keys"
  fi
done <"$TMP/wf"
if [ "$static" = 0 ] && [ "$WF_COUNT" -gt 0 ]; then
  if wfgrep -qE 'id-token:[[:space:]]*write'; then
    pass SEC-03 "no static cloud keys referenced; OIDC (id-token: write) in use"
  else
    pass SEC-03 "no static cloud keys referenced in workflows"
  fi
fi

# SEC-04: a scanner that can fail the build, and automated dependency updates.
if [ "$WF_COUNT" -gt 0 ]; then
  wfgrep -lE 'trivy|grype|snyk|codeql-action|dependency-review-action|osv-scanner' >"$TMP/scanners" || true
  if [ ! -s "$TMP/scanners" ]; then
    fail SEC-04 "no dependency or image scanner found in workflows"
  else
    while IFS= read -r s; do
      if grep -q 'trivy' "$s" && ! grep -qE 'exit-code:[[:space:]]*["'\'']?1' "$s"; then
        warn SEC-04 "$s: trivy runs without exit-code: 1, so it never fails the build"
      else
        pass SEC-04 "$s: scanner present"
      fi
    done <"$TMP/scanners"
  fi
fi
if grep -qE '^(\.github/dependabot\.ya?ml|renovate\.json5?|\.github/renovate\.json5?|\.renovaterc(\.json)?)$' "$TMP/files"; then
  pass SEC-04 "automated dependency updates configured"
else
  warn SEC-04 "no Dependabot or Renovate config; SHA pins and dependencies will go stale"
fi

# SEC-06: dangerous triggers and script injection.
UNTRUSTED='\$\{\{[^}]*(github\.event\.[A-Za-z0-9_.]*\.(title|body|message|name|email|ref|label|default_branch)|github\.head_ref)[^}]*\}\}'
while IFS= read -r f; do
  if triggers "$f" | grep -qx 'pull_request_target'; then
    if grep -qE 'allow-unsafe-pr-checkout:[[:space:]]*true' "$f"; then
      fail SEC-06 "$f: pull_request_target with allow-unsafe-pr-checkout: true runs untrusted code with secrets"
    elif grep -qE 'github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref' "$f"; then
      fail SEC-06 "$f: pull_request_target checks out the PR head; untrusted code runs with secrets"
    else
      warn SEC-06 "$f: uses pull_request_target; confirm it never executes PR code"
    fi
  fi
  # Only code is injectable: run: (shell) and script: (github-script) lines. Values
  # under env: or with: are data, which is the safe way to pass event text.
  codelines "$f" >"$TMP/code"
  grep -nE "$UNTRUSTED" "$f" 2>/dev/null \
    | while IFS= read -r hit; do
      grep -q "^${hit%%:*} " "$TMP/code" || continue
      # github.event.repository.* is set by the repository owner, not by whoever
      # triggers the run; drop it and see whether anything untrusted is left.
      printf '%s' "${hit#*:}" | sed -E 's/github\.event\.repository\.[A-Za-z0-9_.]*//g' | grep -qE "$UNTRUSTED" || continue
      echo "$f:${hit%%:*}" >>"$TMP/inject"
    done || true
done <"$TMP/wf"
if [ -f "$TMP/inject" ]; then
  while IFS= read -r i; do
    fail SEC-06 "$i: untrusted event data interpolated into a script; pass it through env:"
  done <"$TMP/inject"
elif [ "$WF_COUNT" -gt 0 ]; then
  pass SEC-06 "no untrusted event data interpolated into scripts"
fi

# ---------------------------------------------------------------------------
section "Source and build"

# SRC-02: base images pinned, lockfiles committed.
grep -E '(^|/)(Dockerfile|Containerfile)[^/]*$' "$TMP/files" >"$TMP/dockerfiles" || true
while IFS= read -r d; do
  [ -f "$d" ] || continue
  stages=" "
  grep -nE '^[[:space:]]*FROM[[:space:]]' "$d" | while IFS= read -r hit; do
    line=${hit%%:*}
    # shellcheck disable=SC2046 # split the FROM line into words on purpose
    set -- $(printf '%s' "${hit#*:}" | sed -E 's/--[a-z]+=[^[:space:]]+//g')
    image=${2:-}
    alias=""
    [ "${3:-}" = "AS" ] || [ "${3:-}" = "as" ] && alias=${4:-}
    case "$stages" in *" $image "*) [ -n "$alias" ] && stages="$stages$alias "; continue ;; esac
    [ -n "$alias" ] && stages="$stages$alias "
    [ "$image" = "scratch" ] && continue
    case "$image" in
      *@sha256:*) echo x >>"$TMP/digest_ok" ;;
      *:latest | *:\$*) fail SRC-02 "$d:$line: FROM $image uses a mutable tag" ;;
      */*:* | *:*)
        # A colon after the last slash is a tag; a colon only before it is a registry port.
        tagpart=${image##*/}
        case "$tagpart" in
          *:*) warn SRC-02 "$d:$line: FROM $image is tagged but not pinned by digest" ;;
          *) fail SRC-02 "$d:$line: FROM $image has no tag (implies latest)" ;;
        esac
        ;;
      *) fail SRC-02 "$d:$line: FROM $image has no tag (implies latest)" ;;
    esac
  done || true
done <"$TMP/dockerfiles"
if [ -f "$TMP/digest_ok" ]; then
  pass SRC-02 "$(wc -l <"$TMP/digest_ok" | tr -d ' ') base image(s) pinned by digest"
fi

lock_issue=0
grep -E '(^|/)package\.json$' "$TMP/files" | grep -v node_modules | while IFS= read -r p; do
  dir=$(dirname "$p")
  if ! grep -qE "^($dir/)?(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$" "$TMP/files"; then
    fail SRC-02 "$p: no lockfile committed next to it"
    echo x >>"$TMP/lockfail"
  fi
done || true
grep -E '(^|/)go\.mod$' "$TMP/files" | while IFS= read -r g; do
  dir=$(dirname "$g")
  grep -qE "^($dir/)?go\.sum$" "$TMP/files" || { fail SRC-02 "$g: go.sum not committed"; echo x >>"$TMP/lockfail"; }
done || true
if grep -qE '\.(cs|fs|vb)proj$' "$TMP/files" && ! grep -qE '(^|/)packages\.lock\.json$' "$TMP/files"; then
  warn SRC-02 ".NET projects without packages.lock.json; set RestorePackagesWithLockFile=true"
  lock_issue=1
fi
if grep -qE '(^|/)pyproject\.toml$' "$TMP/files" && ! grep -qE '(^|/)(poetry\.lock|uv\.lock|pdm\.lock|requirements[^/]*\.txt)$' "$TMP/files"; then
  warn SRC-02 "pyproject.toml without a lockfile"
  lock_issue=1
fi
if [ ! -f "$TMP/lockfail" ] && [ "$lock_issue" = 0 ]; then
  pass SRC-02 "no missing lockfiles detected"
fi

# SRC-03: fast feedback.
while IFS= read -r f; do
  if triggers "$f" | grep -qx 'pull_request' && ! grep -qE '^concurrency:|^[[:space:]]+concurrency:' "$f"; then
    warn SRC-03 "$f: runs on pull requests without a concurrency group; stale runs keep consuming runners"
  fi
  jobs=$(grep -cE '^[[:space:]]+runs-on:' "$f" || true)
  timeouts=$(grep -cE '^[[:space:]]+timeout-minutes:' "$f" || true)
  if [ "$jobs" -gt "$timeouts" ]; then
    warn SRC-03 "$f: $((jobs - timeouts)) job(s) without timeout-minutes (default is 6 hours)"
  fi
done <"$TMP/wf"
if [ "$WF_COUNT" -gt 0 ]; then
  if wfgrep -qE 'actions/cache|cache:[[:space:]]*(npm|yarn|pnpm|pip|poetry|gradle|maven|sbt)|cache-from:'; then
    pass SRC-03 "dependency or layer caching in use"
  else
    warn SRC-03 "no caching found; every run reinstalls dependencies"
  fi
fi

# SRC-06: shared pipeline code.
if [ "$WF_COUNT" -gt 0 ]; then
  if wfgrep -qE 'workflow_call|uses:[[:space:]]*[^[:space:]]*\.github/workflows/'; then
    pass SRC-06 "reusable workflows in use"
  else
    warn SRC-06 "no reusable workflows; build logic is likely copied between repositories"
  fi
fi

# ---------------------------------------------------------------------------
section "Deployment"

# DEP-01: CI must not change the cluster directly.
direct=0
while IFS= read -r f; do
  if grep -nE '(kubectl[[:space:]]+(apply|create|replace|patch|delete|set[[:space:]]+image|rollout[[:space:]]+restart))|(helm[[:space:]]+(upgrade|install|uninstall|rollback))' "$f" >"$TMP/direct" 2>/dev/null; then
    # Only shell steps deploy; the same words in a comment, a with: value or a
    # github-script string (e.g. install instructions in a PR comment) do not.
    codelines "$f" >"$TMP/code"
    while IFS= read -r hit; do
      grep -q "^${hit%%:*} run\$" "$TMP/code" || continue
      direct=1
      fail DEP-01 "$f:${hit%%:*}: CI changes the cluster directly; let Argo CD apply from Git"
    done <"$TMP/direct"
  fi
done <"$TMP/wf"
[ "$direct" = 0 ] && [ "$WF_COUNT" -gt 0 ] && pass DEP-01 "no direct kubectl/helm changes from CI"

# DEP-06: no secrets committed. Vendored third-party code is skipped; files under
# test paths are usually fixtures, so they are reported as WARN to confirm.
VENDOR='(^|/)(vendor|node_modules|third_party)/'
TESTPATH='(^|/)(test|tests|testdata|__tests__|spec|fixtures|__fixtures__)/|_test\.[A-Za-z]+$|\.test\.[A-Za-z]+$|\.env\.test$'
secrets=0
grep -vE "$VENDOR" "$TMP/files" >"$TMP/owned" || true
grep -E '(^|/)(\.env(\.[A-Za-z0-9_-]+)?|[^/]*\.pem|[^/]*\.key|id_rsa|id_ed25519|[^/]*\.p12|[^/]*\.pfx|credentials\.json)$' "$TMP/owned" \
  | grep -vE '\.(example|sample|template|dist)$|\.env\.(example|sample|template)$' >"$TMP/secretfiles" || true
while IFS= read -r s; do
  if printf '%s' "$s" | grep -qE "$TESTPATH"; then
    warn DEP-06 "$s: secret-like file in a test path; confirm it holds no real secret"
  else
    secrets=1
    fail DEP-06 "$s: secret-like file is committed"
  fi
done <"$TMP/secretfiles"
# One grep over every file: one call per file takes minutes on a vendored tree.
tr '\n' '\0' <"$TMP/owned" | xargs -0 grep -lE -- '-----BEGIN ((RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----' 2>/dev/null >"$TMP/keyfiles" || true
while IFS= read -r t; do
  grep -qxF -- "$t" "$TMP/secretfiles" && continue
  if printf '%s' "$t" | grep -qE "$TESTPATH"; then
    warn DEP-06 "$t: contains a private key in a test path; confirm it is a fixture"
  else
    secrets=1
    fail DEP-06 "$t: contains a private key"
  fi
done <"$TMP/keyfiles"
[ "$secrets" = 0 ] && pass DEP-06 "no committed secret files or private keys found (current tree only; scan history with gitleaks)"

# ---------------------------------------------------------------------------
section "Ownership"

# FLO-03: code owners.
if grep -qE '^(CODEOWNERS|\.github/CODEOWNERS|docs/CODEOWNERS)$' "$TMP/files"; then
  pass FLO-03 "CODEOWNERS present"
else
  fail FLO-03 "no CODEOWNERS file; nobody is required to review pipeline changes"
fi

# ---------------------------------------------------------------------------
FAILS=$(count n_fail); WARNS=$(count n_warn); PASSES=$(count n_pass)
printf '\n%sSummary:%s %s%d fail%s, %s%d warn%s, %s%d pass%s\n' \
  "$BLD" "$RST" "$RED" "$FAILS" "$RST" "$YEL" "$WARNS" "$RST" "$GRN" "$PASSES" "$RST"
printf '%sEach ID is a check in The Pipeline Audit (audit/checklist.md in the kit; scorecard: audit/scorecard.csv).%s\n' "$DIM" "$RST"

if [ "$FAILS" -gt 0 ] && [ "$WARN_ONLY" = 0 ]; then
  exit 1
fi
exit 0
