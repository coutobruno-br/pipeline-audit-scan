# pipeline-audit-scan

One bash script that audits a repository's GitHub Actions setup for the problems
attackers and outages use first: actions pinned to mutable tags, write-all tokens,
long-lived cloud keys, `pull_request_target` running PR code, script injection,
CI applying straight to the cluster, committed secrets and missing code owners.

No install, no account, no network calls. Bash 3.2+ (the macOS default works),
grep, sed, awk. Linux and macOS.

## Try it

```bash
curl -fsSLO https://raw.githubusercontent.com/coutobruno-br/pipeline-audit-scan/main/audit-repo.sh
less audit-repo.sh            # read it first; it is a few hundred lines of bash
bash audit-repo.sh path/to/your/repo
```

Or see it catch problems on the deliberately broken workflow in `demo/`:

```bash
mkdir -p /tmp/demo/.github/workflows
cp demo/insecure-workflow.yml /tmp/demo/.github/workflows/deploy.yml
bash audit-repo.sh /tmp/demo
```

```text
Pipeline Audit Kit audit-repo.sh v1.0.1  /tmp/demo
1 workflow file(s) found

Supply chain and secrets
[FAIL] SEC-01  .github/workflows/deploy.yml:14: not pinned to a commit SHA: actions/checkout@v4
[FAIL] SEC-01  .github/workflows/deploy.yml:20: not pinned to a commit SHA: aws-actions/configure-aws-credentials@main
[FAIL] SEC-02  .github/workflows/deploy.yml: no permissions block; the token gets the organization default
[FAIL] SEC-03  .github/workflows/deploy.yml:23: static cloud credential; use OIDC federation
[FAIL] SEC-04  no dependency or image scanner found in workflows
[WARN] SEC-04  no Dependabot or Renovate config; SHA pins and dependencies will go stale
[FAIL] SEC-06  .github/workflows/deploy.yml: pull_request_target with allow-unsafe-pr-checkout: true runs untrusted code with secrets
[FAIL] SEC-06  .github/workflows/deploy.yml:19: untrusted event data interpolated into a script; pass it through env:

Source and build
[PASS] SRC-02  no missing lockfiles detected
[WARN] SRC-03  .github/workflows/deploy.yml: 1 job(s) without timeout-minutes (default is 6 hours)
[WARN] SRC-03  no caching found; every run reinstalls dependencies
[WARN] SRC-06  no reusable workflows; build logic is likely copied between repositories

Deployment
[FAIL] DEP-01  .github/workflows/deploy.yml:25: CI changes the cluster directly; let Argo CD apply from Git
[PASS] DEP-06  no committed secret files or private keys found (current tree only; scan history with gitleaks)

Ownership
[FAIL] FLO-03  no CODEOWNERS file; nobody is required to review pipeline changes

Summary: 9 fail, 4 warn, 2 pass
Each ID is a check in The Pipeline Audit (audit/checklist.md in the kit; scorecard: audit/scorecard.csv).
```

Exit codes: `0` no FAIL findings, `1` FAIL findings, `2` usage error. Use
`--warn-only` to report without failing.

## What it checks

Every finding carries a check ID from *The Pipeline Audit*, a 36-check method for
CI/CD and Kubernetes delivery.

| ID | Check |
| --- | --- |
| SEC-01 | Every remote action and reusable workflow pinned to a 40-character commit SHA |
| SEC-02 | Least-privilege `GITHUB_TOKEN`: a read-only top-level `permissions:` block |
| SEC-03 | No long-lived cloud keys in workflows; OIDC instead |
| SEC-04 | A dependency or image scanner that can fail the build; Dependabot or Renovate |
| SEC-06 | No `pull_request_target` running PR code; no untrusted event data in `run:` |
| SRC-02 | Base images pinned by digest; lockfiles committed |
| SRC-03 | Concurrency groups, job timeouts and caching on pull request workflows |
| SRC-06 | Reusable workflows instead of copies |
| DEP-01 | CI never runs `kubectl apply` or `helm upgrade` against a cluster |
| DEP-06 | No committed `.env` files, keys or private keys in the current tree |
| FLO-03 | A CODEOWNERS file |

Why SEC-01 matters: in March 2025 the tags of `tj-actions/changed-files` were moved
to a malicious commit that printed CI secrets into build logs. Workflows pinned to
a commit SHA were not affected
([CISA alert](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction)).

## Run it in CI

```yaml
# .github/workflows/pipeline-audit.yml
name: pipeline-audit
on: [pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: pipeline audit
        run: |
          curl -fsSL -o "$RUNNER_TEMP/audit-repo.sh" \
            https://raw.githubusercontent.com/coutobruno-br/pipeline-audit-scan/a564f152b8ae14fbee2a84c2f0eba7d787dff6f9/audit-repo.sh
          bash "$RUNNER_TEMP/audit-repo.sh" --no-color .
```

Pin the download to a commit, as above, for the same reason as SEC-01.

## The other 25 checks

This scanner covers what a machine can see in one repository. The full method also
covers the cluster (requests, probes, PodDisruptionBudgets, security context,
NetworkPolicies), GitOps promotion, SLO alerts, rollback and DORA metrics.

- **[Pipeline Audit Kit](https://pipelineaudit.lemonsqueezy.com/checkout/buy/0a6a56f3-8d8a-4a17-854e-310c8e2efedd)**: the field guide ebook, a cluster scanner,
  a scorecard that turns 36 scores into a maturity level, and tested fixes:
  SHA-pinned workflows, a hardened Helm chart, Argo CD ApplicationSet, Kyverno
  policies, SLO burn-rate alerts and a Terraform module for GitHub OIDC to AWS.
- **[Pipeline audit for your team](https://cal.com/coutobruno/pipeline-scan)**: a fixed-price, five-day
  audit of your delivery path with a scored report and a 30/60/90 roadmap.

## License

MIT. See `LICENSE`.
