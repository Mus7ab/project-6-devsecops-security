# CI/CD Security Pipeline — Design and Known Limitations

## Overview

`.github/workflows/security.yml` runs five independent jobs on every push/PR to `main`:
IaC Security, Container Security, Kubernetes Security, Application Security, and Secrets Security — mirroring the five phases of this project.

## Gating Policy

| Layer | Mechanism | Blocking? |
|---|---|---|
| Trivy (all domains) | `severity: HIGH,CRITICAL`, `exit-code: 1` | Yes — hard fail on HIGH/CRITICAL |
| Checkov — `CKV_AWS_309` specifically | Inline `#checkov:skip` with documented justification | No — explicit, audited, resource-level exception |
| Checkov — all other findings (IaC, Application jobs) | `soft_fail: true` | No — reported visibly, does not fail the job |
| gitleaks | `gitleaks-action@v2` | Yes — any detected secret fails the job |

## Known Limitation — Checkov Gating Granularity

**Design intent (per `docs/findings.md`):** only intentionally-accepted exceptions (like `CKV_AWS_309`) should be non-blocking; deliberately deprioritized-but-real findings (like `CKV_AWS_76`, access logging) should remain visible and non-blocking, while any *new*, unreviewed HIGH-severity Checkov finding ideally should still gate the pipeline.

**What was actually implemented:** `soft_fail: true` is applied at the job level for Checkov, meaning **all** unsuppressed Checkov findings are currently non-blocking — not just the specific ones we've reviewed and accepted. This is broader than the intended policy.

**Why this was the deliberate choice for this project, not an oversight:** Implementing per-check severity-based gating for Checkov (equivalent to Trivy's `severity:` filter) requires either custom post-processing of Checkov's output or a more complex configuration than Checkov's GitHub Action supports natively. Building that properly was assessed as disproportionate scope for the remaining project timeline, per Section 6's minimum-appropriate-toolchain principle. Rather than either (a) leaving the mismatch between documented policy and actual enforcement undocumented, or (b) spending remaining project time building a bespoke severity-parsing framework, this limitation is explicitly documented here.

**What this means in practice:** Trivy remains the primary blocking gate for all four domains. Checkov functions as a comprehensive reporting layer, not (yet) an independently-tuned blocking gate. This is a real, current limitation of this implementation, not a claim that the pipeline enforces more precision than it does.

## Validation Status

- ✅ **YAML syntax validated locally** (`python3 -c "import yaml; yaml.safe_load(...)"` confirms the file parses correctly)
- ✅ **Inline Checkov suppression validated locally** — confirmed via direct `checkov -d` CLI runs that `CKV_AWS_309` shows as SKIPPED with the documented justification visible in output
- ❌ **Not yet validated on a live GitHub Actions runner** — this workflow has not yet been triggered by an actual push/PR to observe real runner behavior, action version compatibility, or live pass/fail results

## Future Improvement (if project scope is extended)

Implement per-check severity gating for Checkov (e.g., via `--check`/`--skip-check` flag lists mapped to documented severity tiers, or post-processing Checkov's JSON output) to bring enforcement granularity in line with the originally designed three-tier policy.
