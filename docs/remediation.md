# Remediation Log

## Remediation 1: RDS Security Group — Unrestricted Egress

**Related finding:** `docs/findings.md` — Finding 1

**Root cause:** The egress rule was likely copied from a template pattern (`0.0.0.0/0`, all ports/protocols) without evaluating whether the RDS instance has any legitimate need to initiate outbound connections. A private PostgreSQL RDS instance responds to inbound queries; it does not need broad outbound access.

**Remediation decision process:**
1. Confirmed via manual code inspection that ingress was already correctly scoped (EC2 SG only).
2. Considered narrowing egress to a specific CIDR/port (e.g., 443 for AWS API calls) but rejected this — no verified outbound dependency existed, and inventing a destination "to satisfy the scanner" would still leave unnecessary access open.
3. Decided on full egress removal (deny-all), based on least privilege: don't grant access until a real requirement is identified.

**Fix applied:** Removed the `egress` block entirely from the `aws_security_group.rds` resource.

**Important technical note:** In Terraform, omitting the `egress` block results in zero egress rules (deny-all) because Terraform manages the security group's rule set declaratively. This differs from a security group created directly in the AWS Console, which defaults to allow-all-egress unless explicitly restricted. This distinction matters if this fix is ever ported to a non-Terraform-managed resource.

**Verification:**
- Re-ran Trivy: `0 Misconfigurations` (previously 1 CRITICAL) — see `evidence/after/trivy_rds_egress.txt`
- Re-ran Checkov: `CKV_AWS_382` changed from FAILED to PASSED — see `evidence/after/checkov_rds_egress.txt`
- Both tools independently confirm the fix at the static-analysis level.

**Known limitation of this verification:** This exercise scanned an isolated example file, not deployed infrastructure. Application-level verification — confirming the live Project 1 RDS instance has no legitimate outbound dependency that this change would break — was not performed, since doing so would require deploying real AWS infrastructure, which is out of scope for this documentation exercise per the project's cost-safety approach. If this fix were applied to the actual Project 1 environment, that verification step would be required before merging.

**Status:** Remediated and verified at the static-analysis level. Application-level verification remains an open item if ported to production.

---

## Remediation 2: Orders/Users Dockerfile — Missing Non-Root USER

**Related finding:** `docs/findings.md` — Finding 3

**Root cause:** The Dockerfile never specified a `USER` instruction, so Docker's default behavior (run as root) applied silently. This is a common oversight in minimal example Dockerfiles that were never hardened past "it works."

**Remediation decision process:**
1. Verified the base image (`node:20-alpine`) ships a usable non-root user (`node`, UID 1000) before assuming one needed to be created manually.
2. Added `USER node` after all file operations requiring root (`COPY`, `RUN npm install`) but before the container's runtime `CMD`, so the build steps still have the permissions they need while the running process does not.

**Fix applied:** Added `USER node` to the Dockerfile, positioned after `COPY app.js .` and before `EXPOSE`/`CMD`.

**Verification:**
- Re-ran Trivy misconfiguration scan: `DS-0002` no longer appears in failures (2 failures → 1, only the unrelated `DS-0026` HEALTHCHECK finding remains) — see `evidence/before/trivy_dockerfile_misconfig.txt` and `evidence/after/trivy_dockerfile_misconfig.txt`.

**Runtime verification (closed):** Directly confirmed the effective container user via `docker run --rm <image> whoami`:
- `orders-service:vulnerable` → `root`
- `orders-service:remediated` → `node`

This confirms the fix takes effect at runtime, not just in the static Dockerfile instructions.

**Status:** Remediated and verified via both static analysis and direct runtime confirmation.
