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

**Known limitation of this verification:** This exercise scanned an isolated example file, not deployed infrastructure. Application-level verification — confirming the live `three-tier-webapp` RDS instance has no legitimate outbound dependency that this change would break — was not performed, since doing so would require deploying real AWS infrastructure, which is out of scope for this documentation exercise per the project's cost-safety approach. If this fix were applied to the actual `three-tier-webapp` environment, that verification step would be required before merging.

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

---

## Remediation 3: Orders Helm Chart — Missing Pod/Container Security Context

**Related finding:** `docs/findings.md` — Finding 5

**Root cause:** `values.yaml` shipped with Helm's default scaffold — `podSecurityContext: {}` and `securityContext: {}` — leaving all hardening options commented out and unenabled.

**Remediation decision process:**
1. Considered whether `readOnlyRootFilesystem: true` could break the running application before applying it — inspected `services/orders/app.js` for filesystem writes (`grep` for `fs.writeFile`, `createWriteStream`, etc.) and found none, but treated this as a strong signal rather than a guarantee, since dependencies (npm, Express) could write outside the visible application code.
2. Rather than skip the control or risk breaking the app, added an explicit `emptyDir` volume mounted at `/tmp` alongside the read-only root filesystem — providing a minimal, scoped writable surface instead of leaving the entire filesystem writable.

**Fix applied (in `values.yaml`):**
```yaml
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  seccompProfile:
    type: RuntimeDefault

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL

volumes:
  - name: tmp
    emptyDir: {}

volumeMounts:
  - name: tmp
    mountPath: /tmp
```

**Verification — static analysis:**
- Trivy: 35 → 23 failures. Every finding referencing the actual `orders-chart` container's security context (`KSV-0001`, `0003`, `0004`, `0012`, `0014`, `0020`, `0021`, `0030`, `0104`, `0106`, `0118`) resolved. Remaining findings after the fix belong exclusively to the separate `wget` test-connection pod (documented in Finding 6) or to out-of-scope domains (resource limits, namespace). See `evidence/before/trivy_k8s_securitycontext.txt` and `evidence/after/trivy_k8s_securitycontext.txt`.

**Verification — live runtime deployment (not just static analysis):**
1. Deployed the remediated chart to an isolated namespace (`security-verify`) on the existing local `kind` cluster (`project3-local`) — no AWS cost involved.
2. Initial deployment failed with `CreateContainerConfigError` — investigated via `kubectl describe pod`, found the cause was missing `orders-config` ConfigMap and `orders-secret` Secret in the new namespace (a namespace-isolation artifact, unrelated to the security context change). Created both using the same non-sensitive demo values already verified safe in `eks-kubernetes-microservices`.
3. Redeployed — both pods reached `1/1 Running`, passing the `/health` readiness probe (confirming the application itself started and responded successfully under the new security context).
4. Directly confirmed the effective container identity via `kubectl exec ... -- id`: `uid=10001 gid=10001 groups=10001` — matching the configured `runAsUser`/`runAsGroup` exactly, on a live running container, not inferred from configuration.
5. Cleaned up the test namespace after verification (`kubectl delete namespace security-verify`).

**Why this verification matters more than the static scan alone:** A clean scanner result only proves the manifest declares the right configuration — it does not prove the application still functions under that configuration. This is the first finding in the project verified through an actual live deployment rather than static analysis alone, directly closing the gap between "scanner passed" and "control applied AND application still works," per the project's evidence-based philosophy.

**Status:** Remediated and verified via static analysis, live deployment, and direct runtime inspection.

---

## Remediation 4: Orders API — Throttling Added as Compensating Control for Public Endpoint

**Related finding:** `docs/findings.md` — Finding 7

**Root cause:** `POST /orders` is an intentionally public, unauthenticated API (confirmed via project README and live usage example), but had no throttling or rate-limiting configured at any level, leaving it fully exposed to abuse and cost-amplification.

**Remediation decision process:**
1. Initial hypothesis, based on `CKV_AWS_309`, was that missing `authorization_type` was the core vulnerability requiring authentication to be added.
2. Verified against the project's own README before acting — found explicit documentation and a live `curl` example confirming the public, unauthenticated design was intentional, not an oversight.
3. Revised the finding: the real gap was the *absence of a compensating control* for a deliberately public endpoint, not the absence of authentication itself.
4. Evaluated `AWS_IAM`, `CUSTOM`, and `JWT` as authorization options, and rejected all three — each would contradict the documented public-API design and require architecture changes outside this finding's scope.
5. Selected throttling as the appropriate compensating control: mitigates the actual risk (abuse/cost-amplification) without altering the intended trust model.

**Fix applied (in `terraform/modules/api-gateway/main.tf`):**
```hcl
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.orders.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 20
    throttling_rate_limit  = 10
  }
}
```

**Verification — static analysis:**
- Ran Trivy and Checkov before and after. Failure counts and specific rule IDs are **identical** in both scans (`AWS-0001`/`CKV_AWS_76` for access logging, `CKV_AWS_309` for authorization type — both pre-existing, unrelated to this fix).
- This is expected and does not indicate the fix failed: neither tool has a rule that checks for API Gateway throttling configuration at all. Confirmed the `default_route_settings` block with `throttling_burst_limit`/`throttling_rate_limit` renders correctly in the Terraform file (visible in the scan's own code-context output at `main.tf:28-31`), meaning the configuration is syntactically valid and present — the scanners simply have no corresponding check to evaluate it against.
- See `evidence/before/trivy_api_gateway.txt`, `evidence/before/checkov_api_gateway.txt`, `evidence/after/trivy_api_gateway.txt`, `evidence/after/checkov_api_gateway.txt`.

**Known limitation of this verification:** Because this is a serverless AWS resource (API Gateway + Lambda), verifying the throttling actually takes effect under real request load would require deploying to AWS and sending live traffic — out of scope per the project's cost-safety approach (unlike Phase 3's Kubernetes verification, this can't be tested for free on local infrastructure). Verification here is therefore limited to confirming valid Terraform syntax and correct placement, not live enforcement behavior. If ported to `serverless-orders`'s actual environment, load-testing the throttle limits before relying on them in production would be a necessary follow-up.

**`authorization_type` (CKV_AWS_309) — not remediated, documented exception:** See the Suppression/Exception record in `docs/findings.md` Finding 7. This is a deliberate decision, not an oversight — changing it would contradict verified project intent.

**Status:** Throttling remediated, verified at the Terraform-syntax level (scanner coverage gap prevents automated verification). Authorization type deliberately left as-is per documented design, with a formal exception record.

---

## Remediation 5: Secrets Security — No Real Remediation Required (Demonstration Only)

**Related findings:** `docs/findings.md` — Finding 9 (portfolio scan, clean) and Finding 10 (controlled demonstration)

**Summary:** No real secrets were found anywhere in the portfolio (Finding 9), so no remediation was necessary against real project code. Finding 10's demonstration fully documents the detect → remediate → rescan → verify workflow, including the critical discovery that naive line-deletion does not remove a secret from git history, and that proper remediation requires history rewriting plus credential rotation for any real-world equivalent. Full detail, evidence, and the reset-based remediation steps used are documented directly in Finding 10 rather than repeated here.

**Status:** N/A (portfolio) / Demonstration verified (see Finding 10).
