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
2. Initial deployment failed with `CreateContainerConfigError` — investigated via `kubectl describe pod`, found the cause was missing `orders-config` ConfigMap and `orders-secret` Secret in the new namespace (a namespace-isolation artifact, unrelated to the security context change). Created both using the same non-sensitive demo values already verified safe in Project 3.
3. Redeployed — both pods reached `1/1 Running`, passing the `/health` readiness probe (confirming the application itself started and responded successfully under the new security context).
4. Directly confirmed the effective container identity via `kubectl exec ... -- id`: `uid=10001 gid=10001 groups=10001` — matching the configured `runAsUser`/`runAsGroup` exactly, on a live running container, not inferred from configuration.
5. Cleaned up the test namespace after verification (`kubectl delete namespace security-verify`).

**Why this verification matters more than the static scan alone:** A clean scanner result only proves the manifest declares the right configuration — it does not prove the application still functions under that configuration. This is the first finding in the project verified through an actual live deployment rather than static analysis alone, directly closing the gap between "scanner passed" and "control applied AND application still works," per the project's evidence-based philosophy.

**Status:** Remediated and verified via static analysis, live deployment, and direct runtime inspection.
