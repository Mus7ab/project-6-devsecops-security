# Security Findings

## Finding 1: RDS Security Group — Unrestricted Egress

- **Domain:** IaC Security
- **Source project:** Project 1 (three-tier-webapp) — `terraform/security_groups.tf`
- **Asset:** `aws_security_group.rds`
- **Detection tools:** Trivy, Checkov (both independently detected this)
- **Rule IDs:**
  - Trivy: `AWS-0104` — Severity: CRITICAL
  - Checkov: `CKV_AWS_382` — "Ensure no security groups allow egress from 0.0.0.0:0 to port -1"
- **Description:** The RDS security group's egress rule allowed all outbound traffic (0.0.0.0/0, all ports, all protocols) with no restriction, while ingress was correctly locked to the EC2 security group only.
- **Risk:** If the RDS instance or anything using its network path were compromised, this rule would permit data exfiltration to any destination on any port, with no network-layer restriction.
- **Exploitability:** Requires an existing compromise of the RDS instance or a resource with equivalent network access — not directly internet-exploitable on its own.
- **Exposure:** Internal to the VPC; not public-facing, but the egress path itself is fully open.
- **Priority:** Immediate remediation — no compensating control existed to justify suppression.
- **Evidence:** `evidence/before/trivy_rds_egress.txt`, `evidence/before/checkov_rds_egress.txt`
- **Status:** Remediated (see `docs/remediation.md`)

---

## Finding 2: CI Pipeline IAM User — Overly Permissive, Not IaC-Managed

- **Domain:** IaC Security (limitation of static analysis)
- **Source project:** Project 1 (three-tier-webapp) — `.github/workflows/terraform.yml`
- **Asset:** IAM user referenced via GitHub Secrets (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), reportedly attached to `PowerUserAccess`
- **Detection tools:** None — not detectable by Trivy or Checkov
- **Description:** The CI/CD pipeline authenticates to AWS using long-lived IAM user credentials (not OIDC role assumption). This IAM user and its policy attachment are not defined anywhere in the Project 1 Terraform codebase — confirmed via repo-wide search (`grep -rn "PowerUserAccess"`, `grep -rln "aws_iam_user"`, both returned no results).
- **Risk:** A CI credential with PowerUserAccess has near-admin blast radius across the AWS account if leaked or compromised (e.g., via a malicious PR, compromised GitHub Actions dependency, or leaked secret).
- **Why this is a genuine limitation, not a scanner failure:** Trivy and Checkov analyze Terraform (`.tf`) files. Because this IAM user was provisioned outside Terraform (console or CLI), there is no resource for either tool to evaluate — this is a structural blind spot of IaC static analysis, not a rule-coverage gap.
- **Priority:** High — but remediation is out of scope for a documentation-only exercise; requires either (a) codifying the IAM user in Terraform with least-privilege permissions so it becomes scannable, or (b) migrating CI to OIDC role assumption, eliminating long-lived credentials entirely.
- **Evidence:** `.github/workflows/terraform.yml` (inspected directly), grep search output (not saved as a file — command and empty result documented here)
- **Status:** Documented, not remediated — flagged as a recommendation for Project 1 going forward

---

## Finding 3: Orders/Users Service Dockerfile — Missing Non-Root USER

- **Domain:** Container Security
- **Source project:** Project 2 (microservices-orders-users) — `services/orders/Dockerfile`, `services/users/Dockerfile` (identical)
- **Asset:** Container image built from `node:20-alpine`
- **Detection tool:** Trivy (misconfiguration scan)
- **Rule ID:** `DS-0002` — Severity: HIGH — "Specify at least 1 USER command in Dockerfile with non-root user as argument"
- **Description:** No `USER` instruction was present in the Dockerfile. Without one, the container's process runs as root by default.
- **Risk:** If code execution is achieved inside the container via any vulnerability, running as root grants the attacker full control within the container boundary and a stronger position for any container-escape attempt.
- **Verification that a non-root user was available:** Confirmed via `docker run --rm node:20-alpine cat /etc/passwd` that the base image ships a built-in `node` user (UID 1000, GID 1000).
- **Evidence:** `evidence/before/trivy_dockerfile_misconfig.txt`, `evidence/after/trivy_dockerfile_misconfig.txt`
- **Status:** Remediated (see `docs/remediation.md`)

---

## Finding 4: OpenSSL CVEs in node:20-alpine Base Image — Accepted Risk (Upstream Not Yet Patched)

- **Domain:** Container Security
- **Source project:** Project 2 (microservices-orders-users) — base image `node:20-alpine`
- **Asset:** `libcrypto3` / `libssl3` packages (Alpine 3.23.4) inside the built container image
- **Detection tool:** Trivy (vulnerability scan)
- **Notable CVEs:** `CVE-2026-45447` (HIGH — Heap Use-After-Free in OpenSSL PKCS7_verify()), plus 12 additional MEDIUM/LOW OpenSSL CVEs — installed version `3.5.6-r0`, fixed version `3.5.7-r0`
- **Description:** The current `node:20-alpine` image, as published, bundles an OpenSSL version with known CVEs. Confirmed via `docker pull node:20-alpine` that this is the latest available image under this tag (digest unchanged) — the patched OpenSSL version is not yet available upstream at this tag.
- **Why this could not be remediated via a simple rebuild:** A base image rebuild only picks up a fix if the maintainer has published one. As of this scan, they have not.
- **Risk:** The vulnerable OpenSSL library remains present inside the container regardless of network-layer controls.
- **Exposure / Compensating control:** In Project 2's actual architecture, this container is not directly internet-facing — external HTTP/HTTPS traffic is routed through an Application Load Balancer (ALB), and ECS tasks run within private-subnet networking protected by security groups. This reduces the network paths through which the vulnerable library could be reached, but does not eliminate the vulnerability itself.
- **Decision:** Accept temporarily, with monitoring. Re-scan periodically (or via CI once Phase 6 is built) and remediate via base image rebuild as soon as an upstream patch is published.
- **Approval:** Self-approved for this portfolio exercise (no formal approval chain applicable).
- **Review/Expiration:** Revisit at next scheduled scan; treat as expired/overdue if unresolved after 30 days from an upstream patch becoming available.
- **Evidence:** `evidence/before/trivy_image_vuln.txt` (vulnerable and remediated builds show identical OpenSSL CVE set)
- **Status:** Documented, accepted with compensating control — not remediated (upstream limitation)

---

## Finding 5: Orders Helm Chart — Missing Pod/Container Security Context

- **Domain:** Kubernetes Security
- **Source project:** Project 3 (eks-kubernetes-microservices) — `orders-chart/values.yaml`, rendered via `orders-chart/templates/deployment.yaml`
- **Asset:** Deployment `release-name-orders-chart` (orders-chart container)
- **Detection tools:** Trivy, Checkov (both independently detected the same root cause via different rule sets)
- **Key rule IDs:**
  - Trivy: `KSV-0118` (HIGH — using default security context, allows root privileges), `KSV-0014` (HIGH — readOnlyRootFilesystem not set), `KSV-0001`/`KSV-0012` (MEDIUM — allowPrivilegeEscalation/runAsNonRoot not set), `KSV-0003`/`KSV-0004`/`KSV-0106` (LOW — capabilities not dropped), `KSV-0030`/`KSV-0104` (seccomp profile missing)
  - Checkov: `CKV_K8S_29`/`CKV_K8S_30` (no security context applied), `CKV_K8S_20` (privilege escalation), `CKV_K8S_23` (root containers), `CKV_K8S_37`/`CKV_K8S_28` (capabilities), `CKV_K8S_22` (read-only filesystem), `CKV_K8S_31` (seccomp)
- **Root cause:** `values.yaml` shipped with the standard Helm scaffold defaults (`podSecurityContext: {}`, `securityContext: {}`) — the security hardening options were present in commented-out form but never enabled.
- **Investigation method (before scanning):** Manually inspected `deployment.yaml`, identified that `securityContext` blocks are conditionally rendered via Helm's `{{- with }}` directive — meaning an empty `values.yaml` entry results in the block being omitted entirely from the rendered manifest, not defaulted to a safe value. Confirmed via `helm template` before running any scanner.
- **Risk:** A compromised container process would run as root, retain default Linux capabilities, be able to write to its own root filesystem (enabling tampering/persistence), and escalate privileges — a substantially larger blast radius than the equivalent finding in Project 2's ECS containers (Finding 3), since a Kubernetes compromise can extend to node-level and cluster-level attack paths.
- **Evidence:** `evidence/before/trivy_k8s_securitycontext.txt`, `evidence/before/checkov_k8s_securitycontext.txt`
- **Status:** Remediated and runtime-verified (see `docs/remediation.md`)

---

## Finding 6: Kubernetes Security — Deliberately Out-of-Scope Items

The following real findings from the same scan were identified but not remediated today, per Section 6 (minimum appropriate toolchain, avoid scope creep for diminishing returns):

- **Helm test-connection pod (`wget`/busybox container):** Still lacks a security context after remediation, since it is defined in a separate template (`templates/tests/test-connection.yaml`) not covered by the `values.yaml` change. Lower priority: this is a transient `helm test` hook, not a persistent workload, and has a substantially smaller attack window than the main Deployment.
- **Resource limits/requests (`KSV-0011/0015/0016/0018`, `CKV_K8S_10/11/12/13`):** Not security-context findings — these relate to reliability/DoS-resistance (unbounded pods can starve node resources). Real, but a different domain than this finding's threat model.
- **Default namespace usage (`KSV-0110`, `CKV_K8S_21`) and missing NetworkPolicy (`CKV2_K8S_6`, Checkov-only):** Real architectural findings — namespace segmentation and network policy enforcement are legitimate Kubernetes security controls, but represent a larger structural change than a `values.yaml` edit. Documented honestly as a recommendation rather than forced into today's session.

**Status:** Documented, not remediated — candidates for future work if this project's scope is extended.

---

## Finding 7: Orders API — Public Endpoint with No Throttling (Compensating Control for Intentional NONE Authorization)

- **Domain:** Application/Serverless Security
- **Source project:** Project 5 (serverless-orders) — `terraform/modules/api-gateway/main.tf`
- **Asset:** `aws_apigatewayv2_route.post_orders` (`POST /orders`), `aws_apigatewayv2_stage.default`
- **Detection tools:** Checkov (`CKV_AWS_309` — authorization type). Trivy did not flag the missing authorization at all.
- **Investigation process:** Initial hypothesis was "missing auth = vulnerability." Verified against the project's own README, which explicitly documents `POST /orders` as a public, unauthenticated API with a plain `curl` usage example — no credentials, no signing. This confirmed `authorization_type = NONE` is intentional design, not an oversight, changing the correct finding from "add authentication" to "verify compensating controls exist for a deliberately public endpoint."
- **Root cause (revised finding):** No throttling/rate-limiting configured at the stage or route level (`grep` for `throttle`/`rate_limit`/`burst` across the module returned no results) — meaning a public, unauthenticated endpoint has no mitigation against abuse or cost-amplification (each request cascades through Lambda → DynamoDB → EventBridge → SNS → 3 consumer Lambdas).
- **Risk:** Unmitigated flooding of the endpoint could drive significant AWS cost amplification across 5 chained services, and/or allow bulk injection of fabricated orders into DynamoDB.
- **Fix applied:** Added `default_route_settings` to `aws_apigatewayv2_stage.default` with `throttling_burst_limit = 20` and `throttling_rate_limit = 10`.
- **Scanner coverage gap (notable finding in itself):** Neither Trivy nor Checkov has any rule checking for API Gateway throttling configuration. Before/after scans show byte-for-byte identical failure counts and IDs — the fix is real and verified structurally (see Remediation 4), but is invisible to both static analysis tools. This is a genuine tool-coverage limitation, not a failed remediation — distinct from Day 1's "scanner didn't catch a known issue" pattern, this is "no rule for this control category exists in either tool at all."
- **`CKV_AWS_309` status:** Deliberately left failing. Documented as an accepted exception below, not remediated, since changing `authorization_type` would contradict the project's documented public-API design.
- **Evidence:** `evidence/before/trivy_api_gateway.txt`, `evidence/before/checkov_api_gateway.txt`, `evidence/after/trivy_api_gateway.txt`, `evidence/after/checkov_api_gateway.txt`
- **Status:** Remediated (throttling) and documented exception (authorization) — see `docs/remediation.md`

**Suppression/Exception record for `CKV_AWS_309`:**
- **Finding:** API GatewayV2 route does not specify an authorization type.
- **Reason:** `POST /orders` is an intentionally public, unauthenticated API per documented project design (README, confirmed via live `curl` usage example with no credentials).
- **Risk:** Any unauthenticated caller can invoke the endpoint.
- **Compensating control:** Throttling (`throttling_burst_limit = 20`, `throttling_rate_limit = 10`) mitigates abuse/cost-amplification without contradicting the public-API design. Full authentication (`AWS_IAM`/`JWT`) was considered and rejected as architecturally inappropriate for a public order-placement endpoint.
- **Approval:** Self-approved for this portfolio exercise, based on verified project documentation of intended design.
- **Review/Expiration:** Revisit if the project's intended consumer model changes (e.g., if the API is no longer meant to be public).

---

## Finding 8: API Gateway Access Logging Not Configured

- **Domain:** Application/Serverless Security
- **Source project:** Project 5 (serverless-orders) — `terraform/modules/api-gateway/main.tf`
- **Asset:** `aws_apigatewayv2_stage.default`
- **Detection tools:** Trivy (`AWS-0001`, MEDIUM), Checkov (`CKV_AWS_76`)
- **Description:** No access log settings configured on the API Gateway stage — meaning there is no request-level audit trail (caller IP, request path, response code, timing) for `POST /orders`.
- **Risk:** Reduced ability to detect or investigate abuse patterns after the fact — this is a detective/observability control, distinct from Finding 7's preventive throttling control.
- **Priority:** Medium/Low — real finding, but lower urgency than the public-auth/throttling question, and does not block the primary threat (unauthenticated abuse is already mitigated by Finding 7's throttling fix).
- **Decision:** Deprioritized given remaining project scope (4 days, 2 phases remaining at time of this finding). Not a scope-avoidance decision — a deliberate triage call distinguishing "quick to implement" from "necessary to fix now," per the project's Definition of Done.
- **Recommendation:** Enable access logging for improved auditability and abuse investigation if this project's scope is extended.
- **Evidence:** Same scan files as Finding 7 (`evidence/before/trivy_api_gateway.txt`, `evidence/after/trivy_api_gateway.txt`)
- **Status:** Documented, not remediated — deliberately deprioritized

---

## Finding 9: Secrets Scan — Portfolio Result (No Real Findings)

- **Domain:** Secrets Security
- **Scope:** Full git history of Project 1 (three-tier-webapp), Project 2 (microservices-orders-users), Project 3 (eks-kubernetes-microservices), Project 5 (serverless-orders), and Project 6 (this repository) — 70 total commits across 5 repositories.
- **Detection tool:** gitleaks 8.16.0
- **Result:** No leaks found in any repository.
- **What this confirms:** The Git Discipline followed throughout Projects 1-6 (`.gitignore` before code, never committing real credentials, using GitHub Secrets for CI, using placeholder/demo values for local secret manifests) was actually effective — independently verified by a dedicated secret-scanning tool, not merely assumed from following a checklist.
- **Honest framing:** This is a real, positive result — not a "finding" in the sense of something to remediate. Per project discipline, a clean scan is documented as evidence rather than skipped past, but it is explicitly not manufactured into a fake vulnerability.
- **Status:** Verified clean. No remediation applicable.

---

## Finding 10: Secrets Security — Controlled Demonstration of Detect/Remediate/Verify Workflow

- **Domain:** Secrets Security
- **Nature:** This is a controlled demonstration, not a real finding recovered from the portfolio (see Finding 9). Conducted to prove the detect → remediate → rescan → verify workflow functions correctly, and to surface real lessons about how git-history-based secret scanning behaves.
- **Method:** Created an isolated, never-pushed local branch (`secrets-demo`) containing a fake AWS-format access key (`AKIAIOSFODNN7EXAMPLE` — AWS's own public documentation example, not a functional credential) and a generic fake password, committed intentionally, then remediated.
- **Detection tool:** gitleaks 8.16.0
- **Key results:**
  1. gitleaks correctly detected the AWS-format key (`RuleID: aws-access-token`) but did **not** detect the generic password string — a real scanner-coverage limitation, consistent with pattern-based detection being strong for recognizable credential formats and weaker for arbitrary secrets without a distinctive signature. This is the same class of limitation documented in Finding 7 (scanner coverage gaps are a recurring, legitimate theme across this project, not a one-off).
  2. **Naive remediation (deleting the line in a new commit) did NOT resolve the finding.** Rescanning after deletion still detected the exact same leak, same commit hash, same fingerprint — proving the secret remains in git's object history and reachable, regardless of the current file state.
  3. **Actual remediation required removing the commit from history entirely** (`git reset --hard` to before the secret was introduced, safe only because this was an isolated, unpushed branch). Rescanning after this confirmed zero leaks.
- **Critical caveat for real-world use, not just this demo:** The reset-based approach used here is only safe on an isolated, never-pushed branch. On any repository that has been pushed/shared, the correct remediation is `git filter-repo` or BFG Repo-Cleaner plus a coordinated force-push — and most importantly, **immediate rotation of the exposed credential**, since any secret that was ever pushed to a remote must be treated as compromised regardless of subsequent history rewriting.
- **Evidence:** `evidence/before/gitleaks_demo_detection.txt`, `evidence/after/gitleaks_demo_naive_removal_still_detected.txt`, `evidence/after/gitleaks_demo_history_rewrite_verified_clean.txt`
- **Status:** Demonstration complete, workflow verified. No real secret was ever exposed to the public repository at any point.
