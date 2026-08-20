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
