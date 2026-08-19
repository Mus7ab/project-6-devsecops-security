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
