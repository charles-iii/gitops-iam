# GitOps for IAM Management
### A DevSecOps + ICAM Portfolio Project

> Manage AWS IAM roles and policies as code — with automated security scanning, human approval gates, and a full audit trail — demonstrating end-to-end Identity, Credential, and Access Management governance.

---

## Project Summary

This project implements a **GitOps workflow for AWS IAM governance**, treating every IAM change (roles, policies, permission boundaries, SCPs) the same way application code is treated: version-controlled, peer-reviewed, security-scanned, and auditable.

Every change to AWS IAM must flow through this pipeline. No one — including pipeline service accounts — can make IAM changes directly in the AWS console. This enforces the core ICAM principle that **access control changes are a governed, traceable process, not an ad-hoc operation**.

---

## ICAM Pillar Mapping

| ICAM Pillar | How This Project Addresses It |
|---|---|
| **Identity** | All pipeline actions performed under OIDC-federated identities — no shared credentials or static keys. Git commit signing ties changes to individual developer identities. |
| **Credential** | Dynamic short-lived tokens via GitHub Actions OIDC. HashiCorp Vault for secrets injection. Zero static IAM access keys in the pipeline. |
| **Access** | Terraform enforces least-privilege role definitions. OPA policies block wildcard actions and overly broad resource scopes at PR time. |
| **Management** | Every change requires PR approval from a designated IAM owner. Full audit trail via Git history + AWS CloudTrail. Automated drift detection alerts when live AWS state diverges from Git. |

---

## Architecture Overview

```
Developer
    │
    ▼
[Pull Request — Terraform IAM change]
    │
    ├──► Checkov / tfsec scan         ← blocks on CRITICAL findings
    ├──► OPA / Conftest policy check  ← enforces org-specific rules
    ├──► terraform plan               ← diff posted to PR as comment
    │
    ▼
[Human Approval Gate]
    │   Security team + IAM owner must approve
    │   Breaking changes require CISO-level sign-off
    │
    ▼
[Merge to main — protected branch]
    │
    ▼
[terraform apply]
    │   Authenticated via OIDC (no static keys)
    │   Scoped to IAM-only permissions
    │
    ▼
[AWS IAM Updated]
    │
    ▼
[Audit & Monitoring]
    ├──► Git history (who changed what, when, why)
    ├──► AWS CloudTrail (what actually happened in AWS)
    ├──► Drift detection (live state vs. Git state)
    └──► CloudWatch alerts on anomalous IAM activity
```

---

## Repository Structure

```
gitops-iam/
│
├── README.md                          # This file
├── SECURITY.md                        # Security policy, break-glass procedure
├── CHANGELOG.md                       # Human-readable change log
│
├── terraform/
│   ├── main.tf                        # Root module, provider config
│   ├── variables.tf
│   ├── outputs.tf
│   ├── backend.tf                     # Remote state (S3 + DynamoDB lock)
│   │
│   ├── roles/                         # IAM role definitions
│   │   ├── developer-readonly.tf
│   │   ├── ci-pipeline-role.tf
│   │   ├── break-glass-admin.tf
│   │   └── cross-account-readonly.tf
│   │
│   ├── policies/                      # IAM policy documents
│   │   ├── least-privilege-s3.tf
│   │   ├── deny-iam-console.tf
│   │   └── require-mfa.tf
│   │
│   ├── permission-boundaries/         # Permission boundary policies
│   │   └── developer-boundary.tf
│   │
│   └── modules/
│       ├── least-privilege-role/      # Reusable role pattern
│       │   ├── main.tf
│       │   ├── variables.tf
│       │   └── README.md
│       └── service-account-role/     # OIDC-federated service role
│           ├── main.tf
│           └── variables.tf
│
├── policies/                          # OPA / Conftest policy files
│   ├── iam_no_wildcards.rego          # Block Action: "*"
│   ├── iam_require_conditions.rego    # PassRole must have conditions
│   ├── iam_no_inline_policies.rego    # Enforce managed policies only
│   └── iam_tag_required.rego         # All roles must have Owner tag
│
├── .github/
│   └── workflows/
│       ├── pr-checks.yml              # Scan + plan on every PR
│       ├── apply.yml                  # Apply on merge to main
│       └── drift-detection.yml        # Nightly drift check
│
├── docs/
│   ├── NIST-control-mapping.md        # This project → NIST 800-53 controls
│   ├── approval-process.md            # Who approves what class of change
│   ├── break-glass-procedure.md       # Emergency access runbook
│   └── threat-model.md               # What this architecture protects against
│
└── scripts/
    ├── drift-report.sh                # Compare Terraform state vs. AWS live
    └── access-review.sh               # Generate quarterly access review report
```

---

## Security Scanning Tools

| Tool | What It Checks | Severity That Blocks PR |
|---|---|---|
| **Checkov** | Terraform misconfigurations, CIS AWS benchmarks | CRITICAL, HIGH |
| **tfsec** | AWS-specific security issues in Terraform | HIGH |
| **OPA / Conftest** | Custom org policy (wildcards, tagging, PassRole) | Any violation |
| **terraform plan** | Diff of what will change — posted to PR for human review | N/A (informational) |
| **git-secrets** | Ensures no credentials committed to repo | Any match |

---

## OPA Policy Examples

### Block wildcard actions
```rego
# policies/iam_no_wildcards.rego
package iam

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_policy"
  statement := resource.change.after.policy.Statement[_]
  statement.Action == "*"
  msg := sprintf("IAM policy '%v' uses wildcard Action — denied", [resource.address])
}
```

### Require conditions on PassRole
```rego
# policies/iam_require_conditions.rego
package iam

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_policy"
  statement := resource.change.after.policy.Statement[_]
  statement.Action[_] == "iam:PassRole"
  not statement.Condition
  msg := sprintf("iam:PassRole in '%v' must include a Condition block", [resource.address])
}
```

---

## Pipeline Authentication (OIDC — No Static Keys)

The pipeline authenticates to AWS using **OpenID Connect (OIDC)**, not stored access keys. GitHub Actions receives a short-lived token that AWS validates against the GitHub OIDC provider.

```yaml
# .github/workflows/apply.yml (excerpt)
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/github-actions-iam-pipeline
    aws-region: us-east-1
    # No access key or secret — OIDC token exchange only
```

The `github-actions-iam-pipeline` role is itself defined in Terraform, with a trust policy that scopes it to only this repository and only the `main` branch — so even a compromised fork cannot trigger an apply.

---

## Approval Process

| Change Class | Example | Approvers Required |
|---|---|---|
| **Low** | Adding a tag, updating a description | 1 IAM owner |
| **Medium** | New role, new managed policy | 1 IAM owner + 1 security reviewer |
| **High** | PassRole grants, cross-account access, SCPs | Security team lead + CISO |
| **Break-glass** | Emergency admin access | Documented separately — see `docs/break-glass-procedure.md` |

---

## Audit Trail

Every IAM change in this system is traceable across two independent sources:

**Git history** answers: Who proposed the change? Who approved it? What was the stated business justification? When was it merged?

**AWS CloudTrail** answers: What API calls were actually made? What was the exact before/after state? Were there any unexpected side effects?

Tying these together — matching a Git commit SHA to a CloudTrail event — provides **non-repudiation**: proof that a specific person, at a specific time, made a specific change, and that it was authorized.

---

## Drift Detection

A nightly GitHub Actions job runs `terraform plan` against the live AWS environment. If the plan output is non-empty (meaning live state differs from Git state), it:

1. Posts a detailed drift report to a Slack/Teams channel
2. Opens a GitHub Issue with the drift details
3. Triggers a CloudWatch alarm

Drift indicates either an unauthorized manual change (a policy violation) or a bug in the pipeline (an operational issue). Both require immediate investigation.

---

## NIST 800-53 Control Mapping

See `docs/NIST-control-mapping.md` for the full mapping. Key controls addressed:

- **AC-2** — Account Management (all roles managed as code, reviewed on change)
- **AC-3** — Access Enforcement (OPA policies enforce least privilege at PR time)
- **AC-6** — Least Privilege (permission boundaries, no wildcard actions)
- **AU-2 / AU-12** — Audit Events (CloudTrail + Git history)
- **CM-2 / CM-3** — Baseline Configuration / Configuration Change Control (GitOps = change control)
- **CM-7** — Least Functionality (deny-list policies block unnecessary permissions)
- **IA-2** — Identification and Authentication (OIDC, MFA enforcement)
- **SI-7** — Software and Information Integrity (drift detection)

---

## Getting Started

```bash
# Clone the repo
git clone https://github.com/yourname/gitops-iam.git
cd gitops-iam

# Install tools
brew install terraform tfsec checkov conftest

# Initialize Terraform
cd terraform
terraform init

# Run local policy checks before opening a PR
checkov -d .
tfsec .
conftest test --policy ../policies .

# Open a PR — the pipeline handles the rest
```

---

## References

- NIST SP 800-53 Rev 5 — Security and Privacy Controls
- NIST SP 800-63 — Digital Identity Guidelines
- CISA Zero Trust Maturity Model
- AWS IAM Best Practices
- CIS AWS Foundations Benchmark
