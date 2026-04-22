# NIST SP 800-53 Rev 5 — Control Mapping
## GitOps for IAM Management

This document maps each component of the GitOps IAM pipeline to the NIST SP 800-53 Rev 5 controls it satisfies. This mapping is intended to support ATO documentation, security assessments, and interview discussions.

---

## AC — Access Control

### AC-2 — Account Management

**Control statement:** Manage system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.

**How this project satisfies it:**

Every IAM role in the AWS environment is defined in Terraform and stored in Git. Creating, modifying, or removing a role requires a pull request — which creates a documented record of who requested the change, what the change was, and when it was approved. Nightly drift detection flags any roles that exist in AWS but not in Git, surfacing unauthorized account creation immediately.

The `scripts/access-review.sh` script generates a quarterly access review report listing all active roles, their last-used dates, and their approvers — directly supporting the periodic review requirement of AC-2(3).

**Relevant sub-controls:** AC-2(1) Automated Management, AC-2(3) Disable Accounts, AC-2(4) Automated Audit Actions, AC-2(7) Privileged User Accounts

---

### AC-3 — Access Enforcement

**Control statement:** Enforce approved authorizations for logical access to information and system resources.

**How this project satisfies it:**

OPA/Conftest policies enforce access rules at the point of code review — before any change reaches AWS. Policies block wildcard actions, require condition blocks on sensitive permissions like `iam:PassRole`, and enforce mandatory tagging for traceability. These checks run automatically on every pull request and cannot be bypassed without pipeline modification (which is itself a governed change).

**Relevant sub-controls:** AC-3(7) Role-Based Access Control, AC-3(15) Discretionary and Mandatory Access Control

---

### AC-5 — Separation of Duties

**Control statement:** Separate the duties of individuals to reduce the risk of malevolent activity.

**How this project satisfies it:**

The engineer who authors an IAM change cannot approve their own pull request (enforced via GitHub branch protection rules). The pipeline service account that runs `terraform apply` does not have permissions to approve pull requests. The human approvers who review changes cannot trigger the pipeline directly. These three roles — author, approver, executor — are technically separated and cannot be collapsed by any single actor.

---

### AC-6 — Least Privilege

**Control statement:** Employ the principle of least privilege, allowing only authorized accesses for users which are necessary to accomplish assigned tasks.

**How this project satisfies it:**

The OPA policy `iam_no_wildcards.rego` blocks any policy document containing `"Action": "*"` from being merged. Permission boundaries in `terraform/permission-boundaries/` cap the maximum permissions any role can ever hold, regardless of what policies are later attached. The pipeline service role itself is scoped to IAM read/write only — it cannot touch compute, storage, or network resources.

**Relevant sub-controls:** AC-6(1) Authorize Access to Security Functions, AC-6(2) Non-Privileged Access, AC-6(5) Privileged Accounts, AC-6(9) Log Use of Privileged Functions, AC-6(10) Prohibit Non-Privileged Users from Executing Privileged Functions

---

### AC-17 — Remote Access

**Control statement:** Establish and document usage restrictions and implementation guidance for remote access.

**How this project satisfies it:**

All pipeline access to AWS occurs over OIDC — short-lived, scoped tokens with no persistent credentials. There are no SSH keys, no long-lived access keys, and no VPN tunnels required. The trust policy on the pipeline role restricts token issuance to the specific repository and branch, preventing lateral movement from a compromised fork or branch.

---

## AU — Audit and Accountability

### AU-2 — Event Logging

**Control statement:** Identify the types of events that the system is capable of logging in support of the audit function.

**How this project satisfies it:**

Two independent audit streams are maintained. Git history captures every proposed change, approval decision, and merge event with timestamps and author identity. AWS CloudTrail captures every IAM API call made after `terraform apply` — including the exact parameters, the caller identity, and the source IP. Together they cover the full lifecycle of an IAM change from proposal to execution.

---

### AU-9 — Protection of Audit Information

**Control statement:** Protect audit information and audit tools from unauthorized access, modification, and deletion.

**How this project satisfies it:**

Git history on a protected branch cannot be force-pushed or rewritten without repository admin privileges. CloudTrail logs are stored in an S3 bucket with Object Lock enabled (WORM — write once, read many), preventing deletion or modification even by users with S3 admin access. The S3 bucket is in a separate logging account with no cross-account write access.

---

### AU-12 — Audit Record Generation

**Control statement:** Provide audit record generation capability for the list of events defined in AU-2.

**How this project satisfies it:**

CloudTrail is configured to log all IAM API calls across all regions with no exclusions. The drift detection job provides an additional audit record — a nightly snapshot comparing intended state (Git) to actual state (AWS). Any discrepancy generates a timestamped incident record in GitHub Issues.

---

## CM — Configuration Management

### CM-2 — Baseline Configuration

**Control statement:** Develop, document, and maintain under configuration control, a current baseline configuration of the system.

**How this project satisfies it:**

The `terraform/` directory is the authoritative baseline configuration of all IAM resources in the AWS environment. Terraform remote state (S3 + DynamoDB locking) ensures the baseline is consistent and protected from concurrent modification. The baseline is versioned — every Git tag represents a known-good state that can be restored.

---

### CM-3 — Configuration Change Control

**Control statement:** Determine the types of changes that are configuration-controlled; review proposed changes; approve or disapprove changes; document configuration change decisions.

**How this project satisfies it:**

This control is the core design principle of the entire project. The PR workflow is a direct technical implementation of a configuration change control board (CCB) process:

- **Determination:** All IAM changes are configuration-controlled (enforced by restricting console access)
- **Review:** Automated scans + human reviewer examination of the `terraform plan` diff
- **Approval:** Required approvers defined per change class (see `docs/approval-process.md`)
- **Documentation:** PR title, description, linked ticket, scan results, and approval record are all preserved in Git

**Relevant sub-controls:** CM-3(1) Automated Documentation, CM-3(2) Test, Validate, and Document Changes, CM-3(6) Cryptography Management

---

### CM-7 — Least Functionality

**Control statement:** Configure the system to provide only essential capabilities.

**How this project satisfies it:**

The `policies/deny-iam-console.tf` Terraform resource attaches an SCP (Service Control Policy) that denies direct IAM write operations from the AWS console for all non-admin accounts. This forces all changes through the pipeline, ensuring the system (the pipeline) has only the functionality needed — and nothing more.

---

### CM-8 — System Component Inventory

**Control statement:** Develop and document an inventory of system components.

**How this project satisfies it:**

The Terraform state file is a live inventory of all IAM resources under management. The `scripts/access-review.sh` script exports this inventory in human-readable form. Every resource in the inventory has a mandatory `Owner` tag (enforced by `policies/iam_tag_required.rego`), enabling traceability to a responsible team or individual.

---

## IA — Identification and Authentication

### IA-2 — Identification and Authentication (Organizational Users)

**Control statement:** Uniquely identify and authenticate organizational users.

**How this project satisfies it:**

Pipeline execution is authenticated via OIDC — the pipeline's identity is the GitHub repository and branch, not a shared credential. Developer identity is established at the commit level via GPG-signed commits, which tie each change to a specific individual's verified key. The `require-mfa.tf` policy enforces MFA for any human assuming a privileged IAM role.

**Relevant sub-controls:** IA-2(1) Multi-Factor Authentication to Privileged Accounts, IA-2(2) Multi-Factor Authentication to Non-Privileged Accounts

---

### IA-4 — Identifier Management

**Control statement:** Manage system identifiers by receiving authorization to assign an identifier; selecting an identifier that identifies an individual, group, role, service, or device; assigning the identifier; preventing reuse of identifiers.

**How this project satisfies it:**

IAM role names follow a naming convention enforced by an OPA policy — `{team}-{function}-{environment}` (e.g., `platform-readonly-prod`). Role ARNs are globally unique and never reused after deletion. The Git history provides a complete lifecycle record for every identifier: created in commit X, modified in commit Y, deleted in commit Z.

---

### IA-5 — Authenticator Management

**Control statement:** Manage system authenticators.

**How this project satisfies it:**

There are no long-lived authenticators in this pipeline. OIDC tokens have a 1-hour TTL. No IAM access keys are created for service accounts (verified by an OPA policy blocking `aws_iam_access_key` resource creation). The `SECURITY.md` documents the process for rotating credentials in the rare cases where static credentials are necessary.

---

## SI — System and Information Integrity

### SI-7 — Software, Firmware, and Information Integrity

**Control statement:** Employ integrity verification tools to detect unauthorized changes.

**How this project satisfies it:**

Drift detection is the primary integrity control. A nightly `terraform plan` compares the live AWS IAM state against the Git-managed baseline. Any unauthorized change — a role created via the console, a policy modified out-of-band — surfaces as a non-empty plan output and triggers an immediate alert. This provides near-real-time integrity verification of the IAM configuration.

---

## Summary Table

| Control | Control Name | Pipeline Component |
|---|---|---|
| AC-2 | Account Management | PR workflow, access review script |
| AC-2(3) | Disable Accounts | Drift detection, access review |
| AC-3 | Access Enforcement | OPA/Conftest policies |
| AC-5 | Separation of Duties | Branch protection, role separation |
| AC-6 | Least Privilege | OPA wildcard check, permission boundaries |
| AC-6(9) | Log Privileged Function Use | CloudTrail |
| AC-17 | Remote Access | OIDC, no static keys |
| AU-2 | Event Logging | Git history + CloudTrail |
| AU-9 | Protection of Audit Info | S3 Object Lock, protected branch |
| AU-12 | Audit Record Generation | CloudTrail, drift detection |
| CM-2 | Baseline Configuration | Terraform state |
| CM-3 | Configuration Change Control | PR + approval + scan workflow |
| CM-7 | Least Functionality | Deny console SCP |
| CM-8 | Component Inventory | Terraform state, Owner tag policy |
| IA-2 | Identification and Authentication | OIDC, GPG commits, MFA policy |
| IA-4 | Identifier Management | Naming convention OPA policy |
| IA-5 | Authenticator Management | No static keys policy |
| SI-7 | Information Integrity | Nightly drift detection |

---

*This mapping references NIST SP 800-53 Rev 5. For FedRAMP or DISA STIG alignment, additional controls may apply.*
