# policies/iam_governance.rego
#
# ICAM Control: CM-8 (System Component Inventory), AC-2 (Account Management)
# NIST 800-53: CM-8, AC-2, AU-2
#
# Enforces organizational governance requirements:
#   - All IAM roles must have required tags (Owner, Environment, ManagedBy)
#   - Role names must follow the naming convention: {team}-{function}-{environment}
#   - Inline policies are prohibited — use managed policies for auditability
#   - No IAM access keys may be created (use OIDC / instance profiles)

package iam

import future.keywords.if
import future.keywords.in

# -------------------------------------------------------
# Required tags on all IAM roles
# -------------------------------------------------------

required_tags := {"Owner", "Environment", "ManagedBy"}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role"
  resource.change.actions[_] in ["create", "update"]

  tags := object.get(resource.change.after, "tags", {})
  missing := required_tags - {tag | tags[tag]}
  count(missing) > 0

  msg := sprintf(
    "[CM-8 VIOLATION] aws_iam_role '%v' is missing required tags: %v. All roles must have Owner, Environment, and ManagedBy tags for inventory tracking.",
    [resource.address, missing]
  )
}

# -------------------------------------------------------
# Naming convention: {team}-{function}-{environment}
# -------------------------------------------------------

valid_environments := {"dev", "staging", "prod"}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role"
  resource.change.actions[_] in ["create", "update"]

  name := resource.change.after.name

  # Must match pattern: lowercase-words-environment
  not regex.match(`^[a-z0-9]+-[a-z0-9-]+-[a-z]+$`, name)

  msg := sprintf(
    "[CM-8 VIOLATION] aws_iam_role '%v' name '%v' does not follow naming convention: {team}-{function}-{environment} (lowercase, hyphens only).",
    [resource.address, name]
  )
}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role"
  resource.change.actions[_] in ["create", "update"]

  name := resource.change.after.name
  parts := split(name, "-")
  env_suffix := parts[count(parts) - 1]

  not env_suffix in valid_environments

  msg := sprintf(
    "[CM-8 VIOLATION] aws_iam_role '%v' name '%v' must end with a valid environment suffix: %v.",
    [resource.address, name, valid_environments]
  )
}

# -------------------------------------------------------
# Deny inline policies — use managed policies only
# -------------------------------------------------------

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role_policy"
  resource.change.actions[_] in ["create", "update"]

  msg := sprintf(
    "[AC-2 VIOLATION] '%v' creates an inline IAM policy. Inline policies are prohibited — use aws_iam_policy (managed) for auditability and reuse.",
    [resource.address]
  )
}

# -------------------------------------------------------
# Deny IAM access key creation — use OIDC / instance profiles
# -------------------------------------------------------

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_access_key"
  resource.change.actions[_] in ["create", "update"]

  msg := sprintf(
    "[IA-5 VIOLATION] '%v' creates a static IAM access key. Static keys are prohibited. Use OIDC federation, IAM instance profiles, or IAM Identity Center instead.",
    [resource.address]
  )
}

# -------------------------------------------------------
# Deny IAM users — use federated identity only
# -------------------------------------------------------

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_user"
  resource.change.actions[_] in ["create", "update"]

  msg := sprintf(
    "[IA-2 VIOLATION] '%v' creates an IAM user. IAM users are prohibited in this environment. Use IAM Identity Center or OIDC-federated roles for all access.",
    [resource.address]
  )
}
