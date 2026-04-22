# policies/iam_no_wildcards.rego
#
# ICAM Control: AC-6 (Least Privilege)
# NIST 800-53: AC-6, AC-3
#
# Blocks any IAM policy document that contains a wildcard Action ("*").
# A wildcard action grants unlimited permissions on the matched resource,
# violating least-privilege. All actions must be explicitly enumerated.
#
# Usage: conftest test --policy policies/ terraform/

package iam

import future.keywords.if
import future.keywords.in

# -------------------------------------------------------
# Deny: wildcard Action in aws_iam_policy
# -------------------------------------------------------

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_policy"
  resource.change.actions[_] in ["create", "update"]

  policy_doc := json.unmarshal(resource.change.after.policy)
  statement := policy_doc.Statement[_]

  # Block both string wildcard and array containing wildcard
  is_wildcard_action(statement.Action)

  msg := sprintf(
    "[AC-6 VIOLATION] aws_iam_policy '%v' contains wildcard Action '*'. Enumerate specific actions instead.",
    [resource.address]
  )
}

# -------------------------------------------------------
# Deny: wildcard Action in aws_iam_role_policy (inline)
# -------------------------------------------------------

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role_policy"
  resource.change.actions[_] in ["create", "update"]

  policy_doc := json.unmarshal(resource.change.after.policy)
  statement := policy_doc.Statement[_]
  is_wildcard_action(statement.Action)

  msg := sprintf(
    "[AC-6 VIOLATION] Inline policy on '%v' contains wildcard Action '*'. Use managed policies with explicit actions.",
    [resource.address]
  )
}

# -------------------------------------------------------
# Deny: wildcard Resource ("*") on sensitive actions
# -------------------------------------------------------

sensitive_actions := {
  "iam:PassRole",
  "iam:CreateRole",
  "iam:DeleteRole",
  "iam:AttachRolePolicy",
  "sts:AssumeRole",
  "secretsmanager:GetSecretValue",
  "kms:Decrypt"
}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type in ["aws_iam_policy", "aws_iam_role_policy"]
  resource.change.actions[_] in ["create", "update"]

  policy_doc := json.unmarshal(resource.change.after.policy)
  statement := policy_doc.Statement[_]
  statement.Effect == "Allow"

  action := get_actions(statement.Action)[_]
  action in sensitive_actions
  statement.Resource == "*"

  msg := sprintf(
    "[AC-6 VIOLATION] '%v' grants '%v' on Resource '*'. Scope to specific resource ARNs.",
    [resource.address, action]
  )
}

# -------------------------------------------------------
# Helper functions
# -------------------------------------------------------

is_wildcard_action(action) if {
  action == "*"
}

is_wildcard_action(action) if {
  is_array(action)
  action[_] == "*"
}

get_actions(action) = [action] if {
  is_string(action)
}

get_actions(action) = action if {
  is_array(action)
}
