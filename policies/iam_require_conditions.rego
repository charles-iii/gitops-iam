# policies/iam_require_conditions.rego
#
# ICAM Control: AC-6(1) (Authorize Access to Security Functions)
# NIST 800-53: AC-6, AC-3, CM-7
#
# iam:PassRole without a Condition is one of the most common privilege
# escalation vectors in AWS. An attacker who can PassRole to any role
# can grant themselves elevated permissions. This policy requires a
# Condition block scoping what roles can be passed and to which services.

package iam

import future.keywords.if
import future.keywords.in

# -------------------------------------------------------
# Deny: iam:PassRole without Condition
# -------------------------------------------------------

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type in ["aws_iam_policy", "aws_iam_role_policy"]
  resource.change.actions[_] in ["create", "update"]

  policy_doc := json.unmarshal(resource.change.after.policy)
  statement := policy_doc.Statement[_]
  statement.Effect == "Allow"

  action := get_actions(statement.Action)[_]
  action == "iam:PassRole"

  # No Condition block present — this is the violation
  not statement.Condition

  msg := sprintf(
    "[AC-6 VIOLATION] '%v' grants iam:PassRole without a Condition block. Add iam:PassedToService or iam:AssociatedResourceArn condition to restrict scope.",
    [resource.address]
  )
}

# -------------------------------------------------------
# Deny: iam:PassRole Condition exists but doesn't restrict service
# -------------------------------------------------------

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type in ["aws_iam_policy", "aws_iam_role_policy"]
  resource.change.actions[_] in ["create", "update"]

  policy_doc := json.unmarshal(resource.change.after.policy)
  statement := policy_doc.Statement[_]
  statement.Effect == "Allow"

  action := get_actions(statement.Action)[_]
  action == "iam:PassRole"

  # Condition exists but doesn't include service restriction
  statement.Condition
  not statement.Condition["StringEquals"]["iam:PassedToService"]
  not statement.Condition["StringLike"]["iam:PassedToService"]

  msg := sprintf(
    "[AC-6 VIOLATION] '%v' grants iam:PassRole but Condition does not restrict iam:PassedToService. Specify which AWS services can receive this role.",
    [resource.address]
  )
}

# -------------------------------------------------------
# Warn: sts:AssumeRole without Condition
# -------------------------------------------------------

warn contains msg if {
  resource := input.resource_changes[_]
  resource.type in ["aws_iam_policy", "aws_iam_role_policy"]
  resource.change.actions[_] in ["create", "update"]

  policy_doc := json.unmarshal(resource.change.after.policy)
  statement := policy_doc.Statement[_]
  statement.Effect == "Allow"

  action := get_actions(statement.Action)[_]
  action == "sts:AssumeRole"
  not statement.Condition

  msg := sprintf(
    "[AC-6 WARNING] '%v' grants sts:AssumeRole without a Condition. Consider adding MFA or source IP conditions.",
    [resource.address]
  )
}

# -------------------------------------------------------
# Helper
# -------------------------------------------------------

get_actions(action) = [action] if {
  is_string(action)
}

get_actions(action) = action if {
  is_array(action)
}
