package iam

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_policy"
  resource.change.actions[_] == "create"
  policy_doc := json.unmarshal(resource.change.after.policy)
  statement := policy_doc.Statement[_]
  statement.Effect == "Allow"
  statement.Action == "iam:PassRole"
  not statement.Condition
  msg := sprintf("[AC-6 VIOLATION] '%v' grants iam:PassRole without a Condition block.", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_policy"
  resource.change.actions[_] == "create"
  policy_doc := json.unmarshal(resource.change.after.policy)
  statement := policy_doc.Statement[_]
  statement.Effect == "Allow"
  is_array(statement.Action)
  statement.Action[_] == "iam:PassRole"
  not statement.Condition
  msg := sprintf("[AC-6 VIOLATION] '%v' grants iam:PassRole without a Condition block.", [resource.address])
}
