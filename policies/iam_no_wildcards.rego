package iam

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_policy"
  resource.change.actions[_] == "create"
  policy_doc := json.unmarshal(resource.change.after.policy)
  statement := policy_doc.Statement[_]
  statement.Action == "*"
  msg := sprintf("[AC-6 VIOLATION] aws_iam_policy '%v' contains wildcard Action '*'.", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_policy"
  resource.change.actions[_] == "create"
  policy_doc := json.unmarshal(resource.change.after.policy)
  statement := policy_doc.Statement[_]
  is_array(statement.Action)
  statement.Action[_] == "*"
  msg := sprintf("[AC-6 VIOLATION] aws_iam_policy '%v' contains wildcard Action '*'.", [resource.address])
}
