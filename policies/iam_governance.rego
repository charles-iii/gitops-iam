package iam

required_tags := {"Owner", "Environment", "ManagedBy"}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role"
  resource.change.actions[_] == "create"
  tags := object.get(resource.change.after, "tags", {})
  missing := required_tags - {tag | tags[tag]}
  count(missing) > 0
  msg := sprintf("[CM-8 VIOLATION] aws_iam_role '%v' is missing required tags: %v.", [resource.address, missing])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_access_key"
  resource.change.actions[_] == "create"
  msg := sprintf("[IA-5 VIOLATION] '%v' creates a static IAM access key. Use OIDC instead.", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_user"
  resource.change.actions[_] == "create"
  msg := sprintf("[IA-2 VIOLATION] '%v' creates an IAM user. Use federated identity instead.", [resource.address])
}
