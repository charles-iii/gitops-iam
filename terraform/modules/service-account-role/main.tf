variable "role_name" {
  description = "IAM role name for the service account"
  type        = string
}

variable "description" {
  description = "Human-readable description of this service account role"
  type        = string
}

variable "github_org" {
  description = "GitHub organization name"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
}

variable "github_branch" {
  description = "GitHub branch that can assume this role"
  type        = string
  default     = "main"
}

variable "policy_arns" {
  description = "List of IAM policy ARNs to attach"
  type        = list(string)
}

variable "owner_team" {
  description = "Team responsible for this service account"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "max_session_duration" {
  type    = number
  default = 3600
}

data "aws_caller_identity" "current" {}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "oidc_trust" {
  statement {
    sid     = "GitHubOIDCTrust"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_org}/${var.github_repo}:ref:refs/heads/${var.github_branch}"]
    }
  }
}

resource "aws_iam_role" "service_account" {
  name                 = var.role_name
  description          = var.description
  assume_role_policy   = data.aws_iam_policy_document.oidc_trust.json
  max_session_duration = var.max_session_duration

  tags = {
    Owner          = var.owner_team
    Environment    = var.environment
    ManagedBy      = "terraform"
    Repository     = "gitops-iam"
    ServiceAccount = "true"
    GitHubOrg      = var.github_org
    GitHubRepo     = var.github_repo
    GitHubBranch   = var.github_branch
  }
}

resource "aws_iam_role_policy_attachment" "service_account" {
  for_each = toset(var.policy_arns)

  role       = aws_iam_role.service_account.name
  policy_arn = each.value
}

output "role_arn" {
  value = aws_iam_role.service_account.arn
}

output "role_name" {
  value = aws_iam_role.service_account.name
}
