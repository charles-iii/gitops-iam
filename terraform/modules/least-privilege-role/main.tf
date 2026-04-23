variable "role_name" {
  description = "IAM role name — must follow convention: {team}-{function}-{environment}"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+-[a-z0-9-]+-[a-z]+$", var.role_name))
    error_message = "role_name must follow naming convention: {team}-{function}-{environment} (lowercase, hyphens only)"
  }
}

variable "description" {
  description = "Human-readable description of what this role is for and who owns it"
  type        = string
}

variable "trusted_accounts" {
  description = "List of AWS account IDs that can assume this role"
  type        = list(string)
}

variable "policy_arns" {
  description = "List of IAM policy ARNs to attach to this role"
  type        = list(string)
}

variable "permission_boundary_arn" {
  description = "ARN of the permission boundary policy to apply"
  type        = string
  default     = null
}

variable "owner_team" {
  description = "Team responsible for this role — required for access review"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "require_mfa" {
  description = "Require MFA when assuming this role"
  type        = bool
  default     = false
}

variable "max_session_duration" {
  description = "Maximum session duration in seconds (900–43200)"
  type        = number
  default     = 3600

  validation {
    condition     = var.max_session_duration >= 900 && var.max_session_duration <= 43200
    error_message = "max_session_duration must be between 900 and 43200 seconds"
  }
}

data "aws_iam_policy_document" "trust_policy" {
  statement {
    sid     = "AllowAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [for acct in var.trusted_accounts : "arn:aws:iam::${acct}:root"]
    }

    dynamic "condition" {
      for_each = var.require_mfa ? [1] : []
      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

resource "aws_iam_role" "this" {
  name                 = var.role_name
  description          = var.description
  assume_role_policy   = data.aws_iam_policy_document.trust_policy.json
  max_session_duration = var.max_session_duration
  permissions_boundary = var.permission_boundary_arn

  tags = {
    Owner       = var.owner_team
    Environment = var.environment
    ManagedBy   = "terraform"
    Repository  = "gitops-iam"
  }
}

resource "aws_iam_role_policy_attachment" "this" {
  count = length(var.policy_arns)

  role       = aws_iam_role.this.name
  policy_arn = var.policy_arns[count.index]
}

output "role_arn" {
  description = "ARN of the created IAM role"
  value       = aws_iam_role.this.arn
}

output "role_name" {
  description = "Name of the created IAM role"
  value       = aws_iam_role.this.name
}
