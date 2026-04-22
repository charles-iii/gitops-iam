variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod"
  }
}

variable "github_org" {
  description = "GitHub organization name — used to scope the OIDC trust policy"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name — used to scope the OIDC trust policy"
  type        = string
}

variable "trusted_account_ids" {
  description = "List of AWS account IDs allowed to assume cross-account roles"
  type        = list(string)
  default     = []
}

variable "security_account_id" {
  description = "AWS account ID of the dedicated security/audit account"
  type        = string
}
