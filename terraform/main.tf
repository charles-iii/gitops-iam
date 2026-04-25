terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "charlescephas-gitops-iam-tfstate"
    key            = "gitops-iam/terraform.tfstate"
    region         = "us-east-2"
    dynamodb_table = "terraform-state-lock"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy   = "terraform"
      Repository  = "gitops-iam"
      Environment = var.environment
    }
  }
}

data "aws_caller_identity" "current" {}

# -------------------------------------------------------
# IAM Roles
# -------------------------------------------------------

module "developer_readonly_role" {
  source = "./modules/least-privilege-role"

  role_name        = "developer-readonly-${var.environment}"
  description      = "Read-only access for developers in ${var.environment}"
  trusted_accounts = [data.aws_caller_identity.current.account_id]
  owner_team       = "platform"
  environment      = var.environment

  policy_arns = [
    "arn:aws:iam::aws:policy/ReadOnlyAccess"
  ]

  permission_boundary_arn = aws_iam_policy.developer_boundary.arn
}

module "ci_pipeline_role" {
  source = "./modules/service-account-role"

  role_name            = "github-actions-iam-pipeline"
  description          = "OIDC-federated role for GitOps IAM pipeline - no static keys"
  github_org           = var.github_org
  github_repo          = var.github_repo
  github_branch        = "main"
  owner_team           = "security"
  environment          = var.environment

  policy_arns = [
    aws_iam_policy.iam_pipeline_policy.arn
  ]
}

module "break_glass_role" {
  source = "./modules/least-privilege-role"

  role_name        = "break-glass-admin-${var.environment}"
  description      = "Emergency elevated access - requires MFA + dual approval. All actions CloudTrail-logged."
  trusted_accounts = [var.security_account_id]
  owner_team       = "security"
  environment      = var.environment
  require_mfa      = true

  policy_arns = [
    aws_iam_policy.break_glass_policy.arn
  ]
}

# -------------------------------------------------------
# IAM Policies
# -------------------------------------------------------

resource "aws_iam_policy" "iam_pipeline_policy" {
  name        = "iam-pipeline-policy-${var.environment}"
  description = "Scoped IAM permissions for the GitOps pipeline service account"
  path        = "/gitops/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowIAMReadWrite"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:ListRoles",
          "iam:UpdateRole",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicies",
          "iam:ListPolicyVersions",
          "iam:CreatePolicyVersion",
          "iam:DeletePolicyVersion",
          "iam:TagPolicy",
          "iam:PutRolePermissionsBoundary",
          "iam:GetRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyEscalation"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:AttachUserPolicy",
          "iam:PutUserPolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowTerraformState"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:DeleteObject",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = [
          "arn:aws:s3:::charlescephas-gitops-iam-tfstate",
          "arn:aws:s3:::charlescephas-gitops-iam-tfstate/*",
          "arn:aws:dynamodb:us-east-2:027038267089:table/terraform-state-lock"
        ]
      }
    ]
  })

  tags = {
    Owner       = "security"
    Environment = var.environment
  }
}

resource "aws_iam_policy" "break_glass_policy" {
  name        = "break-glass-policy-${var.environment}"
  description = "Emergency elevated access policy — use only under documented break-glass procedure"
  path        = "/break-glass/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowIAMFullAccess"
        Effect   = "Allow"
        Action   = ["iam:*"]
        Resource = "*"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = {
    Owner       = "security"
    Environment = var.environment
    Sensitive   = "true"
  }
}

resource "aws_iam_policy" "require_mfa" {
  name        = "require-mfa-${var.environment}"
  description = "Deny all actions except MFA setup if MFA is not present"
  path        = "/security/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyWithoutMFA"
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })

  tags = {
    Owner       = "security"
    Environment = var.environment
  }
}

# -------------------------------------------------------
# Permission Boundary
# -------------------------------------------------------

resource "aws_iam_policy" "developer_boundary" {
  name        = "developer-permission-boundary-${var.environment}"
  description = "Permission boundary — caps max permissions for any developer role regardless of attached policies"
  path        = "/boundaries/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowReadOnly"
        Effect = "Allow"
        Action = [
          "s3:Get*",
          "s3:List*",
          "ec2:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "logs:Get*",
          "logs:Describe*",
          "logs:Filter*"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyIAMWrite"
        Effect = "Deny"
        Action = [
          "iam:Create*",
          "iam:Delete*",
          "iam:Put*",
          "iam:Attach*",
          "iam:Detach*",
          "iam:Update*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Owner       = "security"
    Environment = var.environment
  }
}

# -------------------------------------------------------
# CloudTrail — IAM change audit log
# -------------------------------------------------------

resource "aws_cloudtrail" "iam_audit" {
  name                          = "iam-change-audit-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "WriteOnly"
    include_management_events = true
  }

  tags = {
    Owner       = "security"
    Environment = var.environment
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "charlescephas-iam-cloudtrail-logs-${var.environment}"
  force_destroy = false

  tags = {
    Owner       = "security"
    Environment = var.environment
    Sensitive   = "true"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "DenyDelete"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion"
        ]
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
      }
    ]
  })
}
