# S3 Read-Only Role
# Purpose: Allows authorized services to read from S3 buckets
# Owner: platform team
# NIST Controls: AC-3, AC-6
# Change request: DEMO-001

module "s3_readonly_role" {
  source = "./modules/least-privilege-role"

  role_name        = "s3-readonly-${var.environment}"
  description      = "Read-only access to S3 - least privilege role for data consumers"
  trusted_accounts = [data.aws_caller_identity.current.account_id]
  owner_team       = "platform"
  environment      = var.environment

  policy_arns = [
    aws_iam_policy.s3_readonly_policy.arn
  ]

  permission_boundary_arn = aws_iam_policy.developer_boundary.arn
}

resource "aws_iam_policy" "s3_readonly_policy" {
  name        = "s3-readonly-policy-${var.environment}"
  description = "Least-privilege S3 read-only access - no write, delete, or ACL operations"
  path        = "/least-privilege/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Owner       = "platform"
    Environment = var.environment
  }
}
