output "developer_readonly_role_arn" {
  description = "ARN of the developer read-only role"
  value       = module.developer_readonly_role.role_arn
}

output "ci_pipeline_role_arn" {
  description = "ARN of the GitHub Actions OIDC pipeline role — use this in your GitHub Actions workflow"
  value       = module.ci_pipeline_role.role_arn
}

output "break_glass_role_arn" {
  description = "ARN of the break-glass emergency access role"
  value       = module.break_glass_role.role_arn
  sensitive   = true
}

output "developer_boundary_arn" {
  description = "ARN of the developer permission boundary policy"
  value       = aws_iam_policy.developer_boundary.arn
}

output "cloudtrail_bucket_name" {
  description = "S3 bucket storing CloudTrail IAM audit logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}
