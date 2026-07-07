output "role_name" {
  description = "EC2 IAM role name."
  value       = aws_iam_role.this.name
}

output "instance_profile_name" {
  description = "EC2 instance profile name."
  value       = aws_iam_instance_profile.this.name
}
