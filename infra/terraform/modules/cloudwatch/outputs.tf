output "log_group_names" {
  description = "CloudWatch Log Group names."
  value       = { for key, value in aws_cloudwatch_log_group.this : key => value.name }
}
