output "cpu_alarm_name" {
  description = "CPU alarm name."
  value       = aws_cloudwatch_metric_alarm.cpu_high.alarm_name
}

output "memory_alarm_name" {
  description = "Memory alarm name."
  value       = aws_cloudwatch_metric_alarm.memory_high.alarm_name
}
