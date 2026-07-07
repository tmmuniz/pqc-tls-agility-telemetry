resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "${var.name}-cpu-high"
  alarm_description   = "CPUUtilization above 80 percent for the PQC TLS EC2 instance."
  namespace           = "AWS/EC2"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 60
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"

  dimensions = {
    InstanceId = var.instance_id
  }

  treat_missing_data = "notBreaching"
  tags               = var.tags
}

resource "aws_cloudwatch_metric_alarm" "memory_high" {
  alarm_name          = "${var.name}-memory-high"
  alarm_description   = "Memory usage above 80 percent from CloudWatch Agent."
  namespace           = "CWAgent"
  metric_name         = "mem_used_percent"
  statistic           = "Average"
  period              = 60
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"

  dimensions = {
    InstanceId = var.instance_id
  }

  treat_missing_data = "notBreaching"
  tags               = var.tags
}
