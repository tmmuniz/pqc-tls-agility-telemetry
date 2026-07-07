resource "aws_cloudwatch_log_group" "this" {
  for_each          = var.log_groups
  name              = each.value
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name = each.value
  })
}
