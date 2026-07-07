variable "log_groups" {
  description = "Map of log group keys to CloudWatch Logs names."
  type        = map(string)
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days."
  type        = number
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
