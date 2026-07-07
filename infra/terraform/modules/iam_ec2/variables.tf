variable "name" {
  description = "Name prefix."
  type        = string
}

variable "enable_ecr_pull_policy" {
  description = "Whether to attach ECR pull permissions."
  type        = bool
}

variable "ecr_repository_arn" {
  description = "ECR repository ARN from which the EC2 instance can pull images."
  type        = string
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
