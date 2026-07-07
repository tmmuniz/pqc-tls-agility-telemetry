variable "name" {
  description = "Name prefix."
  type        = string
}

variable "instance_id" {
  description = "EC2 instance ID."
  type        = string
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
