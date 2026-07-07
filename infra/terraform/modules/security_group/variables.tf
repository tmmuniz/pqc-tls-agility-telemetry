variable "name" {
  description = "Name prefix."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID."
  type        = string
}

variable "ssh_allowed_cidr" {
  description = "CIDR allowed to SSH."
  type        = string
}

variable "tls_allowed_cidr" {
  description = "CIDR allowed to TLS ports."
  type        = string
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
