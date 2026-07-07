variable "name" {
  description = "Name prefix."
  type        = string
}

variable "ubuntu_ami_parameter" {
  description = "Canonical public SSM parameter for Ubuntu AMI."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type."
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID."
  type        = string
}

variable "security_group_ids" {
  description = "Security group IDs."
  type        = list(string)
}

variable "ssh_key_name" {
  description = "EC2 key pair name."
  type        = string
}

variable "iam_instance_profile_name" {
  description = "IAM instance profile name."
  type        = string
}

variable "enable_detailed_monitoring" {
  description = "Enable EC2 detailed monitoring."
  type        = bool
}

variable "root_volume_size" {
  description = "Root EBS volume size in GiB."
  type        = number
}

variable "user_data" {
  description = "EC2 user data script."
  type        = string
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
