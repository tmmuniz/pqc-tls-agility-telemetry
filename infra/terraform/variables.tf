variable "aws_region" {
  description = "AWS Region where the lab will be deployed. In GitHub Actions this comes from vars.AWS_REGION."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix used for resource names."
  type        = string
  default     = "pqc-tls-lab"
}

variable "environment" {
  description = "Environment tag."
  type        = string
  default     = "lab"
}

variable "instance_type" {
  description = "EC2 instance type used by the lab."
  type        = string
  default     = "t3.micro"
}

variable "ssh_key_name" {
  description = "Existing EC2 key pair name for SSH access. This is the key pair name, not the key ID. It is case-sensitive. In GitHub Actions this comes from secrets.EC2_KEY_PAIR_NAME."
  type        = string
}

variable "ssh_allowed_cidr" {
  description = "CIDR allowed to access SSH. Prefer your public IP /32. In GitHub Actions this comes from vars.SSH_ALLOWED_CIDR."
  type        = string
}

variable "tls_allowed_cidr" {
  description = "CIDR allowed to access TLS ports 8443, 8444 and 8445. Prefer your public IP /32. In GitHub Actions this comes from vars.TLS_ALLOWED_CIDR."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the lab VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet."
  type        = string
  default     = "10.42.1.0/24"
}

variable "ubuntu_series" {
  description = "Ubuntu series used in Canonical public SSM parameters. Default 'resolute' maps to Ubuntu 26.04 LTS."
  type        = string
  default     = "resolute"
}

variable "ubuntu_arch" {
  description = "Ubuntu architecture used in Canonical public SSM parameters. Use amd64 for t2/t3 x86_64 instances."
  type        = string
  default     = "amd64"
}

variable "ubuntu_ami_parameter" {
  description = "Optional override for the Canonical SSM public parameter. Leave null to use latest Ubuntu 26.04 LTS current image."
  type        = string
  default     = null
}

variable "root_volume_size" {
  description = "Root EBS volume size in GiB."
  type        = number
  default     = 30
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days for application and bootstrap log groups."
  type        = number
  default     = 14
}

variable "device_type" {
  description = "Device type tag used by workflows and telemetry discovery."
  type        = string
  default     = "QDevice"
}


variable "enable_detailed_monitoring" {
  description = "Enable EC2 detailed monitoring for CPUUtilization at 1-minute granularity."
  type        = bool
  default     = true
}

variable "enable_ecr_pull_policy" {
  description = "Attach ECR read permissions to the EC2 role so user_data can pull a private ECR image."
  type        = bool
  default     = true
}

variable "ecr_repository_name" {
  description = "ECR repository name created by Terraform. In GitHub Actions this comes from vars.ECR_REPOSITORY."
  type        = string
  default     = "pqc-tls"
}

variable "ecr_image_tag_mutability" {
  description = "ECR image tag mutability. IMMUTABLE is more controlled; MUTABLE is convenient for latest-based labs."
  type        = string
  default     = "MUTABLE"

  validation {
    condition     = contains(["MUTABLE", "IMMUTABLE"], var.ecr_image_tag_mutability)
    error_message = "ecr_image_tag_mutability must be MUTABLE or IMMUTABLE."
  }
}

variable "ecr_scan_on_push" {
  description = "Enable ECR basic image scan on push."
  type        = bool
  default     = true
}

variable "ecr_force_delete" {
  description = "Allow Terraform destroy to delete the ECR repository even if it contains images. Useful for labs, not recommended for production."
  type        = bool
  default     = true
}
