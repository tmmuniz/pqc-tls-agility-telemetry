variable "repository_name" {
  description = "ECR repository name."
  type        = string
}

variable "image_tag_mutability" {
  description = "Image tag mutability."
  type        = string
}

variable "scan_on_push" {
  description = "Enable scan on push."
  type        = bool
}

variable "force_delete" {
  description = "Force delete repository with images during destroy."
  type        = bool
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
