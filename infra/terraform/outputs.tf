output "ecr_repository_name" {
  description = "ECR repository name created by Terraform."
  value       = module.ecr.repository_name
}

output "ecr_repository_url" {
  description = "ECR repository URL used by the Docker build workflow."
  value       = module.ecr.repository_url
}

output "instance_id" {
  description = "EC2 instance ID. Workflows normally discover the instance by tag deviceType=QDevice instead of reading this output."
  value       = module.ec2.instance_id
}

output "public_ip" {
  description = "Public IP address of the EC2 instance. Workflows normally discover it by tag deviceType=QDevice."
  value       = module.ec2.public_ip
}

output "device_type_tag" {
  description = "EC2 tag used by workflows and telemetry discovery."
  value       = "deviceType=${var.device_type}"
}

output "ssh_command" {
  description = "SSH command."
  value       = "ssh -i <your-key.pem> ubuntu@${module.ec2.public_ip}"
}

output "tls_test_commands" {
  description = "Basic TLS endpoint test commands."
  value = [
    "openssl s_client -connect ${module.ec2.public_ip}:8443 -tls1_3 -groups X25519 -brief",
    "openssl s_client -connect ${module.ec2.public_ip}:8444 -tls1_3 -groups X25519MLKEM768 -brief",
    "openssl s_client -connect ${module.ec2.public_ip}:8445 -tls1_3 -groups MLKEM768 -brief"
  ]
}

output "ubuntu_ami_parameter" {
  description = "Canonical SSM parameter used to resolve the latest Ubuntu AMI."
  value       = nonsensitive(local.ubuntu_ami_parameter)
}

output "ubuntu_ami_id" {
  description = "Resolved Ubuntu AMI ID."
  value       = nonsensitive(module.ec2.ubuntu_ami_id)
}

output "cloudwatch_log_groups" {
  description = "CloudWatch Log Groups used by the C++ application and bootstrap logs."
  value       = module.cloudwatch.log_group_names
}
