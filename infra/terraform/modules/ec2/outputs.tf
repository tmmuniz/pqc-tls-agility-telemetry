output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.this.id
}

output "public_ip" {
  description = "EC2 public IP."
  value       = aws_instance.this.public_ip
}

output "ubuntu_ami_id" {
  description = "Resolved Ubuntu AMI ID."
  value       = nonsensitive(data.aws_ssm_parameter.ubuntu_ami.value)
}
