data "aws_ssm_parameter" "ubuntu_ami" {
  name = var.ubuntu_ami_parameter
}

resource "aws_instance" "this" {
  ami                         = data.aws_ssm_parameter.ubuntu_ami.value
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = var.security_group_ids
  associate_public_ip_address = true
  key_name                    = var.ssh_key_name
  iam_instance_profile        = var.iam_instance_profile_name
  monitoring                  = var.enable_detailed_monitoring

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  root_block_device {
    volume_size = var.root_volume_size
    volume_type = "gp3"
    encrypted   = true
  }

  user_data_replace_on_change = true
  user_data                   = var.user_data

  tags = merge(var.tags, {
    Name = "${var.name}-ec2"
  })
}
