resource "aws_security_group" "this" {
  name        = "${var.name}-sg"
  description = "Security group for PQC TLS lab EC2 instance"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from trusted CIDR"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_allowed_cidr]
  }

  ingress {
    description = "Classic TLS endpoint 8443"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [var.tls_allowed_cidr]
  }

  ingress {
    description = "Hybrid TLS endpoint 8444"
    from_port   = 8444
    to_port     = 8444
    protocol    = "tcp"
    cidr_blocks = [var.tls_allowed_cidr]
  }

  ingress {
    description = "PQC TLS endpoint 8445"
    from_port   = 8445
    to_port     = 8445
    protocol    = "tcp"
    cidr_blocks = [var.tls_allowed_cidr]
  }

  egress {
    description = "Outbound internet access for package installs, Docker pulls and CloudWatch Agent"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.name}-sg"
  })
}
