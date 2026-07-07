locals {
  name = var.project_name

  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Workload    = "pqc-tls-crypto-agility-lab"
    deviceType  = var.device_type
  }

  cloudwatch_log_groups = {
    classic   = "/pqc-tls/rsa3072-classic"
    hybrid    = "/pqc-tls/rsa3072-mldsa44-hybrid"
    pqc       = "/pqc-tls/mldsa44-pqc"
    bootstrap = "/pqc-tls/bootstrap"
  }

  ubuntu_ami_parameter = coalesce(
    var.ubuntu_ami_parameter,
    "/aws/service/canonical/ubuntu/server/${var.ubuntu_series}/stable/current/${var.ubuntu_arch}/hvm/ebs-gp3/ami-id"
  )

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    aws_region = var.aws_region
  })
}

module "network" {
  source = "./modules/network"

  name               = local.name
  vpc_cidr           = var.vpc_cidr
  public_subnet_cidr = var.public_subnet_cidr
  tags               = local.common_tags
}

module "security_group" {
  source = "./modules/security_group"

  name             = local.name
  vpc_id           = module.network.vpc_id
  ssh_allowed_cidr = var.ssh_allowed_cidr
  tls_allowed_cidr = var.tls_allowed_cidr
  tags             = local.common_tags
}

module "ecr" {
  source = "./modules/ecr"

  repository_name      = var.ecr_repository_name
  image_tag_mutability = var.ecr_image_tag_mutability
  scan_on_push         = var.ecr_scan_on_push
  force_delete         = var.ecr_force_delete
  tags                 = local.common_tags
}

module "iam_ec2" {
  source = "./modules/iam_ec2"

  name                   = local.name
  enable_ecr_pull_policy = var.enable_ecr_pull_policy
  ecr_repository_arn     = module.ecr.repository_arn
  tags                   = local.common_tags
}

module "ec2" {
  source = "./modules/ec2"

  name                       = local.name
  ubuntu_ami_parameter       = local.ubuntu_ami_parameter
  instance_type              = var.instance_type
  subnet_id                  = module.network.public_subnet_id
  security_group_ids         = [module.security_group.security_group_id]
  ssh_key_name               = var.ssh_key_name
  iam_instance_profile_name  = module.iam_ec2.instance_profile_name
  enable_detailed_monitoring = var.enable_detailed_monitoring
  root_volume_size           = var.root_volume_size
  user_data                  = local.user_data
  tags                       = local.common_tags

  depends_on = [
    module.iam_ec2,
    module.ecr,
    module.cloudwatch
  ]
}

module "cloudwatch" {
  source = "./modules/cloudwatch"

  log_groups         = local.cloudwatch_log_groups
  log_retention_days = var.log_retention_days
  tags               = local.common_tags
}

module "alarms" {
  source = "./modules/alarms"

  name        = local.name
  instance_id = module.ec2.instance_id
  tags        = local.common_tags
}
