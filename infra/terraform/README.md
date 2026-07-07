# Terraform: modular PQC TLS lab on EC2 + ECR + CloudWatch

This Terraform stack creates the infrastructure required by the C++/Docker PQC TLS lab.

## Modules

```text
terraform/
├── main.tf
├── variables.tf
├── outputs.tf
├── user_data.sh.tftpl
└── modules/
    ├── network/          # VPC, public subnet, IGW, route table
    ├── security_group/   # SSH + TLS ports 8443/8444/8445
    ├── ecr/              # ECR repository for the Docker image
    ├── iam_ec2/          # EC2 instance role/profile + CloudWatch/SSM/ECR pull
    ├── ec2/              # Ubuntu EC2 instance + user_data
    ├── cloudwatch/       # CloudWatch Log Groups for application/bootstrap logs
    └── alarms/           # CPU and memory alarms
```

## EC2 device tag

The EC2 instance receives the tag:

```text
deviceType=QDevice
```

This tag is used by the Docker and telemetry workflows to find the EC2 instance without reading Terraform outputs.

The Terraform workflow sets the value through:

```yaml
TF_VAR_device_type: QDevice
```

## Instance type

Default instance type:

```hcl
instance_type = "t3.micro"
```

## CloudWatch Agent

The user data installs and starts the CloudWatch Agent with a small configuration:

```text
Memory -> CWAgent/mem_used_percent
Logs   -> /opt/pqc-tls/logs/*.log to CloudWatch Logs
```

CPU and networking are read from native EC2 metrics:

```text
AWS/EC2 CPUUtilization
AWS/EC2 NetworkIn
AWS/EC2 NetworkOut
AWS/EC2 NetworkPacketsIn
AWS/EC2 NetworkPacketsOut
```

Disk metrics are intentionally disabled.

Application log groups are created by Terraform:

```text
/pqc-tls/rsa3072-classic
/pqc-tls/rsa3072-mldsa44-hybrid
/pqc-tls/mldsa44-pqc
/pqc-tls/bootstrap
```

## Ubuntu AMI

By default, the AMI is resolved from Canonical's public SSM parameter for Ubuntu 26.04 LTS:

```text
/aws/service/canonical/ubuntu/server/resolute/stable/current/amd64/hvm/ebs-gp3/ami-id
```

Override only if needed:

```hcl
ubuntu_ami_parameter = "/aws/service/canonical/ubuntu/server/resolute/stable/current/amd64/hvm/ebs-gp3/ami-id"
```

## GitHub Actions variables and secrets

The Terraform workflow uses GitHub **Repository variables** for non-sensitive configuration:

```text
AWS_REGION
AWS_GITHUB_OIDC_ROLE_ARN
ECR_REPOSITORY
SSH_ALLOWED_CIDR
TLS_ALLOWED_CIDR
```

It uses GitHub **Repository secrets** for Terraform state and EC2 SSH key configuration:

```text
TF_STATE_BUCKET
TF_STATE_KEY
EC2_KEY_PAIR_NAME
```

## Pipeline order

Recommended order:

```text
1. Terraform workflow -> apply
   Creates VPC, Security Group, ECR, IAM, EC2, CloudWatch Log Groups, CloudWatch Agent setup and alarms.

2. Docker workflow
   Finds EC2 by tag deviceType=QDevice, validates Rego policy, builds/pushes the image and restarts the container through SSM.

3. Telemetry workflow
   Finds EC2 by tag deviceType=QDevice, runs active TLS tests through SSM and collects latest CPU, memory, networking metrics and application logs directly from CloudWatch.
```

## Remote state

`versions.tf` declares an S3 backend with empty config. GitHub Actions initializes it with:

```bash
terraform init \
  -backend-config="bucket=${TF_STATE_BUCKET}" \
  -backend-config="key=${TF_STATE_KEY}" \
  -backend-config="region=${AWS_REGION}" \
  -backend-config="encrypt=true"
```

## Local execution example

```bash
cp terraform.tfvars.example terraform.tfvars
terraform init \
  -backend-config="bucket=<state-bucket>" \
  -backend-config="key=pqc-tls-lab/terraform.tfstate" \
  -backend-config="region=us-east-1" \
  -backend-config="encrypt=true"
terraform plan
terraform apply
```

## ECR

Terraform creates the ECR repository. The Docker workflow does **not** create the repository; it validates that it exists and fails with a clear message if Terraform was not run first.

Default repository name:

```hcl
ecr_repository_name = "pqc-tls"
```

## Runtime logs

The host log directory is still prepared for the Docker container:

```text
/opt/pqc-tls/logs
```

It is mounted into the container as:

```text
/app/logs
```

CloudWatch Agent collects these files and ships them to CloudWatch Logs. The Python collector reads application telemetry from CloudWatch Logs, not from the EC2 filesystem.
