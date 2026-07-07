# NIST Telemetry Collector

This collector produces one JSON document with NIST-oriented evidence for the PQC TLS crypto-agility lab.

It collects three categories of evidence:

1. Active TLS success/failure tests against the three crypto-agility endpoints.
2. The latest available CloudWatch datapoints for CPU, memory and networking.
3. C++ application JSON logs directly from CloudWatch Logs.

The collector does **not** read local metric files or local log files from the EC2 instance. The application writes JSON lines under `/opt/pqc-tls/logs`, the CloudWatch Agent ships those files to CloudWatch Logs, and the collector queries CloudWatch APIs.

Disk metrics are intentionally disabled.

## Instance discovery

The EC2 instance is discovered by AWS tag instead of Terraform output:

```text
deviceType=QDevice
```

The Terraform workflow sets this tag through:

```yaml
TF_VAR_device_type: QDevice
```

The telemetry workflow and Docker deployment workflow resolve the current running EC2 instance with this tag.

## Metric and log sources

```text
CPU       -> CloudWatch Metrics / AWS/EC2: CPUUtilization
Memory    -> CloudWatch Metrics / CWAgent: mem_used_percent
Network   -> CloudWatch Metrics / AWS/EC2: NetworkIn, NetworkOut, NetworkPacketsIn, NetworkPacketsOut
Disk      -> disabled
Logs      -> CloudWatch Logs: /pqc-tls/rsa3072-classic, /pqc-tls/rsa3072-mldsa44-hybrid, /pqc-tls/mldsa44-pqc
```

The CloudWatch Agent is used for:

```text
1. Publishing memory usage to the default CWAgent namespace.
2. Shipping the C++ application JSON log files from /opt/pqc-tls/logs to CloudWatch Logs.
```

## Security model for active TLS tests

The GitHub Actions workflow does **not** connect from the public internet to ports `8443`, `8444` and `8445`.

Instead, it uses AWS Systems Manager Run Command to execute `tools/telemetry/telemetry/tls_tests.py` directly on the EC2 instance. The tests connect to `127.0.0.1`, so the Security Group does not need to expose the TLS ports to the whole WAN just for telemetry collection.

The workflow then retrieves the active TLS test JSON through SSM stdout and uses it as input for the final collector.

## Output

Default output:

```text
telemetry-output/nist-telemetry-summary.json
```

The final JSON includes:

```text
metadata
device
nist_context
active_tls_tests
cloudwatch_metrics
cloudwatch_logs
evidence
findings
```

The report intentionally does not include a `decision_input` block. That kind of field belongs to a later decision-agent layer, not to the NIST evidence artifact itself.

## Local execution: complete collector

```bash
pip install -r tools/telemetry/requirements.txt

python tools/telemetry/nist_telemetry_collector.py \
  --region us-east-1 \
  --device-tag-key deviceType \
  --device-tag-value QDevice \
  --lookback-minutes 15 \
  --active-tests-input telemetry-output/active-tls-tests.json \
  --output telemetry-output/nist-telemetry-summary.json
```

You can still pass `--instance-id` and `--target-host` manually, but the preferred lab mode is discovery by tag.

To override the default CloudWatch Log Groups:

```bash
python tools/telemetry/nist_telemetry_collector.py \
  --region us-east-1 \
  --device-tag-key deviceType \
  --device-tag-value QDevice \
  --log-group /pqc-tls/rsa3072-classic \
  --log-group /pqc-tls/rsa3072-mldsa44-hybrid \
  --log-group /pqc-tls/mldsa44-pqc
```

## Local execution: active TLS tests directly on EC2

Run this command on the EC2 instance to test the local container endpoints without opening public inbound access:

```bash
python3 -m telemetry.tls_tests \
  --target-host 127.0.0.1 \
  --use-oqs-docker \
  --oqs-image openquantumsafe/oqs-ossl3:latest-x86_64 \
  --docker-network host \
  --execution-location ec2_manual \
  --output active-tls-tests.json
```

`--docker-network host` is important when the OQS Docker image is used as the TLS client on EC2. Without host networking, `127.0.0.1` would refer to the temporary OQS client container itself, not to the EC2 host running the PQC TLS server container.

## GitHub Actions

Workflow:

```text
.github/workflows/telemetry-collector.yml
```

Required GitHub variables:

```text
AWS_REGION
AWS_GITHUB_OIDC_ROLE_ARN
```

The telemetry workflow no longer reads Terraform remote state. It finds the EC2 instance by tag:

```text
deviceType=QDevice
```

## AWS permissions required for the GitHub OIDC role

The role used by the telemetry workflow needs permission to discover the EC2 instance, execute SSM commands, read CloudWatch metrics and query CloudWatch Logs:

```json
{
  "Effect": "Allow",
  "Action": [
    "cloudwatch:GetMetricData",
    "cloudwatch:GetMetricStatistics",
    "cloudwatch:ListMetrics",
    "logs:FilterLogEvents",
    "logs:DescribeLogGroups",
    "ssm:SendCommand",
    "ssm:GetCommandInvocation",
    "ssm:ListCommandInvocations",
    "ec2:DescribeInstances"
  ],
  "Resource": "*"
}
```

Your current workflow role uses administrator permissions, so these actions are already covered.

## NIST-oriented mapping

The collector maps telemetry to NIST-oriented control evidence:

- `SI-4`: system monitoring through active TLS tests, CPU, memory, networking metrics and CloudWatch Logs.
- `AU-6`: audit review through JSON application events in CloudWatch Logs.
- `SC-13`: cryptographic protection through expected/observed crypto-agility behavior and observed TLS fields.
- `SC-8`: transmission confidentiality and integrity through TLS active tests and logged TLS negotiation.
- `CM-6`: configuration validation through expected/observed endpoint behavior.
