#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from telemetry.cloudwatch_logs import collect_log_events
from telemetry.cloudwatch_metrics import collect_cloudwatch_metrics
from telemetry.config import DEFAULT_DEVICE_TAG_KEY, DEFAULT_DEVICE_TAG_VALUE, DEFAULT_LOG_GROUPS
from telemetry.ec2_discovery import resolve_ec2_instance_by_tag
from telemetry.report import build_final_report
from telemetry.tls_tests import run_active_tls_tests
from telemetry.utils import json_dumps


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect NIST-oriented active TLS evidence, CloudWatch metrics and CloudWatch Logs for the PQC TLS lab."
    )
    parser.add_argument("--region", required=True, help="AWS region, for example us-east-1.")
    parser.add_argument(
        "--target-host",
        help="Target host used for metadata or local active tests. If omitted, it is resolved from the EC2 device tag.",
    )
    parser.add_argument(
        "--instance-id",
        help="Optional EC2 instance ID. If omitted, the collector resolves the instance by --device-tag-key/--device-tag-value.",
    )
    parser.add_argument("--device-tag-key", default=DEFAULT_DEVICE_TAG_KEY, help="EC2 tag key used to discover the lab instance.")
    parser.add_argument("--device-tag-value", default=DEFAULT_DEVICE_TAG_VALUE, help="EC2 tag value used to discover the lab instance.")
    parser.add_argument(
        "--lookback-minutes",
        type=int,
        default=15,
        help="Maximum CloudWatch search window. Metrics report the latest datapoint found in this window; logs are filtered by the same window.",
    )
    parser.add_argument(
        "--log-group",
        action="append",
        dest="log_groups",
        help="CloudWatch Log Group to query. Can be provided multiple times. Defaults to the PQC TLS application log groups.",
    )
    parser.add_argument("--output", default="telemetry-output/nist-telemetry-summary.json", help="Output JSON path.")
    parser.add_argument("--use-oqs-docker", action="store_true", help="Run openssl s_client via openquantumsafe/oqs-ossl3 Docker image.")
    parser.add_argument("--oqs-image", default="openquantumsafe/oqs-ossl3:latest-x86_64", help="OQS Docker image.")
    parser.add_argument("--openssl-bin", default="openssl", help="Local OpenSSL binary path when not using OQS Docker.")
    parser.add_argument("--tls-timeout-seconds", type=int, default=20, help="Timeout for each active TLS test when executed locally by this collector.")
    parser.add_argument("--active-tests-input", help="Path to a JSON file produced by telemetry.tls_tests. When set, active TLS tests are not executed from the workflow runner.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    device = None
    instance_id = args.instance_id
    target_host = args.target_host

    if not instance_id or not target_host:
        device = resolve_ec2_instance_by_tag(
            region=args.region,
            tag_key=args.device_tag_key,
            tag_value=args.device_tag_value,
            require_ssm_online=False,
        )
        instance_id = instance_id or device["instance_id"]
        target_host = target_host or device.get("public_ip") or device.get("private_ip") or instance_id

    if args.active_tests_input:
        active_tls_tests = json.loads(Path(args.active_tests_input).read_text(encoding="utf-8"))
    else:
        active_tls_tests = run_active_tls_tests(
            target_host,
            use_oqs_docker=args.use_oqs_docker,
            oqs_image=args.oqs_image,
            openssl_bin=args.openssl_bin,
            timeout_seconds=args.tls_timeout_seconds,
        )

    cloudwatch_metrics = collect_cloudwatch_metrics(
        region=args.region,
        instance_id=instance_id,
        lookback_minutes=args.lookback_minutes,
    )

    log_groups = tuple(args.log_groups) if args.log_groups else DEFAULT_LOG_GROUPS
    cloudwatch_logs = collect_log_events(
        region=args.region,
        log_groups=log_groups,
        lookback_minutes=args.lookback_minutes,
    )

    report = build_final_report(
        region=args.region,
        target_host=target_host,
        instance_id=instance_id,
        active_tls_tests=active_tls_tests,
        cloudwatch_metrics=cloudwatch_metrics,
        cloudwatch_logs=cloudwatch_logs,
        lookback_minutes=args.lookback_minutes,
        device=device,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json_dumps(report) + "\n", encoding="utf-8")
    print(f"Wrote telemetry report to {output_path}")
    print(json_dumps({"findings_count": len(report.get("findings", [])), "output": str(output_path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
