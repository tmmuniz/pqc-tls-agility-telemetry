from __future__ import annotations

from typing import Any

from .aggregator import aggregate_active_tests, aggregate_log_events
from .nist_findings import build_nist_context, evaluate_findings
from .utils import utc_now_iso


def build_final_report(
    *,
    region: str,
    target_host: str,
    instance_id: str,
    active_tls_tests: dict[str, Any],
    cloudwatch_metrics: dict[str, Any],
    cloudwatch_logs: dict[str, Any],
    lookback_minutes: int,
    device: dict[str, Any] | None = None,
) -> dict[str, Any]:
    parsed_events = cloudwatch_logs.get("parsed_events", [])
    aggregated_logs = aggregate_log_events(parsed_events)
    aggregated_active = aggregate_active_tests(active_tls_tests)

    report = {
        "metadata": {
            "schema_version": "1.2",
            "collector": "nist-pqc-tls-telemetry-collector",
            "generated_at": utc_now_iso(),
            "aws_region": region,
            "target_host": target_host,
            "instance_id": instance_id,
            "lookback_minutes": lookback_minutes,
            "collection_scope": "active_tls_tests_latest_cloudwatch_metrics_and_cloudwatch_logs",
        },
        "device": device or {},
        "nist_context": build_nist_context(),
        "active_tls_tests": {
            **active_tls_tests,
            "aggregated_metrics": aggregated_active,
        },
        "cloudwatch_metrics": cloudwatch_metrics,
        "cloudwatch_logs": {
            "region": cloudwatch_logs.get("region"),
            "lookback_minutes": cloudwatch_logs.get("lookback_minutes"),
            "collection_source": cloudwatch_logs.get("collection_source", "cloudwatch_logs_api"),
            "log_groups": cloudwatch_logs.get("log_groups", {}),
            "aggregated_metrics": aggregated_logs,
            # Keep only a small sample in the final report so the artifact remains readable.
            "parsed_event_sample": parsed_events[:50],
            "parsed_event_count": len(parsed_events),
        },
        "evidence": {
            "active_tls_test_count": active_tls_tests.get("summary", {}).get("total_tests", 0),
            "cloudwatch_metric_names": sorted(cloudwatch_metrics.get("metrics", {}).keys()),
            "cloudwatch_metric_mode": cloudwatch_metrics.get("metric_policy", {}).get("mode"),
            "cloudwatch_logs_collected": True,
            "cloudwatch_log_group_names": sorted(cloudwatch_logs.get("log_groups", {}).keys()),
            "cloudwatch_log_parsed_event_count": len(parsed_events),
            "cloudwatch_data_sources": {
                "cpu": "AWS/EC2 CloudWatch Metrics",
                "memory": "CWAgent CloudWatch Metrics",
                "network": "AWS/EC2 CloudWatch Metrics",
                "application_logs": "CloudWatch Logs",
            },
        },
    }
    findings = evaluate_findings(report)
    report["findings"] = findings
    return report
