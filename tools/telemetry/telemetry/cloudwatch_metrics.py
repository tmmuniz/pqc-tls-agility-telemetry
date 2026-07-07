from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import boto3

from .config import DEFAULT_CLOUDWATCH_NAMESPACE
from .utils import round_float


def _latest_datapoint(datapoints: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not datapoints:
        return None
    return sorted(datapoints, key=lambda item: item["Timestamp"])[-1]


def _get_latest_metric_statistics(
    cloudwatch_client: Any,
    *,
    namespace: str,
    metric_name: str,
    dimensions: list[dict[str, str]],
    statistic: str,
    period: int,
    lookback_minutes: int,
) -> dict[str, Any]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=lookback_minutes)
    response = cloudwatch_client.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=start,
        EndTime=end,
        Period=period,
        Statistics=[statistic],
    )
    datapoints = response.get("Datapoints", [])
    latest = _latest_datapoint(datapoints)
    value = latest.get(statistic) if latest else None
    return {
        "namespace": namespace,
        "metric_name": metric_name,
        "dimensions": dimensions,
        "statistic": statistic,
        "period_seconds": period,
        "lookback_minutes": lookback_minutes,
        "selection": "latest_datapoint_in_lookback_window",
        "value": round_float(value),
        "unit": latest.get("Unit") if latest else None,
        "timestamp": latest["Timestamp"].isoformat().replace("+00:00", "Z") if latest else None,
        "datapoint_count": len(datapoints),
    }


def _dimension_value(dimensions: list[dict[str, str]], name: str) -> str | None:
    for item in dimensions:
        if item.get("Name") == name:
            return item.get("Value")
    return None


def _candidate_dimensions_for_instance(
    cloudwatch_client: Any,
    *,
    namespace: str,
    metric_name: str,
    instance_id: str,
) -> list[list[dict[str, str]]]:
    """Return CloudWatch metric dimension sets that belong to this instance.

    The expected configuration publishes CWAgent memory with only InstanceId.
    This fallback keeps the collector resilient if CloudWatch Agent later adds
    extra dimensions; the collector will query CloudWatch using the exact
    dimensions advertised by list_metrics.
    """

    candidates: list[list[dict[str, str]]] = []
    paginator = cloudwatch_client.get_paginator("list_metrics")
    for page in paginator.paginate(Namespace=namespace, MetricName=metric_name):
        for metric in page.get("Metrics", []):
            dims = metric.get("Dimensions", [])
            if _dimension_value(dims, "InstanceId") == instance_id:
                candidates.append(dims)
    return candidates


def _get_latest_with_dimension_fallback(
    cloudwatch_client: Any,
    *,
    namespace: str,
    metric_name: str,
    instance_id: str,
    statistic: str,
    period: int,
    lookback_minutes: int,
) -> dict[str, Any]:
    primary_dimensions = [{"Name": "InstanceId", "Value": instance_id}]
    result = _get_latest_metric_statistics(
        cloudwatch_client,
        namespace=namespace,
        metric_name=metric_name,
        dimensions=primary_dimensions,
        statistic=statistic,
        period=period,
        lookback_minutes=lookback_minutes,
    )
    if result.get("datapoint_count", 0) > 0:
        result["dimension_resolution"] = "expected_instance_id_only"
        return result

    for dims in _candidate_dimensions_for_instance(
        cloudwatch_client,
        namespace=namespace,
        metric_name=metric_name,
        instance_id=instance_id,
    ):
        if dims == primary_dimensions:
            continue
        candidate = _get_latest_metric_statistics(
            cloudwatch_client,
            namespace=namespace,
            metric_name=metric_name,
            dimensions=dims,
            statistic=statistic,
            period=period,
            lookback_minutes=lookback_minutes,
        )
        if candidate.get("datapoint_count", 0) > 0:
            candidate["dimension_resolution"] = "list_metrics_fallback"
            return candidate

    result["dimension_resolution"] = "not_found"
    return result


def collect_cloudwatch_metrics(
    *,
    region: str,
    instance_id: str,
    lookback_minutes: int = 15,
    custom_namespace: str = DEFAULT_CLOUDWATCH_NAMESPACE,
) -> dict[str, Any]:
    """Collect the latest CPU, memory and networking datapoints from CloudWatch.

    The collector never reads local host metrics. CPU and networking come from
    the native AWS/EC2 namespace. Memory comes from CloudWatch Agent under the
    default CWAgent namespace. Disk is intentionally not collected.
    """

    cloudwatch = boto3.client("cloudwatch", region_name=region)
    ec2_dimensions = [{"Name": "InstanceId", "Value": instance_id}]

    metrics = {
        "cpu_utilization_percent": _get_latest_metric_statistics(
            cloudwatch,
            namespace="AWS/EC2",
            metric_name="CPUUtilization",
            dimensions=ec2_dimensions,
            statistic="Average",
            period=60,
            lookback_minutes=lookback_minutes,
        ),
        "memory_used_percent": _get_latest_with_dimension_fallback(
            cloudwatch,
            namespace=custom_namespace,
            metric_name="mem_used_percent",
            instance_id=instance_id,
            statistic="Average",
            period=60,
            lookback_minutes=lookback_minutes,
        ),
        "network_in_bytes": _get_latest_metric_statistics(
            cloudwatch,
            namespace="AWS/EC2",
            metric_name="NetworkIn",
            dimensions=ec2_dimensions,
            statistic="Sum",
            period=60,
            lookback_minutes=lookback_minutes,
        ),
        "network_out_bytes": _get_latest_metric_statistics(
            cloudwatch,
            namespace="AWS/EC2",
            metric_name="NetworkOut",
            dimensions=ec2_dimensions,
            statistic="Sum",
            period=60,
            lookback_minutes=lookback_minutes,
        ),
        "network_packets_in": _get_latest_metric_statistics(
            cloudwatch,
            namespace="AWS/EC2",
            metric_name="NetworkPacketsIn",
            dimensions=ec2_dimensions,
            statistic="Sum",
            period=60,
            lookback_minutes=lookback_minutes,
        ),
        "network_packets_out": _get_latest_metric_statistics(
            cloudwatch,
            namespace="AWS/EC2",
            metric_name="NetworkPacketsOut",
            dimensions=ec2_dimensions,
            statistic="Sum",
            period=60,
            lookback_minutes=lookback_minutes,
        ),
    }

    return {
        "region": region,
        "instance_id": instance_id,
        "custom_namespace": custom_namespace,
        "lookback_minutes": lookback_minutes,
        "collection_source": "cloudwatch_metrics_api",
        "metric_policy": {
            "mode": "latest_datapoint_only",
            "cpu_source": "AWS/EC2",
            "memory_source": custom_namespace,
            "network_source": "AWS/EC2",
            "logs_collected_by_metrics_collector": False,
        },
        "metrics": metrics,
    }
