from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3

from .config import DEFAULT_LOG_GROUPS


def collect_log_events(
    *,
    region: str,
    log_groups: tuple[str, ...] = DEFAULT_LOG_GROUPS,
    lookback_minutes: int = 60,
    limit_per_group: int = 10000,
) -> dict[str, Any]:
    """Collect application log events directly from CloudWatch Logs.

    The collector never reads local files from the EC2 host. The C++ application
    writes JSON lines under /opt/pqc-tls/logs inside the EC2 host and the
    CloudWatch Agent ships those files to the log groups listed in config.py.
    """

    logs = boto3.client("logs", region_name=region)
    start = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
    start_time_ms = int(start.timestamp() * 1000)

    groups: dict[str, Any] = {}
    parsed_events: list[dict[str, Any]] = []

    for group in log_groups:
        events_for_group: list[dict[str, Any]] = []
        next_token: str | None = None
        fetched = 0

        while True:
            remaining = max(1, limit_per_group - fetched)
            kwargs: dict[str, Any] = {
                "logGroupName": group,
                "startTime": start_time_ms,
                "limit": min(10000, remaining),
            }
            if next_token:
                kwargs["nextToken"] = next_token

            try:
                response = logs.filter_log_events(**kwargs)
            except logs.exceptions.ResourceNotFoundException:
                groups[group] = {
                    "exists": False,
                    "raw_event_count": 0,
                    "parsed_event_count": 0,
                    "truncated_by_limit": False,
                    "error": "Log group not found.",
                }
                break

            raw_events = response.get("events", [])
            fetched += len(raw_events)

            for event in raw_events:
                parsed = _parse_log_event(group, event)
                events_for_group.append(parsed)
                if parsed.get("json") is not None:
                    parsed_events.append(parsed)

            next_token = response.get("nextToken")
            if not next_token or fetched >= limit_per_group:
                groups[group] = {
                    "exists": True,
                    "raw_event_count": len(events_for_group),
                    "parsed_event_count": sum(1 for item in events_for_group if item.get("json") is not None),
                    "truncated_by_limit": fetched >= limit_per_group,
                }
                break

    return {
        "region": region,
        "lookback_minutes": lookback_minutes,
        "collection_source": "cloudwatch_logs_api",
        "log_groups": groups,
        "parsed_events": parsed_events,
    }


def _parse_log_event(log_group: str, event: dict[str, Any]) -> dict[str, Any]:
    message = event.get("message", "")
    parsed_json = None
    parse_error = None
    try:
        parsed_json = json.loads(message)
    except json.JSONDecodeError as exc:
        parse_error = str(exc)

    return {
        "log_group": log_group,
        "log_stream_name": event.get("logStreamName"),
        "event_id": event.get("eventId"),
        "timestamp": event.get("timestamp"),
        "ingestion_time": event.get("ingestionTime"),
        "json": parsed_json,
        "parse_error": parse_error,
        "message_snippet": message[:1000] if parsed_json is None else None,
    }
