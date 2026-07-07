from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .utils import safe_percent, stats


def aggregate_log_events(parsed_events: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(parsed_events)
    success_events = []
    failure_events = []

    by_event_type = Counter()
    by_status = Counter()
    by_group = Counter()
    by_cipher = Counter()
    by_tls_version = Counter()
    by_signature_algorithm = Counter()
    by_public_key_algorithm = Counter()
    by_pqc_group_used = Counter()
    by_pqc_signature = Counter()
    by_client_ip = Counter()
    by_tls_error_name = Counter()
    by_tls_error_reason = Counter()

    durations_all: list[float] = []
    durations_by_group: dict[str, list[float]] = defaultdict(list)
    bytes_read_by_group: dict[str, list[float]] = defaultdict(list)
    bytes_written_by_group: dict[str, list[float]] = defaultdict(list)

    for event in parsed_events:
        payload = event.get("json") or {}
        metadata = payload.get("metadata", {})
        tls = payload.get("tls", {})
        certificate = tls.get("certificate", {}) if isinstance(tls, dict) else {}
        pqc = tls.get("pqc", {}) if isinstance(tls, dict) else {}
        client = payload.get("client", {})
        tls_error = payload.get("tls_error", {})

        status = metadata.get("status", "unknown")
        event_type = metadata.get("event_type", "unknown")
        by_status[status] += 1
        by_event_type[event_type] += 1

        if status == "ok" or event_type == "tls_request":
            success_events.append(event)
        elif status == "error" or event_type == "tls_handshake_failed":
            failure_events.append(event)

        _count_if_present(by_group, tls.get("group"))
        _count_if_present(by_cipher, tls.get("cipher"))
        _count_if_present(by_tls_version, tls.get("version"))
        _count_if_present(by_signature_algorithm, certificate.get("signature_algorithm"))
        _count_if_present(by_public_key_algorithm, certificate.get("public_key_algorithm"))
        _count_if_present(by_client_ip, client.get("ip"))
        _count_bool(by_pqc_group_used, pqc.get("pqc_group_used"))
        _count_bool(by_pqc_signature, pqc.get("pqc_signature"))
        _count_if_present(by_tls_error_name, tls_error.get("ssl_error_name"))
        _count_if_present(by_tls_error_reason, _first_error_reason(tls_error))

        group = tls.get("group") or "unknown"
        duration = tls.get("handshake_duration_ms")
        if isinstance(duration, (int, float)):
            durations_all.append(float(duration))
            durations_by_group[group].append(float(duration))

        handshake_bytes = tls.get("handshake_bytes", {}) if isinstance(tls, dict) else {}
        read_bytes = handshake_bytes.get("read")
        written_bytes = handshake_bytes.get("written")
        if isinstance(read_bytes, (int, float)):
            bytes_read_by_group[group].append(float(read_bytes))
        if isinstance(written_bytes, (int, float)):
            bytes_written_by_group[group].append(float(written_bytes))

    return {
        "totals": {
            "events": total,
            "success_events": len(success_events),
            "failure_events": len(failure_events),
            "success_percent": safe_percent(len(success_events), total),
            "failure_percent": safe_percent(len(failure_events), total),
        },
        "by_status": dict(by_status),
        "by_event_type": dict(by_event_type),
        "tls": {
            "by_group": dict(by_group),
            "by_cipher": dict(by_cipher),
            "by_version": dict(by_tls_version),
            "by_certificate_signature_algorithm": dict(by_signature_algorithm),
            "by_certificate_public_key_algorithm": dict(by_public_key_algorithm),
            "by_pqc_group_used": _bool_counter_to_dict(by_pqc_group_used),
            "by_pqc_signature": _bool_counter_to_dict(by_pqc_signature),
            "handshake_duration_ms": stats(durations_all),
            "handshake_duration_ms_by_group": {
                group: stats(values) for group, values in sorted(durations_by_group.items())
            },
            "handshake_bytes_read_by_group": {
                group: stats(values) for group, values in sorted(bytes_read_by_group.items())
            },
            "handshake_bytes_written_by_group": {
                group: stats(values) for group, values in sorted(bytes_written_by_group.items())
            },
        },
        "client": {
            "by_ip": dict(by_client_ip),
        },
        "errors": {
            "by_ssl_error_name": dict(by_tls_error_name),
            "by_reason": dict(by_tls_error_reason),
        },
    }


def aggregate_active_tests(active_tests: dict[str, Any]) -> dict[str, Any]:
    results = active_tests.get("results", [])
    by_profile = defaultdict(lambda: {"total": 0, "success": 0, "failure": 0, "expectation_mismatch": 0})
    by_group = defaultdict(lambda: {"total": 0, "success": 0, "failure": 0, "expectation_mismatch": 0})

    for item in results:
        test = item.get("test", {})
        profile = test.get("profile", "unknown")
        group = test.get("group", "unknown")
        observed_success = bool(item.get("observed_success"))
        expectation_met = bool(item.get("expectation_met"))

        for bucket in (by_profile[profile], by_group[group]):
            bucket["total"] += 1
            bucket["success"] += 1 if observed_success else 0
            bucket["failure"] += 0 if observed_success else 1
            bucket["expectation_mismatch"] += 0 if expectation_met else 1

    return {
        "by_profile": {key: _with_percentages(value) for key, value in sorted(by_profile.items())},
        "by_test_group": {key: _with_percentages(value) for key, value in sorted(by_group.items())},
    }


def _with_percentages(value: dict[str, int]) -> dict[str, Any]:
    total = value["total"]
    return {
        **value,
        "success_percent": safe_percent(value["success"], total),
        "failure_percent": safe_percent(value["failure"], total),
    }


def _count_if_present(counter: Counter, value: Any) -> None:
    if value is not None and value != "":
        counter[str(value)] += 1


def _count_bool(counter: Counter, value: Any) -> None:
    if value is True:
        counter["true"] += 1
    elif value is False:
        counter["false"] += 1


def _bool_counter_to_dict(counter: Counter) -> dict[str, int]:
    return {"true": int(counter.get("true", 0)), "false": int(counter.get("false", 0))}


def _first_error_reason(tls_error: dict[str, Any]) -> str | None:
    errors = tls_error.get("openssl_errors")
    if isinstance(errors, list) and errors:
        first = errors[0]
        if isinstance(first, dict):
            return first.get("reason") or first.get("description")
    return tls_error.get("description")
