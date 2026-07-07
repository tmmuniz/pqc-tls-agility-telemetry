from __future__ import annotations

import argparse
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .config import DEFAULT_ACTIVE_TESTS, TlsActiveTest
from .utils import extract_first_json_object, json_dumps, utc_now_iso


def _build_http_request(host_header: str) -> str:
    return f'printf "GET / HTTP/1.1\\r\\nHost: {host_header}\\r\\nConnection: close\\r\\n\\r\\n"'


def _openssl_command_local(target_host: str, test: TlsActiveTest, openssl_bin: str) -> list[str]:
    http_request = _build_http_request(test.host_header)
    cmd = (
        f"{http_request} | {openssl_bin} s_client "
        f"-connect {target_host}:{test.port} "
        f"-tls1_3 -groups {test.group} -quiet"
    )
    return ["bash", "-lc", cmd]


def _openssl_command_oqs_docker(
    target_host: str,
    test: TlsActiveTest,
    oqs_image: str,
    *,
    docker_network: str | None = None,
) -> list[str]:
    http_request = _build_http_request(test.host_header)
    inner = (
        f"{http_request} | /opt/openssl/bin/openssl s_client "
        f"-provider oqsprovider -provider default "
        f"-connect {target_host}:{test.port} "
        f"-tls1_3 -groups {test.group} -quiet"
    )
    cmd = ["docker", "run", "--rm"]
    if docker_network:
        cmd.extend(["--network", docker_network])
    cmd.extend([oqs_image, "sh", "-lc", inner])
    return cmd


def run_active_tls_test(
    target_host: str,
    test: TlsActiveTest,
    *,
    use_oqs_docker: bool,
    oqs_image: str,
    openssl_bin: str,
    timeout_seconds: int,
    docker_network: str | None = None,
) -> dict[str, Any]:
    command = (
        _openssl_command_oqs_docker(target_host, test, oqs_image, docker_network=docker_network)
        if use_oqs_docker
        else _openssl_command_local(target_host, test, openssl_bin)
    )

    started_at = utc_now_iso()
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        combined_output = stdout + "\n" + stderr
        json_response = extract_first_json_object(combined_output)
        observed_success = completed.returncode == 0 and json_response is not None

        return {
            "test": asdict(test),
            "started_at": started_at,
            "completed_at": utc_now_iso(),
            "execution": {
                "location": "ec2_local_or_runner",
                "method": "oqs_docker" if use_oqs_docker else "local_openssl",
                "target_host": target_host,
                "docker_network": docker_network,
                "return_code": completed.returncode,
                "timeout_seconds": timeout_seconds,
            },
            "observed_success": observed_success,
            "expected_success": test.expected_success,
            "expectation_met": observed_success == test.expected_success,
            "json_response": json_response,
            "error": None if observed_success else _summarize_error(stderr, stdout),
            "output_snippet": combined_output[-3000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "test": asdict(test),
            "started_at": started_at,
            "completed_at": utc_now_iso(),
            "execution": {
                "location": "ec2_local_or_runner",
                "method": "oqs_docker" if use_oqs_docker else "local_openssl",
                "target_host": target_host,
                "docker_network": docker_network,
                "return_code": None,
                "timeout_seconds": timeout_seconds,
            },
            "observed_success": False,
            "expected_success": test.expected_success,
            "expectation_met": False == test.expected_success,
            "json_response": None,
            "error": {
                "type": "timeout",
                "description": f"TLS active test exceeded {timeout_seconds} seconds.",
            },
            "output_snippet": ((exc.stdout or "") + "\n" + (exc.stderr or ""))[-3000:],
        }


def _summarize_error(stderr: str, stdout: str) -> dict[str, str | None]:
    output = stderr or stdout or ""
    lower = output.lower()
    if "handshake failure" in lower:
        error_type = "tls_handshake_failure"
    elif "no shared" in lower:
        error_type = "no_shared_tls_parameter"
    elif "certificate" in lower:
        error_type = "certificate_or_signature_error"
    elif "connection refused" in lower:
        error_type = "connection_refused"
    else:
        error_type = "openssl_or_connection_error"
    return {
        "type": error_type,
        "description": output.strip()[-1000:] if output.strip() else None,
    }


def run_active_tls_tests(
    target_host: str,
    *,
    use_oqs_docker: bool = True,
    oqs_image: str = "openquantumsafe/oqs-ossl3:latest-x86_64",
    openssl_bin: str = "openssl",
    timeout_seconds: int = 15,
    tests: tuple[TlsActiveTest, ...] = DEFAULT_ACTIVE_TESTS,
    docker_network: str | None = None,
    execution_location: str = "local",
) -> dict[str, Any]:
    results = [
        run_active_tls_test(
            target_host,
            test,
            use_oqs_docker=use_oqs_docker,
            oqs_image=oqs_image,
            openssl_bin=openssl_bin,
            timeout_seconds=timeout_seconds,
            docker_network=docker_network,
        )
        for test in tests
    ]

    total = len(results)
    observed_success = sum(1 for item in results if item["observed_success"])
    observed_failure = total - observed_success
    expectation_matches = sum(1 for item in results if item["expectation_met"])

    return {
        "execution_context": {
            "location": execution_location,
            "target_host": target_host,
            "method": "oqs_docker" if use_oqs_docker else "local_openssl",
            "docker_network": docker_network,
            "oqs_image": oqs_image if use_oqs_docker else None,
            "openssl_bin": openssl_bin if not use_oqs_docker else "/opt/openssl/bin/openssl",
        },
        "summary": {
            "total_tests": total,
            "observed_success": observed_success,
            "observed_failure": observed_failure,
            "observed_success_percent": round((observed_success / total) * 100, 2) if total else 0.0,
            "observed_failure_percent": round((observed_failure / total) * 100, 2) if total else 0.0,
            "expectation_matches": expectation_matches,
            "expectation_mismatches": total - expectation_matches,
            "expectation_match_percent": round((expectation_matches / total) * 100, 2) if total else 0.0,
        },
        "results": results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run active TLS success/failure tests against the PQC TLS lab endpoints."
    )
    parser.add_argument("--target-host", default="127.0.0.1", help="Target host. Use 127.0.0.1 when running directly on the EC2 instance.")
    parser.add_argument("--output", default="active-tls-tests.json", help="Output JSON path.")
    parser.add_argument("--use-oqs-docker", action="store_true", help="Run openssl s_client through the OQS Docker image.")
    parser.add_argument("--oqs-image", default="openquantumsafe/oqs-ossl3:latest-x86_64", help="OQS Docker image.")
    parser.add_argument("--openssl-bin", default="openssl", help="OpenSSL binary when not using OQS Docker.")
    parser.add_argument("--timeout-seconds", type=int, default=20, help="Timeout for each active TLS test.")
    parser.add_argument("--docker-network", default=None, help="Optional Docker network for OQS Docker tests. Use 'host' on EC2 to reach 127.0.0.1 on the host.")
    parser.add_argument("--execution-location", default="ec2_ssm", help="Label recorded in the JSON execution context.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = run_active_tls_tests(
        args.target_host,
        use_oqs_docker=args.use_oqs_docker,
        oqs_image=args.oqs_image,
        openssl_bin=args.openssl_bin,
        timeout_seconds=args.timeout_seconds,
        docker_network=args.docker_network,
        execution_location=args.execution_location,
    )
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json_dumps(result) + "\n", encoding="utf-8")
    print(f"Wrote active TLS test result to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
