#!/usr/bin/env python3
"""Validate crypto-agility config files with OPA/Rego.

The script evaluates policy/rego/crypto_config.rego against one or more JSON
configuration files. It writes a machine-readable report and exits non-zero
when any deny finding is returned by the Rego policy.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate TLS crypto config files with OPA/Rego.")
    parser.add_argument("configs", nargs="+", help="config.json files to validate")
    parser.add_argument("--policy", default="policy/rego/crypto_config.rego", help="Path to Rego policy file")
    parser.add_argument("--report", default="policy-results/crypto-config-policy-report.json", help="Output JSON report path")
    parser.add_argument("--opa-bin", default="opa", help="OPA binary path")
    return parser.parse_args()


def require_opa(opa_bin: str) -> None:
    if shutil.which(opa_bin) is None:
        raise RuntimeError(f"OPA binary not found: {opa_bin}")


def evaluate_config(opa_bin: str, policy: Path, config_file: Path) -> list[dict[str, Any]]:
    command = [
        opa_bin,
        "eval",
        "--format=json",
        "--data",
        str(policy),
        "--input",
        str(config_file),
        "data.crypto_config.deny",
    ]
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"OPA evaluation failed for {config_file}\n"
            f"STDOUT:\n{completed.stdout}\n"
            f"STDERR:\n{completed.stderr}"
        )

    payload = json.loads(completed.stdout)
    result = payload.get("result", [])
    if not result:
        return []

    expressions = result[0].get("expressions", [])
    if not expressions:
        return []

    findings = expressions[0].get("value", []) or []
    normalized_findings: list[dict[str, Any]] = []
    for finding in findings:
        normalized = dict(finding)
        normalized["file"] = str(config_file)
        normalized_findings.append(normalized)
    return normalized_findings


def main() -> int:
    args = parse_args()
    policy = Path(args.policy)
    report_path = Path(args.report)
    config_files = [Path(item) for item in args.configs]

    try:
        require_opa(args.opa_bin)
        if not policy.is_file():
            raise FileNotFoundError(f"Policy file not found: {policy}")

        all_findings: list[dict[str, Any]] = []
        per_file: dict[str, Any] = {}

        for config_file in config_files:
            if not config_file.is_file():
                raise FileNotFoundError(f"Config file not found: {config_file}")
            findings = evaluate_config(args.opa_bin, policy, config_file)
            per_file[str(config_file)] = {
                "status": "fail" if findings else "pass",
                "finding_count": len(findings),
                "findings": findings,
            }
            all_findings.extend(findings)

        report = {
            "metadata": {
                "schema_version": "1.0",
                "tool": "opa-rego-crypto-config-policy",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "policy_file": str(policy),
            },
            "summary": {
                "status": "fail" if all_findings else "pass",
                "validated_files": len(config_files),
                "finding_count": len(all_findings),
            },
            "files": per_file,
            "findings": all_findings,
        }

        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        print(json.dumps(report["summary"], indent=2, sort_keys=True))
        if all_findings:
            print("\nPolicy findings:", file=sys.stderr)
            for finding in all_findings:
                print(
                    f"- [{finding['severity']}] {finding['file']}::{finding['field']} "
                    f"{finding['rule_id']} - {finding['message']}",
                    file=sys.stderr,
                )
            print(f"\nFull report: {report_path}", file=sys.stderr)
            return 1

        print(f"Policy passed. Report: {report_path}")
        return 0

    except Exception as exc:  # noqa: BLE001 - CI should surface any validation failure clearly.
        print(f"Policy validation error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
