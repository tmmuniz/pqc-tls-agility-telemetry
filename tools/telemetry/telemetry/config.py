from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TlsActiveTest:
    name: str
    profile: str
    port: int
    group: str
    expected_success: bool
    description: str
    host_header: str


DEFAULT_ACTIVE_TESTS: tuple[TlsActiveTest, ...] = (
    TlsActiveTest(
        name="classic_success_x25519",
        profile="classic-rsa3072",
        port=8443,
        group="X25519",
        expected_success=True,
        description="Classic endpoint should accept a classical X25519 TLS 1.3 group.",
        host_header="rsa3072.local",
    ),
    TlsActiveTest(
        name="classic_failure_mlkem768",
        profile="classic-rsa3072",
        port=8443,
        group="MLKEM768",
        expected_success=False,
        description="Classic endpoint should reject a PQC-only MLKEM768 group.",
        host_header="rsa3072.local",
    ),
    TlsActiveTest(
        name="hybrid_success_x25519mlkem768",
        profile="hybrid-rsa3072-mldsa44",
        port=8444,
        group="X25519MLKEM768",
        expected_success=True,
        description="Hybrid endpoint should accept the X25519MLKEM768 hybrid group when the client supports the certificate signature.",
        host_header="rsa3072-mldsa44.local",
    ),
    TlsActiveTest(
        name="hybrid_failure_mlkem768_only",
        profile="hybrid-rsa3072-mldsa44",
        port=8444,
        group="MLKEM768",
        expected_success=False,
        description="Hybrid endpoint is not configured as PQC-only and should reject MLKEM768-only if no shared group is available.",
        host_header="rsa3072-mldsa44.local",
    ),
    TlsActiveTest(
        name="pqc_success_mlkem768",
        profile="pqc-mldsa44",
        port=8445,
        group="MLKEM768",
        expected_success=True,
        description="PQC-only endpoint should accept MLKEM768 when the client explicitly advertises it.",
        host_header="mldsa44.local",
    ),
    TlsActiveTest(
        name="pqc_failure_x25519",
        profile="pqc-mldsa44",
        port=8445,
        group="X25519",
        expected_success=False,
        description="PQC-only endpoint should reject a classical X25519-only test.",
        host_header="mldsa44.local",
    ),
)


DEFAULT_DEVICE_TAG_KEY = "deviceType"
DEFAULT_DEVICE_TAG_VALUE = "QDevice"

# The CloudWatch Agent default namespace is CWAgent when no custom namespace is configured.
DEFAULT_CLOUDWATCH_NAMESPACE = "CWAgent"


DEFAULT_LOG_GROUPS: tuple[str, ...] = (
    "/pqc-tls/rsa3072-classic",
    "/pqc-tls/rsa3072-mldsa44-hybrid",
    "/pqc-tls/mldsa44-pqc",
)

