#!/usr/bin/env bash
set -Eeuo pipefail

export LD_LIBRARY_PATH="/opt/openssl/lib64:/opt/openssl/lib:${LD_LIBRARY_PATH:-}"

if [ -d /opt/openssl/lib64/ossl-modules ]; then
  export OPENSSL_MODULES="/opt/openssl/lib64/ossl-modules"
elif [ -d /opt/openssl/lib/ossl-modules ]; then
  export OPENSSL_MODULES="/opt/openssl/lib/ossl-modules"
fi

APP_BIN="/app/bin/tls_crypto_server"
OPENSSL_BIN="${OPENSSL_BIN:-/opt/openssl/bin/openssl}"

CERT_BASE_DIR="/app/certs"
LOG_BASE_DIR="/app/logs"

CLASSIC_CERT_DIR="${CERT_BASE_DIR}/rsa3072"
HYBRID_CERT_DIR="${CERT_BASE_DIR}/rsa3072_mldsa44"
PQC_CERT_DIR="${CERT_BASE_DIR}/mldsa44"

CONFIGS=(
  "/app/config/config-rsa3072-classic.json"
  "/app/config/config-rsa3072-mldsa44-hybrid.json"
  "/app/config/config-mldsa44-pqc.json"
)

pids=()

log() {
  printf '[entrypoint] %s\n' "$*"
}

die() {
  printf '[entrypoint] ERROR: %s\n' "$*" >&2
  exit 1
}

require_file() {
  local file="$1"
  [ -r "$file" ] || die "Missing or unreadable file: $file"
}

require_executable() {
  local file="$1"
  [ -x "$file" ] || die "Missing or non-executable file: $file"
}

prepare_directories() {
  mkdir -p \
    "$LOG_BASE_DIR" \
    "$CLASSIC_CERT_DIR" \
    "$HYBRID_CERT_DIR" \
    "$PQC_CERT_DIR"
}

validate_openssl() {
  require_executable "$OPENSSL_BIN"

  log "Using OpenSSL binary: $OPENSSL_BIN"

  if [ -n "${OPENSSL_MODULES:-}" ]; then
    log "Using OpenSSL modules: $OPENSSL_MODULES"
  fi

  "$OPENSSL_BIN" version >/dev/null

  "$OPENSSL_BIN" list -providers \
    -provider oqsprovider \
    -provider default >/dev/null 2>&1 \
    || die "Unable to load oqsprovider and default provider."
}

generate_cert_if_missing() {
  local cert_dir="$1"
  local algorithm="$2"
  local subject="$3"
  local requires_oqs_provider="$4"

  local key_file="${cert_dir}/server.key"
  local cert_file="${cert_dir}/server.crt"

  if [ -f "$key_file" ] && [ -f "$cert_file" ]; then
    log "Certificate already exists in $cert_dir; keeping existing files."
    return
  fi

  log "Generating lab certificate: algorithm=$algorithm dir=$cert_dir"

  if [ "$requires_oqs_provider" = "true" ]; then
    "$OPENSSL_BIN" req -x509 -new -newkey "$algorithm" \
      -provider oqsprovider \
      -provider default \
      -keyout "$key_file" \
      -out "$cert_file" \
      -days 365 \
      -nodes \
      -subj "$subject"
  else
    "$OPENSSL_BIN" req -x509 -newkey "$algorithm" \
      -keyout "$key_file" \
      -out "$cert_file" \
      -days 365 \
      -nodes \
      -subj "$subject"
  fi

  chmod 600 "$key_file"
  chmod 644 "$cert_file"
}

generate_lab_certificates() {
  generate_cert_if_missing \
    "$CLASSIC_CERT_DIR" \
    "rsa:3072" \
    "/C=BR/ST=SP/L=SaoPaulo/O=CryptoLab/OU=Classic/CN=rsa3072.local" \
    "false"

  generate_cert_if_missing \
    "$HYBRID_CERT_DIR" \
    "rsa3072_mldsa44" \
    "/C=BR/ST=SP/L=SaoPaulo/O=CryptoLab/OU=Hybrid/CN=rsa3072-mldsa44.local" \
    "true"

  generate_cert_if_missing \
    "$PQC_CERT_DIR" \
    "mldsa44" \
    "/C=BR/ST=SP/L=SaoPaulo/O=CryptoLab/OU=PQC/CN=mldsa44.local" \
    "true"
}

validate_runtime_files() {
  require_executable "$APP_BIN"

  for config in "${CONFIGS[@]}"; do
    require_file "$config"
  done

  require_file "$CLASSIC_CERT_DIR/server.crt"
  require_file "$CLASSIC_CERT_DIR/server.key"
  require_file "$HYBRID_CERT_DIR/server.crt"
  require_file "$HYBRID_CERT_DIR/server.key"
  require_file "$PQC_CERT_DIR/server.crt"
  require_file "$PQC_CERT_DIR/server.key"
}

start_instance() {
  local config="$1"
  log "Starting tls_crypto_server with $config"
  "$APP_BIN" "$config" &
  pids+=("$!")
}

shutdown() {
  local code=${1:-0}

  if [ "${#pids[@]}" -gt 0 ]; then
    log "Stopping pqc-tls instances..."
    kill -TERM "${pids[@]}" 2>/dev/null || true
    wait "${pids[@]}" 2>/dev/null || true
  fi

  exit "$code"
}

main() {
  trap 'shutdown 143' TERM INT

  prepare_directories
  validate_openssl
  generate_lab_certificates
  validate_runtime_files

  for config in "${CONFIGS[@]}"; do
    start_instance "$config"
  done

  log "All TLS instances started."
  log "8443 classic RSA3072"
  log "8444 hybrid RSA3072_MLDSA44 + X25519MLKEM768"
  log "8445 PQC MLDSA44 + MLKEM768"

  set +e
  wait -n "${pids[@]}"
  status=$?
  set -e

  shutdown "$status"
}

main "$@"
