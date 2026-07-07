# Docker runtime

The Docker image builds one C++ binary and runs three instances with different configuration files:

| Port | Profile | Certificate | TLS groups | Log file |
|---:|---|---|---|---|
| 8443 | Classic | RSA 3072 | X25519:P-256:P-384 | /app/logs/rsa3072-classic.log |
| 8444 | Hybrid | RSA3072_MLDSA44 | X25519MLKEM768:X25519:P-256:P-384 | /app/logs/rsa3072-mldsa44-hybrid.log |
| 8445 | PQC-only | MLDSA44 | MLKEM768 | /app/logs/mldsa44-pqc.log |

The entrypoint generates lab certificates inside the container in `/app/certs` if they are missing.

## Build

```bash
docker build -t pqc-tls:latest .
```

## Run

```bash
mkdir -p logs
sudo chown -R 10001:10001 logs
sudo chmod -R 750 logs

docker run -d \
  --name pqc-tls \
  -p 8443:8443 \
  -p 8444:8444 \
  -p 8445:8445 \
  -v "$PWD/logs:/app/logs:rw" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --restart unless-stopped \
  pqc-tls:latest
```

Do not use `--read-only` with this current lab image unless you also provide a writable tmpfs for `/app/certs`, because certificates are generated inside the container at startup.
