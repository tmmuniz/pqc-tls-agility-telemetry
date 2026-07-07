# Crypto Config Policy-as-Code

This directory contains the CI helper used by the Docker workflow to validate
TLS crypto-agility configuration before building the image.

The policy is implemented in Rego:

```text
policies/crypto_config.rego
```

The Python helper runs OPA against all project configuration files and writes a
single JSON report:

```text
policy-results/crypto-config-policy-report.json
```

## What is checked

The policy denies configs containing weak or obsolete values in:

- `app.digest_algorithm`
- `app.cipher_algorithm`
- `tls.minimum_version`
- `tls.maximum_version`
- `tls.tls12_cipher_list`
- `tls.tls13_ciphersuites`
- `tls.groups`
- `tls.signature_algorithms`

Examples of denied values include:

- Digest: `MD5`, `SHA1`
- Application cipher: `DES`, `3DES`, `RC4`, `AES-*-CBC`
- TLS versions: `SSLv2`, `SSLv3`, `TLSv1.0`, `TLSv1.1`
- TLS cipher list entries: `NULL`, `EXPORT`, `RC4`, `3DES`, `MD5`, `SHA1`
- TLS groups: `P-192`, `P-224`, `secp192r1`, `ffdhe1024`
- Signature algorithms: `RSA+SHA1`, `ECDSA+SHA1`, `DSA+SHA256`

## Local execution

Install OPA, then run:

```bash
python3 scripts/policy/validate_crypto_config.py \
  --policy policies/crypto_config.rego \
  --report policy-results/crypto-config-policy-report.json \
  config.json docker/config/*.json
```

If any finding is returned by the Rego policy, the script exits with status `1`.
That behavior is used by the Docker workflow to stop the image build before it
starts.
