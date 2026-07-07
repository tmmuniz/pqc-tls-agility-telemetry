package crypto_config

import rego.v1

default allow := true

# Deny findings are intentionally structured so the CI report can be consumed
# by humans and automation. The policy validates the categorized config.json
# schema used by this project:
# - app.digest_algorithm
# - app.cipher_algorithm
# - tls.minimum_version / tls.maximum_version
# - tls.tls12_cipher_list
# - tls.tls13_ciphersuites
# - tls.groups
# - tls.signature_algorithms

deny contains finding if {
  app := object.get(input, "app", {})
  algo := normalize(object.get(app, "digest_algorithm", ""))
  weak_digest_algorithms[algo]

  finding := build_finding(
    "high",
    "app.digest_algorithm",
    algo,
    "weak_or_obsolete_digest_algorithm",
    sprintf("Digest algorithm %q is weak or obsolete.", [algo]),
    "Use SHA256, SHA384, SHA512, SHA3-256, SHA3-384 or SHA3-512."
  )
}

deny contains finding if {
  app := object.get(input, "app", {})
  algo := normalize(object.get(app, "cipher_algorithm", ""))
  weak_cipher_algorithms[algo]

  finding := build_finding(
    "high",
    "app.cipher_algorithm",
    algo,
    "weak_or_obsolete_cipher_algorithm",
    sprintf("Cipher algorithm %q is weak, obsolete or not AEAD-oriented for this baseline.", [algo]),
    "Use an AEAD cipher such as AES-256-GCM, AES-128-GCM or CHACHA20-POLY1305."
  )
}

deny contains finding if {
  tls := object.get(input, "tls", {})
  field := tls_version_fields[_]
  value := normalize(object.get(tls, field, ""))
  weak_tls_versions[value]

  finding := build_finding(
    "critical",
    sprintf("tls.%s", [field]),
    value,
    "weak_or_obsolete_tls_version",
    sprintf("TLS version %q is obsolete and must not be configured.", [value]),
    "Use TLSv1.2 as the minimum legacy-compatible baseline or TLSv1.3 for this PQC lab."
  )
}

deny contains finding if {
  tls := object.get(input, "tls", {})
  field := tls_list_fields[_]
  raw_value := object.get(tls, field, "")
  entry := split_config_list(raw_value)[_]
  token := weak_tls_list_tokens[field][_]
  indexof(entry, token) != -1

  finding := build_finding(
    severity_for_tls_list_field(field),
    sprintf("tls.%s", [field]),
    entry,
    sprintf("weak_or_obsolete_%s_entry", [field]),
    sprintf("TLS configuration field %q contains weak or obsolete entry %q matching token %q.", [field, entry, token]),
    recommendation_for_tls_list_field(field)
  )
}

deny contains finding if {
  tls := object.get(input, "tls", {})
  field := "signature_algorithms"
  raw_value := object.get(tls, field, "")
  entry := split_config_list(raw_value)[_]
  weak_signature_algorithms[entry]

  finding := build_finding(
    "high",
    "tls.signature_algorithms",
    entry,
    "weak_or_obsolete_signature_algorithm",
    sprintf("TLS signature algorithm list contains weak or obsolete entry %q.", [entry]),
    "Use SHA-256 or stronger RSA/ECDSA signatures, or approved PQC signatures such as ML-DSA where client compatibility is expected. Avoid classic DSA and SHA-1/MD5-based signatures."
  )
}

# Flag empty security-relevant lists. This prevents accidentally building an image
# with an unconstrained OpenSSL/default policy where the intended crypto baseline
# is not explicit.
deny contains finding if {
  tls := object.get(input, "tls", {})
  field := required_tls_fields[_]
  value := object.get(tls, field, "")
  normalize(value) == ""

  finding := build_finding(
    "medium",
    sprintf("tls.%s", [field]),
    value,
    "missing_tls_security_field",
    sprintf("Required TLS security field %q is empty or missing.", [field]),
    "Declare the TLS setting explicitly in config.json."
  )
}

# Helper data

tls_version_fields := {"minimum_version", "maximum_version"}

weak_tls_versions := {
  "sslv2",
  "sslv3",
  "tlsv1",
  "tlsv1.0",
  "tlsv1.1",
  "tls1",
  "tls1.0",
  "tls1.1",
  "1.0",
  "1.1"
}

weak_digest_algorithms := {
  "md2",
  "md4",
  "md5",
  "sha1",
  "sha-1",
  "ripemd160"
}

weak_cipher_algorithms := {
  "des",
  "3des",
  "des-ede3-cbc",
  "des-ede-cbc",
  "rc2",
  "rc4",
  "bf-cbc",
  "blowfish",
  "idea",
  "seed",
  "aes-128-cbc",
  "aes-256-cbc"
}

tls_list_fields := {"tls12_cipher_list", "tls13_ciphersuites", "groups"}

required_tls_fields := {
  "minimum_version",
  "maximum_version",
  "tls13_ciphersuites",
  "groups",
  "signature_algorithms"
}

weak_tls_list_tokens := {
  "tls12_cipher_list": {
    "null",
    "anon",
    "export",
    "rc4",
    "3des",
    "des-cbc",
    "des-ede",
    "md5",
    "sha1",
    "psk-null",
    "anull",
    "enull"
  },
  "tls13_ciphersuites": {
    "null",
    "anon",
    "export",
    "rc4",
    "3des",
    "des",
    "md5",
    "sha1"
  },
  "groups": {
    "p-192",
    "p-224",
    "secp192",
    "secp224",
    "prime192v1",
    "sect163",
    "sect233",
    "sect283",
    "ffdhe1024",
    "dh1024"
  }
}

# Signature algorithms are matched exactly to avoid false positives such as
# matching "dsa+sha256" inside "ecdsa+sha256".
weak_signature_algorithms := {
  "md5",
  "sha1",
  "rsa+md5",
  "rsa+sha1",
  "ecdsa+sha1",
  "dsa+sha1",
  "dsa+sha224",
  "dsa+sha256",
  "dsa+sha384",
  "dsa+sha512"
}

severity_for_tls_list_field(field) := severity if {
  field == "groups"
  severity := "high"
} else := severity if {
  field != "groups"
  severity := "critical"
}

recommendation_for_tls_list_field(field) := recommendation if {
  field == "groups"
  recommendation := "Use modern classical groups such as X25519/P-256/P-384, hybrid groups such as X25519MLKEM768, or approved PQC groups where supported."
} else := recommendation if {
  field != "groups"
  recommendation := "Use AEAD cipher suites with SHA-256 or stronger, such as TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 or ECDHE-RSA-AES256-GCM-SHA384."
}

split_config_list(raw_value) := entries if {
  parts := split(normalize(raw_value), ":")
  entries := {entry |
    some i
    entry := parts[i]
    entry != ""
  }
}

normalize(value) := lower(sprintf("%v", [value]))

build_finding(severity, field, value, rule_id, message, recommendation) := finding if {
  finding := {
    "severity": severity,
    "field": field,
    "value": value,
    "rule_id": rule_id,
    "message": message,
    "recommendation": recommendation
  }
}
