#pragma once

#include "AppConfig.hpp"
#include "TlsServer.hpp"

#include <array>
#include <string>
#include <vector>

/*
  Result of the AES-GCM self-test.

  AES-GCM returns ciphertext and an authentication tag.
*/
struct EncryptionResult {
    std::vector<unsigned char> ciphertext;
    std::array<unsigned char, 16> tag{};
};

/*
  Calculates a digest using an EVP algorithm selected by name.

  Example:
    calculateDigest("SHA256", "hello")
*/
std::vector<unsigned char> calculateDigest(
    const std::string& algorithm,
    const std::string& message
);

/*
  Encrypts a message using an EVP symmetric cipher selected by name.

  Example:
    encryptMessage("AES-256-GCM", "hello")
*/
EncryptionResult encryptMessage(
    const std::string& algorithm,
    const std::string& message
);

/*
  Builds the JSON body returned by the TLS server.

  The response exposes categorized telemetry:
  - metadata: service, status, event type, timestamp and schema version;
  - device: hostname and local IPv4 address;
  - client: source IP address captured from accept();
  - tls: negotiated TLS values, handshake timing, PQC flags and certificate data;
  - evp_selftest: digest and cipher self-test output.
*/
std::string buildCryptoJsonResponse(
    const AppConfig& config,
    const TlsConnectionInfo& connection_info
);
