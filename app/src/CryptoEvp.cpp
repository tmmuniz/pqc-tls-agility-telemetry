#include "CryptoEvp.hpp"

#include "OpenSslUtils.hpp"
#include "SystemInfo.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <stdexcept>
#include <vector>

#include <nlohmann/json.hpp>

using json = nlohmann::ordered_json;

/*
  Calculates a message digest using OpenSSL EVP.

  Crypto-agility point:
  the algorithm is loaded by name with EVP_MD_fetch().
  The code does not call SHA256() directly.
*/
std::vector<unsigned char> calculateDigest(
    const std::string& algorithm,
    const std::string& message
) {
    using MdPtr = std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)>;
    using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

    MdPtr md(
        EVP_MD_fetch(nullptr, algorithm.c_str(), nullptr),
        EVP_MD_free
    );

    if (!md) {
        throw std::runtime_error(
            "Could not load digest algorithm '" + algorithm + "': " + getOpenSslError()
        );
    }

    MdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!ctx) {
        throw std::runtime_error("Could not create digest context");
    }

    if (EVP_DigestInit_ex(ctx.get(), md.get(), nullptr) != 1) {
        throw std::runtime_error("EVP_DigestInit_ex failed: " + getOpenSslError());
    }

    if (EVP_DigestUpdate(ctx.get(), message.data(), message.size()) != 1) {
        throw std::runtime_error("EVP_DigestUpdate failed: " + getOpenSslError());
    }

    std::vector<unsigned char> digest(EVP_MD_get_size(md.get()));
    unsigned int digest_length = 0;

    if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &digest_length) != 1) {
        throw std::runtime_error("EVP_DigestFinal_ex failed: " + getOpenSslError());
    }

    digest.resize(digest_length);

    return digest;
}

/*
  Encrypts a message using OpenSSL EVP.

  Crypto-agility point:
  the cipher is loaded by name with EVP_CIPHER_fetch().

  This is not PQC. It is only a symmetric encryption self-test.
  PQC in this version is limited to TLS group configuration.
*/
EncryptionResult encryptMessage(
    const std::string& algorithm,
    const std::string& message
) {
    using CipherPtr = std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)>;
    using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

    CipherPtr cipher(
        EVP_CIPHER_fetch(nullptr, algorithm.c_str(), nullptr),
        EVP_CIPHER_free
    );

    if (!cipher) {
        throw std::runtime_error(
            "Could not load cipher algorithm '" + algorithm + "': " + getOpenSslError()
        );
    }

    CipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (!ctx) {
        throw std::runtime_error("Could not create cipher context");
    }

    /*
      Demo key and IV.

      This is only for a portfolio self-test.
      In production:
      - never hardcode keys;
      - never reuse IVs with the same key in AES-GCM;
      - generate IVs securely;
      - use KMS, HSM or another secure key-management layer.
    */
    const int key_length = EVP_CIPHER_get_key_length(cipher.get());

    std::vector<unsigned char> key(key_length, 0x42);
    std::vector<unsigned char> iv(12, 0x24);

    if (EVP_EncryptInit_ex(ctx.get(), cipher.get(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("EVP_EncryptInit_ex failed: " + getOpenSslError());
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
        throw std::runtime_error("Could not set GCM IV length: " + getOpenSslError());
    }

    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw std::runtime_error("Could not set key and IV: " + getOpenSslError());
    }

    std::vector<unsigned char> plaintext(message.begin(), message.end());

    std::vector<unsigned char> ciphertext(
        plaintext.size() + EVP_CIPHER_get_block_size(cipher.get())
    );

    int output_length = 0;
    int total_length = 0;

    if (EVP_EncryptUpdate(
            ctx.get(),
            ciphertext.data(),
            &output_length,
            plaintext.data(),
            plaintext.size()
        ) != 1) {
        throw std::runtime_error("EVP_EncryptUpdate failed: " + getOpenSslError());
    }

    total_length += output_length;

    if (EVP_EncryptFinal_ex(
            ctx.get(),
            ciphertext.data() + total_length,
            &output_length
        ) != 1) {
        throw std::runtime_error("EVP_EncryptFinal_ex failed: " + getOpenSslError());
    }

    total_length += output_length;
    ciphertext.resize(total_length);

    EncryptionResult result;
    result.ciphertext = ciphertext;

    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(),
            EVP_CTRL_GCM_GET_TAG,
            result.tag.size(),
            result.tag.data()
        ) != 1) {
        throw std::runtime_error("Could not get GCM tag: " + getOpenSslError());
    }

    return result;
}

/*
  Returns true when a text value looks like a post-quantum algorithm name.

  This helper is intentionally broad because algorithm naming may vary across
  OpenSSL builds and providers, for example:
  - ML-DSA-65;
  - MLDSA65;
  - SLH-DSA;
  - SPHINCS+;
  - Dilithium, in older experimental provider naming.
*/
static bool containsPqcName(const std::string& value) {
    std::string lower = value;

    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    return lower.find("mlkem") != std::string::npos ||
           lower.find("ml-kem") != std::string::npos ||
           lower.find("mldsa") != std::string::npos ||
           lower.find("ml-dsa") != std::string::npos ||
           lower.find("slhdsa") != std::string::npos ||
           lower.find("slh-dsa") != std::string::npos ||
           lower.find("sphincs") != std::string::npos ||
           lower.find("dilithium") != std::string::npos ||
           lower.find("falcon") != std::string::npos;
}

/*
  Builds a JSON response for collection by curl, Python or GitHub Actions.

  The response exposes only values that were used or observed in the current
  request, plus the EVP self-test result.
*/
std::string buildCryptoJsonResponse(
    const AppConfig& config,
    const TlsConnectionInfo& connection_info
) {
    std::vector<unsigned char> digest =
        calculateDigest(config.digest_algorithm, config.message);

    EncryptionResult encrypted =
        encryptMessage(config.cipher_algorithm, config.message);

    const bool tls_group_available =
        !connection_info.tls_group.empty() && connection_info.tls_group != "unknown";

    const bool pqc_group_used =
        tls_group_available && containsPqcName(connection_info.tls_group);

    const bool pqc_signature =
        containsPqcName(connection_info.certificate.signature_algorithm) ||
        containsPqcName(connection_info.certificate.public_key_algorithm);

    json tls;
    tls["version"] = connection_info.tls_version;
    tls["cipher"] = connection_info.tls_cipher;

    if (tls_group_available) {
        tls["group"] = connection_info.tls_group;
    }

    tls["handshake_duration_ms"] = connection_info.handshake_duration_ms;
    tls["handshake_bytes"] = {
        {"read", connection_info.handshake_bytes_read},
        {"written", connection_info.handshake_bytes_written}
    };

    /*
      Keep pqc before certificate in the serialized output.
    */
    tls["pqc"] = {
        {"pqc_group_used", pqc_group_used},
        {"pqc_signature", pqc_signature}
    };

    tls["certificate"] = {
        {"signature_algorithm", connection_info.certificate.signature_algorithm},
        {"public_key_algorithm", connection_info.certificate.public_key_algorithm},
        {"public_key_bits", connection_info.certificate.public_key_bits},
        {"days_to_expire", connection_info.certificate.days_to_expire}
    };

    json response;
    response["metadata"] = {
        {"service", "pqc-tls"},
        {"status", "ok"},
        {"event_type", "tls_request"},
        {"timestamp", getUnixTimestamp()},
        {"schema_version", "1.0"}
    };

    response["device"] = {
        {"name", getDeviceHostname()},
        {"ip", getDeviceIPv4Address()}
    };

    response["client"] = {
        {"ip", connection_info.client_ip}
    };

    response["tls"] = tls;

    response["evp_selftest"] = {
        {"digest", {
            {"algorithm", config.digest_algorithm},
            {"status", "pass"},
            {"digest_hex", toHex(digest.data(), digest.size())}
        }},
        {"cipher", {
            {"algorithm", config.cipher_algorithm},
            {"status", "pass"},
            {"ciphertext_hex", toHex(encrypted.ciphertext.data(), encrypted.ciphertext.size())},
            {"gcm_tag_hex", toHex(encrypted.tag.data(), encrypted.tag.size())}
        }},
        {"message", config.message}
    };

    return response.dump(2);
}
