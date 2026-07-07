#include "AppConfig.hpp"
#include "CryptoEvp.hpp"
#include "OpenSslUtils.hpp"
#include "TlsServer.hpp"

#include <openssl/provider.h>

#include <nlohmann/json.hpp>

#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

using json = nlohmann::ordered_json;

/*
  Builds a simple JSON response for unknown endpoints.
*/
static std::string buildNotFoundResponse(const std::string& path) {
    json response;
    response["metadata"] = {
        {"service", "pqc-tls"},
        {"status", "not_found"},
        {"event_type", "route_not_found"},
        {"schema_version", "1.0"}
    };
    response["path"] = path;
    response["available_paths"] = {"/", "/crypto-selftest"};

    return response.dump(2);
}

/*
  Application entry point.

  Responsibilities:
  1. Read the configuration file.
  2. Load the OpenSSL default provider.
  3. Create a TLS server using libssl.
  4. Route simple HTTP paths:
     - / and /crypto-selftest: categorized TLS + EVP response.
  5. Log each JSON response to log_file in append-only write mode.

  PQC scope in this version:
  - PQC appears in TLS telemetry through the negotiated TLS group.
  - No direct ML-KEM or ML-DSA EVP self-test is implemented here.
*/
int main(int argc, char* argv[]) {
    try {
        /*
          Allow a custom config file path:
            ./build/tls_crypto_server app/config/config.json
            ./build/tls_crypto_server app/config/config.classic.json
        */
        std::string config_path = "app/config/config.json";

        if (argc > 1) {
            config_path = argv[1];
        }

        AppConfig config = loadConfig(config_path);

        /*
          Load OpenSSL providers.

          The default provider supplies common algorithms such as SHA256 and
          AES-256-GCM. The OQS provider is loaded when available so the same
          binary can be used with PQC and hybrid TLS groups/signatures.
        */
        using ProviderPtr = std::unique_ptr<OSSL_PROVIDER, decltype(&OSSL_PROVIDER_unload)>;

        ProviderPtr oqs_provider(
            OSSL_PROVIDER_load(nullptr, "oqsprovider"),
            OSSL_PROVIDER_unload
        );

        if (!oqs_provider) {
            std::cerr << "Warning: OpenSSL OQS provider was not loaded. "
                      << "Hybrid/PQC configs may fail if algorithms are unavailable.\n";
        } else {
            std::cout << "Loaded OpenSSL OQS provider.\n";
        }

        ProviderPtr default_provider(
            OSSL_PROVIDER_load(nullptr, "default"),
            OSSL_PROVIDER_unload
        );

        if (!default_provider) {
            throw std::runtime_error(
                "Could not load OpenSSL default provider: " + getOpenSslError()
            );
        }

        std::cout << "Loaded config file: " << config_path << "\n";

        TlsServer server(config);

        /*
          The TLS server parses the HTTP path and provides runtime TLS data
          from the current request. The lambda below routes the response.
        */
        server.run([&config](
            const HttpRequest& request,
            const TlsConnectionInfo& connection_info
        ) {
            if (request.path == "/" || request.path == "/crypto-selftest") {
                return buildCryptoJsonResponse(config, connection_info);
            }

            return buildNotFoundResponse(request.path);
        });

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Fatal error: " << ex.what() << "\n";
        return 1;
    }
}
