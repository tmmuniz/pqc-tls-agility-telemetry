#pragma once

#include "AppConfig.hpp"

#include <openssl/ssl.h>

#include <cstdint>
#include <functional>
#include <string>

/*
  HttpRequest stores the minimal HTTP request data needed by this lab.

  This is not a complete HTTP parser. It only extracts the first request line,
  for example:
    GET / HTTP/1.1

  That is enough to route endpoints such as:
    /
    /crypto-selftest
*/
struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::string raw;
};

/*
  CertificateInfo stores selected information from the server certificate
  actually used by the TLS connection.

  These values are useful as device-level telemetry and can be used by
  collectors to create thresholds such as:
  - certificate expiration < 30 days;
  - RSA key length below baseline;
  - PQC signature present or absent.
*/
struct CertificateInfo {
    std::string signature_algorithm;
    std::string public_key_algorithm;
    int public_key_bits = 0;
    int days_to_expire = 0;
};

/*
  TlsConnectionInfo stores values observed from the actual TLS request.

  These fields are runtime telemetry, not only declared configuration.
*/
struct TlsConnectionInfo {
    std::string tls_version;
    std::string tls_cipher;
    std::string tls_group;
    double handshake_duration_ms = 0.0;
    std::uint64_t handshake_bytes_read = 0;
    std::uint64_t handshake_bytes_written = 0;
    std::string client_ip;
    CertificateInfo certificate;
};

/*
  TlsServer owns the network and TLS transport layer.

  Responsibilities:
  - create a TCP socket;
  - bind to listen_address:listen_port;
  - create and configure SSL_CTX;
  - apply TLS settings from config.json;
  - accept TLS connections;
  - collect request-level TLS telemetry;
  - log TLS handshake failures as JSON events;
  - parse the HTTP path;
  - return and log a simple HTTP JSON response.
*/
class TlsServer {
public:
    using ResponseBuilder = std::function<std::string(
        const HttpRequest&,
        const TlsConnectionInfo&
    )>;

    explicit TlsServer(const AppConfig& config);

    ~TlsServer();

    TlsServer(const TlsServer&) = delete;
    TlsServer& operator=(const TlsServer&) = delete;

    /*
      Starts the blocking server loop.

      This demo handles one connection at a time.
    */
    void run(const ResponseBuilder& response_builder);

private:
    AppConfig config_;
    SSL_CTX* ssl_ctx_;
    int server_fd_;

    SSL_CTX* createTlsContext();

    int createTcpServerSocket();

    void handleClientConnection(
        int client_fd,
        const std::string& client_ip,
        const ResponseBuilder& response_builder
    );

    int parseTlsVersion(const std::string& version);

    std::string getNegotiatedGroupName(SSL* ssl);

    CertificateInfo getServerCertificateInfo(SSL* ssl);

    HttpRequest parseHttpRequest(const std::string& raw_request);
};
