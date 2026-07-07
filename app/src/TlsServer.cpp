#include "TlsServer.hpp"

#include "JsonLogger.hpp"
#include "OpenSslUtils.hpp"
#include "SystemInfo.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <iomanip>
#include <cstdint>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <vector>
#include <stdexcept>


using json = nlohmann::ordered_json;

static std::string sslErrorName(int error_code) {
    switch (error_code) {
        case SSL_ERROR_NONE:
            return "SSL_ERROR_NONE";
        case SSL_ERROR_SSL:
            return "SSL_ERROR_SSL";
        case SSL_ERROR_WANT_READ:
            return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE:
            return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_WANT_X509_LOOKUP:
            return "SSL_ERROR_WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL:
            return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_ZERO_RETURN:
            return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_WANT_CONNECT:
            return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT:
            return "SSL_ERROR_WANT_ACCEPT";
        default:
            return "SSL_ERROR_UNKNOWN";
    }
}

static std::string toUpperHex(unsigned long value) {
    std::ostringstream oss;
    oss << std::uppercase
        << std::hex
        << std::setw(8)
        << std::setfill('0')
        << value;
    return oss.str();
}

static json drainOpenSslErrorQueue() {
    json errors = json::array();

    while (true) {
        unsigned long error_code = ERR_get_error();

        if (error_code == 0) {
            break;
        }

        char error_buffer[256]{};
        ERR_error_string_n(error_code, error_buffer, sizeof(error_buffer));

        const char* reason = ERR_reason_error_string(error_code);
        const char* library = ERR_lib_error_string(error_code);
        json item;
        item["code"] = error_code;
        item["hex"] = toUpperHex(error_code);
        item["description"] = std::string(error_buffer);

        if (library != nullptr) {
            item["library"] = library;
        }

        if (reason != nullptr) {
            item["reason"] = reason;
        }

        errors.push_back(item);
    }

    return errors;
}

static std::string buildTlsErrorJson(
    const AppConfig& config,
    const std::string& client_ip,
    int ssl_error_code,
    const std::string& phase
) {
    json openssl_errors = drainOpenSslErrorQueue();

    std::string description = sslErrorName(ssl_error_code);

    if (!openssl_errors.empty() && openssl_errors[0].contains("description")) {
        description = openssl_errors[0]["description"].get<std::string>();
    }

    json response;
    response["metadata"] = {
        {"service", "pqc-tls"},
        {"status", "error"},
        {"event_type", "tls_handshake_failed"},
        {"timestamp", getUnixTimestamp()},
        {"schema_version", "1.0"}
    };

    response["device"] = {
        {"name", getDeviceHostname()},
        {"ip", getDeviceIPv4Address()}
    };

    response["client"] = {
        {"ip", client_ip}
    };

    response["tls_error"] = {
        {"phase", phase},
        {"ssl_error_code", ssl_error_code},
        {"ssl_error_name", sslErrorName(ssl_error_code)},
        {"description", description},
        {"openssl_errors", openssl_errors}
    };

    response["tls_policy"] = {
        {"listen_port", config.listen_port},
        {"groups", config.tls_groups},
        {"signature_algorithms", config.tls_signature_algorithms},
        {"minimum_version", config.minimum_tls_version},
        {"maximum_version", config.maximum_tls_version}
    };

    return response.dump(2);
}

static void logTlsErrorEvent(
    const AppConfig& config,
    const std::string& client_ip,
    int ssl_error_code,
    const std::string& phase
) {
    const std::string error_json = buildTlsErrorJson(
        config,
        client_ip,
        ssl_error_code,
        phase
    );

    std::cerr << "TLS error event:\n" << error_json << "\n";

    try {
        appendJsonLogLine(config.log_file, error_json);
    } catch (const std::exception& ex) {
        std::cerr << "Log write error while recording TLS error: " << ex.what() << "\n";
    }
}

/*
  Constructor.

  It creates the TLS context first, then creates the TCP listening socket.
*/
TlsServer::TlsServer(const AppConfig& config)
    : config_(config),
      ssl_ctx_(nullptr),
      server_fd_(-1) {
    ssl_ctx_ = createTlsContext();
    server_fd_ = createTcpServerSocket();
}

/*
  Destructor.

  Releases the socket and SSL_CTX resources.
*/
TlsServer::~TlsServer() {
    if (server_fd_ >= 0) {
        close(server_fd_);
    }

    if (ssl_ctx_ != nullptr) {
        SSL_CTX_free(ssl_ctx_);
    }
}

/*
  Converts TLS version names from config.json to OpenSSL constants.
*/
int TlsServer::parseTlsVersion(const std::string& version) {
    if (version == "TLSv1.2") {
        return TLS1_2_VERSION;
    }

    if (version == "TLSv1.3") {
        return TLS1_3_VERSION;
    }

    throw std::runtime_error("Unsupported TLS version: " + version);
}

/*
  Creates the OpenSSL TLS server context and applies all TLS configuration.

  Important OpenSSL separation:
  - SSL_CTX_set_cipher_list() controls TLS 1.2 and earlier cipher suites.
  - SSL_CTX_set_ciphersuites() controls TLS 1.3 ciphersuites.
  - SSL_CTX_set1_groups_list() controls supported groups, including hybrid
    PQC groups such as X25519MLKEM768 when OpenSSL supports them.
*/
SSL_CTX* TlsServer::createTlsContext() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());

    if (!ctx) {
        throw std::runtime_error("Could not create SSL_CTX: " + getOpenSslError());
    }

    // Disable TLS compression.
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    // Apply minimum TLS version from config.json.
    int minimum_version = parseTlsVersion(config_.minimum_tls_version);

    if (SSL_CTX_set_min_proto_version(ctx, minimum_version) != 1) {
        SSL_CTX_free(ctx);
        throw std::runtime_error("Could not set minimum TLS version: " + getOpenSslError());
    }

    // Apply maximum TLS version from config.json.
    int maximum_version = parseTlsVersion(config_.maximum_tls_version);

    if (SSL_CTX_set_max_proto_version(ctx, maximum_version) != 1) {
        SSL_CTX_free(ctx);
        throw std::runtime_error("Could not set maximum TLS version: " + getOpenSslError());
    }

    // Apply TLS 1.2 cipher list from config.json.
    if (SSL_CTX_set_cipher_list(ctx, config_.tls12_cipher_list.c_str()) != 1) {
        SSL_CTX_free(ctx);
        throw std::runtime_error(
            "Could not set TLS 1.2 cipher list: " + getOpenSslError()
        );
    }

    // Apply TLS 1.3 ciphersuites from config.json.
    if (SSL_CTX_set_ciphersuites(ctx, config_.tls13_ciphersuites.c_str()) != 1) {
        SSL_CTX_free(ctx);
        throw std::runtime_error(
            "Could not set TLS 1.3 ciphersuites: " + getOpenSslError()
        );
    }

    /*
      Apply TLS supported groups from config.json.

      This is the initial PQC integration point.

      With OpenSSL 3.5+, a value such as:
        X25519MLKEM768:X25519:P-256:P-384

      allows the server to support a hybrid PQC group for TLS 1.3 key exchange,
      as long as the client also supports it.
    */
    if (SSL_CTX_set1_groups_list(ctx, config_.tls_groups.c_str()) != 1) {
        SSL_CTX_free(ctx);
        throw std::runtime_error(
            "Could not set TLS groups '" + config_.tls_groups + "': " + getOpenSslError()
        );
    }

    // Apply TLS signature algorithms from config.json.
    if (SSL_CTX_set1_sigalgs_list(ctx, config_.tls_signature_algorithms.c_str()) != 1) {
        SSL_CTX_free(ctx);
        throw std::runtime_error(
            "Could not set TLS signature algorithms: " + getOpenSslError()
        );
    }

    // Load server certificate.
    if (SSL_CTX_use_certificate_file(
            ctx,
            config_.certificate_file.c_str(),
            SSL_FILETYPE_PEM
        ) != 1) {
        SSL_CTX_free(ctx);
        throw std::runtime_error("Could not load certificate: " + getOpenSslError());
    }

    // Load server private key.
    if (SSL_CTX_use_PrivateKey_file(
            ctx,
            config_.private_key_file.c_str(),
            SSL_FILETYPE_PEM
        ) != 1) {
        SSL_CTX_free(ctx);
        throw std::runtime_error("Could not load private key: " + getOpenSslError());
    }

    // Check whether certificate and private key match.
    if (SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        throw std::runtime_error(
            "Certificate and private key do not match: " + getOpenSslError()
        );
    }

    return ctx;
}

/*
  Creates the TCP socket below the TLS layer.
*/
int TlsServer::createTcpServerSocket() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        throw std::runtime_error("Could not create socket");
    }

    // Allows the server to restart quickly on the same port.
    int opt = 1;

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(server_fd);
        throw std::runtime_error("Could not set SO_REUSEADDR");
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config_.listen_port);

    if (inet_pton(AF_INET, config_.listen_address.c_str(), &address.sin_addr) != 1) {
        close(server_fd);
        throw std::runtime_error("Invalid listen address: " + config_.listen_address);
    }

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        close(server_fd);
        throw std::runtime_error("Could not bind socket");
    }

    if (listen(server_fd, 10) < 0) {
        close(server_fd);
        throw std::runtime_error("Could not listen on socket");
    }

    return server_fd;
}

/*
  Returns the negotiated TLS group name when OpenSSL exposes it.

  SSL_get_negotiated_group() returns the TLS group identifier negotiated during
  key exchange. For modern TLS groups, especially hybrid PQC groups, convert the
  identifier with SSL_group_to_name().
*/
std::string TlsServer::getNegotiatedGroupName(SSL* ssl) {
    int group_id = SSL_get_negotiated_group(ssl);

    if (group_id <= 0) {
        return "unknown";
    }

    const char* group_name = SSL_group_to_name(ssl, group_id);

    if (group_name != nullptr) {
        return group_name;
    }

    return "unknown";
}

/*
  Extracts selected information from the server certificate used by this TLS
  connection.

  The collected fields are useful for telemetry and threshold checks:
  - signature_algorithm;
  - public_key_algorithm;
  - public_key_bits;
  - days_to_expire.
*/
CertificateInfo TlsServer::getServerCertificateInfo(SSL* ssl) {
    CertificateInfo info;

    X509* cert = SSL_get_certificate(ssl);

    if (cert == nullptr) {
        info.signature_algorithm = "unknown";
        info.public_key_algorithm = "unknown";
        info.public_key_bits = 0;
        info.days_to_expire = 0;
        return info;
    }

    const int signature_nid = X509_get_signature_nid(cert);
    const char* signature_name = OBJ_nid2ln(signature_nid);
    info.signature_algorithm = signature_name != nullptr ? signature_name : "unknown";

    EVP_PKEY* public_key = X509_get_pubkey(cert);

    if (public_key != nullptr) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        const char* key_type = EVP_PKEY_get0_type_name(public_key);
        info.public_key_algorithm = key_type != nullptr ? key_type : "unknown";
#else
        const int key_nid = EVP_PKEY_base_id(public_key);
        const char* key_name = OBJ_nid2ln(key_nid);
        info.public_key_algorithm = key_name != nullptr ? key_name : "unknown";
#endif
        info.public_key_bits = EVP_PKEY_bits(public_key);
        EVP_PKEY_free(public_key);
    } else {
        info.public_key_algorithm = "unknown";
        info.public_key_bits = 0;
    }

    const ASN1_TIME* not_after = X509_get0_notAfter(cert);

    int days = 0;
    int seconds = 0;

    if (not_after != nullptr && ASN1_TIME_diff(&days, &seconds, nullptr, not_after) == 1) {
        info.days_to_expire = days;
    } else {
        info.days_to_expire = 0;
    }

    return info;
}

/*
  Parses the first HTTP request line and extracts method, path and version.
*/
HttpRequest TlsServer::parseHttpRequest(const std::string& raw_request) {
    HttpRequest request;
    request.raw = raw_request;

    std::istringstream stream(raw_request);
    std::string first_line;

    std::getline(stream, first_line);

    if (!first_line.empty() && first_line.back() == '\r') {
        first_line.pop_back();
    }

    std::istringstream first_line_stream(first_line);

    first_line_stream >> request.method;
    first_line_stream >> request.path;
    first_line_stream >> request.version;

    if (request.method.empty()) {
        request.method = "UNKNOWN";
    }

    if (request.path.empty()) {
        request.path = "/";
    }

    // Remove query string for routing. Example: /?x=1 becomes /.
    const std::size_t query_pos = request.path.find('?');
    if (query_pos != std::string::npos) {
        request.path = request.path.substr(0, query_pos);
    }

    if (request.version.empty()) {
        request.version = "HTTP/1.1";
    }

    return request;
}

/*
  Handles one TLS client connection.
*/
void TlsServer::handleClientConnection(
    int client_fd,
    const std::string& client_ip,
    const ResponseBuilder& response_builder
) {
    SSL* ssl = SSL_new(ssl_ctx_);

    if (!ssl) {
        logTlsErrorEvent(config_, client_ip, SSL_ERROR_SSL, "ssl_object_creation");
        close(client_fd);
        return;
    }

    SSL_set_fd(ssl, client_fd);

    /*
      Capture BIO counters immediately before the TLS handshake.

      BIO_number_read() and BIO_number_written() count bytes on the SSL BIOs.
      By taking the delta before and after SSL_accept(), the telemetry records
      only handshake bytes, not the later HTTP request or response payload.
    */
    BIO* rbio = SSL_get_rbio(ssl);
    BIO* wbio = SSL_get_wbio(ssl);

    const std::uint64_t bytes_read_before =
        rbio != nullptr ? BIO_number_read(rbio) : 0;

    const std::uint64_t bytes_written_before =
        wbio != nullptr ? BIO_number_written(wbio) : 0;

    const auto handshake_start = std::chrono::steady_clock::now();

    // Perform the server-side TLS handshake.
    const int handshake_result = SSL_accept(ssl);

    if (handshake_result != 1) {
        const int ssl_error_code = SSL_get_error(ssl, handshake_result);

        logTlsErrorEvent(
            config_,
            client_ip,
            ssl_error_code,
            "SSL_accept"
        );

        SSL_free(ssl);
        close(client_fd);

        return;
    }

    const auto handshake_end = std::chrono::steady_clock::now();

    const std::uint64_t bytes_read_after =
        rbio != nullptr ? BIO_number_read(rbio) : 0;

    const std::uint64_t bytes_written_after =
        wbio != nullptr ? BIO_number_written(wbio) : 0;

    const std::chrono::duration<double, std::milli> handshake_duration =
        handshake_end - handshake_start;

    TlsConnectionInfo connection_info;
    connection_info.tls_version = SSL_get_version(ssl);
    connection_info.tls_cipher = SSL_get_cipher(ssl);
    connection_info.tls_group = getNegotiatedGroupName(ssl);
    connection_info.handshake_duration_ms = handshake_duration.count();
    connection_info.handshake_bytes_read =
        bytes_read_after >= bytes_read_before ? bytes_read_after - bytes_read_before : 0;
    connection_info.handshake_bytes_written =
        bytes_written_after >= bytes_written_before ? bytes_written_after - bytes_written_before : 0;
    connection_info.client_ip = client_ip;
    connection_info.certificate = getServerCertificateInfo(ssl);

    char buffer[4096];
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);

    HttpRequest request;

    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';

        std::string raw_request(buffer);
        request = parseHttpRequest(raw_request);

        std::cout << "Received request from " << client_ip << ":\n";
        std::cout << buffer << "\n";
        std::cout << "Parsed path: " << request.path << "\n";
    } else {
        request.method = "GET";
        request.path = "/";
        request.version = "HTTP/1.1";
    }

    std::string body;
    std::string status_line;

    // Build JSON body based on the parsed HTTP path.
    try {
        body = response_builder(request, connection_info);
        status_line = "HTTP/1.1 200 OK\r\n";
    } catch (const std::exception& ex) {
        body = std::string("{\"status\":\"error\",\"service\":\"pqc-tls\",\"message\":\"") + ex.what() + "\"}";
        status_line = "HTTP/1.1 500 Internal Server Error\r\n";
    }

    // Present the output on stdout for interactive execution and demos.
    std::cout << "Response JSON:\n" << body << "\n";

    // Append the same output to the configured JSON log file.
    try {
        appendJsonLogLine(config_.log_file, body);
    } catch (const std::exception& ex) {
        std::cerr << "Log write error: " << ex.what() << "\n";
    }

    std::ostringstream http_response;

    http_response
        << status_line
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "\r\n"
        << body;

    std::string response = http_response.str();

    SSL_write(ssl, response.data(), response.size());

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
}

/*
  Blocking server loop.
*/
void TlsServer::run(const ResponseBuilder& response_builder) {
    std::cout << "TLS server listening on "
              << config_.listen_address
              << ":"
              << config_.listen_port
              << "\n";

    std::cout << "Configured TLS groups: " << config_.tls_groups << "\n";
    std::cout << "JSON log file: " << config_.log_file << "\n";

    while (true) {
        sockaddr_in client_address{};
        socklen_t client_length = sizeof(client_address);

        int client_fd = accept(
            server_fd_,
            reinterpret_cast<sockaddr*>(&client_address),
            &client_length
        );

        if (client_fd < 0) {
            std::cerr << "Could not accept client connection\n";
            continue;
        }

        char client_ip_buffer[INET_ADDRSTRLEN]{};

        if (inet_ntop(
                AF_INET,
                &client_address.sin_addr,
                client_ip_buffer,
                sizeof(client_ip_buffer)
            ) == nullptr) {
            handleClientConnection(client_fd, "unknown", response_builder);
        } else {
            handleClientConnection(client_fd, client_ip_buffer, response_builder);
        }
    }
}
