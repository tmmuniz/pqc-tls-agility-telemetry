#pragma once

#include <string>

/*
  AppConfig stores all runtime configuration loaded from JSON.

  The configuration file is intentionally categorized into sections:
  - app: network binding, demo message and EVP self-test algorithms;
  - tls: certificate, protocol, ciphersuites, groups and signature algorithms;
  - logging: JSON log destination.

  The struct keeps flat C++ fields to keep the rest of the code simple.
*/
struct AppConfig {
    // Path of the configuration file loaded at startup.
    std::string config_source;

    // Application/network binding.
    std::string listen_address;
    int listen_port;

    // Server certificate and private key.
    std::string certificate_file;
    std::string private_key_file;

    // TLS protocol version boundaries applied by libssl.
    std::string minimum_tls_version;
    std::string maximum_tls_version;

    // TLS 1.2 and earlier cipher list applied by libssl.
    std::string tls12_cipher_list;

    // TLS 1.3 ciphersuites applied by libssl.
    std::string tls13_ciphersuites;

    // TLS supported groups. This is the main TLS/PQC crypto-agility point.
    std::string tls_groups;

    // TLS signature algorithms.
    std::string tls_signature_algorithms;

    // EVP digest algorithm for the internal self-test.
    std::string digest_algorithm;

    // EVP symmetric cipher algorithm for the internal self-test.
    std::string cipher_algorithm;

    // Demo message used by the EVP self-test.
    std::string message;

    /*
      Path where each JSON event is appended.

      The code opens this file with O_WRONLY | O_CREAT | O_APPEND.
      It never opens the file for reading.
    */
    std::string log_file;
};

/*
  Loads configuration from a JSON file.

  The preferred format is categorized, for example:
    app.listen_port
    tls.groups
    app.digest_algorithm
    app.cipher_algorithm
    logging.log_file

  For compatibility with older versions of this lab, the loader also accepts
  the previous flat keys when a section is not present.
*/
AppConfig loadConfig(const std::string& path);
