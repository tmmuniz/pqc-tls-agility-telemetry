#include "AppConfig.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>
#include <string>

using json = nlohmann::json;

static const json& sectionOrRoot(
    const json& data,
    const std::string& section_name
) {
    if (data.contains(section_name) && data[section_name].is_object()) {
        return data[section_name];
    }

    return data;
}

static std::string getRequiredString(
    const json& data,
    const std::string& field_name
) {
    if (!data.contains(field_name) || !data[field_name].is_string()) {
        throw std::runtime_error("Missing or invalid string field: " + field_name);
    }

    return data[field_name].get<std::string>();
}

static int getRequiredInt(
    const json& data,
    const std::string& field_name
) {
    if (!data.contains(field_name) || !data[field_name].is_number_integer()) {
        throw std::runtime_error("Missing or invalid integer field: " + field_name);
    }

    return data[field_name].get<int>();
}

static std::string getStringWithAlias(
    const json& section,
    const std::string& preferred_name,
    const std::string& legacy_name
) {
    if (section.contains(preferred_name) && section[preferred_name].is_string()) {
        return section[preferred_name].get<std::string>();
    }

    return getRequiredString(section, legacy_name);
}

/*
  Loads config.json into AppConfig.

  Important design choice:
  this function does not decide whether an algorithm is approved or not.
  Policy checks can be done in CI/CD with OPA/Rego or another external tool.
*/
AppConfig loadConfig(const std::string& path) {
    std::ifstream file(path);

    if (!file.is_open()) {
        throw std::runtime_error("Could not open config file: " + path);
    }

    json data = json::parse(file);

    const json& app = sectionOrRoot(data, "app");
    const json& tls = sectionOrRoot(data, "tls");
    const json& logging = sectionOrRoot(data, "logging");

    AppConfig config;
    config.config_source = path;

    config.listen_address = getRequiredString(app, "listen_address");
    config.listen_port = getRequiredInt(app, "listen_port");
    config.message = getRequiredString(app, "message");

    config.certificate_file = getRequiredString(tls, "certificate_file");
    config.private_key_file = getRequiredString(tls, "private_key_file");

    config.minimum_tls_version = getStringWithAlias(tls, "minimum_version", "minimum_tls_version");
    config.maximum_tls_version = getStringWithAlias(tls, "maximum_version", "maximum_tls_version");

    config.tls12_cipher_list = getRequiredString(tls, "tls12_cipher_list");
    config.tls13_ciphersuites = getRequiredString(tls, "tls13_ciphersuites");
    config.tls_groups = getStringWithAlias(tls, "groups", "tls_groups");
    config.tls_signature_algorithms = getStringWithAlias(
        tls,
        "signature_algorithms",
        "tls_signature_algorithms"
    );

    config.digest_algorithm = getRequiredString(app, "digest_algorithm");
    config.cipher_algorithm = getRequiredString(app, "cipher_algorithm");

    config.log_file = getRequiredString(logging, "log_file");

    return config;
}
