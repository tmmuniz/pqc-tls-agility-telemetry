#include "JsonLogger.hpp"

#include <nlohmann/json.hpp>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <stdexcept>
#include <string>

using json = nlohmann::ordered_json;

void appendJsonLogLine(
    const std::string& log_file,
    const std::string& json_payload
) {
    /*
      O_WRONLY: open for writing only.
      O_APPEND: every write goes to the end of the file.
      O_CREAT: create the file if it does not exist.
      O_CLOEXEC: do not leak the file descriptor across exec().

      Mode 0220 creates the file as write-only for owner and group when the
      file does not already exist. The process still depends on directory
      permissions to create the file under /var/log.
    */
    int fd = open(
        log_file.c_str(),
        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
        S_IWUSR | S_IWGRP
    );

    if (fd < 0) {
        throw std::runtime_error(
            "Could not open log file in append-only write mode: " + log_file +
            " error: " + std::strerror(errno)
        );
    }

    std::string compact_json;

    try {
        compact_json = json::parse(json_payload).dump();
    } catch (...) {
        compact_json = json{{"status", "invalid_json_log_payload"}, {"raw", json_payload}}.dump();
    }

    compact_json.push_back('\n');

    const char* data = compact_json.data();
    std::size_t remaining = compact_json.size();

    while (remaining > 0) {
        ssize_t written = write(fd, data, remaining);

        if (written < 0) {
            close(fd);
            throw std::runtime_error(
                "Could not write JSON log line: " + std::string(std::strerror(errno))
            );
        }

        data += written;
        remaining -= static_cast<std::size_t>(written);
    }

    close(fd);
}
