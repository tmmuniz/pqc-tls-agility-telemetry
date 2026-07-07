#include "OpenSslUtils.hpp"

#include <openssl/err.h>

#include <iomanip>
#include <sstream>

/*
  Extracts a readable OpenSSL error.
*/
std::string getOpenSslError() {
    char buffer[256];

    unsigned long err = ERR_get_error();

    if (err == 0) {
        return "no OpenSSL error available";
    }

    ERR_error_string_n(err, buffer, sizeof(buffer));

    return std::string(buffer);
}

/*
  Converts bytes to hexadecimal representation.
*/
std::string toHex(const unsigned char* data, std::size_t length) {
    std::ostringstream oss;

    for (std::size_t i = 0; i < length; ++i) {
        oss << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(data[i]);
    }

    return oss.str();
}
