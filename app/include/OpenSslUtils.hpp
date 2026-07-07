#pragma once

#include <cstddef>
#include <string>

/*
  Returns the latest OpenSSL error from the OpenSSL error queue.

  This helper is used whenever an OpenSSL function fails, so the application
  prints a meaningful diagnostic message.
*/
std::string getOpenSslError();

/*
  Converts binary data to a hexadecimal string.

  This is used to display digest, ciphertext and GCM authentication tag values
  in the JSON response.
*/
std::string toHex(const unsigned char* data, std::size_t length);
