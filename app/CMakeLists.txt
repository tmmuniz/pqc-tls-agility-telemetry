cmake_minimum_required(VERSION 3.16)

project(tls_crypto_agility_server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)

add_executable(tls_crypto_server
    src/main.cpp
    src/AppConfig.cpp
    src/CryptoEvp.cpp
    src/JsonLogger.cpp
    src/OpenSslUtils.cpp
    src/SystemInfo.cpp
    src/TlsServer.cpp
)

target_include_directories(tls_crypto_server PRIVATE include)

target_link_libraries(tls_crypto_server
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
)
