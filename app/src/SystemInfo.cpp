#include "SystemInfo.hpp"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>

#include <ctime>
#include <cstring>

std::string getDeviceHostname() {
    char hostname[256]{};

    if (gethostname(hostname, sizeof(hostname) - 1) != 0) {
        return "unknown";
    }

    hostname[sizeof(hostname) - 1] = '\0';
    return std::string(hostname);
}

std::string getDeviceIPv4Address() {
    struct ifaddrs* interfaces = nullptr;

    if (getifaddrs(&interfaces) != 0) {
        return "unknown";
    }

    std::string selected_ip = "unknown";

    for (struct ifaddrs* ifa = interfaces; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        if (ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) {
            continue;
        }

        char ip_buffer[INET_ADDRSTRLEN]{};
        auto* ipv4 = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);

        if (inet_ntop(AF_INET, &ipv4->sin_addr, ip_buffer, sizeof(ip_buffer)) != nullptr) {
            selected_ip = ip_buffer;
            break;
        }
    }

    freeifaddrs(interfaces);
    return selected_ip;
}

std::int64_t getUnixTimestamp() {
    return static_cast<std::int64_t>(std::time(nullptr));
}
