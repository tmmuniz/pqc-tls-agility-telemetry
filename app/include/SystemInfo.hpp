#pragma once

#include <cstdint>
#include <string>

/*
  Returns the operating system hostname of the current host.
*/
std::string getDeviceHostname();

/*
  Returns the first non-loopback IPv4 address found on the host.

  On EC2, this normally returns the private IPv4 address of the instance.
*/
std::string getDeviceIPv4Address();

/*
  Returns the current Unix timestamp in seconds.
*/
std::int64_t getUnixTimestamp();
