#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>

#include "core/incident.hpp"

namespace watchdog {

[[nodiscard]] inline bool is_ipv4_mapped(std::span<const std::uint8_t, 16> address) {
  for (std::size_t i = 0; i < 10; ++i) {
    if (address[i] != 0) return false;
  }
  return address[10] == 0xFF && address[11] == 0xFF;
}

[[nodiscard]] inline std::string format_address(const std::array<std::uint8_t, 16>& address) {
  std::array<char, 48> buffer{};
  if (is_ipv4_mapped(address)) {
    std::snprintf(buffer.data(), buffer.size(), "%u.%u.%u.%u", address[12], address[13],
                  address[14], address[15]);
    return buffer.data();
  }
  int written = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    const auto group = static_cast<unsigned>(address[2 * i] << 8 | address[2 * i + 1]);
    written +=
        std::snprintf(buffer.data() + written, buffer.size() - static_cast<std::size_t>(written),
                      i == 0 ? "%x" : ":%x", group);
  }
  return buffer.data();
}

[[nodiscard]] inline const char* transport_name(std::uint8_t transport) {
  switch (transport) {
    case 0:
      return "tcp";
    case 1:
      return "udp";
    case 2:
      return "icmp";
    default:
      return "other";
  }
}

[[nodiscard]] inline std::string format_contexts(std::uint8_t context_mask) {
  static constexpr std::array<const char*, 5> names{"mac-ip", "host", "channel", "jitter",
                                                    "socket"};
  std::string result;
  for (std::size_t i = 0; i < names.size(); ++i) {
    if ((context_mask & (1U << i)) == 0) continue;
    if (!result.empty()) result += "+";
    result += names[i];
  }
  return result.empty() ? "unknown" : result;
}

[[nodiscard]] inline std::string format_new_entities(std::uint8_t new_entity_mask) {
  static constexpr std::array<const char*, 4> names{"mac-ip", "host", "channel", "socket"};
  std::string result;
  for (std::size_t i = 0; i < names.size(); ++i) {
    if ((new_entity_mask & (1U << i)) == 0) continue;
    if (!result.empty()) result += "+";
    result += names[i];
  }
  return result;
}

}  // namespace watchdog
