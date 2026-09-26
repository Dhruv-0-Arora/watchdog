#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace watchdog {

inline constexpr std::size_t snap_length = 128;

struct PacketRecord {
  std::uint64_t timestamp_ns;
  std::uint32_t wire_length;
  std::uint16_t captured_length;
  std::array<std::byte, snap_length> headers;
};

static_assert(std::is_trivially_copyable_v<PacketRecord>);

}  // namespace watchdog
