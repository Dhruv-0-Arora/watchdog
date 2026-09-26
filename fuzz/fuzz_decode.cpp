#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "core/decode.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 1) return 0;
  constexpr std::array<int, 4> link_types{watchdog::link_type_ethernet,
                                          watchdog::link_type_null_loopback,
                                          watchdog::link_type_raw_ip, 999};
  const int link_type = link_types[data[0] % link_types.size()];
  const std::span<const std::byte> frame(reinterpret_cast<const std::byte*>(data + 1), size - 1);
  const auto meta = watchdog::decode_packet(frame, link_type, 0, static_cast<std::uint32_t>(size));
  (void)meta;
  return 0;
}
