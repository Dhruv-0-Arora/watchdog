#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>

namespace watchdog {

inline constexpr int link_type_null_loopback = 0;
inline constexpr int link_type_ethernet = 1;
inline constexpr int link_type_raw_ip = 12;

enum class Transport : std::uint8_t { tcp, udp, icmp, other };

struct PacketMeta {
  std::uint64_t timestamp_ns = 0;
  std::uint32_t wire_length = 0;
  std::array<std::uint8_t, 16> src_ip{};
  std::array<std::uint8_t, 16> dst_ip{};
  std::array<std::uint8_t, 6> src_mac{};
  std::array<std::uint8_t, 6> dst_mac{};
  std::uint16_t ether_type = 0;
  std::uint16_t src_port = 0;
  std::uint16_t dst_port = 0;
  Transport transport = Transport::other;
  std::uint8_t ip_protocol = 0;
  std::uint8_t tcp_flags = 0;
  bool is_ipv6 = false;
};

class ByteView {
 public:
  explicit ByteView(std::span<const std::byte> bytes) : bytes_(bytes) {}

  [[nodiscard]] std::size_t size() const { return bytes_.size(); }

  [[nodiscard]] bool has(std::size_t offset, std::size_t length) const {
    return offset <= bytes_.size() && length <= bytes_.size() - offset;
  }

  [[nodiscard]] std::uint8_t u8(std::size_t offset) const {
    return std::to_integer<std::uint8_t>(bytes_[offset]);
  }

  [[nodiscard]] std::uint16_t be16(std::size_t offset) const {
    return static_cast<std::uint16_t>((u8(offset) << 8) | u8(offset + 1));
  }

  void copy(std::size_t offset, std::span<std::uint8_t> destination) const {
    std::memcpy(destination.data(), bytes_.data() + offset, destination.size());
  }

  [[nodiscard]] ByteView from(std::size_t offset) const {
    return ByteView(bytes_.subspan(std::min(offset, bytes_.size())));
  }

 private:
  std::span<const std::byte> bytes_;
};

namespace detail {

inline constexpr std::uint8_t protocol_icmp = 1;
inline constexpr std::uint8_t protocol_tcp = 6;
inline constexpr std::uint8_t protocol_udp = 17;
inline constexpr std::uint8_t protocol_icmpv6 = 58;

inline void decode_transport(const ByteView& segment, std::uint8_t protocol, PacketMeta& meta) {
  meta.ip_protocol = protocol;
  switch (protocol) {
    case protocol_tcp:
      if (!segment.has(0, 14)) return;
      meta.transport = Transport::tcp;
      meta.src_port = segment.be16(0);
      meta.dst_port = segment.be16(2);
      meta.tcp_flags = segment.u8(13);
      return;
    case protocol_udp:
      if (!segment.has(0, 4)) return;
      meta.transport = Transport::udp;
      meta.src_port = segment.be16(0);
      meta.dst_port = segment.be16(2);
      return;
    case protocol_icmp:
    case protocol_icmpv6:
      meta.transport = Transport::icmp;
      return;
    default:
      return;
  }
}

inline void copy_ipv4_mapped(const ByteView& packet, std::size_t offset,
                             std::array<std::uint8_t, 16>& address) {
  address[10] = 0xFF;
  address[11] = 0xFF;
  packet.copy(offset, std::span(address).subspan(12));
}

inline bool decode_ipv4(const ByteView& packet, PacketMeta& meta) {
  if (!packet.has(0, 20)) return false;
  const std::uint8_t version_and_length = packet.u8(0);
  if (version_and_length >> 4 != 4) return false;
  const std::size_t header_length = static_cast<std::size_t>(version_and_length & 0x0F) * 4;
  if (header_length < 20 || !packet.has(0, header_length)) return false;
  meta.is_ipv6 = false;
  copy_ipv4_mapped(packet, 12, meta.src_ip);
  copy_ipv4_mapped(packet, 16, meta.dst_ip);
  const std::uint8_t protocol = packet.u8(9);
  const bool is_fragment_tail = (packet.be16(6) & 0x1FFF) != 0;
  if (is_fragment_tail) {
    meta.ip_protocol = protocol;
    return true;
  }
  decode_transport(packet.from(header_length), protocol, meta);
  return true;
}

inline bool decode_ipv6(const ByteView& packet, PacketMeta& meta) {
  if (!packet.has(0, 40)) return false;
  if (packet.u8(0) >> 4 != 6) return false;
  meta.is_ipv6 = true;
  packet.copy(8, meta.src_ip);
  packet.copy(24, meta.dst_ip);
  std::uint8_t next_header = packet.u8(6);
  std::size_t offset = 40;
  for (int chain_depth = 0; chain_depth < 8; ++chain_depth) {
    constexpr std::uint8_t hop_by_hop = 0;
    constexpr std::uint8_t routing = 43;
    constexpr std::uint8_t fragment = 44;
    constexpr std::uint8_t destination_options = 60;
    switch (next_header) {
      case hop_by_hop:
      case routing:
      case destination_options: {
        if (!packet.has(offset, 2)) {
          meta.ip_protocol = next_header;
          return true;
        }
        const std::size_t extension_length =
            8 + static_cast<std::size_t>(packet.u8(offset + 1)) * 8;
        next_header = packet.u8(offset);
        offset += extension_length;
        break;
      }
      case fragment: {
        if (!packet.has(offset, 8)) {
          meta.ip_protocol = next_header;
          return true;
        }
        const bool is_fragment_tail = (packet.be16(offset + 2) & 0xFFF8) != 0;
        next_header = packet.u8(offset);
        offset += 8;
        if (is_fragment_tail) {
          meta.ip_protocol = next_header;
          return true;
        }
        break;
      }
      default:
        decode_transport(packet.from(offset), next_header, meta);
        return true;
    }
  }
  meta.ip_protocol = next_header;
  return true;
}

inline bool decode_ip_payload(const ByteView& payload, std::uint16_t ether_type, PacketMeta& meta) {
  constexpr std::uint16_t ether_type_ipv4 = 0x0800;
  constexpr std::uint16_t ether_type_ipv6 = 0x86DD;
  meta.ether_type = ether_type;
  if (ether_type == ether_type_ipv4) return decode_ipv4(payload, meta);
  if (ether_type == ether_type_ipv6) return decode_ipv6(payload, meta);
  return true;
}

inline std::optional<PacketMeta> decode_ethernet(const ByteView& frame, PacketMeta meta) {
  if (!frame.has(0, 14)) return std::nullopt;
  frame.copy(0, meta.dst_mac);
  frame.copy(6, meta.src_mac);
  std::size_t type_offset = 12;
  std::uint16_t ether_type = frame.be16(type_offset);
  constexpr std::uint16_t vlan_tag = 0x8100;
  constexpr std::uint16_t vlan_qinq_tag = 0x88A8;
  for (int tags = 0; tags < 2 && (ether_type == vlan_tag || ether_type == vlan_qinq_tag); ++tags) {
    if (!frame.has(type_offset + 4, 2)) return std::nullopt;
    type_offset += 4;
    ether_type = frame.be16(type_offset);
  }
  if (!decode_ip_payload(frame.from(type_offset + 2), ether_type, meta)) return std::nullopt;
  return meta;
}

inline std::optional<PacketMeta> decode_null_loopback(const ByteView& frame, PacketMeta meta) {
  if (!frame.has(0, 4)) return std::nullopt;
  const auto family_of = [](std::uint8_t value) -> std::optional<std::uint16_t> {
    if (value == 2) return std::uint16_t{0x0800};
    if (value == 24 || value == 28 || value == 30) return std::uint16_t{0x86DD};
    return std::nullopt;
  };
  const std::optional<std::uint16_t> ether_type =
      family_of(frame.u8(0)) ? family_of(frame.u8(0)) : family_of(frame.u8(3));
  if (!ether_type) return std::nullopt;
  if (!decode_ip_payload(frame.from(4), *ether_type, meta)) return std::nullopt;
  return meta;
}

inline std::optional<PacketMeta> decode_raw_ip(const ByteView& frame, PacketMeta meta) {
  if (!frame.has(0, 1)) return std::nullopt;
  const std::uint8_t version = frame.u8(0) >> 4;
  if (version == 4 && decode_ip_payload(frame, 0x0800, meta)) return meta;
  if (version == 6 && decode_ip_payload(frame, 0x86DD, meta)) return meta;
  return std::nullopt;
}

}  // namespace detail

[[nodiscard]] inline std::optional<PacketMeta> decode_packet(std::span<const std::byte> frame,
                                                             int link_type,
                                                             std::uint64_t timestamp_ns,
                                                             std::uint32_t wire_length) {
  PacketMeta meta;
  meta.timestamp_ns = timestamp_ns;
  meta.wire_length = wire_length;
  const ByteView view(frame);
  switch (link_type) {
    case link_type_ethernet:
      return detail::decode_ethernet(view, meta);
    case link_type_null_loopback:
      return detail::decode_null_loopback(view, meta);
    case link_type_raw_ip:
      return detail::decode_raw_ip(view, meta);
    default:
      return std::nullopt;
  }
}

}  // namespace watchdog
