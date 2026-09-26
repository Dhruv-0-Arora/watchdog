#include <doctest/doctest.h>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <vector>

#include "core/decode.hpp"

namespace {

using watchdog::decode_packet;
using watchdog::link_type_ethernet;
using watchdog::link_type_null_loopback;
using watchdog::link_type_raw_ip;
using watchdog::PacketMeta;
using watchdog::Transport;

class PacketBuilder {
 public:
  PacketBuilder& u8(std::uint8_t value) {
    bytes_.push_back(static_cast<std::byte>(value));
    return *this;
  }

  PacketBuilder& be16(std::uint16_t value) {
    return u8(static_cast<std::uint8_t>(value >> 8)).u8(static_cast<std::uint8_t>(value & 0xFF));
  }

  PacketBuilder& raw(std::initializer_list<std::uint8_t> values) {
    for (const std::uint8_t value : values) u8(value);
    return *this;
  }

  PacketBuilder& repeat(std::uint8_t value, std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) u8(value);
    return *this;
  }

  PacketBuilder& ethernet(std::uint16_t ether_type) {
    return raw({0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
        .raw({0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
        .be16(ether_type);
  }

  PacketBuilder& ipv4_header(std::uint8_t protocol, std::uint16_t fragment_field = 0) {
    u8(0x45).u8(0).be16(40);
    be16(0x1234).be16(fragment_field);
    u8(64).u8(protocol).be16(0);
    raw({10, 0, 0, 1});
    raw({10, 0, 0, 2});
    return *this;
  }

  PacketBuilder& ipv6_header(std::uint8_t next_header) {
    u8(0x60).u8(0).be16(0);
    be16(20).u8(next_header).u8(64);
    repeat(0xAA, 16);
    repeat(0xBB, 16);
    return *this;
  }

  PacketBuilder& tcp_header(std::uint16_t src_port, std::uint16_t dst_port, std::uint8_t flags) {
    be16(src_port).be16(dst_port);
    repeat(0, 9);
    u8(flags).be16(0).be16(0);
    return *this;
  }

  PacketBuilder& udp_header(std::uint16_t src_port, std::uint16_t dst_port) {
    return be16(src_port).be16(dst_port).be16(8).be16(0);
  }

  [[nodiscard]] std::optional<PacketMeta> decode(int link_type) const {
    return decode_packet(std::span(bytes_), link_type, 1'000, 1'500);
  }

 private:
  std::vector<std::byte> bytes_;
};

TEST_CASE("ethernet ipv4 tcp decodes addresses ports and flags") {
  const auto meta = PacketBuilder()
                        .ethernet(0x0800)
                        .ipv4_header(6)
                        .tcp_header(443, 50123, 0x12)
                        .decode(link_type_ethernet);
  REQUIRE(meta.has_value());
  CHECK(meta->transport == Transport::tcp);
  CHECK(!meta->is_ipv6);
  CHECK(meta->src_port == 443);
  CHECK(meta->dst_port == 50123);
  CHECK(meta->tcp_flags == 0x12);
  CHECK(meta->ip_protocol == 6);
  CHECK(meta->ether_type == 0x0800);
  CHECK(meta->src_mac[5] == 0x02);
  CHECK(meta->dst_mac[5] == 0x01);
  CHECK(meta->src_ip[10] == 0xFF);
  CHECK(meta->src_ip[11] == 0xFF);
  CHECK(meta->src_ip[12] == 10);
  CHECK(meta->src_ip[15] == 1);
  CHECK(meta->dst_ip[15] == 2);
  CHECK(meta->timestamp_ns == 1'000);
  CHECK(meta->wire_length == 1'500);
}

TEST_CASE("vlan tagged ipv4 udp decodes through the tag") {
  const auto meta = PacketBuilder()
                        .ethernet(0x8100)
                        .be16(0x0064)
                        .be16(0x0800)
                        .ipv4_header(17)
                        .udp_header(53, 33000)
                        .decode(link_type_ethernet);
  REQUIRE(meta.has_value());
  CHECK(meta->transport == Transport::udp);
  CHECK(meta->src_port == 53);
  CHECK(meta->dst_port == 33000);
}

TEST_CASE("ipv6 tcp decodes addresses and ports") {
  const auto meta = PacketBuilder()
                        .ethernet(0x86DD)
                        .ipv6_header(6)
                        .tcp_header(22, 40000, 0x18)
                        .decode(link_type_ethernet);
  REQUIRE(meta.has_value());
  CHECK(meta->is_ipv6);
  CHECK(meta->transport == Transport::tcp);
  CHECK(meta->src_ip[0] == 0xAA);
  CHECK(meta->dst_ip[0] == 0xBB);
  CHECK(meta->src_port == 22);
  CHECK(meta->dst_port == 40000);
}

TEST_CASE("ipv6 hop-by-hop extension is skipped before udp") {
  const auto meta = PacketBuilder()
                        .ethernet(0x86DD)
                        .ipv6_header(0)
                        .u8(17)
                        .u8(0)
                        .repeat(0, 6)
                        .udp_header(5353, 5353)
                        .decode(link_type_ethernet);
  REQUIRE(meta.has_value());
  CHECK(meta->transport == Transport::udp);
  CHECK(meta->src_port == 5353);
}

TEST_CASE("ipv4 fragment tail keeps protocol but no ports") {
  const auto meta =
      PacketBuilder().ethernet(0x0800).ipv4_header(6, 0x00B9).tcp_header(1, 2, 0).decode(
          link_type_ethernet);
  REQUIRE(meta.has_value());
  CHECK(meta->transport == Transport::other);
  CHECK(meta->ip_protocol == 6);
  CHECK(meta->src_port == 0);
}

TEST_CASE("icmp decodes as icmp transport") {
  const auto meta =
      PacketBuilder().ethernet(0x0800).ipv4_header(1).raw({8, 0, 0, 0}).decode(link_type_ethernet);
  REQUIRE(meta.has_value());
  CHECK(meta->transport == Transport::icmp);
}

TEST_CASE("arp frame is valid traffic with transport other") {
  const auto meta = PacketBuilder().ethernet(0x0806).repeat(0, 28).decode(link_type_ethernet);
  REQUIRE(meta.has_value());
  CHECK(meta->transport == Transport::other);
  CHECK(meta->ether_type == 0x0806);
}

TEST_CASE("truncated ipv4 header fails to decode") {
  const auto meta = PacketBuilder().ethernet(0x0800).raw({0x45, 0x00}).decode(link_type_ethernet);
  CHECK(!meta.has_value());
}

TEST_CASE("truncated tcp header keeps layer three data") {
  const auto meta =
      PacketBuilder().ethernet(0x0800).ipv4_header(6).be16(443).decode(link_type_ethernet);
  REQUIRE(meta.has_value());
  CHECK(meta->transport == Transport::other);
  CHECK(meta->ip_protocol == 6);
  CHECK(meta->src_ip[15] == 1);
}

TEST_CASE("null loopback ipv4 decodes") {
  const auto meta = PacketBuilder()
                        .raw({2, 0, 0, 0})
                        .ipv4_header(17)
                        .udp_header(123, 123)
                        .decode(link_type_null_loopback);
  REQUIRE(meta.has_value());
  CHECK(meta->transport == Transport::udp);
}

TEST_CASE("raw ip link decodes from the version nibble") {
  const auto ipv4 = PacketBuilder().ipv4_header(6).tcp_header(1, 2, 0).decode(link_type_raw_ip);
  REQUIRE(ipv4.has_value());
  CHECK(!ipv4->is_ipv6);
  const auto ipv6 = PacketBuilder().ipv6_header(17).udp_header(1, 2).decode(link_type_raw_ip);
  REQUIRE(ipv6.has_value());
  CHECK(ipv6->is_ipv6);
}

TEST_CASE("unknown link type fails to decode") {
  const auto meta = PacketBuilder().repeat(0, 64).decode(999);
  CHECK(!meta.has_value());
}

TEST_CASE("random garbage never crashes the decoder") {
  std::uint64_t state = 0x9E3779B97F4A7C15ULL;
  const auto next_random = [&state] {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
  };
  for (int iteration = 0; iteration < 50'000; ++iteration) {
    const std::size_t size = next_random() % 200;
    std::vector<std::byte> bytes(size);
    for (std::byte& value : bytes) value = static_cast<std::byte>(next_random() & 0xFF);
    const int link_type =
        static_cast<int>(next_random() % 4) == 3 ? 999 : static_cast<int>(next_random() % 13);
    const auto meta = decode_packet(std::span(bytes), link_type, 0, 0);
    if (meta.has_value()) CHECK(meta->timestamp_ns == 0);
  }
}

}  // namespace
