#include <doctest/doctest.h>

#include <array>
#include <cstdint>

#include "core/decode.hpp"
#include "core/features.hpp"

namespace {

using watchdog::FeatureExtractor;
using watchdog::FeatureTableSizes;
using watchdog::PacketMeta;
using watchdog::Transport;

PacketMeta make_packet(std::uint8_t src_last, std::uint8_t dst_last, std::uint16_t src_port,
                       std::uint16_t dst_port, std::uint32_t size, std::uint64_t time_ns) {
  PacketMeta meta;
  meta.timestamp_ns = time_ns;
  meta.wire_length = size;
  // 192.168.0.x: these stand for hosts on the local segment, which is what the
  // new-MAC-IP signal reports on.
  meta.src_ip[10] = 0xFF;
  meta.src_ip[11] = 0xFF;
  meta.src_ip[12] = 192;
  meta.src_ip[13] = 168;
  meta.src_ip[15] = src_last;
  meta.dst_ip[10] = 0xFF;
  meta.dst_ip[11] = 0xFF;
  meta.dst_ip[12] = 192;
  meta.dst_ip[13] = 168;
  meta.dst_ip[15] = dst_last;
  meta.src_mac[5] = src_last;
  meta.dst_mac[5] = dst_last;
  meta.src_port = src_port;
  meta.dst_port = dst_port;
  meta.transport = Transport::tcp;
  return meta;
}

TEST_CASE("feature vector has the documented dimensionality") {
  CHECK(FeatureExtractor::feature_count == 115);
}

TEST_CASE("first sight of each entity is flagged exactly once") {
  FeatureExtractor extractor;
  FeatureExtractor::Output output;
  extractor.extract(make_packet(1, 2, 1000, 80, 500, 1'000'000), output);
  CHECK(output.new_mac_ip);
  CHECK(output.new_host);
  CHECK(output.new_channel);
  CHECK(output.new_socket);
  extractor.extract(make_packet(1, 2, 1000, 80, 600, 2'000'000), output);
  CHECK(!output.new_mac_ip);
  CHECK(!output.new_host);
  CHECK(!output.new_channel);
  CHECK(!output.new_socket);
  extractor.extract(make_packet(1, 2, 1000, 443, 600, 3'000'000), output);
  CHECK(!output.new_channel);
  CHECK(output.new_socket);
  extractor.extract(make_packet(3, 2, 1000, 80, 600, 4'000'000), output);
  CHECK(output.new_mac_ip);
  CHECK(output.new_host);
  CHECK(output.new_channel);
  CHECK(output.new_socket);
}

TEST_CASE("both directions of a conversation share channel state") {
  FeatureExtractor forward_only;
  FeatureExtractor both_directions;
  FeatureExtractor::Output output;
  for (int i = 0; i < 50; ++i) {
    const std::uint64_t time_ns = 1'000'000ULL * static_cast<std::uint64_t>(i + 1);
    both_directions.extract(make_packet(1, 2, 1000, 80, 500, time_ns), output);
    CHECK((i == 0) == output.new_channel);
    both_directions.extract(make_packet(2, 1, 80, 1000, 1400, time_ns + 500'000), output);
    CHECK(!output.new_channel);
    forward_only.extract(make_packet(1, 2, 1000, 80, 500, time_ns), output);
  }
  both_directions.extract(make_packet(1, 2, 1000, 80, 500, 60'000'000), output);
  const auto with_reverse = output.values;
  forward_only.extract(make_packet(1, 2, 1000, 80, 500, 60'000'000), output);
  const auto without_reverse = output.values;
  constexpr std::size_t channel_offset = 2 * 15;
  const float magnitude_with = with_reverse[channel_offset + 3];
  const float magnitude_without = without_reverse[channel_offset + 3];
  CHECK(magnitude_with > magnitude_without);
}

TEST_CASE("packet size is reflected in mean features") {
  FeatureExtractor extractor;
  FeatureExtractor::Output output;
  for (int i = 0; i < 20; ++i) {
    const std::uint64_t time_ns = 1'000'000ULL * static_cast<std::uint64_t>(i + 1);
    extractor.extract(make_packet(1, 2, 1000, 80, 750, time_ns), output);
  }
  CHECK(output.values[1] == doctest::Approx(750.0F).epsilon(0.001));
  CHECK(output.values[2] < 5.0F);
  CHECK(output.values[0] > 1.0F);
}

TEST_CASE("identical input produces identical output") {
  FeatureExtractor first;
  FeatureExtractor second;
  FeatureExtractor::Output first_output;
  FeatureExtractor::Output second_output;
  for (int i = 0; i < 200; ++i) {
    const auto packet = make_packet(static_cast<std::uint8_t>(i % 5), 2, 1000, 80,
                                    500 + static_cast<std::uint32_t>(i),
                                    1'000'000ULL * static_cast<std::uint64_t>(i + 1));
    first.extract(packet, first_output);
    second.extract(packet, second_output);
  }
  CHECK(first_output.values == second_output.values);
}

TEST_CASE("tiny tables absorb unbounded key churn") {
  FeatureExtractor extractor(FeatureTableSizes{16, 16, 16, 16});
  FeatureExtractor::Output output;
  for (int i = 0; i < 100'000; ++i) {
    const auto packet = make_packet(
        static_cast<std::uint8_t>(i % 251), static_cast<std::uint8_t>(i % 241),
        static_cast<std::uint16_t>(i % 60'000), static_cast<std::uint16_t>((i * 7) % 60'000), 500,
        1'000'000ULL * static_cast<std::uint64_t>(i + 1));
    extractor.extract(packet, output);
  }
  CHECK(extractor.evictions() > 0);
}

}  // namespace

TEST_CASE("new MAC-IP bindings are reported for the local segment only") {
  FeatureExtractor extractor;
  FeatureExtractor::Output output;

  // Every remote address on the internet reaches us wearing the router's MAC, so
  // treating each one as a new MAC-IP binding turns "a new device appeared on your
  // network" into a counter of how many servers you talked to. The live daemon had
  // logged 10,722 of them against a LAN of roughly twenty hosts.
  PacketMeta remote = make_packet(1, 2, 1000, 443, 500, 1'000'000);
  remote.src_ip[12] = 17;  // 17.253.27.150, an Apple server
  remote.src_ip[13] = 253;
  remote.src_ip[14] = 27;
  remote.src_ip[15] = 150;
  extractor.extract(remote, output);
  CHECK(!output.new_mac_ip);
  CHECK(output.new_host);  // still novel as a host, just not as a neighbour

  PacketMeta neighbour = make_packet(9, 2, 1000, 443, 500, 2'000'000);
  extractor.extract(neighbour, output);
  CHECK(output.new_mac_ip);

  PacketMeta link_local = make_packet(11, 2, 1000, 443, 500, 3'000'000);
  link_local.src_ip[12] = 169;
  link_local.src_ip[13] = 254;
  extractor.extract(link_local, output);
  CHECK(output.new_mac_ip);

  PacketMeta v6 = make_packet(12, 2, 1000, 443, 500, 4'000'000);
  v6.is_ipv6 = true;
  v6.src_ip = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12};
  extractor.extract(v6, output);
  CHECK(output.new_mac_ip);
}
