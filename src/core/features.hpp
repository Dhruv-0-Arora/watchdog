#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "core/decode.hpp"
#include "core/incident.hpp"
#include "core/stats.hpp"
#include "core/table.hpp"

namespace watchdog {

struct MacIpKey {
  std::array<std::uint8_t, 6> mac{};
  std::array<std::uint8_t, 16> ip{};
  bool operator==(const MacIpKey&) const = default;
};

struct HostKey {
  std::array<std::uint8_t, 16> ip{};
  bool operator==(const HostKey&) const = default;
};

struct ChannelKey {
  std::array<std::uint8_t, 16> low_ip{};
  std::array<std::uint8_t, 16> high_ip{};
  bool operator==(const ChannelKey&) const = default;
};

struct SocketKey {
  std::array<std::uint8_t, 16> low_ip{};
  std::array<std::uint8_t, 16> high_ip{};
  std::uint16_t low_port = 0;
  std::uint16_t high_port = 0;
  bool operator==(const SocketKey&) const = default;
};

struct FeatureTableSizes {
  std::size_t mac_ip = 4096;
  std::size_t host = 4096;
  std::size_t channel = 32768;
  std::size_t socket = 32768;
};

class FeatureExtractor {
 public:
  static constexpr std::size_t feature_count = 2 * WindowedStats::feature_count +
                                               2 * PairedWindowedStats::feature_count +
                                               WindowedStats::feature_count;

  struct Output {
    std::array<float, feature_count> values{};
    bool new_mac_ip = false;
    bool new_host = false;
    bool new_channel = false;
    bool new_socket = false;
  };

  [[nodiscard]] static FeatureContext context_of(std::size_t index) {
    constexpr std::size_t host_start = WindowedStats::feature_count;
    constexpr std::size_t channel_start = host_start + WindowedStats::feature_count;
    constexpr std::size_t jitter_start = channel_start + PairedWindowedStats::feature_count;
    constexpr std::size_t socket_start = jitter_start + WindowedStats::feature_count;
    if (index < host_start) return FeatureContext::mac_ip;
    if (index < channel_start) return FeatureContext::host;
    if (index < jitter_start) return FeatureContext::channel;
    if (index < socket_start) return FeatureContext::jitter;
    return FeatureContext::socket;
  }

  explicit FeatureExtractor(const FeatureTableSizes& sizes = {})
      : mac_ip_table_(sizes.mac_ip),
        host_table_(sizes.host),
        channel_table_(sizes.channel),
        socket_table_(sizes.socket) {}

  void extract(const PacketMeta& meta, Output& out) {
    const std::uint64_t now = meta.timestamp_ns;
    const auto size_value = static_cast<float>(meta.wire_length);
    const bool forward = direction_is_forward(meta);
    std::size_t offset = 0;

    {
      const auto slot = mac_ip_table_.find_or_insert(mac_ip_key(meta), now);
      // A new MAC-IP binding is only news for a neighbour on our own segment. Every
      // remote address on the internet arrives wearing the router's MAC, so reporting
      // those turns "a new device appeared" into a per-remote-IP counter: the live
      // daemon had logged 10,722 of them, against a LAN of roughly twenty hosts. The
      // statistics context still keys on every peer; only the alert signal is narrowed.
      out.new_mac_ip = slot.inserted && is_local_segment(meta);
      slot.value.size.observe(size_value, decay_factors(slot.previous_seen_ns, now));
      slot.value.size.write_features(feature_span(out, offset, WindowedStats::feature_count));
    }
    {
      const auto slot = host_table_.find_or_insert(HostKey{meta.src_ip}, now);
      out.new_host = slot.inserted;
      slot.value.size.observe(size_value, decay_factors(slot.previous_seen_ns, now));
      slot.value.size.write_features(feature_span(out, offset, WindowedStats::feature_count));
    }
    {
      const auto slot = channel_table_.find_or_insert(channel_key(meta), now);
      out.new_channel = slot.inserted;
      const DecayFactors factors = decay_factors(slot.previous_seen_ns, now);
      slot.value.size.observe(forward, size_value, factors);
      slot.value.size.write_features(forward,
                                     feature_span(out, offset, PairedWindowedStats::feature_count));
      observe_jitter(slot.value, forward, now, factors);
      slot.value.jitter[forward ? 0 : 1].write_features(
          feature_span(out, offset, WindowedStats::feature_count));
    }
    {
      const auto slot = socket_table_.find_or_insert(socket_key(meta), now);
      out.new_socket = slot.inserted;
      slot.value.size.observe(forward, size_value, decay_factors(slot.previous_seen_ns, now));
      slot.value.size.write_features(forward,
                                     feature_span(out, offset, PairedWindowedStats::feature_count));
    }
  }

  [[nodiscard]] std::uint64_t evictions() const {
    return mac_ip_table_.evictions() + host_table_.evictions() + channel_table_.evictions() +
           socket_table_.evictions();
  }

 private:
  struct MacIpEntry {
    WindowedStats size;
  };

  struct HostEntry {
    WindowedStats size;
  };

  struct ChannelEntry {
    PairedWindowedStats size;
    std::array<WindowedStats, 2> jitter;
    std::array<std::uint64_t, 2> last_arrival_ns{};
  };

  struct SocketEntry {
    PairedWindowedStats size;
  };

  static std::span<float> feature_span(Output& out, std::size_t& offset, std::size_t count) {
    const std::span<float> span(out.values.data() + offset, count);
    offset += count;
    return span;
  }

  static bool direction_is_forward(const PacketMeta& meta) {
    const int ip_order = std::memcmp(meta.src_ip.data(), meta.dst_ip.data(), meta.src_ip.size());
    if (ip_order != 0) return ip_order < 0;
    return meta.src_port <= meta.dst_port;
  }

  static MacIpKey mac_ip_key(const PacketMeta& meta) { return {meta.src_mac, meta.src_ip}; }

  // True when the source address is one a host on this link can legitimately hold:
  // RFC1918, CGNAT, IPv4 link-local, or IPv6 link-local / unique-local.
  static bool is_local_segment(const PacketMeta& meta) {
    const std::array<std::uint8_t, 16>& ip = meta.src_ip;
    if (meta.is_ipv6) {
      const bool link_local = ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80;
      const bool unique_local = (ip[0] & 0xFE) == 0xFC;
      return link_local || unique_local;
    }
    // IPv4 is stored right-aligned in the 16-byte field by the decoder.
    const std::uint8_t a = ip[12];
    const std::uint8_t b = ip[13];
    if (a == 10) return true;
    if (a == 192 && b == 168) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 169 && b == 254) return true;
    if (a == 100 && b >= 64 && b <= 127) return true;
    return false;
  }

  static ChannelKey channel_key(const PacketMeta& meta) {
    if (direction_is_forward(meta)) return {meta.src_ip, meta.dst_ip};
    return {meta.dst_ip, meta.src_ip};
  }

  static SocketKey socket_key(const PacketMeta& meta) {
    if (direction_is_forward(meta)) return {meta.src_ip, meta.dst_ip, meta.src_port, meta.dst_port};
    return {meta.dst_ip, meta.src_ip, meta.dst_port, meta.src_port};
  }

  static void observe_jitter(ChannelEntry& entry, bool forward, std::uint64_t now,
                             const DecayFactors& factors) {
    const std::size_t direction = forward ? 0 : 1;
    const std::uint64_t previous_arrival = entry.last_arrival_ns[direction];
    entry.last_arrival_ns[direction] = now;
    if (previous_arrival == 0) return;
    const std::uint64_t gap_ns = now > previous_arrival ? now - previous_arrival : 0;
    entry.jitter[direction].observe(static_cast<float>(gap_ns) * 1e-9F, factors);
  }

  EntityTable<MacIpKey, MacIpEntry> mac_ip_table_;
  EntityTable<HostKey, HostEntry> host_table_;
  EntityTable<ChannelKey, ChannelEntry> channel_table_;
  EntityTable<SocketKey, SocketEntry> socket_table_;
};

}  // namespace watchdog
