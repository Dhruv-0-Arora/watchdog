#pragma once

#include <array>
#include <cstdint>
#include <type_traits>

#include "core/incident.hpp"

namespace watchdog {

inline constexpr std::uint32_t snapshot_magic = 0x5747534E;
inline constexpr std::uint32_t snapshot_version = 1;
inline constexpr std::size_t snapshot_incident_capacity = 128;

struct Snapshot {
  std::uint32_t magic = snapshot_magic;
  std::uint32_t version = snapshot_version;
  std::uint32_t byte_size = 0;
  std::uint32_t open_count = 0;
  std::uint32_t recent_count = 0;
  std::uint32_t model_phase = 0;
  std::uint64_t started_ns = 0;
  std::uint64_t latest_packet_ns = 0;
  std::uint64_t packets = 0;
  std::uint64_t bytes = 0;
  std::uint64_t ring_dropped = 0;
  std::uint64_t kernel_dropped = 0;
  std::uint64_t new_mac_ips = 0;
  std::uint64_t new_hosts = 0;
  std::uint64_t new_channels = 0;
  std::uint64_t new_sockets = 0;
  std::uint64_t model_packets = 0;
  std::uint64_t alert_packets = 0;
  std::uint64_t incidents_opened = 0;
  std::uint64_t resident_bytes = 0;
  std::uint64_t open_descriptors = 0;
  float threshold = 0.0F;
  float max_score = 0.0F;
  std::array<Incident, snapshot_incident_capacity> open{};
  std::array<Incident, snapshot_incident_capacity> recent{};
};

static_assert(std::is_trivially_copyable_v<Snapshot>);

}  // namespace watchdog
