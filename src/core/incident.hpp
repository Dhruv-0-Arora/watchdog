#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace watchdog {

enum class FeatureContext : std::uint8_t { mac_ip, host, channel, jitter, socket };

inline constexpr std::uint8_t context_bit(FeatureContext context) {
  return static_cast<std::uint8_t>(1U << static_cast<unsigned>(context));
}

inline constexpr std::uint8_t new_mac_ip_bit = 0x01;
inline constexpr std::uint8_t new_host_bit = 0x02;
inline constexpr std::uint8_t new_channel_bit = 0x04;
inline constexpr std::uint8_t new_socket_bit = 0x08;

struct Incident {
  std::uint64_t sequence = 0;
  std::uint64_t first_ns = 0;
  std::uint64_t last_ns = 0;
  std::uint64_t packets = 0;
  float peak_score = 0.0F;
  float threshold = 0.0F;
  std::array<std::uint8_t, 16> src_ip{};
  std::array<std::uint8_t, 16> dst_ip{};
  std::uint16_t src_port = 0;
  std::uint16_t dst_port = 0;
  std::uint8_t transport = 0;
  std::uint8_t context_mask = 0;
  std::uint8_t new_entity_mask = 0;
  std::uint8_t is_ipv6 = 0;
};

struct AlertEvent {
  std::uint64_t timestamp_ns = 0;
  float score = 0.0F;
  float threshold = 0.0F;
  std::array<std::uint8_t, 16> src_ip{};
  std::array<std::uint8_t, 16> dst_ip{};
  std::uint16_t src_port = 0;
  std::uint16_t dst_port = 0;
  std::uint8_t transport = 0;
  std::uint8_t context_mask = 0;
  std::uint8_t new_entity_mask = 0;
  std::uint8_t is_ipv6 = 0;
};

struct IncidentConfig {
  std::uint64_t cooldown_ns = 5'000'000'000ULL;
  std::uint64_t max_duration_ns = 60'000'000'000ULL;
  std::size_t open_capacity = 64;
  std::size_t closed_capacity = 256;
};

class IncidentTracker {
 public:
  explicit IncidentTracker(const IncidentConfig& config = {})
      : config_(config), closed_(config.closed_capacity) {
    open_.reserve(config.open_capacity);
  }

  void observe(const AlertEvent& event) {
    if (Incident* existing = find_open(event)) {
      fold_into(*existing, event);
      if (existing->last_ns - existing->first_ns >= config_.max_duration_ns) close(*existing);
      return;
    }
    if (open_.size() == config_.open_capacity) close(oldest_open());
    open_.push_back(open_incident(event));
  }

  void expire(std::uint64_t now_ns) {
    if (open_.empty()) return;
    for (std::size_t i = open_.size(); i-- > 0;) {
      if (now_ns - open_[i].last_ns >= config_.cooldown_ns) close(open_[i]);
    }
  }

  void close_all() {
    while (!open_.empty()) close(open_.back());
  }

  [[nodiscard]] std::size_t drain_closed(std::span<Incident> out) {
    const std::size_t count = std::min(out.size(), closed_count_);
    for (std::size_t i = 0; i < count; ++i) {
      out[i] = closed_[(closed_head_ + i) % closed_.size()];
    }
    closed_head_ = (closed_head_ + count) % closed_.size();
    closed_count_ -= count;
    return count;
  }

  [[nodiscard]] std::span<const Incident> open_incidents() const { return open_; }
  [[nodiscard]] std::uint64_t sequence() const { return next_sequence_ - 1; }
  [[nodiscard]] std::uint64_t opened() const { return next_sequence_ - 1; }
  [[nodiscard]] std::uint64_t dropped() const { return dropped_; }

 private:
  [[nodiscard]] static bool same_channel(const Incident& incident, const AlertEvent& event) {
    return incident.src_ip == event.src_ip && incident.dst_ip == event.dst_ip;
  }

  Incident* find_open(const AlertEvent& event) {
    for (Incident& incident : open_) {
      if (same_channel(incident, event)) return &incident;
    }
    return nullptr;
  }

  Incident& oldest_open() {
    return *std::min_element(open_.begin(), open_.end(), [](const Incident& a, const Incident& b) {
      return a.last_ns < b.last_ns;
    });
  }

  Incident open_incident(const AlertEvent& event) {
    Incident incident;
    incident.sequence = next_sequence_;
    incident.first_ns = event.timestamp_ns;
    incident.last_ns = event.timestamp_ns;
    incident.packets = 1;
    incident.peak_score = event.score;
    incident.threshold = event.threshold;
    incident.src_ip = event.src_ip;
    incident.dst_ip = event.dst_ip;
    incident.src_port = event.src_port;
    incident.dst_port = event.dst_port;
    incident.transport = event.transport;
    incident.context_mask = event.context_mask;
    incident.new_entity_mask = event.new_entity_mask;
    incident.is_ipv6 = event.is_ipv6;
    next_sequence_ += 1;
    return incident;
  }

  static void fold_into(Incident& incident, const AlertEvent& event) {
    incident.packets += 1;
    incident.last_ns = std::max(incident.last_ns, event.timestamp_ns);
    incident.context_mask = static_cast<std::uint8_t>(incident.context_mask | event.context_mask);
    incident.new_entity_mask =
        static_cast<std::uint8_t>(incident.new_entity_mask | event.new_entity_mask);
    if (event.score <= incident.peak_score) return;
    incident.peak_score = event.score;
    incident.threshold = event.threshold;
    incident.src_port = event.src_port;
    incident.dst_port = event.dst_port;
    incident.transport = event.transport;
  }

  void close(Incident& incident) {
    if (closed_count_ == closed_.size()) {
      closed_head_ = (closed_head_ + 1) % closed_.size();
      closed_count_ -= 1;
      dropped_ += 1;
    }
    closed_[(closed_head_ + closed_count_) % closed_.size()] = incident;
    closed_count_ += 1;
    const auto slot = static_cast<std::size_t>(&incident - open_.data());
    open_[slot] = open_.back();
    open_.pop_back();
  }

  IncidentConfig config_;
  std::vector<Incident> open_;
  std::vector<Incident> closed_;
  std::size_t closed_head_ = 0;
  std::size_t closed_count_ = 0;
  std::uint64_t next_sequence_ = 1;
  std::uint64_t dropped_ = 0;
};

}  // namespace watchdog
