#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "core/incident.hpp"

namespace {

using watchdog::AlertEvent;
using watchdog::Incident;
using watchdog::IncidentConfig;
using watchdog::IncidentTracker;

AlertEvent alert(std::uint8_t source, std::uint8_t destination, std::uint64_t time_ns,
                 float score) {
  AlertEvent event;
  event.timestamp_ns = time_ns;
  event.score = score;
  event.threshold = 1.0F;
  event.src_ip[15] = source;
  event.dst_ip[15] = destination;
  event.src_port = 40000;
  event.dst_port = 443;
  return event;
}

std::vector<Incident> drain(IncidentTracker& tracker) {
  std::array<Incident, 16> buffer{};
  const std::size_t count = tracker.drain_closed(buffer);
  return {buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(count)};
}

TEST_CASE("repeated alerts on one channel fold into a single incident") {
  IncidentTracker tracker;
  for (int i = 0; i < 10'000; ++i) {
    tracker.observe(alert(1, 2, 1'000'000ULL * static_cast<std::uint64_t>(i), 5.0F));
  }
  CHECK(tracker.open_incidents().size() == 1);
  CHECK(tracker.open_incidents()[0].packets == 10'000);
  CHECK(drain(tracker).empty());
}

TEST_CASE("distinct channels open distinct incidents") {
  IncidentTracker tracker;
  tracker.observe(alert(1, 2, 0, 5.0F));
  tracker.observe(alert(3, 4, 1'000, 5.0F));
  tracker.observe(alert(1, 2, 2'000, 5.0F));
  CHECK(tracker.open_incidents().size() == 2);
  CHECK(tracker.opened() == 2);
}

TEST_CASE("an incident closes after the cooldown and is drained once") {
  IncidentConfig config;
  config.cooldown_ns = 1'000'000'000ULL;
  IncidentTracker tracker(config);
  tracker.observe(alert(1, 2, 0, 5.0F));
  tracker.expire(500'000'000ULL);
  CHECK(tracker.open_incidents().size() == 1);
  tracker.expire(2'000'000'000ULL);
  CHECK(tracker.open_incidents().empty());
  const std::vector<Incident> closed = drain(tracker);
  REQUIRE(closed.size() == 1);
  CHECK(closed[0].packets == 1);
  CHECK(closed[0].sequence == 1);
  CHECK(drain(tracker).empty());
}

TEST_CASE("a long-running attack is cut into bounded incidents") {
  IncidentConfig config;
  config.max_duration_ns = 1'000'000'000ULL;
  IncidentTracker tracker(config);
  for (int i = 0; i < 40; ++i) {
    tracker.observe(alert(1, 2, 100'000'000ULL * static_cast<std::uint64_t>(i), 5.0F));
  }
  const std::vector<Incident> closed = drain(tracker);
  CHECK(closed.size() >= 3);
  for (const Incident& incident : closed) {
    CHECK(incident.last_ns - incident.first_ns <= config.max_duration_ns);
  }
  CHECK(tracker.open_incidents().size() == 1);
}

TEST_CASE("the peak score and its packet details win") {
  IncidentTracker tracker;
  tracker.observe(alert(1, 2, 0, 3.0F));
  AlertEvent peak = alert(1, 2, 1'000, 42.0F);
  peak.dst_port = 22;
  peak.context_mask = watchdog::context_bit(watchdog::FeatureContext::jitter);
  tracker.observe(peak);
  tracker.observe(alert(1, 2, 2'000, 4.0F));
  const Incident& incident = tracker.open_incidents()[0];
  CHECK(incident.peak_score == 42.0F);
  CHECK(incident.dst_port == 22);
  CHECK(incident.packets == 3);
  CHECK((incident.context_mask & watchdog::context_bit(watchdog::FeatureContext::jitter)) != 0);
}

TEST_CASE("context and new-entity flags accumulate across folded packets") {
  IncidentTracker tracker;
  AlertEvent first = alert(1, 2, 0, 5.0F);
  first.context_mask = watchdog::context_bit(watchdog::FeatureContext::host);
  first.new_entity_mask = watchdog::new_host_bit;
  AlertEvent second = alert(1, 2, 1'000, 4.0F);
  second.context_mask = watchdog::context_bit(watchdog::FeatureContext::socket);
  second.new_entity_mask = watchdog::new_socket_bit;
  tracker.observe(first);
  tracker.observe(second);
  const Incident& incident = tracker.open_incidents()[0];
  CHECK(incident.context_mask == (watchdog::context_bit(watchdog::FeatureContext::host) |
                                  watchdog::context_bit(watchdog::FeatureContext::socket)));
  CHECK(incident.new_entity_mask == (watchdog::new_host_bit | watchdog::new_socket_bit));
}

TEST_CASE("open capacity is bounded by closing the stalest incident") {
  IncidentConfig config;
  config.open_capacity = 4;
  IncidentTracker tracker(config);
  for (std::uint8_t host = 1; host <= 20; ++host) {
    tracker.observe(alert(host, 100, 1'000ULL * host, 5.0F));
    CHECK(tracker.open_incidents().size() <= config.open_capacity);
  }
  CHECK(drain(tracker).size() == 16);
}

TEST_CASE("closed overflow drops oldest and counts the loss") {
  IncidentConfig config;
  config.closed_capacity = 4;
  config.cooldown_ns = 1;
  IncidentTracker tracker(config);
  for (std::uint8_t host = 1; host <= 10; ++host) {
    tracker.observe(alert(host, 100, 1'000'000ULL * host, 5.0F));
    tracker.expire(1'000'000ULL * host + 10);
  }
  CHECK(tracker.dropped() == 6);
  const std::vector<Incident> closed = drain(tracker);
  CHECK(closed.size() == 4);
  CHECK(closed.front().sequence == 7);
}

TEST_CASE("close_all flushes open incidents at shutdown") {
  IncidentTracker tracker;
  tracker.observe(alert(1, 2, 0, 5.0F));
  tracker.observe(alert(3, 4, 0, 5.0F));
  tracker.close_all();
  CHECK(tracker.open_incidents().empty());
  CHECK(drain(tracker).size() == 2);
}

}  // namespace
