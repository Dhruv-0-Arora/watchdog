#include <doctest/doctest.h>

#include <string>

#include "core/config.hpp"

namespace {

using watchdog::parse_settings;
using watchdog::Settings;
using watchdog::SettingsLoad;

SettingsLoad parse(const std::string& text) { return parse_settings(text, Settings{}); }

TEST_CASE("an empty config keeps every default") {
  const SettingsLoad load = parse("");
  const Settings defaults;
  CHECK(load.errors.empty());
  CHECK(load.settings.grace_packets == defaults.grace_packets);
  CHECK(load.settings.channel_slots == defaults.channel_slots);
  CHECK(load.settings.alert_factor == defaults.alert_factor);
}

TEST_CASE("comments and blank lines are ignored") {
  const SettingsLoad load = parse("# a comment\n\n   \n# grace_packets = 5\n");
  CHECK(load.errors.empty());
  CHECK(load.settings.grace_packets == Settings{}.grace_packets);
}

TEST_CASE("recognised settings are applied with surrounding space trimmed") {
  const SettingsLoad load = parse(
      "interface = en0\n"
      "  grace_packets=250000\n"
      "channel_slots = 65536\n"
      "alert_factor = 2.5\n"
      "alerts =/tmp/a.jsonl\n"
      "incident_cooldown_seconds = 10\n");
  CHECK(load.errors.empty());
  CHECK(load.settings.interface_name == "en0");
  CHECK(load.settings.grace_packets == 250'000);
  CHECK(load.settings.channel_slots == 65'536);
  CHECK(load.settings.alert_factor == doctest::Approx(2.5));
  CHECK(load.settings.alert_log_path == "/tmp/a.jsonl");
  CHECK(load.settings.incident_cooldown_seconds == 10);
}

TEST_CASE("an unknown setting is reported and leaves defaults intact") {
  const SettingsLoad load = parse("grace_packets = 5000\nnonsense = 1\n");
  REQUIRE(load.errors.size() == 1);
  CHECK(load.errors[0].find("nonsense") != std::string::npos);
  CHECK(load.errors[0].find("line 2") != std::string::npos);
  CHECK(load.settings.grace_packets == 5'000);
}

TEST_CASE("out-of-range numbers are rejected rather than clamped") {
  const SettingsLoad load = parse("grace_packets = 10\n");
  REQUIRE(load.errors.size() == 1);
  CHECK(load.errors[0].find("between") != std::string::npos);
  CHECK(load.settings.grace_packets == Settings{}.grace_packets);
}

TEST_CASE("non-numeric values are rejected") {
  const SettingsLoad load = parse("grace_packets = many\nalert_factor = high\n");
  CHECK(load.errors.size() == 2);
  CHECK(load.settings.grace_packets == Settings{}.grace_packets);
  CHECK(load.settings.alert_factor == Settings{}.alert_factor);
}

TEST_CASE("table sizes must be powers of two") {
  const SettingsLoad load = parse("channel_slots = 1000\n");
  REQUIRE(load.errors.size() == 1);
  CHECK(load.errors[0].find("power of two") != std::string::npos);
  CHECK(load.settings.channel_slots == Settings{}.channel_slots);
}

TEST_CASE("a line without an equals sign is reported") {
  const SettingsLoad load = parse("interface en0\n");
  REQUIRE(load.errors.size() == 1);
  CHECK(load.errors[0].find("key = value") != std::string::npos);
}

TEST_CASE("a setting with no value is reported") {
  const SettingsLoad load = parse("interface =\n");
  REQUIRE(load.errors.size() == 1);
  CHECK(load.settings.interface_name.empty());
}

TEST_CASE("contradictory incident windows are rejected") {
  const SettingsLoad load =
      parse("incident_cooldown_seconds = 100\nincident_max_duration_seconds = 10\n");
  REQUIRE(load.errors.size() == 1);
  CHECK(load.errors[0].find("must not be below") != std::string::npos);
}

TEST_CASE("supplied defaults are the starting point") {
  Settings defaults;
  defaults.interface_name = "eth9";
  defaults.grace_packets = 4'242;
  const SettingsLoad load = parse_settings("alert_factor = 3\n", defaults);
  CHECK(load.errors.empty());
  CHECK(load.settings.interface_name == "eth9");
  CHECK(load.settings.grace_packets == 4'242);
  CHECK(load.settings.alert_factor == doctest::Approx(3.0));
}

}  // namespace
