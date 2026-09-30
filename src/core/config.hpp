#pragma once

#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace watchdog {

struct Settings {
  std::string interface_name;
  std::string model_path;
  std::string alert_log_path;
  std::string socket_path;
  std::uint64_t grace_packets = 1'000'000;
  std::uint64_t alert_log_max_bytes = 8 * 1024 * 1024;
  std::uint64_t mac_ip_slots = 4096;
  std::uint64_t host_slots = 4096;
  std::uint64_t channel_slots = 32768;
  std::uint64_t socket_slots = 32768;
  std::uint64_t incident_cooldown_seconds = 5;
  std::uint64_t incident_max_duration_seconds = 60;
  double alert_factor = 1.5;
  double alert_quantile = 0.999;
  double train_gate_factor = 1.0;
};

struct SettingsLoad {
  Settings settings;
  std::vector<std::string> errors;
  bool file_present = false;
};

namespace detail {

inline std::string trim(std::string_view text) {
  const auto first = text.find_first_not_of(" \t\r");
  if (first == std::string_view::npos) return {};
  const auto last = text.find_last_not_of(" \t\r");
  return std::string(text.substr(first, last - first + 1));
}

class SettingAssigner {
 public:
  SettingAssigner(std::string key, std::string value, std::size_t line,
                  std::vector<std::string>& errors)
      : key_(std::move(key)), value_(std::move(value)), line_(line), errors_(errors) {}

  [[nodiscard]] bool matches(std::string_view name) const { return key_ == name; }
  [[nodiscard]] bool named() const { return !key_.empty(); }
  [[nodiscard]] bool has_value() const { return !value_.empty(); }

  void text(std::string& target) const { target = value_; }

  void number(std::uint64_t& target, std::uint64_t low, std::uint64_t high) const {
    std::uint64_t parsed = 0;
    const char* end = value_.data() + value_.size();
    const auto [stop, code] = std::from_chars(value_.data(), end, parsed);
    if (code != std::errc{} || stop != end) return reject("expects a whole number");
    if (parsed < low || parsed > high) {
      return reject("must be between " + std::to_string(low) + " and " + std::to_string(high));
    }
    target = parsed;
  }

  void power_of_two(std::uint64_t& target, std::uint64_t low, std::uint64_t high) const {
    std::uint64_t parsed = target;
    number(parsed, low, high);
    if (parsed == target) return;
    if ((parsed & (parsed - 1)) != 0) return reject("must be a power of two");
    target = parsed;
  }

  void fraction(double& target, double low, double high) const {
    char* end = nullptr;
    errno = 0;
    const double parsed = std::strtod(value_.c_str(), &end);
    if (errno != 0 || end != value_.c_str() + value_.size()) return reject("expects a number");
    if (parsed < low || parsed > high) {
      return reject("must be between " + std::to_string(low) + " and " + std::to_string(high));
    }
    target = parsed;
  }

  void reject(const std::string& reason) const {
    errors_.push_back("line " + std::to_string(line_) + ": " + key_ + " " + reason);
  }

 private:
  std::string key_;
  std::string value_;
  std::size_t line_;
  std::vector<std::string>& errors_;
};

}  // namespace detail

[[nodiscard]] inline SettingsLoad parse_settings(const std::string& text,
                                                 const Settings& defaults) {
  SettingsLoad load;
  load.settings = defaults;
  Settings& settings = load.settings;
  std::istringstream stream(text);
  std::string raw;
  std::size_t line_number = 0;
  while (std::getline(stream, raw)) {
    line_number += 1;
    const std::string line = detail::trim(raw);
    if (line.empty() || line[0] == '#') continue;
    const auto separator = line.find('=');
    if (separator == std::string::npos) {
      load.errors.push_back("line " + std::to_string(line_number) + ": expected 'key = value'");
      continue;
    }
    const detail::SettingAssigner assign(detail::trim(std::string_view(line).substr(0, separator)),
                                         detail::trim(std::string_view(line).substr(separator + 1)),
                                         line_number, load.errors);
    if (!assign.named()) {
      load.errors.push_back("line " + std::to_string(line_number) + ": setting has no name");
    } else if (!assign.has_value()) {
      assign.reject("has no value");
    } else if (assign.matches("interface")) {
      assign.text(settings.interface_name);
    } else if (assign.matches("model")) {
      assign.text(settings.model_path);
    } else if (assign.matches("alerts")) {
      assign.text(settings.alert_log_path);
    } else if (assign.matches("socket")) {
      assign.text(settings.socket_path);
    } else if (assign.matches("grace_packets")) {
      assign.number(settings.grace_packets, 1'000, 1'000'000'000);
    } else if (assign.matches("alert_log_max_bytes")) {
      assign.number(settings.alert_log_max_bytes, 4'096, 1'000'000'000);
    } else if (assign.matches("mac_ip_slots")) {
      assign.power_of_two(settings.mac_ip_slots, 16, 1 << 22);
    } else if (assign.matches("host_slots")) {
      assign.power_of_two(settings.host_slots, 16, 1 << 22);
    } else if (assign.matches("channel_slots")) {
      assign.power_of_two(settings.channel_slots, 16, 1 << 22);
    } else if (assign.matches("socket_slots")) {
      assign.power_of_two(settings.socket_slots, 16, 1 << 22);
    } else if (assign.matches("incident_cooldown_seconds")) {
      assign.number(settings.incident_cooldown_seconds, 1, 3'600);
    } else if (assign.matches("incident_max_duration_seconds")) {
      assign.number(settings.incident_max_duration_seconds, 1, 86'400);
    } else if (assign.matches("alert_factor")) {
      assign.fraction(settings.alert_factor, 1.0, 1'000.0);
    } else if (assign.matches("alert_quantile")) {
      assign.fraction(settings.alert_quantile, 0.9, 0.99999);
    } else if (assign.matches("train_gate_factor")) {
      assign.fraction(settings.train_gate_factor, 1.0, 100.0);
    } else {
      assign.reject("is not a known setting");
    }
  }
  if (settings.incident_max_duration_seconds < settings.incident_cooldown_seconds) {
    load.errors.emplace_back(
        "incident_max_duration_seconds must not be below incident_cooldown_seconds");
  }
  return load;
}

}  // namespace watchdog
