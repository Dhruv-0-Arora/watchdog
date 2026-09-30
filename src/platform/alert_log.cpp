#include "platform/alert_log.hpp"

#include <array>
#include <cinttypes>
#include <ctime>
#include <utility>

#include "core/format.hpp"

namespace watchdog {

namespace {

std::string iso_time(std::uint64_t timestamp_ns) {
  const auto seconds = static_cast<std::time_t>(timestamp_ns / 1'000'000'000ULL);
  const auto milliseconds = static_cast<unsigned>((timestamp_ns % 1'000'000'000ULL) / 1'000'000);
  std::tm parts{};
  gmtime_r(&seconds, &parts);
  std::array<char, 40> buffer{};
  const std::size_t written =
      std::strftime(buffer.data(), buffer.size(), "%Y-%m-%dT%H:%M:%S", &parts);
  std::snprintf(buffer.data() + written, buffer.size() - written, ".%03uZ", milliseconds);
  return buffer.data();
}

}  // namespace

AlertLog::AlertLog(std::string path, std::uint64_t max_bytes)
    : path_(std::move(path)), max_bytes_(max_bytes) {}

AlertLog::~AlertLog() {
  if (file_ != nullptr) std::fclose(file_);
}

bool AlertLog::open() {
  if (path_.empty()) return true;
  file_ = std::fopen(path_.c_str(), "ab");
  if (file_ == nullptr) return false;
  bytes_ = static_cast<std::uint64_t>(std::ftell(file_));
  return true;
}

void AlertLog::rotate_if_needed() {
  if (bytes_ < max_bytes_) return;
  std::fclose(file_);
  const std::string previous = path_ + ".1";
  std::remove(previous.c_str());
  std::rename(path_.c_str(), previous.c_str());
  file_ = std::fopen(path_.c_str(), "wb");
  bytes_ = 0;
}

void AlertLog::write(const Incident& incident) {
  written_ += 1;
  if (file_ == nullptr) return;
  rotate_if_needed();
  const std::string source = format_address(incident.src_ip);
  const std::string destination = format_address(incident.dst_ip);
  const std::string contexts = format_contexts(incident.context_mask);
  const std::string new_entities = format_new_entities(incident.new_entity_mask);
  const double duration_seconds = static_cast<double>(incident.last_ns - incident.first_ns) / 1e9;
  const int count = std::fprintf(
      file_,
      "{\"seq\":%" PRIu64
      ",\"first\":\"%s\",\"last\":\"%s\",\"duration_s\":%.3f,\"packets\":%" PRIu64
      ",\"src\":\"%s\",\"dst\":\"%s\",\"src_port\":%u,\"dst_port\":%u,\"transport\":\"%s\""
      ",\"score\":%.4f,\"threshold\":%.4f,\"severity\":%.2f,\"contexts\":\"%s\",\"new\":\"%s\"}\n",
      incident.sequence, iso_time(incident.first_ns).c_str(), iso_time(incident.last_ns).c_str(),
      duration_seconds, incident.packets, source.c_str(), destination.c_str(), incident.src_port,
      incident.dst_port, transport_name(incident.transport),
      static_cast<double>(incident.peak_score), static_cast<double>(incident.threshold),
      incident.threshold > 0.0F ? static_cast<double>(incident.peak_score / incident.threshold)
                                : 0.0,
      contexts.c_str(), new_entities.c_str());
  if (count > 0) bytes_ += static_cast<std::uint64_t>(count);
  std::fflush(file_);
}

}  // namespace watchdog
