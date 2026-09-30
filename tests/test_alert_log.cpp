#include <doctest/doctest.h>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "core/format.hpp"
#include "core/incident.hpp"
#include "platform/alert_log.hpp"

namespace {

using watchdog::AlertLog;
using watchdog::Incident;

Incident sample_incident(std::uint64_t sequence) {
  Incident incident;
  incident.sequence = sequence;
  incident.first_ns = 1'700'000'000'000'000'000ULL;
  incident.last_ns = incident.first_ns + 2'500'000'000ULL;
  incident.packets = 4096;
  incident.peak_score = 17.5F;
  incident.threshold = 0.25F;
  incident.src_ip = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 0, 0, 99};
  incident.dst_ip = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 0, 1, 5};
  incident.src_port = 43210;
  incident.dst_port = 22;
  incident.context_mask = watchdog::context_bit(watchdog::FeatureContext::channel);
  incident.new_entity_mask = watchdog::new_host_bit;
  return incident;
}

std::vector<std::string> read_lines(const std::string& path) {
  std::ifstream input(path);
  std::vector<std::string> lines;
  for (std::string line; std::getline(input, line);) lines.push_back(line);
  return lines;
}

TEST_CASE("an incident becomes one json line with readable fields") {
  const std::string path = "alert_log_test.jsonl";
  std::remove(path.c_str());
  {
    AlertLog log(path, 8 * 1024 * 1024);
    REQUIRE(log.open());
    log.write(sample_incident(7));
  }
  const std::vector<std::string> lines = read_lines(path);
  REQUIRE(lines.size() == 1);
  const std::string& line = lines[0];
  CHECK(line.find("\"seq\":7") != std::string::npos);
  CHECK(line.find("\"src\":\"10.0.0.99\"") != std::string::npos);
  CHECK(line.find("\"dst\":\"10.0.1.5\"") != std::string::npos);
  CHECK(line.find("\"dst_port\":22") != std::string::npos);
  CHECK(line.find("\"packets\":4096") != std::string::npos);
  CHECK(line.find("\"duration_s\":2.500") != std::string::npos);
  CHECK(line.find("\"contexts\":\"channel\"") != std::string::npos);
  CHECK(line.find("\"new\":\"host\"") != std::string::npos);
  CHECK(line.find("2023-11-14T") != std::string::npos);
  std::remove(path.c_str());
}

TEST_CASE("appending preserves earlier lines across reopen") {
  const std::string path = "alert_log_append.jsonl";
  std::remove(path.c_str());
  {
    AlertLog log(path, 8 * 1024 * 1024);
    REQUIRE(log.open());
    log.write(sample_incident(1));
  }
  {
    AlertLog log(path, 8 * 1024 * 1024);
    REQUIRE(log.open());
    log.write(sample_incident(2));
  }
  CHECK(read_lines(path).size() == 2);
  std::remove(path.c_str());
}

TEST_CASE("rotation keeps disk usage bounded at two files") {
  const std::string path = "alert_log_rotate.jsonl";
  const std::string previous = path + ".1";
  std::remove(path.c_str());
  std::remove(previous.c_str());
  {
    AlertLog log(path, 2'000);
    REQUIRE(log.open());
    for (std::uint64_t i = 1; i <= 200; ++i) log.write(sample_incident(i));
  }
  const std::vector<std::string> current = read_lines(path);
  const std::vector<std::string> rolled = read_lines(previous);
  CHECK(!current.empty());
  CHECK(!rolled.empty());
  CHECK(current.size() + rolled.size() < 200);
  for (const std::string& line : current) CHECK(line.size() < 2'000);
  std::remove(path.c_str());
  std::remove(previous.c_str());
}

TEST_CASE("an empty path disables logging without failing") {
  AlertLog log("", 1'000);
  CHECK(log.open());
  log.write(sample_incident(1));
  CHECK(log.written() == 1);
}

TEST_CASE("ipv6 addresses format in colon notation") {
  Incident incident = sample_incident(1);
  incident.src_ip = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  CHECK(watchdog::format_address(incident.src_ip) == "2001:db8:0:0:0:0:0:1");
}

}  // namespace
