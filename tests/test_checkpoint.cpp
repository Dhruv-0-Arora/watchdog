#include <doctest/doctest.h>

#include <cstddef>
#include <cstdio>
#include <string>
#include <vector>

#include "platform/checkpoint.hpp"

namespace {

using watchdog::read_file;
using watchdog::write_file_atomic;

std::vector<std::byte> pattern_bytes(std::size_t count, std::uint8_t seed) {
  std::vector<std::byte> bytes(count);
  for (std::size_t i = 0; i < count; ++i) {
    bytes[i] = static_cast<std::byte>((seed + i) & 0xFF);
  }
  return bytes;
}

TEST_CASE("checkpoint file roundtrip preserves bytes") {
  const std::string path = "checkpoint_test.bin";
  const std::vector<std::byte> written = pattern_bytes(70'000, 3);
  REQUIRE(write_file_atomic(path, written));
  CHECK(read_file(path) == written);
  const std::vector<std::byte> replacement = pattern_bytes(1'000, 9);
  REQUIRE(write_file_atomic(path, replacement));
  CHECK(read_file(path) == replacement);
  std::remove(path.c_str());
}

TEST_CASE("reading a missing file returns empty") {
  CHECK(read_file("does_not_exist.bin").empty());
}

}  // namespace
