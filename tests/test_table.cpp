#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <cstring>

#include "core/table.hpp"
#include "support/alloc_probe.hpp"

namespace {

using watchdog::EntityTable;

struct TestKey {
  std::uint64_t id = 0;
  bool operator==(const TestKey&) const = default;
};

struct TestValue {
  std::uint64_t hits = 0;
};

TEST_CASE("find_or_insert returns the same entry for the same key") {
  EntityTable<TestKey, TestValue> table(64);
  const auto first = table.find_or_insert({7}, 100);
  CHECK(first.inserted);
  CHECK(first.previous_seen_ns == 100);
  first.value.hits = 5;
  const auto second = table.find_or_insert({7}, 250);
  CHECK(!second.inserted);
  CHECK(second.previous_seen_ns == 100);
  CHECK(second.value.hits == 5);
  CHECK(table.occupied() == 1);
}

TEST_CASE("distinct keys get distinct entries") {
  EntityTable<TestKey, TestValue> table(64);
  for (std::uint64_t id = 0; id < 32; ++id) {
    const auto slot = table.find_or_insert({id}, id);
    CHECK(slot.inserted);
    slot.value.hits = id;
  }
  CHECK(table.occupied() == 32);
  for (std::uint64_t id = 0; id < 32; ++id) {
    const auto slot = table.find_or_insert({id}, 1'000 + id);
    CHECK(!slot.inserted);
    CHECK(slot.value.hits == id);
  }
}

TEST_CASE("eviction replaces the stalest entry when a probe window fills") {
  EntityTable<TestKey, TestValue> table(16);
  for (std::uint64_t id = 0; id < 16; ++id) table.find_or_insert({id}, 1'000 + id);
  CHECK(table.occupied() == 16);
  CHECK(table.evictions() == 0);
  const auto slot = table.find_or_insert({999}, 5'000);
  CHECK(slot.inserted);
  CHECK(table.evictions() == 1);
  CHECK(table.occupied() == 16);
}

TEST_CASE("adversarial key churn stays within fixed memory and never allocates") {
  EntityTable<TestKey, TestValue> table(1024);
  std::uint64_t state = 0xDEADBEEF;
  const std::size_t allocations_before = watchdog::alloc_probe::allocation_count();
  for (int i = 0; i < 2'000'000; ++i) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    const auto slot = table.find_or_insert({state}, static_cast<std::uint64_t>(i));
    slot.value.hits += 1;
    CHECK(table.occupied() <= table.capacity());
  }
  const std::size_t allocations_after = watchdog::alloc_probe::allocation_count();
  if constexpr (watchdog::alloc_probe::enabled) {
    CHECK(allocations_after == allocations_before);
  }
  CHECK(table.occupied() == table.capacity());
  CHECK(table.evictions() > 0);
}

}  // namespace
