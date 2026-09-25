#include <doctest/doctest.h>

#include <cstddef>
#include <cstdint>
#include <new>

#include "support/alloc_probe.hpp"

namespace probe = watchdog::alloc_probe;

TEST_CASE("plain new and delete are each counted once" * doctest::skip(!probe::enabled)) {
  const std::size_t allocations_before = probe::allocation_count();
  void* memory = ::operator new(64);
  const std::size_t allocations_after = probe::allocation_count();

  const std::size_t deallocations_before = probe::deallocation_count();
  ::operator delete(memory);
  const std::size_t deallocations_after = probe::deallocation_count();

  CHECK(allocations_after == allocations_before + 1);
  CHECK(deallocations_after == deallocations_before + 1);
}

TEST_CASE("aligned new and delete are each counted once" * doctest::skip(!probe::enabled)) {
  const std::size_t allocations_before = probe::allocation_count();
  void* memory = ::operator new(64, std::align_val_t{128});
  const std::size_t allocations_after = probe::allocation_count();

  const std::size_t deallocations_before = probe::deallocation_count();
  ::operator delete(memory, std::align_val_t{128});
  const std::size_t deallocations_after = probe::deallocation_count();

  CHECK(reinterpret_cast<std::uintptr_t>(memory) % 128 == 0);
  CHECK(allocations_after == allocations_before + 1);
  CHECK(deallocations_after == deallocations_before + 1);
}

TEST_CASE("live allocations return to baseline after balanced use" *
          doctest::skip(!probe::enabled)) {
  const std::size_t live_before = probe::live_allocation_count();
  void* first = ::operator new(32);
  void* second = ::operator new[](32);
  const std::size_t live_during = probe::live_allocation_count();

  ::operator delete[](second);
  ::operator delete(first);
  const std::size_t live_after = probe::live_allocation_count();

  CHECK(live_during == live_before + 2);
  CHECK(live_after == live_before);
}
