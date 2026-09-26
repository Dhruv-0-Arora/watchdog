#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <span>
#include <thread>

#include "core/ring.hpp"

namespace {

using watchdog::SpscRing;

TEST_CASE("capacity rounds up to a power of two") {
  CHECK(SpscRing<int>(3).capacity() == 4);
  CHECK(SpscRing<int>(4).capacity() == 4);
  CHECK(SpscRing<int>(5).capacity() == 8);
}

TEST_CASE("pop returns pushed values in order") {
  SpscRing<int> ring(8);
  for (int value = 0; value < 5; ++value) CHECK(ring.try_push(value));
  std::array<int, 8> out{};
  CHECK(ring.pop(std::span(out)) == 5);
  for (int value = 0; value < 5; ++value) CHECK(out[static_cast<std::size_t>(value)] == value);
  CHECK(ring.pop(std::span(out)) == 0);
}

TEST_CASE("try_push fails only when full") {
  SpscRing<int> ring(4);
  for (int value = 0; value < 4; ++value) CHECK(ring.try_push(value));
  CHECK(!ring.try_push(99));
  std::array<int, 1> out{};
  CHECK(ring.pop(std::span(out)) == 1);
  CHECK(ring.try_push(99));
}

TEST_CASE("close wakes a blocked consumer") {
  SpscRing<int> ring(4);
  std::size_t popped = 1;
  std::thread consumer([&] {
    std::array<int, 4> out{};
    popped = ring.pop_wait(std::span(out));
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  ring.close();
  consumer.join();
  CHECK(popped == 0);
}

TEST_CASE("concurrent transfer delivers every value exactly once") {
  constexpr std::uint64_t total = 1'000'000;
  SpscRing<std::uint64_t> ring(1024);
  std::thread producer([&] {
    for (std::uint64_t value = 0; value < total; ++value) {
      while (!ring.try_push(value)) {
        ring.notify_consumer();
        std::this_thread::yield();
      }
      if (value % 4096 == 0) ring.notify_consumer();
    }
    ring.close();
  });
  std::uint64_t received = 0;
  std::uint64_t checksum = 0;
  std::uint64_t expected_next = 0;
  bool ordered = true;
  std::array<std::uint64_t, 256> batch{};
  while (true) {
    const std::size_t count = ring.pop_wait(std::span(batch));
    if (count == 0) break;
    for (std::size_t i = 0; i < count; ++i) {
      ordered = ordered && batch[i] == expected_next;
      expected_next += 1;
      checksum += batch[i];
      received += 1;
    }
  }
  producer.join();
  CHECK(received == total);
  CHECK(ordered);
  CHECK(checksum == total * (total - 1) / 2);
}

}  // namespace
