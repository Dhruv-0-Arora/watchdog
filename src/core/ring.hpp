#pragma once

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <type_traits>

namespace watchdog {

inline constexpr std::size_t cache_line_size = 128;

template <typename T>
class SpscRing {
  static_assert(std::is_trivially_copyable_v<T>);

 public:
  explicit SpscRing(std::size_t min_capacity)
      : mask_(std::bit_ceil(min_capacity) - 1), slots_(std::make_unique<T[]>(mask_ + 1)) {}

  [[nodiscard]] std::size_t capacity() const { return mask_ + 1; }

  [[nodiscard]] bool try_push(const T& value) {
    const std::uint64_t tail = tail_.load(std::memory_order_relaxed);
    if (tail - cached_head_ == capacity()) {
      cached_head_ = head_.load(std::memory_order_acquire);
      if (tail - cached_head_ == capacity()) return false;
    }
    slots_[tail & mask_] = value;
    tail_.store(tail + 1, std::memory_order_release);
    return true;
  }

  void notify_consumer() {
    wake_epoch_.fetch_add(1, std::memory_order_release);
    wake_epoch_.notify_one();
  }

  void close() {
    closed_.store(true, std::memory_order_release);
    notify_consumer();
  }

  [[nodiscard]] std::size_t pop(std::span<T> out) {
    const std::uint64_t head = head_.load(std::memory_order_relaxed);
    if (head == cached_tail_) {
      cached_tail_ = tail_.load(std::memory_order_acquire);
      if (head == cached_tail_) return 0;
    }
    const std::size_t count =
        static_cast<std::size_t>(std::min<std::uint64_t>(cached_tail_ - head, out.size()));
    for (std::size_t i = 0; i < count; ++i) out[i] = slots_[(head + i) & mask_];
    head_.store(head + count, std::memory_order_release);
    return count;
  }

  [[nodiscard]] std::size_t pop_wait(std::span<T> out) {
    while (true) {
      if (const std::size_t count = pop(out); count > 0) return count;
      const std::uint64_t epoch = wake_epoch_.load(std::memory_order_acquire);
      if (const std::size_t count = pop(out); count > 0) return count;
      if (closed_.load(std::memory_order_acquire)) return 0;
      wake_epoch_.wait(epoch, std::memory_order_acquire);
    }
  }

 private:
  std::size_t mask_;
  std::unique_ptr<T[]> slots_;
  alignas(cache_line_size) std::atomic<std::uint64_t> head_{0};
  alignas(cache_line_size) std::atomic<std::uint64_t> tail_{0};
  alignas(cache_line_size) std::atomic<std::uint64_t> wake_epoch_{0};
  std::atomic<bool> closed_{false};
  alignas(cache_line_size) std::uint64_t cached_head_{0};
  alignas(cache_line_size) std::uint64_t cached_tail_{0};
};

}  // namespace watchdog
