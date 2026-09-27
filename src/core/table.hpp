#pragma once

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <type_traits>

namespace watchdog {

[[nodiscard]] inline std::uint64_t hash_bytes(const void* data, std::size_t size) {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  std::uint64_t hash = 14695981039346656037ULL;
  for (std::size_t i = 0; i < size; ++i) {
    hash ^= bytes[i];
    hash *= 1099511628211ULL;
  }
  hash ^= hash >> 33;
  hash *= 0xFF51AFD7ED558CCDULL;
  hash ^= hash >> 33;
  return hash;
}

template <typename Key, typename Value>
class EntityTable {
  static_assert(std::is_trivially_copyable_v<Key>);
  static_assert(std::has_unique_object_representations_v<Key>);

 public:
  static constexpr std::size_t probe_window = 16;

  struct SlotRef {
    Value& value;
    std::uint64_t previous_seen_ns;
    bool inserted;
  };

  explicit EntityTable(std::size_t min_slot_count)
      : mask_(std::bit_ceil(std::max(min_slot_count, probe_window)) - 1),
        slots_(std::make_unique<Slot[]>(mask_ + 1)) {}

  [[nodiscard]] std::size_t capacity() const { return mask_ + 1; }
  [[nodiscard]] std::size_t occupied() const { return occupied_; }
  [[nodiscard]] std::uint64_t evictions() const { return evictions_; }

  SlotRef find_or_insert(const Key& key, std::uint64_t now_ns) {
    const std::uint64_t start = hash_bytes(&key, sizeof key);
    std::size_t victim_index = start & mask_;
    std::uint64_t victim_seen = UINT64_MAX;
    for (std::size_t probe = 0; probe < probe_window; ++probe) {
      const std::size_t index = (start + probe) & mask_;
      Slot& slot = slots_[index];
      if (!slot.occupied) return claim(slot, key, now_ns, false);
      if (slot.key == key) {
        const std::uint64_t previous = slot.last_seen_ns;
        slot.last_seen_ns = now_ns;
        return SlotRef{slot.value, previous, false};
      }
      if (slot.last_seen_ns < victim_seen) {
        victim_seen = slot.last_seen_ns;
        victim_index = index;
      }
    }
    evictions_ += 1;
    return claim(slots_[victim_index], key, now_ns, true);
  }

 private:
  struct Slot {
    Key key{};
    Value value{};
    std::uint64_t last_seen_ns = 0;
    bool occupied = false;
  };

  SlotRef claim(Slot& slot, const Key& key, std::uint64_t now_ns, bool evicted) {
    occupied_ += evicted ? 0 : 1;
    slot.key = key;
    slot.value = Value{};
    slot.last_seen_ns = now_ns;
    slot.occupied = true;
    return SlotRef{slot.value, now_ns, true};
  }

  std::size_t mask_;
  std::unique_ptr<Slot[]> slots_;
  std::size_t occupied_ = 0;
  std::uint64_t evictions_ = 0;
};

}  // namespace watchdog
