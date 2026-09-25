#include "support/alloc_probe.hpp"

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <new>

namespace {

std::atomic<std::size_t> allocations{0};
std::atomic<std::size_t> deallocations{0};

}  // namespace

namespace watchdog::alloc_probe {

std::size_t allocation_count() noexcept { return allocations.load(std::memory_order_relaxed); }

std::size_t deallocation_count() noexcept { return deallocations.load(std::memory_order_relaxed); }

std::size_t live_allocation_count() noexcept { return allocation_count() - deallocation_count(); }

}  // namespace watchdog::alloc_probe

#ifdef WATCHDOG_COUNT_ALLOCATIONS

namespace {

void* counted_allocation(std::size_t size) {
  void* memory = std::malloc(size == 0 ? 1 : size);
  if (memory == nullptr) throw std::bad_alloc{};
  allocations.fetch_add(1, std::memory_order_relaxed);
  return memory;
}

void* counted_aligned_allocation(std::size_t size, std::align_val_t alignment) {
  const std::size_t requested = static_cast<std::size_t>(alignment);
  const std::size_t usable = requested < sizeof(void*) ? sizeof(void*) : requested;
  void* memory = nullptr;
  if (::posix_memalign(&memory, usable, size == 0 ? 1 : size) != 0) throw std::bad_alloc{};
  allocations.fetch_add(1, std::memory_order_relaxed);
  return memory;
}

void counted_deallocation(void* memory) noexcept {
  if (memory == nullptr) return;
  deallocations.fetch_add(1, std::memory_order_relaxed);
  std::free(memory);
}

}  // namespace

void* operator new(std::size_t size) { return counted_allocation(size); }
void* operator new[](std::size_t size) { return counted_allocation(size); }
void* operator new(std::size_t size, std::align_val_t alignment) {
  return counted_aligned_allocation(size, alignment);
}
void* operator new[](std::size_t size, std::align_val_t alignment) {
  return counted_aligned_allocation(size, alignment);
}

void operator delete(void* memory) noexcept { counted_deallocation(memory); }
void operator delete[](void* memory) noexcept { counted_deallocation(memory); }
void operator delete(void* memory, std::size_t) noexcept { counted_deallocation(memory); }
void operator delete[](void* memory, std::size_t) noexcept { counted_deallocation(memory); }
void operator delete(void* memory, std::align_val_t) noexcept { counted_deallocation(memory); }
void operator delete[](void* memory, std::align_val_t) noexcept { counted_deallocation(memory); }
void operator delete(void* memory, std::size_t, std::align_val_t) noexcept {
  counted_deallocation(memory);
}
void operator delete[](void* memory, std::size_t, std::align_val_t) noexcept {
  counted_deallocation(memory);
}

#endif
