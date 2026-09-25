#pragma once

#include <cstddef>

namespace watchdog::alloc_probe {

#ifdef WATCHDOG_COUNT_ALLOCATIONS
inline constexpr bool enabled = true;
#else
inline constexpr bool enabled = false;
#endif

[[nodiscard]] std::size_t allocation_count() noexcept;
[[nodiscard]] std::size_t deallocation_count() noexcept;
[[nodiscard]] std::size_t live_allocation_count() noexcept;

}  // namespace watchdog::alloc_probe
