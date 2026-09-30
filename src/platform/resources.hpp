#pragma once

#include <cstddef>

namespace watchdog {

std::size_t resident_bytes();
std::size_t open_descriptor_count();

}  // namespace watchdog
