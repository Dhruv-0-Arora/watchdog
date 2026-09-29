#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace watchdog {

bool write_file_atomic(const std::string& path, std::span<const std::byte> bytes);
std::vector<std::byte> read_file(const std::string& path);

}  // namespace watchdog
