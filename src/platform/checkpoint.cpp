#include "platform/checkpoint.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <memory>

namespace watchdog {

namespace {

struct FileCloser {
  void operator()(std::FILE* file) const { std::fclose(file); }
};
using FileHandle = std::unique_ptr<std::FILE, FileCloser>;

}  // namespace

bool write_file_atomic(const std::string& path, std::span<const std::byte> bytes) {
  const std::string temporary = path + ".tmp";
  {
    const FileHandle file(std::fopen(temporary.c_str(), "wb"));
    if (!file) return false;
    if (std::fwrite(bytes.data(), 1, bytes.size(), file.get()) != bytes.size()) {
      std::remove(temporary.c_str());
      return false;
    }
    if (std::fflush(file.get()) != 0 || ::fsync(::fileno(file.get())) != 0) {
      std::remove(temporary.c_str());
      return false;
    }
  }
  if (std::rename(temporary.c_str(), path.c_str()) != 0) {
    std::remove(temporary.c_str());
    return false;
  }
  return true;
}

std::vector<std::byte> read_file(const std::string& path) {
  const FileHandle file(std::fopen(path.c_str(), "rb"));
  if (!file) return {};
  if (std::fseek(file.get(), 0, SEEK_END) != 0) return {};
  const long size = std::ftell(file.get());
  if (size <= 0 || std::fseek(file.get(), 0, SEEK_SET) != 0) return {};
  std::vector<std::byte> bytes(static_cast<std::size_t>(size));
  if (std::fread(bytes.data(), 1, bytes.size(), file.get()) != bytes.size()) return {};
  return bytes;
}

}  // namespace watchdog
