#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

#include "core/incident.hpp"

namespace watchdog {

class AlertLog {
 public:
  AlertLog(std::string path, std::uint64_t max_bytes);
  ~AlertLog();
  AlertLog(const AlertLog&) = delete;
  AlertLog& operator=(const AlertLog&) = delete;

  [[nodiscard]] bool open();
  void write(const Incident& incident);

  [[nodiscard]] const std::string& path() const { return path_; }
  [[nodiscard]] std::uint64_t written() const { return written_; }

 private:
  void rotate_if_needed();

  std::string path_;
  std::uint64_t max_bytes_;
  std::FILE* file_ = nullptr;
  std::uint64_t bytes_ = 0;
  std::uint64_t written_ = 0;
};

}  // namespace watchdog
