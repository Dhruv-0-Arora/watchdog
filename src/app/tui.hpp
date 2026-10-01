#pragma once

#include <string>

namespace watchdog {

struct TopOptions {
  std::string socket_path;
  bool watch = false;
  bool peek = false;
};

int run_top(const TopOptions& options);

}  // namespace watchdog
