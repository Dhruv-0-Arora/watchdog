#pragma once

#include <string>

namespace watchdog {

struct PrivilegeDrop {
  bool attempted = false;
  bool succeeded = false;
  std::string account;
  std::string error;
};

PrivilegeDrop drop_privileges();

}  // namespace watchdog
