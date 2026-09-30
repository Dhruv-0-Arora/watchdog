#include "platform/paths.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>

namespace watchdog {

std::string state_directory() {
  if (const char* state_home = std::getenv("XDG_STATE_HOME"); state_home != nullptr) {
    return std::string(state_home) + "/watchdog";
  }
  const char* home = std::getenv("HOME");
  return std::string(home == nullptr ? "." : home) + "/.local/state/watchdog";
}

std::string config_directory() {
  if (const char* config_home = std::getenv("XDG_CONFIG_HOME"); config_home != nullptr) {
    return std::string(config_home) + "/watchdog";
  }
  const char* home = std::getenv("HOME");
  return std::string(home == nullptr ? "." : home) + "/.config/watchdog";
}

std::string default_config_path() { return config_directory() + "/watchdog.conf"; }

bool ensure_state_directory() {
  const std::string directory = state_directory();
  std::string partial;
  for (std::size_t i = 1; i <= directory.size(); ++i) {
    const bool boundary = i == directory.size() || directory[i] == '/';
    if (!boundary) continue;
    partial = directory.substr(0, i);
    ::mkdir(partial.c_str(), 0755);
  }
  return ::access(directory.c_str(), W_OK) == 0;
}

std::string default_socket_path() {
  if (const char* runtime_dir = std::getenv("XDG_RUNTIME_DIR"); runtime_dir != nullptr) {
    return std::string(runtime_dir) + "/watchdog.sock";
  }
  return "/tmp/watchdog-" + std::to_string(::getuid()) + ".sock";
}

std::string default_alert_log_path() { return state_directory() + "/alerts.jsonl"; }

std::string acknowledged_path() { return state_directory() + "/acknowledged"; }

}  // namespace watchdog
