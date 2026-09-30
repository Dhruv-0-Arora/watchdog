#pragma once

#include <string>

namespace watchdog {

std::string state_directory();
std::string config_directory();
bool ensure_state_directory();
std::string default_config_path();
std::string default_socket_path();
std::string default_alert_log_path();
std::string acknowledged_path();

}  // namespace watchdog
