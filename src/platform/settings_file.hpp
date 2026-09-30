#pragma once

#include <string>

#include "core/config.hpp"

namespace watchdog {

SettingsLoad load_settings(const std::string& path, const Settings& defaults);

}  // namespace watchdog
