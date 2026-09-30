#include "platform/settings_file.hpp"

#include <fstream>
#include <sstream>

namespace watchdog {

SettingsLoad load_settings(const std::string& path, const Settings& defaults) {
  std::ifstream input(path);
  if (!input) {
    SettingsLoad load;
    load.settings = defaults;
    return load;
  }
  std::ostringstream buffer;
  buffer << input.rdbuf();
  SettingsLoad load = parse_settings(buffer.str(), defaults);
  load.file_present = true;
  return load;
}

}  // namespace watchdog
