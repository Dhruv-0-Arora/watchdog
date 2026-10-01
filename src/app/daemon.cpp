#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "app/pipeline.hpp"
#include "app/tui.hpp"
#include "core/config.hpp"
#include "platform/capture.hpp"
#include "platform/paths.hpp"
#include "platform/settings_file.hpp"

namespace {

constexpr const char* usage_text =
    "usage: watchdog <command> [options]\n"
    "\n"
    "commands:\n"
    "  run [interface]  capture live traffic and alert on anomalies\n"
    "  replay <pcap>    run the detection pipeline over a capture file\n"
    "  top              show what has happened since your last checkin\n"
    "\n"
    "run and replay options:\n"
    "  --config PATH    read settings from PATH ('none' to skip the config file)\n"
    "  --grace N        train for N packets before alerting\n"
    "  --model PATH     resume from and checkpoint to this model file\n"
    "  --alerts PATH    append incidents to this JSONL log ('none' to disable)\n"
    "  --socket PATH    serve status on this unix socket ('none' to disable)\n"
    "  --scores PATH    dump one float per packet of anomaly score\n"
    "  --loop N         replay the file N times (soak testing)\n"
    "\n"
    "top options:\n"
    "  --socket PATH    connect to a daemon on this unix socket\n"
    "  --watch          refresh continuously; 'a' acknowledges, 'q' quits\n"
    "  --peek           do not acknowledge what is shown\n"
    "\n"
    "  --help           print this message\n"
    "  --version        print the version\n";

constexpr const char* disabled_value = "none";

struct Arguments {
  watchdog::PipelineOptions pipeline;
  watchdog::TopOptions top;
  int loop_count = 1;
  bool valid = true;
  bool config_rejected = false;
};

bool takes_value(const char* flag) {
  return std::strcmp(flag, "--watch") != 0 && std::strcmp(flag, "--peek") != 0;
}

std::string optional_path(const char* value) {
  return std::strcmp(value, disabled_value) == 0 ? std::string{} : std::string(value);
}

const char* find_flag_value(int argc, char** argv, int first_option, const char* flag) {
  for (int i = first_option; i + 1 < argc; ++i) {
    if (std::strcmp(argv[i], flag) == 0) return argv[i + 1];
  }
  return nullptr;
}

watchdog::Settings default_settings() {
  watchdog::Settings settings;
  settings.alert_log_path = watchdog::default_alert_log_path();
  settings.socket_path = watchdog::default_socket_path();
  return settings;
}

enum class ConfigLookup { explicit_only, include_default };

bool load_config(int argc, char** argv, int first_option, ConfigLookup lookup,
                 watchdog::Settings& settings) {
  const char* requested = find_flag_value(argc, argv, first_option, "--config");
  if (requested != nullptr && std::strcmp(requested, disabled_value) == 0) return true;
  if (requested == nullptr && lookup == ConfigLookup::explicit_only) return true;
  const std::string path = requested == nullptr ? watchdog::default_config_path() : requested;
  const watchdog::SettingsLoad load = watchdog::load_settings(path, settings);
  if (requested != nullptr && !load.file_present) {
    std::fprintf(stderr, "watchdog: cannot read config %s\n", path.c_str());
    return false;
  }
  for (const std::string& problem : load.errors) {
    std::fprintf(stderr, "watchdog: %s: %s\n", path.c_str(), problem.c_str());
  }
  if (!load.errors.empty()) return false;
  if (load.file_present) std::printf("config: %s\n", path.c_str());
  settings = load.settings;
  return true;
}

Arguments parse(int argc, char** argv, int first_option, ConfigLookup lookup) {
  Arguments arguments;
  arguments.pipeline.settings = default_settings();
  if (!load_config(argc, argv, first_option, lookup, arguments.pipeline.settings)) {
    arguments.valid = false;
    arguments.config_rejected = true;
    return arguments;
  }
  watchdog::Settings& settings = arguments.pipeline.settings;
  for (int i = first_option; i < argc;) {
    const char* flag = argv[i];
    const bool needs_value = takes_value(flag);
    if (needs_value && i + 1 >= argc) {
      arguments.valid = false;
      return arguments;
    }
    const char* value = needs_value ? argv[i + 1] : "";
    i += needs_value ? 2 : 1;
    if (std::strcmp(flag, "--config") == 0) {
      continue;
    } else if (std::strcmp(flag, "--loop") == 0) {
      arguments.loop_count = std::atoi(value);
      arguments.valid = arguments.valid && arguments.loop_count >= 1;
    } else if (std::strcmp(flag, "--grace") == 0) {
      settings.grace_packets = static_cast<std::uint64_t>(std::atoll(value));
      arguments.valid = arguments.valid && settings.grace_packets >= 1'000;
    } else if (std::strcmp(flag, "--model") == 0) {
      settings.model_path = optional_path(value);
    } else if (std::strcmp(flag, "--scores") == 0) {
      arguments.pipeline.scores_path = optional_path(value);
    } else if (std::strcmp(flag, "--alerts") == 0) {
      settings.alert_log_path = optional_path(value);
    } else if (std::strcmp(flag, "--socket") == 0) {
      settings.socket_path = optional_path(value);
      arguments.top.socket_path = value;
    } else if (std::strcmp(flag, "--watch") == 0) {
      arguments.top.watch = true;
    } else if (std::strcmp(flag, "--peek") == 0) {
      arguments.top.peek = true;
    } else {
      arguments.valid = false;
      return arguments;
    }
  }
  return arguments;
}

int reject(const Arguments& arguments) {
  if (arguments.config_rejected) return 1;
  std::fputs(usage_text, stderr);
  return 2;
}

int run_live_command(int argc, char** argv) {
  int first_option = 2;
  std::string requested_interface;
  if (argc >= 3 && argv[2][0] != '-') {
    requested_interface = argv[2];
    first_option = 3;
  }
  const Arguments arguments = parse(argc, argv, first_option, ConfigLookup::include_default);
  if (!arguments.valid) return reject(arguments);
  std::string interface_name = requested_interface.empty()
                                   ? arguments.pipeline.settings.interface_name
                                   : requested_interface;
  if (interface_name.empty()) {
    std::string error;
    interface_name = watchdog::default_interface(error);
    if (interface_name.empty()) {
      std::fprintf(stderr, "watchdog: %s\n", error.c_str());
      return 1;
    }
  }
  return watchdog::run_live(interface_name, arguments.pipeline);
}

int run_replay_command(int argc, char** argv) {
  if (argc < 3) {
    std::fputs(usage_text, stderr);
    return 2;
  }
  Arguments arguments = parse(argc, argv, 3, ConfigLookup::explicit_only);
  if (!arguments.valid) return reject(arguments);
  if (arguments.pipeline.settings.alert_log_path == watchdog::default_alert_log_path()) {
    arguments.pipeline.settings.alert_log_path.clear();
  }
  if (arguments.pipeline.settings.socket_path == watchdog::default_socket_path()) {
    arguments.pipeline.settings.socket_path.clear();
  }
  return watchdog::run_replay(argv[2], arguments.loop_count, arguments.pipeline);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fputs(usage_text, stderr);
    return 2;
  }
  const char* command = argv[1];
  if (std::strcmp(command, "--help") == 0) {
    std::fputs(usage_text, stdout);
    return 0;
  }
  if (std::strcmp(command, "--version") == 0) {
    std::puts(WATCHDOG_VERSION);
    return 0;
  }
  if (std::strcmp(command, "run") == 0) return run_live_command(argc, argv);
  if (std::strcmp(command, "replay") == 0) return run_replay_command(argc, argv);
  if (std::strcmp(command, "top") == 0) {
    const Arguments arguments = parse(argc, argv, 2, ConfigLookup::explicit_only);
    if (!arguments.valid) return reject(arguments);
    return watchdog::run_top(arguments.top);
  }
  std::fprintf(stderr, "watchdog: unknown command '%s'\n", command);
  std::fputs(usage_text, stderr);
  return 2;
}
