#pragma once

#include <string>

#include "core/config.hpp"

namespace watchdog {

struct PipelineOptions {
  Settings settings;
  std::string scores_path;
};

int run_replay(const std::string& pcap_path, int loop_count, const PipelineOptions& options);
int run_live(const std::string& interface_name, const PipelineOptions& options);

}  // namespace watchdog
