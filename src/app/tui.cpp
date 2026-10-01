#include "app/tui.hpp"

#include <poll.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "core/format.hpp"
#include "core/incident.hpp"
#include "core/snapshot.hpp"
#include "platform/ipc.hpp"
#include "platform/paths.hpp"

namespace watchdog {
namespace {

constexpr int watch_poll_interval_ms = 1000;
constexpr std::size_t displayed_source_limit = 8;

struct Style {
  const char* bold = "";
  const char* dim = "";
  const char* red = "";
  const char* yellow = "";
  const char* reset = "";
};

Style style_for(bool colored) {
  if (!colored) return {};
  return {"\033[1m", "\033[2m", "\033[31m", "\033[33m", "\033[0m"};
}

std::uint64_t read_acknowledged() {
  std::FILE* file = std::fopen(acknowledged_path().c_str(), "r");
  if (file == nullptr) return 0;
  std::uint64_t sequence = 0;
  if (std::fscanf(file, "%" SCNu64, &sequence) != 1) sequence = 0;
  std::fclose(file);
  return sequence;
}

bool write_acknowledged(std::uint64_t sequence) {
  ensure_state_directory();
  const std::string path = acknowledged_path();
  const std::string temporary = path + ".tmp";
  std::FILE* file = std::fopen(temporary.c_str(), "w");
  if (file == nullptr) return false;
  std::fprintf(file, "%" PRIu64 "\n", sequence);
  std::fclose(file);
  return std::rename(temporary.c_str(), path.c_str()) == 0;
}

std::string format_duration(std::uint64_t nanoseconds) {
  const std::uint64_t seconds = nanoseconds / 1'000'000'000ULL;
  std::array<char, 32> buffer{};
  if (seconds < 60) {
    std::snprintf(buffer.data(), buffer.size(), "%" PRIu64 "s", seconds);
  } else if (seconds < 3600) {
    std::snprintf(buffer.data(), buffer.size(), "%" PRIu64 "m%02" PRIu64 "s", seconds / 60,
                  seconds % 60);
  } else {
    std::snprintf(buffer.data(), buffer.size(), "%" PRIu64 "h%02" PRIu64 "m", seconds / 3600,
                  (seconds % 3600) / 60);
  }
  return buffer.data();
}

std::string format_count(std::uint64_t value) {
  std::array<char, 32> buffer{};
  if (value < 1'000) {
    std::snprintf(buffer.data(), buffer.size(), "%" PRIu64, value);
  } else if (value < 1'000'000) {
    std::snprintf(buffer.data(), buffer.size(), "%.1fk", static_cast<double>(value) / 1e3);
  } else {
    std::snprintf(buffer.data(), buffer.size(), "%.1fM", static_cast<double>(value) / 1e6);
  }
  return buffer.data();
}

const char* phase_label(std::uint32_t phase) {
  switch (phase) {
    case 0:
      return "learning layout";
    case 1:
      return "training";
    default:
      return "detecting";
  }
}

std::vector<Incident> collect_incidents(const Snapshot& snapshot) {
  std::vector<Incident> incidents;
  incidents.reserve(snapshot.open_count + snapshot.recent_count);
  incidents.insert(incidents.end(), snapshot.recent.begin(),
                   snapshot.recent.begin() + snapshot.recent_count);
  incidents.insert(incidents.end(), snapshot.open.begin(),
                   snapshot.open.begin() + snapshot.open_count);
  std::sort(incidents.begin(), incidents.end(),
            [](const Incident& a, const Incident& b) { return a.sequence > b.sequence; });
  return incidents;
}

double severity_of(const Incident& incident) {
  return incident.threshold > 0.0F ? static_cast<double>(incident.peak_score / incident.threshold)
                                   : 0.0;
}

struct SourceSummary {
  Incident peak;
  std::vector<std::array<std::uint8_t, 16>> peers;
  std::uint64_t incidents = 0;
  std::uint64_t packets = 0;
  std::uint64_t last_ns = 0;
  std::uint8_t context_mask = 0;
  std::uint8_t new_entity_mask = 0;
};

std::vector<SourceSummary> summarize_by_source(std::span<const Incident> incidents) {
  std::vector<SourceSummary> summaries;
  for (const Incident& incident : incidents) {
    const auto match =
        std::find_if(summaries.begin(), summaries.end(), [&incident](const SourceSummary& summary) {
          return summary.peak.src_ip == incident.src_ip;
        });
    SourceSummary& summary = match == summaries.end() ? summaries.emplace_back() : *match;
    if (severity_of(incident) > severity_of(summary.peak)) summary.peak = incident;
    if (std::find(summary.peers.begin(), summary.peers.end(), incident.dst_ip) ==
        summary.peers.end()) {
      summary.peers.push_back(incident.dst_ip);
    }
    summary.incidents += 1;
    summary.packets += incident.packets;
    summary.last_ns = std::max(summary.last_ns, incident.last_ns);
    summary.context_mask = static_cast<std::uint8_t>(summary.context_mask | incident.context_mask);
    summary.new_entity_mask =
        static_cast<std::uint8_t>(summary.new_entity_mask | incident.new_entity_mask);
  }
  std::sort(summaries.begin(), summaries.end(), [](const SourceSummary& a, const SourceSummary& b) {
    return severity_of(a.peak) > severity_of(b.peak);
  });
  return summaries;
}

void print_summary(const SourceSummary& summary, std::uint64_t now_ns, const Style& style) {
  const double severity = severity_of(summary.peak);
  const char* severity_color = severity >= 10.0 ? style.red : style.yellow;
  const std::string age =
      now_ns > summary.last_ns ? format_duration(now_ns - summary.last_ns) + " ago" : "just now";
  std::string endpoints =
      format_address(summary.peak.src_ip) + " -> " + format_address(summary.peak.dst_ip);
  if (summary.peers.size() > 1) {
    endpoints += " +" + std::to_string(summary.peers.size() - 1) + " peers";
  }
  const std::string new_entities = format_new_entities(summary.new_entity_mask);
  std::printf("  %s%4.0fx%s %-38s %6s pkts  %s%-10s %s%s%s\n", severity_color, severity,
              style.reset, endpoints.c_str(), format_count(summary.packets).c_str(), style.dim,
              age.c_str(), format_contexts(summary.context_mask).c_str(),
              new_entities.empty() ? "" : (", new " + new_entities).c_str(), style.reset);
}

void render(const Snapshot& snapshot, std::uint64_t acknowledged, const Style& style,
            bool interactive) {
  const std::vector<Incident> incidents = collect_incidents(snapshot);
  const auto unseen = static_cast<std::size_t>(
      std::count_if(incidents.begin(), incidents.end(),
                    [acknowledged](const Incident& i) { return i.sequence > acknowledged; }));

  std::printf("%swatchdog%s  %s  up %s  %s packets  %s drops  %.0f MB  %" PRIu64 " fds\n",
              style.bold, style.reset, phase_label(snapshot.model_phase),
              format_duration(snapshot.latest_packet_ns - snapshot.started_ns).c_str(),
              format_count(snapshot.packets).c_str(),
              format_count(snapshot.ring_dropped + snapshot.kernel_dropped).c_str(),
              static_cast<double>(snapshot.resident_bytes) / 1e6, snapshot.open_descriptors);

  if (snapshot.model_phase != 2) {
    std::printf("%slearning what normal looks like: %s of %s packets%s\n", style.dim,
                format_count(snapshot.model_packets).c_str(),
                format_count(snapshot.packets).c_str(), style.reset);
  }

  std::printf("\n");
  if (unseen == 0) {
    std::printf("Nothing new since your last checkin.\n");
  } else {
    std::vector<Incident> fresh;
    for (const Incident& incident : incidents) {
      if (incident.sequence > acknowledged) fresh.push_back(incident);
    }
    const std::vector<SourceSummary> summaries = summarize_by_source(fresh);
    const std::size_t shown = std::min(summaries.size(), displayed_source_limit);
    std::printf("%s%zu new incident%s from %zu host%s since your last checkin:%s\n", style.bold,
                unseen, unseen == 1 ? "" : "s", summaries.size(), summaries.size() == 1 ? "" : "s",
                style.reset);
    for (std::size_t i = 0; i < shown; ++i) {
      print_summary(summaries[i], snapshot.latest_packet_ns, style);
    }
    if (shown < summaries.size()) {
      std::printf("%s  ... and %zu quieter host%s; full history in %s%s\n", style.dim,
                  summaries.size() - shown, summaries.size() - shown == 1 ? "" : "s",
                  default_alert_log_path().c_str(), style.reset);
    }
  }

  std::printf("\n%sfirst seen: %s hosts, %s channels   alert threshold %.3f%s\n", style.dim,
              format_count(snapshot.new_hosts).c_str(), format_count(snapshot.new_channels).c_str(),
              static_cast<double>(snapshot.threshold), style.reset);
  if (interactive) {
    std::printf("%s[a] acknowledge   [q] quit%s\n", style.dim, style.reset);
  }
  std::fflush(stdout);
}

std::uint64_t highest_sequence(const Snapshot& snapshot) {
  std::uint64_t highest = 0;
  for (std::uint32_t i = 0; i < snapshot.open_count; ++i) {
    highest = std::max(highest, snapshot.open[i].sequence);
  }
  for (std::uint32_t i = 0; i < snapshot.recent_count; ++i) {
    highest = std::max(highest, snapshot.recent[i].sequence);
  }
  return highest;
}

class RawTerminal {
 public:
  RawTerminal() {
    if (::tcgetattr(STDIN_FILENO, &original_) != 0) return;
    restore_ = true;
    termios raw = original_;
    raw.c_lflag &= ~static_cast<tcflag_t>(ICANON | ECHO);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    ::tcsetattr(STDIN_FILENO, TCSANOW, &raw);
  }
  RawTerminal(const RawTerminal&) = delete;
  RawTerminal& operator=(const RawTerminal&) = delete;
  ~RawTerminal() {
    if (restore_) ::tcsetattr(STDIN_FILENO, TCSANOW, &original_);
  }

 private:
  termios original_{};
  bool restore_ = false;
};

int run_watch(const std::string& socket_path, const Style& style) {
  const RawTerminal raw_terminal;
  std::uint64_t acknowledged = read_acknowledged();
  while (true) {
    Snapshot snapshot;
    std::string error;
    std::printf("\033[H\033[2J");
    if (!fetch_snapshot(socket_path, snapshot, error)) {
      std::printf("watchdog: %s\n", error.c_str());
      std::fflush(stdout);
    } else {
      render(snapshot, acknowledged, style, true);
    }
    pollfd input{STDIN_FILENO, POLLIN, 0};
    if (::poll(&input, 1, watch_poll_interval_ms) <= 0) continue;
    char key = 0;
    const ssize_t got = ::read(STDIN_FILENO, &key, 1);
    if (got == 0) return 0;
    if (got < 0) continue;
    if (key == 'q') return 0;
    if (key == 'a') {
      acknowledged = std::max(acknowledged, highest_sequence(snapshot));
      write_acknowledged(acknowledged);
    }
  }
}

}  // namespace

int run_top(const TopOptions& options) {
  const std::string socket_path =
      options.socket_path.empty() ? default_socket_path() : options.socket_path;
  const Style style = style_for(::isatty(STDOUT_FILENO) == 1);
  if (options.watch) return run_watch(socket_path, style);

  Snapshot snapshot;
  std::string error;
  if (!fetch_snapshot(socket_path, snapshot, error)) {
    std::fprintf(stderr, "watchdog: %s\n", error.c_str());
    std::fprintf(stderr, "start the daemon with 'watchdog run' first\n");
    return 1;
  }
  const std::uint64_t acknowledged = read_acknowledged();
  render(snapshot, acknowledged, style, false);
  if (!options.peek) write_acknowledged(std::max(acknowledged, highest_sequence(snapshot)));
  return 0;
}

}  // namespace watchdog
