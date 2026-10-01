#include "app/pipeline.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "core/config.hpp"
#include "core/decode.hpp"
#include "core/features.hpp"
#include "core/format.hpp"
#include "core/incident.hpp"
#include "core/model.hpp"
#include "core/packet_record.hpp"
#include "core/ring.hpp"
#include "core/snapshot.hpp"
#include "platform/alert_log.hpp"
#include "platform/capture.hpp"
#include "platform/checkpoint.hpp"
#include "platform/ipc.hpp"
#include "platform/paths.hpp"
#include "platform/privilege.hpp"
#include "platform/resources.hpp"
#include "support/alloc_probe.hpp"

namespace watchdog {
namespace {

constexpr std::size_t ring_capacity = 4096;
constexpr std::size_t batch_capacity = 256;
constexpr auto publish_interval = std::chrono::milliseconds(200);
constexpr auto checkpoint_interval = std::chrono::minutes(5);

enum class OverflowPolicy { drop, block };

class RingSink final : public PacketSink {
 public:
  RingSink(SpscRing<PacketRecord>& ring, OverflowPolicy policy) : ring_(ring), policy_(policy) {}

  void on_packet(const PacketRecord& record) override {
    if (ring_.try_push(record)) return;
    if (policy_ == OverflowPolicy::drop) {
      dropped_ += 1;
      return;
    }
    ring_.notify_consumer();
    while (!ring_.try_push(record)) std::this_thread::yield();
  }

  void on_batch_end() override { ring_.notify_consumer(); }

  [[nodiscard]] std::uint64_t dropped() const { return dropped_; }

 private:
  SpscRing<PacketRecord>& ring_;
  OverflowPolicy policy_;
  std::uint64_t dropped_ = 0;
};

struct ProcessingTotals {
  std::uint64_t packets = 0;
  std::uint64_t bytes = 0;
  std::uint64_t decode_failures = 0;
  std::uint64_t tcp = 0;
  std::uint64_t udp = 0;
  std::uint64_t icmp = 0;
  std::uint64_t other = 0;
  std::uint64_t new_mac_ips = 0;
  std::uint64_t new_hosts = 0;
  std::uint64_t new_channels = 0;
  std::uint64_t new_sockets = 0;
  std::uint64_t alert_packets = 0;
  float max_score = 0.0F;
  std::chrono::nanoseconds decode_time{0};
  std::chrono::nanoseconds feature_time{0};
  std::chrono::nanoseconds model_time{0};
};

const char* phase_name(ModelPhase phase) {
  switch (phase) {
    case ModelPhase::mapping:
      return "mapping";
    case ModelPhase::training:
      return "training";
    case ModelPhase::detecting:
      return "detecting";
  }
  return "unknown";
}

FeatureTableSizes table_sizes_of(const Settings& settings) {
  return {settings.mac_ip_slots, settings.host_slots, settings.channel_slots,
          settings.socket_slots};
}

IncidentConfig incident_config_of(const Settings& settings) {
  IncidentConfig config;
  config.cooldown_ns = settings.incident_cooldown_seconds * 1'000'000'000ULL;
  config.max_duration_ns = settings.incident_max_duration_seconds * 1'000'000'000ULL;
  return config;
}

std::uint8_t new_entity_mask_of(const FeatureExtractor::Output& features) {
  std::uint8_t mask = 0;
  if (features.new_mac_ip) mask |= new_mac_ip_bit;
  if (features.new_host) mask |= new_host_bit;
  if (features.new_channel) mask |= new_channel_bit;
  if (features.new_socket) mask |= new_socket_bit;
  return mask;
}

std::uint8_t dominant_context_mask(const KitNet& model) {
  const std::span<const float> errors = model.group_errors();
  if (errors.empty()) return 0;
  const auto peak =
      static_cast<std::size_t>(std::max_element(errors.begin(), errors.end()) - errors.begin());
  std::uint8_t mask = 0;
  for (const std::uint16_t feature : model.group_members(peak)) {
    mask |= context_bit(FeatureExtractor::context_of(feature));
  }
  return mask;
}

void print_progress(const ProcessingTotals& totals, const KitNet& model,
                    const IncidentTracker& tracker) {
  std::printf("packets %" PRIu64 "  bytes %" PRIu64 "  tcp %" PRIu64 "  udp %" PRIu64
              "  icmp %" PRIu64 "  other %" PRIu64 "  undecodable %" PRIu64 "  new: mac-ip %" PRIu64
              " host %" PRIu64 " channel %" PRIu64 " socket %" PRIu64 "\n",
              totals.packets, totals.bytes, totals.tcp, totals.udp, totals.icmp, totals.other,
              totals.decode_failures, totals.new_mac_ips, totals.new_hosts, totals.new_channels,
              totals.new_sockets);
  std::printf("model: %s  incidents %" PRIu64 "  alerting packets %" PRIu64
              "  threshold %.4f  max score %.4f\n",
              phase_name(model.phase()), tracker.opened(), totals.alert_packets, model.threshold(),
              static_cast<double>(totals.max_score));
  std::fflush(stdout);
}

class Processor {
 public:
  Processor(SpscRing<PacketRecord>& ring, int link_type, bool report_progress,
            std::unique_ptr<KitNet> model, std::FILE* scores_out, AlertLog& alert_log,
            SnapshotPublisher* publisher, const Settings& settings, bool checkpoint)
      : ring_(ring),
        link_type_(link_type),
        report_progress_(report_progress),
        model_(std::move(model)),
        scores_out_(scores_out),
        alert_log_(alert_log),
        publisher_(publisher),
        model_path_(checkpoint ? settings.model_path : std::string{}),
        extractor_(table_sizes_of(settings)),
        tracker_(incident_config_of(settings)) {}

  void run() {
    std::array<PacketRecord, batch_capacity> batch;
    auto last_report = std::chrono::steady_clock::now();
    auto last_publish = last_report;
    auto last_checkpoint = last_report;
    while (true) {
      const std::size_t count = ring_.pop_wait(std::span(batch));
      if (count == 0) break;
      const auto decode_start = std::chrono::steady_clock::now();
      const std::size_t decoded = decode_batch(std::span(batch).first(count));
      const auto decode_end = std::chrono::steady_clock::now();
      extract_batch(decoded);
      const auto feature_end = std::chrono::steady_clock::now();
      score_batch(decoded);
      const auto model_end = std::chrono::steady_clock::now();

      totals_.decode_time += decode_end - decode_start;
      totals_.feature_time += feature_end - decode_end;
      totals_.model_time += model_end - feature_end;

      flush_closed_incidents();
      if (model_end - last_publish >= publish_interval) {
        last_publish = model_end;
        publish();
      }
      if (!model_path_.empty() && model_end - last_checkpoint >= checkpoint_interval) {
        last_checkpoint = model_end;
        save_checkpoint();
      }
      if (report_progress_ && model_end - last_report >= std::chrono::seconds(5)) {
        last_report = model_end;
        print_progress(totals_, *model_, tracker_);
      }
    }
    tracker_.close_all();
    flush_closed_incidents();
    publish();
  }

  [[nodiscard]] const ProcessingTotals& totals() const { return totals_; }
  [[nodiscard]] std::uint64_t evictions() const { return extractor_.evictions(); }
  [[nodiscard]] const KitNet& model() const { return *model_; }
  [[nodiscard]] const IncidentTracker& tracker() const { return tracker_; }
  [[nodiscard]] std::span<const Incident> recent_incidents() const { return recent_; }

  void set_capture_drops(std::uint64_t ring_dropped, std::uint64_t kernel_dropped) {
    ring_dropped_ = ring_dropped;
    kernel_dropped_ = kernel_dropped;
  }

 private:
  std::size_t decode_batch(std::span<const PacketRecord> records) {
    std::size_t decoded = 0;
    for (const PacketRecord& record : records) {
      const std::span<const std::byte> frame(record.headers.data(), record.captured_length);
      const std::optional<PacketMeta> meta =
          decode_packet(frame, link_type_, record.timestamp_ns, record.wire_length);
      totals_.packets += 1;
      totals_.bytes += record.wire_length;
      if (!meta) {
        totals_.decode_failures += 1;
        continue;
      }
      switch (meta->transport) {
        case Transport::tcp:
          totals_.tcp += 1;
          break;
        case Transport::udp:
          totals_.udp += 1;
          break;
        case Transport::icmp:
          totals_.icmp += 1;
          break;
        case Transport::other:
          totals_.other += 1;
          break;
      }
      metas_[decoded] = *meta;
      decoded += 1;
    }
    if (decoded > 0) {
      latest_packet_ns_ = metas_[decoded - 1].timestamp_ns;
      if (started_ns_ == 0) started_ns_ = metas_[0].timestamp_ns;
    }
    return decoded;
  }

  void extract_batch(std::size_t decoded) {
    for (std::size_t i = 0; i < decoded; ++i) {
      extractor_.extract(metas_[i], features_);
      totals_.new_mac_ips += features_.new_mac_ip ? 1 : 0;
      totals_.new_hosts += features_.new_host ? 1 : 0;
      totals_.new_channels += features_.new_channel ? 1 : 0;
      totals_.new_sockets += features_.new_socket ? 1 : 0;
      new_entity_masks_[i] = new_entity_mask_of(features_);
      std::copy(features_.values.begin(), features_.values.end(),
                batch_features_.begin() +
                    static_cast<std::ptrdiff_t>(i * FeatureExtractor::feature_count));
    }
  }

  void score_batch(std::size_t decoded) {
    for (std::size_t i = 0; i < decoded; ++i) {
      const std::span<const float> vector(
          batch_features_.data() + i * FeatureExtractor::feature_count,
          FeatureExtractor::feature_count);
      const ScoreResult result = model_->process(vector, metas_[i].timestamp_ns);
      totals_.max_score = std::max(totals_.max_score, result.score);
      if (scores_out_ != nullptr) std::fwrite(&result.score, sizeof result.score, 1, scores_out_);
      tracker_.expire(metas_[i].timestamp_ns);
      if (!result.alert) continue;
      totals_.alert_packets += 1;
      tracker_.observe(alert_event(metas_[i], result, new_entity_masks_[i]));
    }
  }

  [[nodiscard]] AlertEvent alert_event(const PacketMeta& meta, const ScoreResult& result,
                                       std::uint8_t new_entity_mask) const {
    AlertEvent event;
    event.timestamp_ns = meta.timestamp_ns;
    event.score = result.score;
    event.threshold = result.threshold;
    event.src_ip = meta.src_ip;
    event.dst_ip = meta.dst_ip;
    event.src_port = meta.src_port;
    event.dst_port = meta.dst_port;
    event.transport = static_cast<std::uint8_t>(meta.transport);
    event.context_mask = dominant_context_mask(*model_);
    event.new_entity_mask = new_entity_mask;
    event.is_ipv6 = meta.is_ipv6 ? 1 : 0;
    return event;
  }

  void flush_closed_incidents() {
    std::array<Incident, 64> closed{};
    while (const std::size_t count = tracker_.drain_closed(closed)) {
      for (std::size_t i = 0; i < count; ++i) {
        alert_log_.write(closed[i]);
        if (recent_.size() == snapshot_incident_capacity) recent_.erase(recent_.begin());
        recent_.push_back(closed[i]);
      }
    }
  }

  void publish() {
    if (publisher_ == nullptr) return;
    Snapshot snapshot;
    snapshot.byte_size = static_cast<std::uint32_t>(sizeof(Snapshot));
    snapshot.model_phase = static_cast<std::uint32_t>(model_->phase());
    snapshot.started_ns = started_ns_;
    snapshot.latest_packet_ns = latest_packet_ns_;
    snapshot.packets = totals_.packets;
    snapshot.bytes = totals_.bytes;
    snapshot.ring_dropped = ring_dropped_;
    snapshot.kernel_dropped = kernel_dropped_;
    snapshot.new_mac_ips = totals_.new_mac_ips;
    snapshot.new_hosts = totals_.new_hosts;
    snapshot.new_channels = totals_.new_channels;
    snapshot.new_sockets = totals_.new_sockets;
    snapshot.model_packets = model_->packets();
    snapshot.alert_packets = totals_.alert_packets;
    snapshot.incidents_opened = tracker_.opened();
    snapshot.resident_bytes = resident_bytes();
    snapshot.open_descriptors = open_descriptor_count();
    snapshot.threshold = model_->threshold();
    snapshot.max_score = totals_.max_score;

    const std::span<const Incident> open = tracker_.open_incidents();
    snapshot.open_count =
        static_cast<std::uint32_t>(std::min(open.size(), snapshot_incident_capacity));
    std::copy_n(open.begin(), snapshot.open_count, snapshot.open.begin());

    snapshot.recent_count = static_cast<std::uint32_t>(recent_.size());
    std::copy(recent_.begin(), recent_.end(), snapshot.recent.begin());
    publisher_->publish(snapshot);
  }

  void save_checkpoint() {
    std::vector<std::byte> bytes(model_->serialized_size());
    if (bytes.empty() || !model_->serialize(bytes)) return;
    write_file_atomic(model_path_, bytes);
  }

  SpscRing<PacketRecord>& ring_;
  int link_type_;
  bool report_progress_;
  std::unique_ptr<KitNet> model_;
  std::FILE* scores_out_;
  AlertLog& alert_log_;
  SnapshotPublisher* publisher_;
  std::string model_path_;
  FeatureExtractor extractor_;
  FeatureExtractor::Output features_;
  IncidentTracker tracker_;
  std::vector<PacketMeta> metas_ = std::vector<PacketMeta>(batch_capacity);
  std::vector<std::uint8_t> new_entity_masks_ = std::vector<std::uint8_t>(batch_capacity, 0);
  std::vector<float> batch_features_ =
      std::vector<float>(batch_capacity * FeatureExtractor::feature_count, 0.0F);
  std::vector<Incident> recent_;
  std::uint64_t latest_packet_ns_ = 0;
  std::uint64_t started_ns_ = 0;
  std::uint64_t ring_dropped_ = 0;
  std::uint64_t kernel_dropped_ = 0;
  ProcessingTotals totals_{};
};

double per_packet_ns(std::chrono::nanoseconds duration, std::uint64_t packets) {
  return packets == 0 ? 0.0 : static_cast<double>(duration.count()) / static_cast<double>(packets);
}

void print_incidents(std::span<const Incident> incidents);

void print_incident(const Incident& incident) {
  const std::string source = format_address(incident.src_ip);
  const std::string destination = format_address(incident.dst_ip);
  std::printf("  #%" PRIu64 " %s -> %s:%u %s  %" PRIu64 " packets  score %.2f (%.1fx)  %s\n",
              incident.sequence, source.c_str(), destination.c_str(), incident.dst_port,
              transport_name(incident.transport), incident.packets,
              static_cast<double>(incident.peak_score),
              incident.threshold > 0.0F
                  ? static_cast<double>(incident.peak_score / incident.threshold)
                  : 0.0,
              format_contexts(incident.context_mask).c_str());
}

void print_incidents(std::span<const Incident> incidents) {
  std::vector<Incident> ordered(incidents.begin(), incidents.end());
  std::sort(ordered.begin(), ordered.end(),
            [](const Incident& a, const Incident& b) { return a.sequence < b.sequence; });
  std::printf("incidents:\n");
  for (const Incident& incident : ordered) print_incident(incident);
}

void print_report(const Processor& processor, std::chrono::nanoseconds elapsed,
                  std::uint64_t ring_dropped, std::uint64_t kernel_dropped) {
  const ProcessingTotals& totals = processor.totals();
  const double seconds = std::chrono::duration<double>(elapsed).count();
  const double rate = seconds == 0.0 ? 0.0 : static_cast<double>(totals.packets) / seconds;
  print_progress(totals, processor.model(), processor.tracker());
  std::printf(
      "elapsed %.3f s  %.0f packets/s  %.0f ns/packet decode  %.0f ns/packet features  "
      "%.0f ns/packet model  evictions %" PRIu64 "\n",
      seconds, rate, per_packet_ns(totals.decode_time, totals.packets),
      per_packet_ns(totals.feature_time, totals.packets),
      per_packet_ns(totals.model_time, totals.packets), processor.evictions());
  std::printf("drops: ring %" PRIu64 "  kernel %" PRIu64 "  rss %.1f MB  fds %zu\n", ring_dropped,
              kernel_dropped, static_cast<double>(resident_bytes()) / 1e6, open_descriptor_count());
}

std::atomic<Capture*> active_capture{nullptr};

void handle_stop_signal(int) {
  if (Capture* capture = active_capture.load(std::memory_order_acquire)) capture->request_stop();
}

std::unique_ptr<KitNet> make_model(const PipelineOptions& options) {
  if (!options.settings.model_path.empty()) {
    const std::vector<std::byte> bytes = read_file(options.settings.model_path);
    if (!bytes.empty()) {
      std::unique_ptr<KitNet> restored = KitNet::deserialize(bytes);
      if (restored) {
        std::printf("model: resumed from %s (phase %s, %" PRIu64 " packets)\n",
                    options.settings.model_path.c_str(), phase_name(restored->phase()),
                    restored->packets());
        return restored;
      }
      std::fprintf(stderr, "watchdog: ignoring incompatible checkpoint %s\n",
                   options.settings.model_path.c_str());
    }
  }
  ModelConfig config;
  config.grace_packets = options.settings.grace_packets;
  config.mapping_packets = std::max<std::uint64_t>(options.settings.grace_packets / 10, 1);
  config.alert_factor = options.settings.alert_factor;
  config.alert_quantile = options.settings.alert_quantile;
  config.train_gate_factor = options.settings.train_gate_factor;
  return std::make_unique<KitNet>(FeatureExtractor::feature_count, config);
}

void save_model(const KitNet& model, const std::string& path) {
  if (path.empty()) return;
  std::vector<std::byte> bytes(model.serialized_size());
  if (bytes.empty() || !model.serialize(bytes)) {
    std::fprintf(stderr, "watchdog: model not ready, checkpoint skipped\n");
    return;
  }
  if (!write_file_atomic(path, bytes)) {
    std::fprintf(stderr, "watchdog: failed to write checkpoint %s\n", path.c_str());
    return;
  }
  std::printf("model: checkpoint saved to %s\n", path.c_str());
}

struct ScoresFile {
  explicit ScoresFile(const std::string& path)
      : handle(path.empty() ? nullptr : std::fopen(path.c_str(), "wb")) {}
  ScoresFile(const ScoresFile&) = delete;
  ScoresFile& operator=(const ScoresFile&) = delete;
  ~ScoresFile() {
    if (handle != nullptr) std::fclose(handle);
  }
  std::FILE* handle;
};

}  // namespace

int run_replay(const std::string& pcap_path, int loop_count, const PipelineOptions& options) {
  std::string error;
  std::unique_ptr<Capture> first = open_replay_capture(pcap_path, error);
  if (!first) {
    std::fprintf(stderr, "watchdog: %s\n", error.c_str());
    return 1;
  }
  AlertLog alert_log(options.settings.alert_log_path, options.settings.alert_log_max_bytes);
  if (!alert_log.open()) {
    std::fprintf(stderr, "watchdog: cannot write %s\n", options.settings.alert_log_path.c_str());
    return 1;
  }
  SnapshotPublisher publisher;
  SnapshotServer server(options.settings.socket_path, publisher);
  if (!options.settings.socket_path.empty()) {
    if (!server.start(error)) {
      std::fprintf(stderr, "watchdog: %s\n", error.c_str());
      return 1;
    }
    std::signal(SIGPIPE, SIG_IGN);
    std::printf("status: %s\n", server.path().c_str());
    std::fflush(stdout);
  }
  SpscRing<PacketRecord> ring(ring_capacity);
  RingSink sink(ring, OverflowPolicy::block);
  const ScoresFile scores(options.scores_path);
  Processor processor(ring, first->link_type(), false, make_model(options), scores.handle,
                      alert_log, options.settings.socket_path.empty() ? nullptr : &publisher,
                      options.settings, false);
  std::uint64_t kernel_dropped = 0;
  const auto start = std::chrono::steady_clock::now();
  std::thread consumer([&] { processor.run(); });
  int exit_code = 0;
  for (int loop = 0; loop < loop_count; ++loop) {
    std::unique_ptr<Capture> capture =
        loop == 0 ? std::move(first) : open_replay_capture(pcap_path, error);
    if (!capture) {
      std::fprintf(stderr, "watchdog: %s\n", error.c_str());
      exit_code = 1;
      break;
    }
    const CaptureResult result = capture->run(sink);
    if (!result.ok) {
      std::fprintf(stderr, "watchdog: %s\n", result.error.c_str());
      exit_code = 1;
      break;
    }
    kernel_dropped += result.kernel_dropped;
    if (loop_count > 1) {
      std::printf("loop %d/%d  rss %.1f MB  allocations %zu  live %zu\n", loop + 1, loop_count,
                  static_cast<double>(resident_bytes()) / 1e6, alloc_probe::allocation_count(),
                  alloc_probe::live_allocation_count());
      std::fflush(stdout);
    }
  }
  ring.close();
  consumer.join();
  server.stop();
  if (exit_code == 0) {
    print_report(processor, std::chrono::steady_clock::now() - start, sink.dropped(),
                 kernel_dropped);
    if (!processor.recent_incidents().empty()) print_incidents(processor.recent_incidents());
    save_model(processor.model(), options.settings.model_path);
  }
  return exit_code;
}

int run_live(const std::string& interface_name, const PipelineOptions& options) {
  std::string error;
  const std::unique_ptr<Capture> capture = open_live_capture(interface_name, error);
  if (!capture) {
    std::fprintf(stderr, "watchdog: %s\n", error.c_str());
    return 1;
  }
  const PrivilegeDrop dropped = drop_privileges();
  if (dropped.attempted && !dropped.succeeded) {
    std::fprintf(stderr, "watchdog: refusing to run as root: %s\n", dropped.error.c_str());
    return 1;
  }
  if (dropped.succeeded) {
    std::printf("privileges: dropped to %s after opening the capture device\n",
                dropped.account.c_str());
  } else if (!dropped.error.empty()) {
    std::fprintf(stderr, "watchdog: warning: %s\n", dropped.error.c_str());
  }
  if (!options.settings.alert_log_path.empty() && !ensure_state_directory()) {
    std::fprintf(stderr, "watchdog: cannot create %s\n", state_directory().c_str());
    return 1;
  }
  AlertLog alert_log(options.settings.alert_log_path, options.settings.alert_log_max_bytes);
  if (!alert_log.open()) {
    std::fprintf(stderr, "watchdog: cannot write %s\n", options.settings.alert_log_path.c_str());
    return 1;
  }
  SnapshotPublisher publisher;
  SnapshotServer server(options.settings.socket_path, publisher);
  if (!server.start(error)) {
    std::fprintf(stderr, "watchdog: %s\n", error.c_str());
    return 1;
  }
  std::signal(SIGPIPE, SIG_IGN);
  std::printf("capturing on %s (snaplen %zu)\n", interface_name.c_str(), snap_length);
  std::printf("alerts: %s   status: %s\n",
              options.settings.alert_log_path.empty() ? "(disabled)"
                                                      : options.settings.alert_log_path.c_str(),
              server.path().c_str());
  std::fflush(stdout);

  SpscRing<PacketRecord> ring(ring_capacity);
  RingSink sink(ring, OverflowPolicy::drop);
  const ScoresFile scores(options.scores_path);
  Processor processor(ring, capture->link_type(), true, make_model(options), scores.handle,
                      alert_log, &publisher, options.settings, true);
  active_capture.store(capture.get(), std::memory_order_release);
  std::signal(SIGINT, handle_stop_signal);
  std::signal(SIGTERM, handle_stop_signal);
  const auto start = std::chrono::steady_clock::now();
  std::thread consumer([&] { processor.run(); });
  const CaptureResult result = capture->run(sink);
  processor.set_capture_drops(sink.dropped(), result.kernel_dropped);
  ring.close();
  consumer.join();
  std::signal(SIGINT, SIG_DFL);
  std::signal(SIGTERM, SIG_DFL);
  active_capture.store(nullptr, std::memory_order_release);
  server.stop();
  if (!result.ok) {
    std::fprintf(stderr, "watchdog: %s\n", result.error.c_str());
    return 1;
  }
  print_report(processor, std::chrono::steady_clock::now() - start, sink.dropped(),
               result.kernel_dropped);
  if (!processor.recent_incidents().empty()) print_incidents(processor.recent_incidents());
  save_model(processor.model(), options.settings.model_path);
  return 0;
}

}  // namespace watchdog
