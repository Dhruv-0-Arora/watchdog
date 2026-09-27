#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "core/packet_record.hpp"

namespace watchdog {

class PacketSink {
 public:
  virtual ~PacketSink() = default;
  virtual void on_packet(const PacketRecord& record) = 0;
  virtual void on_batch_end() = 0;
};

struct CaptureResult {
  std::uint64_t packets_delivered = 0;
  std::uint64_t kernel_dropped = 0;
  bool ok = false;
  std::string error;
};

class Capture {
 public:
  virtual ~Capture() = default;
  [[nodiscard]] virtual int link_type() const = 0;
  virtual CaptureResult run(PacketSink& sink) = 0;
  virtual void request_stop() = 0;
};

std::unique_ptr<Capture> open_live_capture(const std::string& interface_name, std::string& error);
std::unique_ptr<Capture> open_replay_capture(const std::string& path, std::string& error);
std::string default_interface(std::string& error);

}  // namespace watchdog
