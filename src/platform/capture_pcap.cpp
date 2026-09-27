#include <netinet/in.h>
#include <pcap/pcap.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include "platform/capture.hpp"

namespace watchdog {
namespace {

struct PcapCloser {
  void operator()(pcap_t* handle) const { pcap_close(handle); }
};
using PcapHandle = std::unique_ptr<pcap_t, PcapCloser>;

struct DeviceListCloser {
  void operator()(pcap_if_t* list) const { pcap_freealldevs(list); }
};
using DeviceList = std::unique_ptr<pcap_if_t, DeviceListCloser>;

bool is_routable(const sockaddr* address) {
  if (address == nullptr) return false;
  if (address->sa_family == AF_INET) {
    const auto* inet4 = reinterpret_cast<const sockaddr_in*>(address);
    const std::uint32_t host_order = ntohl(inet4->sin_addr.s_addr);
    const bool link_local = (host_order >> 16) == 0xA9FE;
    return host_order != 0 && !link_local;
  }
  if (address->sa_family == AF_INET6) {
    const auto* inet6 = reinterpret_cast<const sockaddr_in6*>(address);
    const std::uint8_t* bytes = inet6->sin6_addr.s6_addr;
    const bool link_local = bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80;
    const bool unspecified = std::all_of(bytes, bytes + 16, [](std::uint8_t b) { return b == 0; });
    return !link_local && !unspecified;
  }
  return false;
}

int interface_score(const pcap_if_t& device) {
  const bool up = (device.flags & PCAP_IF_UP) != 0;
  const bool loopback = (device.flags & PCAP_IF_LOOPBACK) != 0;
  if (!up || loopback) return 0;
  bool routable_ipv4 = false;
  bool routable_ipv6 = false;
  for (const pcap_addr* address = device.addresses; address != nullptr; address = address->next) {
    if (!is_routable(address->addr)) continue;
    routable_ipv4 = routable_ipv4 || address->addr->sa_family == AF_INET;
    routable_ipv6 = routable_ipv6 || address->addr->sa_family == AF_INET6;
  }
  if (!routable_ipv4 && !routable_ipv6) return 0;
  int score = 1;
  if (routable_ipv4) score += 4;
  if (routable_ipv6) score += 2;
#ifdef PCAP_IF_CONNECTION_STATUS_CONNECTED
  if ((device.flags & PCAP_IF_CONNECTION_STATUS) == PCAP_IF_CONNECTION_STATUS_CONNECTED) score += 8;
#endif
  return score;
}

std::uint64_t to_nanoseconds(const timeval& time) {
  return static_cast<std::uint64_t>(time.tv_sec) * 1'000'000'000ULL +
         static_cast<std::uint64_t>(time.tv_usec) * 1'000ULL;
}

void deliver(u_char* user, const pcap_pkthdr* header, const u_char* bytes) {
  auto& sink = *reinterpret_cast<PacketSink*>(user);
  PacketRecord record{};
  record.timestamp_ns = to_nanoseconds(header->ts);
  record.wire_length = header->len;
  record.captured_length =
      static_cast<std::uint16_t>(std::min<bpf_u_int32>(header->caplen, snap_length));
  std::memcpy(record.headers.data(), bytes, record.captured_length);
  sink.on_packet(record);
}

class PcapCapture final : public Capture {
 public:
  PcapCapture(PcapHandle handle, bool stop_at_idle)
      : handle_(std::move(handle)), stop_at_idle_(stop_at_idle) {}

  [[nodiscard]] int link_type() const override { return pcap_datalink(handle_.get()); }

  CaptureResult run(PacketSink& sink) override {
    CaptureResult result;
    while (!stop_requested_.load(std::memory_order_acquire)) {
      const int processed =
          pcap_dispatch(handle_.get(), -1, deliver, reinterpret_cast<u_char*>(&sink));
      if (processed == PCAP_ERROR_BREAK) break;
      if (processed < 0) {
        result.error = pcap_geterr(handle_.get());
        return result;
      }
      if (processed > 0) {
        result.packets_delivered += static_cast<std::uint64_t>(processed);
        sink.on_batch_end();
      }
      if (processed == 0 && stop_at_idle_) break;
    }
    pcap_stat statistics{};
    if (pcap_stats(handle_.get(), &statistics) == 0) result.kernel_dropped = statistics.ps_drop;
    result.ok = true;
    return result;
  }

  void request_stop() override {
    stop_requested_.store(true, std::memory_order_release);
    pcap_breakloop(handle_.get());
  }

 private:
  PcapHandle handle_;
  bool stop_at_idle_;
  std::atomic<bool> stop_requested_{false};
};

}  // namespace

std::unique_ptr<Capture> open_live_capture(const std::string& interface_name, std::string& error) {
  std::array<char, PCAP_ERRBUF_SIZE> error_buffer{};
  PcapHandle handle(pcap_create(interface_name.c_str(), error_buffer.data()));
  if (!handle) {
    error = error_buffer.data();
    return nullptr;
  }
  pcap_set_snaplen(handle.get(), snap_length);
  pcap_set_timeout(handle.get(), 100);
  pcap_set_buffer_size(handle.get(), 4 * 1024 * 1024);
  const int status = pcap_activate(handle.get());
  if (status < 0) {
    error = std::string(pcap_statustostr(status)) + ": " + pcap_geterr(handle.get());
    return nullptr;
  }
  return std::make_unique<PcapCapture>(std::move(handle), false);
}

std::unique_ptr<Capture> open_replay_capture(const std::string& path, std::string& error) {
  std::array<char, PCAP_ERRBUF_SIZE> error_buffer{};
  PcapHandle handle(pcap_open_offline(path.c_str(), error_buffer.data()));
  if (!handle) {
    error = error_buffer.data();
    return nullptr;
  }
  return std::make_unique<PcapCapture>(std::move(handle), true);
}

std::string default_interface(std::string& error) {
  std::array<char, PCAP_ERRBUF_SIZE> error_buffer{};
  pcap_if_t* raw_list = nullptr;
  if (pcap_findalldevs(&raw_list, error_buffer.data()) != 0) {
    error = error_buffer.data();
    return {};
  }
  const DeviceList list(raw_list);
  std::string best_name;
  int best_score = 0;
  for (const pcap_if_t* device = list.get(); device != nullptr; device = device->next) {
    const int score = interface_score(*device);
    if (score > best_score) {
      best_score = score;
      best_name = device->name;
    }
  }
  if (best_name.empty()) error = "no active interface with a routable address found";
  return best_name;
}

}  // namespace watchdog
