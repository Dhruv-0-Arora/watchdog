#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <thread>

#include "core/snapshot.hpp"

namespace watchdog {

class SnapshotPublisher {
 public:
  void publish(const Snapshot& snapshot) {
    const std::lock_guard<std::mutex> guard(mutex_);
    snapshot_ = snapshot;
  }

  [[nodiscard]] Snapshot read() const {
    const std::lock_guard<std::mutex> guard(mutex_);
    return snapshot_;
  }

 private:
  mutable std::mutex mutex_;
  Snapshot snapshot_{};
};

class SnapshotServer {
 public:
  SnapshotServer(std::string path, const SnapshotPublisher& publisher);
  ~SnapshotServer();
  SnapshotServer(const SnapshotServer&) = delete;
  SnapshotServer& operator=(const SnapshotServer&) = delete;

  [[nodiscard]] bool start(std::string& error);
  void stop();

  [[nodiscard]] const std::string& path() const { return path_; }

 private:
  void serve();

  std::string path_;
  const SnapshotPublisher& publisher_;
  int listen_fd_ = -1;
  std::atomic<bool> stopping_{false};
  std::thread thread_;
};

[[nodiscard]] bool fetch_snapshot(const std::string& path, Snapshot& out, std::string& error);

}  // namespace watchdog
