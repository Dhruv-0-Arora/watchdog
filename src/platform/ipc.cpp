#include "platform/ipc.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <utility>

namespace watchdog {

namespace {

constexpr int accept_poll_timeout_ms = 200;

bool fill_address(const std::string& path, sockaddr_un& address, std::string& error) {
  if (path.size() >= sizeof address.sun_path) {
    error = "socket path is too long";
    return false;
  }
  address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
  return true;
}

bool write_all(int fd, const void* data, std::size_t size) {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  std::size_t sent = 0;
  while (sent < size) {
    const ssize_t written = ::write(fd, bytes + sent, size - sent);
    if (written < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    sent += static_cast<std::size_t>(written);
  }
  return true;
}

bool read_all(int fd, void* data, std::size_t size) {
  auto* bytes = static_cast<std::uint8_t*>(data);
  std::size_t received = 0;
  while (received < size) {
    const ssize_t got = ::read(fd, bytes + received, size - received);
    if (got == 0) return false;
    if (got < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    received += static_cast<std::size_t>(got);
  }
  return true;
}

}  // namespace

SnapshotServer::SnapshotServer(std::string path, const SnapshotPublisher& publisher)
    : path_(std::move(path)), publisher_(publisher) {}

SnapshotServer::~SnapshotServer() { stop(); }

bool SnapshotServer::start(std::string& error) {
  listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (listen_fd_ < 0) {
    error = std::strerror(errno);
    return false;
  }
  sockaddr_un address{};
  if (!fill_address(path_, address, error)) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  ::unlink(path_.c_str());
  if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&address), sizeof address) != 0) {
    error = std::string("bind ") + path_ + ": " + std::strerror(errno);
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  if (::chmod(path_.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) != 0) {
    error = std::string("chmod ") + path_ + ": " + std::strerror(errno);
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  if (::listen(listen_fd_, 8) != 0) {
    error = std::strerror(errno);
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  thread_ = std::thread([this] { serve(); });
  return true;
}

void SnapshotServer::stop() {
  if (listen_fd_ < 0) return;
  stopping_.store(true, std::memory_order_release);
  if (thread_.joinable()) thread_.join();
  ::close(listen_fd_);
  ::unlink(path_.c_str());
  listen_fd_ = -1;
}

void SnapshotServer::serve() {
  while (!stopping_.load(std::memory_order_acquire)) {
    pollfd waiter{listen_fd_, POLLIN, 0};
    const int ready = ::poll(&waiter, 1, accept_poll_timeout_ms);
    if (ready <= 0) continue;
    const int client = ::accept(listen_fd_, nullptr, nullptr);
    if (client < 0) continue;
    const Snapshot snapshot = publisher_.read();
    write_all(client, &snapshot, sizeof snapshot);
    ::close(client);
  }
}

bool fetch_snapshot(const std::string& path, Snapshot& out, std::string& error) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    error = std::strerror(errno);
    return false;
  }
  sockaddr_un address{};
  if (!fill_address(path, address, error)) {
    ::close(fd);
    return false;
  }
  if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof address) != 0) {
    error = std::string("no daemon listening on ") + path;
    ::close(fd);
    return false;
  }
  const bool received = read_all(fd, &out, sizeof out);
  ::close(fd);
  if (!received) {
    error = "daemon closed the connection early";
    return false;
  }
  if (out.magic != snapshot_magic || out.version != snapshot_version ||
      out.byte_size != sizeof(Snapshot)) {
    error = "daemon speaks a different snapshot version";
    return false;
  }
  return true;
}

}  // namespace watchdog
