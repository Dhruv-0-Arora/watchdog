#include <doctest/doctest.h>
#include <unistd.h>

#include <string>
#include <thread>

#include "core/snapshot.hpp"
#include "platform/ipc.hpp"

namespace {

using watchdog::fetch_snapshot;
using watchdog::Snapshot;
using watchdog::SnapshotPublisher;
using watchdog::SnapshotServer;

std::string test_socket_path(const char* name) {
  return "/tmp/watchdog-test-" + std::to_string(::getpid()) + "-" + name + ".sock";
}

Snapshot sample_snapshot() {
  Snapshot snapshot;
  snapshot.byte_size = sizeof(Snapshot);
  snapshot.packets = 123'456;
  snapshot.model_phase = 2;
  snapshot.threshold = 0.25F;
  snapshot.open_count = 1;
  snapshot.open[0].sequence = 9;
  snapshot.open[0].packets = 4096;
  snapshot.recent_count = 2;
  snapshot.recent[0].sequence = 7;
  snapshot.recent[1].sequence = 8;
  return snapshot;
}

TEST_CASE("a client receives the published snapshot") {
  const std::string path = test_socket_path("basic");
  SnapshotPublisher publisher;
  publisher.publish(sample_snapshot());
  SnapshotServer server(path, publisher);
  std::string error;
  REQUIRE(server.start(error));

  Snapshot received;
  REQUIRE(fetch_snapshot(path, received, error));
  CHECK(received.packets == 123'456);
  CHECK(received.open_count == 1);
  CHECK(received.open[0].sequence == 9);
  CHECK(received.recent_count == 2);
  CHECK(received.recent[1].sequence == 8);
  server.stop();
}

TEST_CASE("later publishes are visible to later clients") {
  const std::string path = test_socket_path("update");
  SnapshotPublisher publisher;
  publisher.publish(sample_snapshot());
  SnapshotServer server(path, publisher);
  std::string error;
  REQUIRE(server.start(error));

  Snapshot first;
  REQUIRE(fetch_snapshot(path, first, error));
  Snapshot updated = sample_snapshot();
  updated.packets = 999;
  publisher.publish(updated);
  Snapshot second;
  REQUIRE(fetch_snapshot(path, second, error));
  CHECK(first.packets == 123'456);
  CHECK(second.packets == 999);
  server.stop();
}

TEST_CASE("many sequential clients are served") {
  const std::string path = test_socket_path("many");
  SnapshotPublisher publisher;
  publisher.publish(sample_snapshot());
  SnapshotServer server(path, publisher);
  std::string error;
  REQUIRE(server.start(error));
  for (int i = 0; i < 20; ++i) {
    Snapshot received;
    REQUIRE(fetch_snapshot(path, received, error));
    CHECK(received.packets == 123'456);
  }
  server.stop();
}

TEST_CASE("connecting with no daemon reports a clear error") {
  Snapshot received;
  std::string error;
  CHECK(!fetch_snapshot(test_socket_path("absent"), received, error));
  CHECK(error.find("no daemon listening") != std::string::npos);
}

TEST_CASE("stopping the server removes its socket file") {
  const std::string path = test_socket_path("cleanup");
  SnapshotPublisher publisher;
  SnapshotServer server(path, publisher);
  std::string error;
  REQUIRE(server.start(error));
  CHECK(::access(path.c_str(), F_OK) == 0);
  server.stop();
  CHECK(::access(path.c_str(), F_OK) != 0);
}

TEST_CASE("an over-long socket path is rejected instead of truncated") {
  const std::string path = "/tmp/" + std::string(200, 'x') + ".sock";
  SnapshotPublisher publisher;
  SnapshotServer server(path, publisher);
  std::string error;
  CHECK(!server.start(error));
  CHECK(error.find("too long") != std::string::npos);
}

}  // namespace
