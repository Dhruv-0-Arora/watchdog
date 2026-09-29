#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "core/model.hpp"

namespace {

using watchdog::KitNet;
using watchdog::ModelConfig;
using watchdog::ModelPhase;
using watchdog::ScoreResult;

constexpr std::size_t feature_count = 12;

float next_unit(std::uint64_t& state) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return static_cast<float>(state >> 40) * 0x1.0p-24F;
}

ModelConfig tiny_config() {
  ModelConfig config;
  config.max_group_size = 4;
  config.mapping_packets = 500;
  config.grace_packets = 5'000;
  config.min_threshold_samples = 500;
  return config;
}

std::array<float, feature_count> normal_vector(std::uint64_t& state) {
  const float base = next_unit(state);
  std::array<float, feature_count> features{};
  for (std::size_t i = 0; i < feature_count; ++i) {
    const float jitter = 0.05F * next_unit(state);
    features[i] = 10.0F * base + static_cast<float>(i) + jitter;
  }
  return features;
}

std::array<float, feature_count> anomalous_vector(std::uint64_t& state) {
  std::array<float, feature_count> features = normal_vector(state);
  features[0] = 500.0F;
  features[5] = -200.0F;
  features[11] = 900.0F;
  return features;
}

std::unique_ptr<KitNet> trained_model(std::uint64_t& state) {
  auto model = std::make_unique<KitNet>(feature_count, tiny_config());
  std::uint64_t time_ns = 0;
  while (model->phase() != ModelPhase::detecting || !model->threshold_ready()) {
    time_ns += 1'000'000;
    model->process(normal_vector(state), time_ns);
  }
  return model;
}

TEST_CASE("model walks through mapping, training, and detecting phases") {
  KitNet model(feature_count, tiny_config());
  std::uint64_t state = 1;
  CHECK(model.phase() == ModelPhase::mapping);
  std::uint64_t time_ns = 0;
  for (int i = 0; i < 600; ++i) {
    time_ns += 1'000'000;
    model.process(normal_vector(state), time_ns);
  }
  CHECK(model.phase() == ModelPhase::training);
  CHECK(model.group_count() >= feature_count / 4);
  for (int i = 0; i < 5'000; ++i) {
    time_ns += 1'000'000;
    model.process(normal_vector(state), time_ns);
  }
  CHECK(model.phase() == ModelPhase::detecting);
}

TEST_CASE("anomalies score far above normal traffic and raise alerts") {
  std::uint64_t state = 12;
  const auto model = trained_model(state);
  float normal_maximum = 0.0F;
  for (int i = 0; i < 200; ++i) {
    const ScoreResult result = model->process(normal_vector(state), 0);
    normal_maximum = std::max(normal_maximum, result.score);
    CHECK(!result.alert);
  }
  const ScoreResult anomaly = model->process(anomalous_vector(state), 0);
  CHECK(anomaly.score > 5.0F * normal_maximum);
  CHECK(anomaly.alert);
}

TEST_CASE("a sustained attack cannot raise the threshold to absorb itself") {
  std::uint64_t state = 23;
  const auto model = trained_model(state);
  const float threshold_before = model->threshold();
  ScoreResult last{};
  std::uint64_t alerts = 0;
  for (int i = 0; i < 5'000; ++i) {
    last = model->process(anomalous_vector(state), 0);
    alerts += last.alert ? 1 : 0;
  }
  CHECK(alerts == 5'000);
  CHECK(model->threshold() < last.score / 10.0F);
  CHECK(model->threshold() < threshold_before * 2.0F);
}

TEST_CASE("the threshold holds steady through long normal operation") {
  std::uint64_t state = 31;
  const auto model = trained_model(state);
  const float threshold_before = model->threshold();
  std::uint64_t alerts = 0;
  for (int i = 0; i < 50'000; ++i) {
    alerts += model->process(normal_vector(state), 0).alert ? 1 : 0;
  }
  CHECK(alerts == 0);
  CHECK(model->threshold() > threshold_before * 0.75F);
  CHECK(model->threshold() < threshold_before * 1.5F);
}

TEST_CASE("grace duration gate delays detection even after enough packets") {
  ModelConfig config = tiny_config();
  config.grace_min_duration_ns = 1'000'000'000'000ULL;
  KitNet model(feature_count, config);
  std::uint64_t state = 3;
  for (int i = 0; i < 10'000; ++i) model.process(normal_vector(state), 1'000'000);
  CHECK(model.phase() == ModelPhase::training);
}

TEST_CASE("checkpoint roundtrip reproduces scores exactly") {
  std::uint64_t state = 77;
  const auto original = trained_model(state);
  std::vector<std::byte> bytes(original->serialized_size());
  REQUIRE(original->serialize(bytes));
  const auto restored = KitNet::deserialize(bytes);
  REQUIRE(restored != nullptr);
  CHECK(restored->phase() == ModelPhase::detecting);
  CHECK(restored->group_count() == original->group_count());
  std::uint64_t probe_state = 555;
  for (int i = 0; i < 100; ++i) {
    const auto features = normal_vector(probe_state);
    const ScoreResult expected = original->process(features, 0);
    const ScoreResult actual = restored->process(features, 0);
    CHECK(actual.score == expected.score);
    CHECK(actual.alert == expected.alert);
  }
}

TEST_CASE("corrupt checkpoints are rejected") {
  std::uint64_t state = 88;
  const auto model = trained_model(state);
  std::vector<std::byte> bytes(model->serialized_size());
  REQUIRE(model->serialize(bytes));
  std::vector<std::byte> bad_magic = bytes;
  bad_magic[0] = std::byte{0x00};
  CHECK(KitNet::deserialize(bad_magic) == nullptr);
  std::vector<std::byte> truncated(bytes.begin(), bytes.begin() + 40);
  CHECK(KitNet::deserialize(truncated) == nullptr);
  std::vector<std::byte> bad_version = bytes;
  bad_version[4] = std::byte{0x99};
  CHECK(KitNet::deserialize(bad_version) == nullptr);
}

TEST_CASE("model in mapping phase refuses to serialize") {
  KitNet model(feature_count, tiny_config());
  CHECK(model.serialized_size() == 0);
}

}  // namespace

// --- regression tests for the detector deadlock -------------------------------------
//
// The live daemon spent 375 hours alerting on 61% of every packet it saw, with the
// threshold frozen to seven identical digits the whole time. Nothing above caught it
// because every case here feeds a stationary stream, and the deadlock needs drift: once
// the training gate falls below ordinary scores the model stops training, untrained
// scores stay high, high scores are fed to the sketch capped, and capping pins the
// maximum marker so the threshold can never climb back out.

TEST_CASE("the training gate never withholds traffic that does not alert") {
  std::uint64_t state = 101;
  const auto model = trained_model(state);
  // A gate below the threshold opens a band where a packet neither alerts nor teaches
  // the model anything. That band is what the deadlock grows in.
  CHECK(model->train_gate() >= model->threshold());
}

TEST_CASE("the detector keeps learning when normal traffic drifts") {
  std::uint64_t state = 202;
  const auto model = trained_model(state);

  // Benign drift: the same shape of traffic, scaled up over time, as happens when a
  // machine's normal workload changes. Nothing here is an attack.
  std::uint64_t alerts = 0;
  float previous_threshold = model->threshold();
  bool threshold_ever_moved = false;
  for (int i = 0; i < 60'000; ++i) {
    const float drift = 1.0F + 0.5F * static_cast<float>(i) / 60'000.0F;
    std::array<float, feature_count> features = normal_vector(state);
    for (float& value : features) value *= drift;
    alerts += model->process(features, 0).alert ? 1 : 0;
    if (model->threshold() != previous_threshold) {
      threshold_ever_moved = true;
      previous_threshold = model->threshold();
    }
  }
  // Before the fix this stream alerted on the large majority of packets and the
  // threshold never changed by a single bit.
  CHECK(alerts < 6'000);
  CHECK(threshold_ever_moved);
}

TEST_CASE("the threshold recovers after a burst instead of freezing") {
  std::uint64_t state = 303;
  const auto model = trained_model(state);
  for (int i = 0; i < 2'000; ++i) model->process(anomalous_vector(state), 0);

  // After the burst, ordinary traffic must be quiet again. The failure mode is that the
  // burst leaves the sketch pinned and every later packet keeps alerting forever.
  std::uint64_t alerts = 0;
  for (int i = 0; i < 40'000; ++i) {
    alerts += model->process(normal_vector(state), 0).alert ? 1 : 0;
  }
  CHECK(alerts < 400);
}

TEST_CASE("a runaway feature cannot drive the score out of the estimator's range") {
  std::uint64_t state = 404;
  const auto model = trained_model(state);
  std::array<float, feature_count> features = normal_vector(state);
  features[3] = 1e12F;  // a damped counter that ran away during a burst
  const ScoreResult result = model->process(features, 0);
  // Unclamped normalization put scores at 1.4e7 in replay, which leaves a quantile
  // sketch estimating a tail across eight decades. It still has to read as an anomaly.
  CHECK(result.score < 100.0F);
  CHECK(result.alert);
}
