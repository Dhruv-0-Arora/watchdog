#include <doctest/doctest.h>

#include <array>
#include <cmath>
#include <cstdint>
#include <vector>

#include "core/stats.hpp"

namespace {

using watchdog::decay_factors;
using watchdog::DecayFactors;
using watchdog::PairedWindowedStats;
using watchdog::window_count;
using watchdog::window_lambdas;
using watchdog::WindowedStats;

struct Sample {
  std::uint64_t time_ns;
  float value;
};

struct Reference {
  double weight = 0;
  double mean = 0;
  double std_dev = 0;
};

Reference reference_stats(const std::vector<Sample>& samples, double lambda) {
  Reference result;
  double linear_sum = 0;
  double squared_sum = 0;
  const double last_time = static_cast<double>(samples.back().time_ns) * 1e-9;
  for (const Sample& sample : samples) {
    const double age = last_time - static_cast<double>(sample.time_ns) * 1e-9;
    const double decayed = std::exp2(-lambda * age);
    result.weight += decayed;
    linear_sum += decayed * static_cast<double>(sample.value);
    squared_sum += decayed * static_cast<double>(sample.value) * static_cast<double>(sample.value);
  }
  result.mean = linear_sum / result.weight;
  const double variance = std::max(0.0, squared_sum / result.weight - result.mean * result.mean);
  result.std_dev = std::sqrt(variance);
  return result;
}

std::uint64_t next_random(std::uint64_t& state) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return state;
}

TEST_CASE("incremental damped stats match the closed-form reference") {
  std::uint64_t state = 42;
  std::vector<Sample> samples;
  std::uint64_t time_ns = 1'000'000'000;
  WindowedStats stats;
  std::uint64_t previous_ns = time_ns;
  for (int i = 0; i < 500; ++i) {
    time_ns += 1'000'000 + next_random(state) % 500'000'000;
    const float value = static_cast<float>(next_random(state) % 1500) + 60.0F;
    samples.push_back({time_ns, value});
    stats.observe(value, decay_factors(previous_ns, time_ns));
    previous_ns = time_ns;
  }
  std::array<float, WindowedStats::feature_count> features{};
  stats.write_features(features);
  for (std::size_t window = 0; window < window_count; ++window) {
    const Reference expected =
        reference_stats(samples, static_cast<double>(window_lambdas[window]));
    CHECK(features[3 * window] == doctest::Approx(expected.weight).epsilon(0.02));
    CHECK(features[3 * window + 1] == doctest::Approx(expected.mean).epsilon(0.02));
    CHECK(features[3 * window + 2] == doctest::Approx(expected.std_dev).epsilon(0.05));
  }
}

TEST_CASE("weight decays toward zero when time passes without traffic") {
  WindowedStats stats;
  stats.observe(100.0F, decay_factors(0, 0));
  std::array<float, WindowedStats::feature_count> before{};
  stats.write_features(before);
  stats.observe(100.0F, decay_factors(0, 200'000'000'000ULL));
  std::array<float, WindowedStats::feature_count> after{};
  stats.write_features(after);
  CHECK(before[0] == doctest::Approx(1.0F));
  CHECK(after[0] == doctest::Approx(1.0F).epsilon(0.01));
}

TEST_CASE("paired stats expose correlation between directions") {
  PairedWindowedStats stats;
  std::uint64_t time_ns = 0;
  std::uint64_t state = 7;
  for (int i = 0; i < 2'000; ++i) {
    const float value = static_cast<float>(next_random(state) % 1000);
    const DecayFactors factors = decay_factors(time_ns, time_ns + 1'000'000);
    time_ns += 1'000'000;
    stats.observe(true, value, factors);
    stats.observe(false, value, decay_factors(time_ns, time_ns));
  }
  std::array<float, PairedWindowedStats::feature_count> features{};
  stats.write_features(true, features);
  for (std::size_t window = 0; window < window_count; ++window) {
    const float weight = features[7 * window];
    const float correlation = features[7 * window + 6];
    CHECK(weight > 0.0F);
    CHECK(correlation >= -1.01F);
    CHECK(correlation <= 1.01F);
    CHECK(correlation > 0.4F);
  }
}

TEST_CASE("uncorrelated directions have correlation near zero") {
  PairedWindowedStats stats;
  std::uint64_t time_ns = 0;
  std::uint64_t state = 99;
  for (int i = 0; i < 5'000; ++i) {
    const DecayFactors factors = decay_factors(time_ns, time_ns + 1'000'000);
    time_ns += 1'000'000;
    stats.observe(true, static_cast<float>(next_random(state) % 1000), factors);
    stats.observe(false, static_cast<float>(next_random(state) % 1000),
                  decay_factors(time_ns, time_ns));
  }
  std::array<float, PairedWindowedStats::feature_count> features{};
  stats.write_features(true, features);
  const float slowest_window_correlation = features[7 * (window_count - 1) + 6];
  CHECK(std::abs(slowest_window_correlation) < 0.2F);
}

}  // namespace
