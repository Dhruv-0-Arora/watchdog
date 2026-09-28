#include <doctest/doctest.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

#include "core/quantile.hpp"

namespace {

using watchdog::P2Quantile;

double next_uniform(std::uint64_t& state) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return static_cast<double>(state >> 11) * 0x1.0p-53;
}

double exact_quantile(std::vector<double> values, double quantile) {
  std::sort(values.begin(), values.end());
  const double rank = quantile * static_cast<double>(values.size() - 1);
  const auto low = static_cast<std::size_t>(rank);
  const std::size_t high = std::min(low + 1, values.size() - 1);
  const double fraction = rank - static_cast<double>(low);
  return values[low] + fraction * (values[high] - values[low]);
}

void check_distribution(const std::vector<double>& samples, double quantile, double tolerance) {
  P2Quantile estimator(quantile);
  for (const double sample : samples) estimator.observe(sample);
  const double exact = exact_quantile(samples, quantile);
  const double spread = exact_quantile(samples, 0.999) - exact_quantile(samples, 0.001);
  CHECK(std::abs(estimator.value() - exact) < tolerance * spread);
}

TEST_CASE("p2 tracks quantiles of a uniform distribution") {
  std::uint64_t state = 12345;
  std::vector<double> samples;
  for (int i = 0; i < 100'000; ++i) samples.push_back(next_uniform(state));
  check_distribution(samples, 0.5, 0.01);
  check_distribution(samples, 0.99, 0.01);
  check_distribution(samples, 0.999, 0.01);
}

TEST_CASE("p2 tracks quantiles of a heavy-tailed distribution") {
  std::uint64_t state = 777;
  std::vector<double> samples;
  for (int i = 0; i < 100'000; ++i) {
    const double uniform = next_uniform(state);
    samples.push_back(std::exp(4.0 * uniform));
  }
  check_distribution(samples, 0.99, 0.02);
  check_distribution(samples, 0.9999, 0.05);
}

TEST_CASE("fewer than five samples interpolate directly") {
  P2Quantile estimator(0.5);
  CHECK(estimator.value() == 0.0);
  estimator.observe(10.0);
  CHECK(estimator.value() == 10.0);
  estimator.observe(20.0);
  CHECK(estimator.value() == doctest::Approx(15.0));
  estimator.observe(30.0);
  CHECK(estimator.value() == doctest::Approx(20.0));
}

TEST_CASE("capped observations count tail mass without widening the scale") {
  std::uint64_t state = 4242;
  P2Quantile estimator(0.99);
  for (int i = 0; i < 100'000; ++i) estimator.observe(next_uniform(state));
  const double before = estimator.value();
  for (int i = 0; i < 10'000; ++i) estimator.observe_capped(1'000.0);
  CHECK(estimator.value() >= before);
  CHECK(estimator.value() <= 1.0);
}

TEST_CASE("dropping the upper tail instead of capping it ratchets the estimate down") {
  std::uint64_t capped_state = 7;
  std::uint64_t dropped_state = 7;
  P2Quantile capped(0.999);
  P2Quantile dropped(0.999);
  for (int i = 0; i < 200'000; ++i) {
    const double capped_sample = next_uniform(capped_state);
    if (capped_sample > capped.value() && capped.count() > 1'000) {
      capped.observe_capped(capped_sample);
    } else {
      capped.observe(capped_sample);
    }
    const double dropped_sample = next_uniform(dropped_state);
    if (dropped_sample <= dropped.value() || dropped.count() <= 1'000)
      dropped.observe(dropped_sample);
  }
  CHECK(dropped.value() < capped.value());
  CHECK(capped.value() > 0.9);
}

TEST_CASE("state roundtrip preserves the estimate") {
  std::uint64_t state = 55;
  P2Quantile original(0.99);
  for (int i = 0; i < 10'000; ++i) original.observe(next_uniform(state));
  P2Quantile restored(0.99);
  restored.restore(original.state());
  CHECK(restored.value() == original.value());
  CHECK(restored.count() == original.count());
  original.observe(0.5);
  restored.observe(0.5);
  CHECK(restored.value() == original.value());
}

}  // namespace
