#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <span>

namespace watchdog {

inline constexpr std::size_t window_count = 5;
inline constexpr std::array<float, window_count> window_lambdas{5.0F, 3.0F, 1.0F, 0.1F, 0.01F};
inline constexpr float stat_epsilon = 1e-6F;

using DecayFactors = std::array<float, window_count>;

[[nodiscard]] inline DecayFactors decay_factors(std::uint64_t previous_ns, std::uint64_t now_ns) {
  const std::uint64_t elapsed_ns = now_ns > previous_ns ? now_ns - previous_ns : 0;
  const float elapsed_seconds = static_cast<float>(elapsed_ns) * 1e-9F;
  DecayFactors factors;
  for (std::size_t i = 0; i < window_count; ++i) {
    factors[i] = std::exp2(-window_lambdas[i] * elapsed_seconds);
  }
  return factors;
}

struct Damped1D {
  float weight = 0.0F;
  float linear_sum = 0.0F;
  float squared_sum = 0.0F;

  void decay(float factor) {
    weight *= factor;
    linear_sum *= factor;
    squared_sum *= factor;
  }

  void insert(float value) {
    weight += 1.0F;
    linear_sum += value;
    squared_sum += value * value;
  }

  [[nodiscard]] float mean() const { return linear_sum / std::max(weight, stat_epsilon); }

  [[nodiscard]] float variance() const {
    const float average = mean();
    return std::max(0.0F, squared_sum / std::max(weight, stat_epsilon) - average * average);
  }

  [[nodiscard]] float std_dev() const { return std::sqrt(variance()); }
};

class WindowedStats {
 public:
  static constexpr std::size_t feature_count = 3 * window_count;

  void observe(float value, const DecayFactors& factors) {
    for (std::size_t i = 0; i < window_count; ++i) {
      windows_[i].decay(factors[i]);
      windows_[i].insert(value);
    }
  }

  void write_features(std::span<float> out) const {
    for (std::size_t i = 0; i < window_count; ++i) {
      out[3 * i] = windows_[i].weight;
      out[3 * i + 1] = windows_[i].mean();
      out[3 * i + 2] = windows_[i].std_dev();
    }
  }

  [[nodiscard]] const Damped1D& window(std::size_t index) const { return windows_[index]; }

 private:
  std::array<Damped1D, window_count> windows_{};
};

class PairedWindowedStats {
 public:
  static constexpr std::size_t feature_count = 7 * window_count;

  void observe(bool forward, float value, const DecayFactors& factors) {
    Direction& mine = forward ? forward_ : reverse_;
    Direction& theirs = forward ? reverse_ : forward_;
    for (std::size_t i = 0; i < window_count; ++i) {
      mine.windows[i].decay(factors[i]);
      theirs.windows[i].decay(factors[i]);
      residual_products_[i] *= factors[i];
      mine.windows[i].insert(value);
      const float residual = value - mine.windows[i].mean();
      residual_products_[i] += residual * theirs.last_residual[i];
      mine.last_residual[i] = residual;
    }
  }

  void write_features(bool forward, std::span<float> out) const {
    const Direction& mine = forward ? forward_ : reverse_;
    const Direction& theirs = forward ? reverse_ : forward_;
    for (std::size_t i = 0; i < window_count; ++i) {
      const Damped1D& own = mine.windows[i];
      const Damped1D& other = theirs.windows[i];
      const float own_mean = own.mean();
      const float other_mean = other.mean();
      const float own_variance = own.variance();
      const float other_variance = other.variance();
      const float combined_weight = own.weight + other.weight;
      const float covariance = residual_products_[i] / std::max(combined_weight, stat_epsilon);
      const float deviation_product = std::sqrt(own_variance) * std::sqrt(other_variance);
      out[7 * i] = own.weight;
      out[7 * i + 1] = own_mean;
      out[7 * i + 2] = std::sqrt(own_variance);
      out[7 * i + 3] = std::sqrt(own_mean * own_mean + other_mean * other_mean);
      out[7 * i + 4] = std::sqrt(own_variance * own_variance + other_variance * other_variance);
      out[7 * i + 5] = covariance;
      out[7 * i + 6] = covariance / std::max(deviation_product, stat_epsilon);
    }
  }

 private:
  struct Direction {
    std::array<Damped1D, window_count> windows{};
    std::array<float, window_count> last_residual{};
  };

  Direction forward_{};
  Direction reverse_{};
  std::array<float, window_count> residual_products_{};
};

}  // namespace watchdog
