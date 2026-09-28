#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>

namespace watchdog {

class P2Quantile {
 public:
  struct State {
    std::array<double, 5> heights{};
    std::array<double, 5> positions{};
    std::array<double, 5> desired{};
    std::uint64_t count = 0;
  };

  explicit P2Quantile(double quantile)
      : quantile_(quantile),
        increments_{0.0, quantile / 2.0, quantile, (1.0 + quantile) / 2.0, 1.0} {}

  void observe(double value) {
    state_.count += 1;
    if (state_.count <= 5) {
      state_.heights[state_.count - 1] = value;
      if (state_.count == 5) initialize_markers();
      return;
    }
    const std::size_t cell = locate_cell(value);
    for (std::size_t i = cell + 1; i < 5; ++i) state_.positions[i] += 1.0;
    for (std::size_t i = 0; i < 5; ++i) state_.desired[i] += increments_[i];
    for (std::size_t i = 1; i <= 3; ++i) adjust_marker(i);
  }

  void observe_capped(double value) {
    observe(state_.count < 5 ? value : std::min(value, state_.heights[4]));
  }

  [[nodiscard]] double value() const {
    if (state_.count == 0) return 0.0;
    if (state_.count < 5) return partial_estimate();
    return state_.heights[2];
  }

  [[nodiscard]] std::uint64_t count() const { return state_.count; }
  [[nodiscard]] double quantile() const { return quantile_; }

  [[nodiscard]] const State& state() const { return state_; }
  void restore(const State& state) { state_ = state; }

 private:
  void initialize_markers() {
    std::sort(state_.heights.begin(), state_.heights.end());
    state_.positions = {1.0, 2.0, 3.0, 4.0, 5.0};
    state_.desired = {1.0, 1.0 + 2.0 * quantile_, 1.0 + 4.0 * quantile_, 3.0 + 2.0 * quantile_,
                      5.0};
  }

  [[nodiscard]] double partial_estimate() const {
    std::array<double, 5> sorted = state_.heights;
    std::sort(sorted.begin(), sorted.begin() + static_cast<std::ptrdiff_t>(state_.count));
    const double rank = quantile_ * static_cast<double>(state_.count - 1);
    const auto low = static_cast<std::size_t>(rank);
    const std::size_t high = std::min(low + 1, static_cast<std::size_t>(state_.count - 1));
    const double fraction = rank - static_cast<double>(low);
    return sorted[low] + fraction * (sorted[high] - sorted[low]);
  }

  [[nodiscard]] std::size_t locate_cell(double value) {
    if (value < state_.heights[0]) {
      state_.heights[0] = value;
      return 0;
    }
    if (value >= state_.heights[4]) {
      state_.heights[4] = value;
      return 3;
    }
    std::size_t cell = 0;
    while (cell < 3 && state_.heights[cell + 1] <= value) cell += 1;
    return cell;
  }

  void adjust_marker(std::size_t i) {
    const double offset = state_.desired[i] - state_.positions[i];
    const bool move_up = offset >= 1.0 && state_.positions[i + 1] - state_.positions[i] > 1.0;
    const bool move_down = offset <= -1.0 && state_.positions[i - 1] - state_.positions[i] < -1.0;
    if (!move_up && !move_down) return;
    const double sign = move_up ? 1.0 : -1.0;
    const double parabolic = parabolic_height(i, sign);
    if (state_.heights[i - 1] < parabolic && parabolic < state_.heights[i + 1]) {
      state_.heights[i] = parabolic;
    } else {
      state_.heights[i] = linear_height(i, sign);
    }
    state_.positions[i] += sign;
  }

  [[nodiscard]] double parabolic_height(std::size_t i, double sign) const {
    const double n_prev = state_.positions[i - 1];
    const double n_here = state_.positions[i];
    const double n_next = state_.positions[i + 1];
    const double h_prev = state_.heights[i - 1];
    const double h_here = state_.heights[i];
    const double h_next = state_.heights[i + 1];
    const double upper = (n_here - n_prev + sign) * (h_next - h_here) / (n_next - n_here);
    const double lower = (n_next - n_here - sign) * (h_here - h_prev) / (n_here - n_prev);
    return h_here + sign / (n_next - n_prev) * (upper + lower);
  }

  [[nodiscard]] double linear_height(std::size_t i, double sign) const {
    const std::size_t neighbor = sign > 0.0 ? i + 1 : i - 1;
    return state_.heights[i] + sign * (state_.heights[neighbor] - state_.heights[i]) /
                                   (state_.positions[neighbor] - state_.positions[i]);
  }

  double quantile_;
  std::array<double, 5> increments_;
  State state_{};
};

}  // namespace watchdog
