#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace watchdog {

class FeatureMapper {
 public:
  FeatureMapper(std::size_t feature_count, std::size_t max_group_size)
      : feature_count_(feature_count),
        max_group_size_(max_group_size),
        sums_(feature_count, 0.0),
        squared_sums_(feature_count, 0.0),
        products_(feature_count * feature_count, 0.0) {}

  void accumulate(std::span<const float> features) {
    samples_ += 1;
    for (std::size_t i = 0; i < feature_count_; ++i) {
      const auto value = static_cast<double>(features[i]);
      sums_[i] += value;
      squared_sums_[i] += value * value;
      for (std::size_t j = i + 1; j < feature_count_; ++j) {
        products_[i * feature_count_ + j] += value * static_cast<double>(features[j]);
      }
    }
  }

  void freeze() {
    struct Edge {
      float distance;
      std::uint16_t first;
      std::uint16_t second;
    };
    std::vector<Edge> edges;
    edges.reserve(feature_count_ * (feature_count_ - 1) / 2);
    for (std::size_t i = 0; i < feature_count_; ++i) {
      for (std::size_t j = i + 1; j < feature_count_; ++j) {
        edges.push_back({1.0F - std::abs(correlation(i, j)), static_cast<std::uint16_t>(i),
                         static_cast<std::uint16_t>(j)});
      }
    }
    std::sort(edges.begin(), edges.end(),
              [](const Edge& a, const Edge& b) { return a.distance < b.distance; });

    std::vector<std::uint16_t> parent(feature_count_);
    std::vector<std::uint16_t> size(feature_count_, 1);
    for (std::size_t i = 0; i < feature_count_; ++i) parent[i] = static_cast<std::uint16_t>(i);
    const auto find_root = [&parent](std::uint16_t node) {
      while (parent[node] != node) {
        parent[node] = parent[parent[node]];
        node = parent[node];
      }
      return node;
    };
    for (const Edge& edge : edges) {
      const std::uint16_t root_a = find_root(edge.first);
      const std::uint16_t root_b = find_root(edge.second);
      if (root_a == root_b) continue;
      if (size[root_a] + size[root_b] > max_group_size_) continue;
      parent[root_b] = root_a;
      size[root_a] = static_cast<std::uint16_t>(size[root_a] + size[root_b]);
    }

    std::vector<std::uint16_t> root_to_group(feature_count_, UINT16_MAX);
    group_offsets_.assign(1, 0);
    members_.clear();
    members_.reserve(feature_count_);
    std::vector<std::vector<std::uint16_t>> collected;
    for (std::size_t i = 0; i < feature_count_; ++i) {
      const std::uint16_t root = find_root(static_cast<std::uint16_t>(i));
      if (root_to_group[root] == UINT16_MAX) {
        root_to_group[root] = static_cast<std::uint16_t>(collected.size());
        collected.emplace_back();
      }
      collected[root_to_group[root]].push_back(static_cast<std::uint16_t>(i));
    }
    for (const std::vector<std::uint16_t>& group : collected) {
      members_.insert(members_.end(), group.begin(), group.end());
      group_offsets_.push_back(static_cast<std::uint32_t>(members_.size()));
    }
    frozen_ = true;
  }

  [[nodiscard]] bool frozen() const { return frozen_; }
  [[nodiscard]] std::size_t feature_count() const { return feature_count_; }
  [[nodiscard]] std::size_t group_count() const { return frozen_ ? group_offsets_.size() - 1 : 0; }

  [[nodiscard]] std::span<const std::uint16_t> group(std::size_t index) const {
    return std::span(members_).subspan(group_offsets_[index],
                                       group_offsets_[index + 1] - group_offsets_[index]);
  }

  void restore_groups(std::span<const std::uint16_t> members,
                      std::span<const std::uint32_t> offsets) {
    members_.assign(members.begin(), members.end());
    group_offsets_.assign(offsets.begin(), offsets.end());
    frozen_ = true;
  }

  [[nodiscard]] std::span<const std::uint16_t> members() const { return members_; }
  [[nodiscard]] std::span<const std::uint32_t> group_offsets() const { return group_offsets_; }

 private:
  [[nodiscard]] float correlation(std::size_t i, std::size_t j) const {
    const auto n = static_cast<double>(samples_);
    if (samples_ < 2) return 0.0F;
    const double covariance = n * products_[i * feature_count_ + j] - sums_[i] * sums_[j];
    const double variance_i = n * squared_sums_[i] - sums_[i] * sums_[i];
    const double variance_j = n * squared_sums_[j] - sums_[j] * sums_[j];
    const double denominator = std::sqrt(std::max(variance_i, 0.0) * std::max(variance_j, 0.0));
    if (denominator <= 0.0) return 0.0F;
    return static_cast<float>(covariance / denominator);
  }

  std::size_t feature_count_;
  std::size_t max_group_size_;
  std::uint64_t samples_ = 0;
  std::vector<double> sums_;
  std::vector<double> squared_sums_;
  std::vector<double> products_;
  std::vector<std::uint16_t> members_;
  std::vector<std::uint32_t> group_offsets_;
  bool frozen_ = false;
};

}  // namespace watchdog
