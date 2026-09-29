#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <span>
#include <type_traits>
#include <vector>

#include "core/autoencoder.hpp"
#include "core/mapper.hpp"
#include "core/quantile.hpp"

namespace watchdog {

class MinMaxNormalizer {
 public:
  explicit MinMaxNormalizer(std::size_t dimensions)
      : minimums_(dimensions, std::numeric_limits<float>::max()),
        maximums_(dimensions, std::numeric_limits<float>::lowest()) {}

  void observe(std::span<const float> values) {
    for (std::size_t i = 0; i < minimums_.size(); ++i) {
      minimums_[i] = std::min(minimums_[i], values[i]);
      maximums_[i] = std::max(maximums_[i], values[i]);
    }
  }

  // `limit` bounds how far outside the learned range a feature may read. Out-of-range is
  // the anomaly signal and must survive, so the bound is deliberately loose; it exists
  // only to keep one runaway feature from carrying the score to 1e7 and drowning the
  // quantile sketch that has to estimate a tail from it.
  void normalize(std::span<const float> values, std::span<float> out, float limit) const {
    for (std::size_t i = 0; i < minimums_.size(); ++i) {
      const float range = maximums_[i] - minimums_[i];
      const float scaled = range > 0.0F ? (values[i] - minimums_[i]) / range : 0.0F;
      out[i] = std::clamp(scaled, -limit, 1.0F + limit);
    }
  }

  [[nodiscard]] std::span<const float> minimums() const { return minimums_; }
  [[nodiscard]] std::span<const float> maximums() const { return maximums_; }

  void restore(std::span<const float> minimums, std::span<const float> maximums) {
    std::copy(minimums.begin(), minimums.end(), minimums_.begin());
    std::copy(maximums.begin(), maximums.end(), maximums_.begin());
  }

 private:
  std::vector<float> minimums_;
  std::vector<float> maximums_;
};

enum class ModelPhase : std::uint8_t { mapping, training, detecting };

struct ModelConfig {
  std::size_t max_group_size = 10;
  std::uint64_t mapping_packets = 100'000;
  std::uint64_t grace_packets = 1'000'000;
  std::uint64_t grace_min_duration_ns = 0;
  float train_learning_rate = 0.1F;
  float steady_learning_rate = 0.01F;
  // A five-marker P2 sketch cannot resolve a 1-in-100,000 quantile: markers 2, 3 and 4
  // all want position n, they move at most one rank per observation, and they only move
  // when a gap opens below the marker above. The estimate then reflects the order the
  // first few samples arrived in rather than the distribution, and replaying identical
  // traffic with different grace lengths moves the threshold by eight orders of
  // magnitude. 1-in-1000 is the tightest quantile this sketch actually resolves.
  double alert_quantile = 0.999;
  double alert_factor = 1.5;
  // Multiplier on the *alert threshold*, not on the raw quantile. Anything at or above
  // 1.0 means "learn from every packet that does not alert". A gate below the threshold
  // opens a band where traffic neither alerts nor trains, and once that band covers the
  // bulk of the distribution the detector deadlocks: no training keeps scores high, high
  // scores keep every observation capped, and capping pins the sketch's maximum marker so
  // the threshold can never rise back out.
  double train_gate_factor = 1.0;
  // Out-of-range features are the anomaly signal, so normalization does not clamp. It
  // does have to stay finite: an unclamped score reached 1.4e7 in replay, and log-scores
  // spanning eight decades leave the quantile sketch nothing to estimate. Ten times
  // outside the learned range is already unmistakable.
  float max_normalized_magnitude = 10.0F;
  std::uint64_t min_threshold_samples = 50'000;
  std::uint64_t seed = 0xC0FFEE;
};

struct ScoreResult {
  float score = 0.0F;
  float threshold = 0.0F;
  bool alert = false;
  ModelPhase phase = ModelPhase::mapping;
};

class KitNet {
 public:
  KitNet(std::size_t feature_count, const ModelConfig& config)
      : config_(config),
        feature_count_(feature_count),
        mapper_(feature_count, config.max_group_size),
        input_normalizer_(feature_count),
        log_score_quantile_(config.alert_quantile),
        normalized_(feature_count, 0.0F) {}

  ScoreResult process(std::span<const float> features, std::uint64_t timestamp_ns) {
    packets_ += 1;
    if (first_timestamp_ns_ == 0) first_timestamp_ns_ = timestamp_ns;
    switch (phase_) {
      case ModelPhase::mapping:
        input_normalizer_.observe(features);
        mapper_.accumulate(features);
        if (packets_ >= config_.mapping_packets) build_ensemble();
        return {0.0F, 0.0F, false, ModelPhase::mapping};
      case ModelPhase::training: {
        input_normalizer_.observe(features);
        const float score = forward_packet(features, true);
        backprop_packet(config_.train_learning_rate);
        if (grace_complete(timestamp_ns)) phase_ = ModelPhase::detecting;
        return {score, threshold(), false, ModelPhase::training};
      }
      case ModelPhase::detecting: {
        const float score = forward_packet(features, false);
        const float limit = threshold();
        const bool alert = threshold_ready() && score > limit;
        const bool trustworthy = !threshold_ready() || score < train_gate();
        if (trustworthy) {
          backprop_packet(config_.steady_learning_rate);
          log_score_quantile_.observe(log_score(score));
        } else {
          log_score_quantile_.observe_capped(log_score(score));
        }
        return {score, limit, alert, ModelPhase::detecting};
      }
    }
    return {};
  }

  [[nodiscard]] ModelPhase phase() const { return phase_; }
  [[nodiscard]] std::uint64_t packets() const { return packets_; }
  [[nodiscard]] std::size_t group_count() const { return mapper_.group_count(); }
  [[nodiscard]] float threshold() const {
    return std::exp(static_cast<float>(log_score_quantile_.value())) *
           static_cast<float>(config_.alert_factor);
  }
  [[nodiscard]] float train_gate() const {
    return threshold() * static_cast<float>(config_.train_gate_factor);
  }
  [[nodiscard]] bool threshold_ready() const {
    return log_score_quantile_.count() >= config_.min_threshold_samples;
  }
  [[nodiscard]] std::span<const float> group_errors() const { return rmse_normalized_; }
  [[nodiscard]] std::span<const std::uint16_t> group_members(std::size_t group) const {
    return mapper_.group(group);
  }

  [[nodiscard]] std::size_t serialized_size() const;
  bool serialize(std::span<std::byte> out) const;
  static std::unique_ptr<KitNet> deserialize(std::span<const std::byte> bytes);

 private:
  static float log_score(float score) { return std::log(std::max(score, 1e-9F)); }

  [[nodiscard]] bool grace_complete(std::uint64_t timestamp_ns) const {
    const bool enough_packets = packets_ >= config_.grace_packets;
    const bool enough_time = timestamp_ns - first_timestamp_ns_ >= config_.grace_min_duration_ns;
    return enough_packets && enough_time;
  }

  void build_ensemble() {
    mapper_.freeze();
    build_ensemble_from_groups();
    initialize_parameters();
    phase_ = ModelPhase::training;
  }

  void build_ensemble_from_groups() {
    const std::size_t groups = mapper_.group_count();
    std::size_t arena_size = Autoencoder::parameter_count(groups);
    for (std::size_t g = 0; g < groups; ++g) {
      arena_size += Autoencoder::parameter_count(mapper_.group(g).size());
    }
    arena_.assign(arena_size, 0.0F);
    ensemble_.clear();
    ensemble_.reserve(groups);
    std::size_t offset = 0;
    for (std::size_t g = 0; g < groups; ++g) {
      const std::size_t count = Autoencoder::parameter_count(mapper_.group(g).size());
      ensemble_.emplace_back(mapper_.group(g).size(), std::span(arena_).subspan(offset, count),
                             Autoencoder::FromExisting{});
      offset += count;
    }
    const std::size_t output_count = Autoencoder::parameter_count(groups);
    output_ = std::make_unique<Autoencoder>(groups, std::span(arena_).subspan(offset, output_count),
                                            Autoencoder::FromExisting{});
    rmse_normalizer_ = std::make_unique<MinMaxNormalizer>(groups);
    rmse_values_.assign(groups, 0.0F);
    rmse_normalized_.assign(groups, 0.0F);
    build_activation_layout();
  }

  void build_activation_layout() {
    const std::size_t groups = mapper_.group_count();
    permutation_.clear();
    permutation_.reserve(feature_count_);
    group_starts_.assign(groups, 0);
    activation_starts_.assign(groups, 0);
    std::size_t activation_size = 0;
    for (std::size_t g = 0; g < groups; ++g) {
      group_starts_[g] = permutation_.size();
      activation_starts_[g] = activation_size;
      const std::span<const std::uint16_t> members = mapper_.group(g);
      permutation_.insert(permutation_.end(), members.begin(), members.end());
      activation_size += ensemble_[g].hidden_size() + members.size();
    }
    output_activation_start_ = activation_size;
    activation_size += output_->hidden_size() + output_->input_dim();
    grouped_.assign(permutation_.size(), 0.0F);
    activations_.assign(activation_size, 0.0F);
  }

  void initialize_parameters() {
    std::size_t offset = 0;
    for (std::size_t g = 0; g < mapper_.group_count(); ++g) {
      const std::size_t count = Autoencoder::parameter_count(mapper_.group(g).size());
      Autoencoder(mapper_.group(g).size(), std::span(arena_).subspan(offset, count),
                  Autoencoder::RandomInit{config_.seed + g});
      offset += count;
    }
    Autoencoder(
        mapper_.group_count(),
        std::span(arena_).subspan(offset, Autoencoder::parameter_count(mapper_.group_count())),
        Autoencoder::RandomInit{config_.seed + mapper_.group_count()});
  }

  [[nodiscard]] std::span<float> group_input(std::size_t group) {
    return std::span(grouped_).subspan(group_starts_[group], mapper_.group(group).size());
  }

  [[nodiscard]] std::span<float> group_hidden(std::size_t group) {
    return std::span(activations_)
        .subspan(activation_starts_[group], ensemble_[group].hidden_size());
  }

  [[nodiscard]] std::span<float> group_output(std::size_t group) {
    return std::span(activations_)
        .subspan(activation_starts_[group] + ensemble_[group].hidden_size(),
                 ensemble_[group].input_dim());
  }

  float forward_packet(std::span<const float> features, bool update_normalizers) {
    input_normalizer_.normalize(features, normalized_, config_.max_normalized_magnitude);
    for (std::size_t k = 0; k < grouped_.size(); ++k) grouped_[k] = normalized_[permutation_[k]];
    for (std::size_t g = 0; g < ensemble_.size(); ++g) {
      rmse_values_[g] = ensemble_[g].forward(group_input(g), group_hidden(g), group_output(g));
    }
    if (update_normalizers) rmse_normalizer_->observe(rmse_values_);
    rmse_normalizer_->normalize(rmse_values_, rmse_normalized_, config_.max_normalized_magnitude);
    return output_->forward(rmse_normalized_, output_hidden(), output_output());
  }

  void backprop_packet(float learning_rate) {
    output_->backprop(rmse_normalized_, output_hidden(), output_output(), learning_rate);
    for (std::size_t g = 0; g < ensemble_.size(); ++g) {
      ensemble_[g].backprop(group_input(g), group_hidden(g), group_output(g), learning_rate);
    }
  }

  [[nodiscard]] std::span<float> output_hidden() {
    return std::span(activations_).subspan(output_activation_start_, output_->hidden_size());
  }

  [[nodiscard]] std::span<float> output_output() {
    return std::span(activations_)
        .subspan(output_activation_start_ + output_->hidden_size(), output_->input_dim());
  }

  ModelConfig config_;
  std::size_t feature_count_;
  ModelPhase phase_ = ModelPhase::mapping;
  std::uint64_t packets_ = 0;
  std::uint64_t first_timestamp_ns_ = 0;
  FeatureMapper mapper_;
  MinMaxNormalizer input_normalizer_;
  P2Quantile log_score_quantile_;
  std::vector<float> arena_;
  std::vector<Autoencoder> ensemble_;
  std::unique_ptr<Autoencoder> output_;
  std::unique_ptr<MinMaxNormalizer> rmse_normalizer_;
  std::vector<float> normalized_;
  std::vector<float> rmse_values_;
  std::vector<float> rmse_normalized_;
  std::vector<std::uint16_t> permutation_;
  std::vector<std::size_t> group_starts_;
  std::vector<std::size_t> activation_starts_;
  std::vector<float> grouped_;
  std::vector<float> activations_;
  std::size_t output_activation_start_ = 0;
};

namespace detail {

inline constexpr std::uint32_t checkpoint_magic = 0x5747444D;
// v2: added max_normalized_magnitude, and alert_quantile/train_gate_factor changed
// meaning. A v1 checkpoint carries a deadlocked quantile sketch, so it must not load.
inline constexpr std::uint32_t checkpoint_version = 2;

class ByteWriter {
 public:
  explicit ByteWriter(std::span<std::byte> out) : out_(out) {}

  template <typename T>
  void write(const T& value) {
    static_assert(std::is_trivially_copyable_v<T>);
    if (offset_ + sizeof value > out_.size()) {
      overflow_ = true;
      return;
    }
    std::memcpy(out_.data() + offset_, &value, sizeof value);
    offset_ += sizeof value;
  }

  template <typename T>
  void write_span(std::span<const T> values) {
    write(static_cast<std::uint64_t>(values.size()));
    const std::size_t bytes = values.size_bytes();
    if (offset_ + bytes > out_.size()) {
      overflow_ = true;
      return;
    }
    std::memcpy(out_.data() + offset_, values.data(), bytes);
    offset_ += bytes;
  }

  [[nodiscard]] bool ok() const { return !overflow_; }
  [[nodiscard]] std::size_t offset() const { return offset_; }

 private:
  std::span<std::byte> out_;
  std::size_t offset_ = 0;
  bool overflow_ = false;
};

class ByteReader {
 public:
  explicit ByteReader(std::span<const std::byte> in) : in_(in) {}

  template <typename T>
  bool read(T& value) {
    static_assert(std::is_trivially_copyable_v<T>);
    if (offset_ + sizeof value > in_.size()) return false;
    std::memcpy(&value, in_.data() + offset_, sizeof value);
    offset_ += sizeof value;
    return true;
  }

  template <typename T>
  bool read_vector(std::vector<T>& values, std::size_t max_count) {
    std::uint64_t count = 0;
    if (!read(count) || count > max_count) return false;
    const std::size_t bytes = static_cast<std::size_t>(count) * sizeof(T);
    if (offset_ + bytes > in_.size()) return false;
    values.resize(count);
    std::memcpy(values.data(), in_.data() + offset_, bytes);
    offset_ += bytes;
    return true;
  }

 private:
  std::span<const std::byte> in_;
  std::size_t offset_ = 0;
};

}  // namespace detail

inline std::size_t KitNet::serialized_size() const {
  if (phase_ == ModelPhase::mapping) return 0;
  const auto span_bytes = [](std::size_t count, std::size_t element_size) {
    return 8 + count * element_size;
  };
  const std::size_t groups = mapper_.group_count();
  const std::size_t header = 4 + 4 + 8;
  const std::size_t config = 5 * 8 + 2 * 4 + 3 * 8 + 4 + 8;
  const std::size_t counters = 1 + 8 + 8;
  const std::size_t group_data =
      span_bytes(mapper_.members().size(), 2) + span_bytes(mapper_.group_offsets().size(), 4);
  const std::size_t normalizers = 2 * span_bytes(feature_count_, 4) + 2 * span_bytes(groups, 4);
  const std::size_t arena = span_bytes(arena_.size(), 4);
  const std::size_t quantile = sizeof(P2Quantile::State);
  return header + config + counters + group_data + normalizers + arena + quantile;
}

inline bool KitNet::serialize(std::span<std::byte> out) const {
  if (phase_ == ModelPhase::mapping) return false;
  detail::ByteWriter writer(out);
  writer.write(detail::checkpoint_magic);
  writer.write(detail::checkpoint_version);
  writer.write(static_cast<std::uint64_t>(feature_count_));
  writer.write(config_.max_group_size);
  writer.write(config_.mapping_packets);
  writer.write(config_.grace_packets);
  writer.write(config_.grace_min_duration_ns);
  writer.write(config_.train_learning_rate);
  writer.write(config_.steady_learning_rate);
  writer.write(config_.alert_quantile);
  writer.write(config_.alert_factor);
  writer.write(config_.train_gate_factor);
  writer.write(config_.max_normalized_magnitude);
  writer.write(config_.min_threshold_samples);
  writer.write(config_.seed);
  writer.write(static_cast<std::uint8_t>(phase_));
  writer.write(packets_);
  writer.write(first_timestamp_ns_);
  writer.write_span(mapper_.members());
  writer.write_span(mapper_.group_offsets());
  writer.write_span(input_normalizer_.minimums());
  writer.write_span(input_normalizer_.maximums());
  writer.write_span(rmse_normalizer_->minimums());
  writer.write_span(rmse_normalizer_->maximums());
  writer.write_span(std::span<const float>(arena_));
  writer.write(log_score_quantile_.state());
  return writer.ok();
}

inline std::unique_ptr<KitNet> KitNet::deserialize(std::span<const std::byte> bytes) {
  detail::ByteReader reader(bytes);
  std::uint32_t magic = 0;
  std::uint32_t version = 0;
  std::uint64_t feature_count = 0;
  if (!reader.read(magic) || magic != detail::checkpoint_magic) return nullptr;
  if (!reader.read(version) || version != detail::checkpoint_version) return nullptr;
  if (!reader.read(feature_count) || feature_count == 0 || feature_count > 4096) return nullptr;
  ModelConfig config;
  std::uint8_t phase = 0;
  if (!reader.read(config.max_group_size) || !reader.read(config.mapping_packets) ||
      !reader.read(config.grace_packets) || !reader.read(config.grace_min_duration_ns) ||
      !reader.read(config.train_learning_rate) || !reader.read(config.steady_learning_rate) ||
      !reader.read(config.alert_quantile) || !reader.read(config.alert_factor) ||
      !reader.read(config.train_gate_factor) ||
      !reader.read(config.max_normalized_magnitude) ||
      !reader.read(config.min_threshold_samples) ||
      !reader.read(config.seed)) {
    return nullptr;
  }
  auto model = std::make_unique<KitNet>(feature_count, config);
  if (!reader.read(phase) || phase < 1 || phase > 2) return nullptr;
  if (!reader.read(model->packets_) || !reader.read(model->first_timestamp_ns_)) return nullptr;
  std::vector<std::uint16_t> members;
  std::vector<std::uint32_t> offsets;
  if (!reader.read_vector(members, feature_count)) return nullptr;
  if (!reader.read_vector(offsets, feature_count + 1)) return nullptr;
  if (members.size() != feature_count || offsets.size() < 2) return nullptr;
  model->mapper_.restore_groups(members, offsets);
  model->build_ensemble_from_groups();
  std::vector<float> minimums;
  std::vector<float> maximums;
  if (!reader.read_vector(minimums, feature_count) || minimums.size() != feature_count ||
      !reader.read_vector(maximums, feature_count) || maximums.size() != feature_count) {
    return nullptr;
  }
  model->input_normalizer_.restore(minimums, maximums);
  const std::size_t groups = model->mapper_.group_count();
  if (!reader.read_vector(minimums, groups) || minimums.size() != groups ||
      !reader.read_vector(maximums, groups) || maximums.size() != groups) {
    return nullptr;
  }
  model->rmse_normalizer_->restore(minimums, maximums);
  std::vector<float> arena;
  if (!reader.read_vector(arena, model->arena_.size()) || arena.size() != model->arena_.size()) {
    return nullptr;
  }
  std::copy(arena.begin(), arena.end(), model->arena_.begin());
  P2Quantile::State quantile_state;
  if (!reader.read(quantile_state)) return nullptr;
  model->log_score_quantile_.restore(quantile_state);
  model->phase_ = static_cast<ModelPhase>(phase);
  return model;
}

}  // namespace watchdog
