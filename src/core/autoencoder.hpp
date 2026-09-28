#pragma once

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <span>

namespace watchdog {

inline constexpr std::size_t max_autoencoder_dim = 128;

class Autoencoder {
 public:
  [[nodiscard]] static constexpr std::size_t hidden_dim(std::size_t input_dim) {
    return (3 * input_dim + 3) / 4;
  }

  [[nodiscard]] static constexpr std::size_t parameter_count(std::size_t input_dim) {
    const std::size_t hidden = hidden_dim(input_dim);
    return 2 * hidden * input_dim + hidden + input_dim;
  }

  struct RandomInit {
    std::uint64_t seed;
  };
  struct FromExisting {};

  Autoencoder(std::size_t input_dim, std::span<float> parameters, RandomInit init)
      : Autoencoder(input_dim, parameters, FromExisting{}) {
    std::uint64_t state = init.seed | 1;
    const float scale = 1.0F / std::sqrt(static_cast<float>(input_dim));
    for (float& parameter : parameters) {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      const float uniform = static_cast<float>(state >> 40) * 0x1.0p-24F;
      parameter = (2.0F * uniform - 1.0F) * scale;
    }
  }

  Autoencoder(std::size_t input_dim, std::span<float> parameters, FromExisting)
      : input_dim_(input_dim), hidden_dim_(hidden_dim(input_dim)) {
    std::size_t offset = 0;
    const auto take = [&](std::size_t count) {
      const std::span<float> view = parameters.subspan(offset, count);
      offset += count;
      return view;
    };
    encode_weights_ = take(hidden_dim_ * input_dim_);
    encode_bias_ = take(hidden_dim_);
    decode_weights_ = take(input_dim_ * hidden_dim_);
    decode_bias_ = take(input_dim_);
  }

  [[nodiscard]] std::size_t input_dim() const { return input_dim_; }
  [[nodiscard]] std::size_t hidden_size() const { return hidden_dim_; }

  [[nodiscard]] float forward(std::span<const float> input, std::span<float> hidden,
                              std::span<float> output) const {
    activate(input, hidden, output);
    return rmse(input, output);
  }

  void backprop(std::span<const float> input, std::span<const float> hidden,
                std::span<const float> output, float learning_rate) {
    std::array<float, max_autoencoder_dim> output_delta;
    const float inverse_dim = 1.0F / static_cast<float>(input_dim_);
    for (std::size_t i = 0; i < input_dim_; ++i) {
      const float error = output[i] - input[i];
      output_delta[i] = 2.0F * inverse_dim * error * output[i] * (1.0F - output[i]);
    }

    std::array<float, max_autoencoder_dim> hidden_delta;
    for (std::size_t j = 0; j < hidden_dim_; ++j) {
      float back = 0.0F;
      for (std::size_t i = 0; i < input_dim_; ++i) {
        back += decode_weights_[i * hidden_dim_ + j] * output_delta[i];
      }
      hidden_delta[j] = back * hidden[j] * (1.0F - hidden[j]);
    }

    for (std::size_t i = 0; i < input_dim_; ++i) {
      const float step = learning_rate * output_delta[i];
      for (std::size_t j = 0; j < hidden_dim_; ++j) {
        decode_weights_[i * hidden_dim_ + j] -= step * hidden[j];
      }
      decode_bias_[i] -= step;
    }
    for (std::size_t j = 0; j < hidden_dim_; ++j) {
      const float step = learning_rate * hidden_delta[j];
      for (std::size_t i = 0; i < input_dim_; ++i) {
        encode_weights_[j * input_dim_ + i] -= step * input[i];
      }
      encode_bias_[j] -= step;
    }
  }

  [[nodiscard]] float execute(std::span<const float> input) const {
    std::array<float, max_autoencoder_dim> hidden;
    std::array<float, max_autoencoder_dim> output;
    return forward(input, hidden, output);
  }

  float train(std::span<const float> input, float learning_rate) {
    std::array<float, max_autoencoder_dim> hidden;
    std::array<float, max_autoencoder_dim> output;
    const float error = forward(input, hidden, output);
    backprop(input, std::span(hidden).first(hidden_dim_), std::span(output).first(input_dim_),
             learning_rate);
    return error;
  }

 private:
  static float sigmoid(float value) { return 1.0F / (1.0F + std::exp(-value)); }

  void activate(std::span<const float> input, std::span<float> hidden,
                std::span<float> output) const {
    for (std::size_t j = 0; j < hidden_dim_; ++j) {
      float sum = encode_bias_[j];
      for (std::size_t i = 0; i < input_dim_; ++i) {
        sum += encode_weights_[j * input_dim_ + i] * input[i];
      }
      hidden[j] = sigmoid(sum);
    }
    for (std::size_t i = 0; i < input_dim_; ++i) {
      float sum = decode_bias_[i];
      for (std::size_t j = 0; j < hidden_dim_; ++j) {
        sum += decode_weights_[i * hidden_dim_ + j] * hidden[j];
      }
      output[i] = sigmoid(sum);
    }
  }

  [[nodiscard]] float rmse(std::span<const float> input, std::span<const float> output) const {
    float sum = 0.0F;
    for (std::size_t i = 0; i < input_dim_; ++i) {
      const float error = output[i] - input[i];
      sum += error * error;
    }
    return std::sqrt(sum / static_cast<float>(input_dim_));
  }

  std::size_t input_dim_;
  std::size_t hidden_dim_;
  std::span<float> encode_weights_;
  std::span<float> encode_bias_;
  std::span<float> decode_weights_;
  std::span<float> decode_bias_;
};

}  // namespace watchdog
