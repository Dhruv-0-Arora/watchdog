#include <doctest/doctest.h>

#include <array>
#include <cmath>
#include <cstdint>
#include <vector>

#include "core/autoencoder.hpp"

namespace {

using watchdog::Autoencoder;

float next_unit(std::uint64_t& state) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return static_cast<float>(state >> 40) * 0x1.0p-24F;
}

TEST_CASE("hidden layer is three quarters of the input rounded up") {
  CHECK(Autoencoder::hidden_dim(1) == 1);
  CHECK(Autoencoder::hidden_dim(4) == 3);
  CHECK(Autoencoder::hidden_dim(10) == 8);
  CHECK(Autoencoder::parameter_count(10) == 2 * 8 * 10 + 8 + 10);
}

TEST_CASE("training on a repeated input drives its reconstruction error down") {
  std::vector<float> parameters(Autoencoder::parameter_count(8));
  Autoencoder autoencoder(8, parameters, Autoencoder::RandomInit{42});
  const std::array<float, 8> input{0.2F, 0.9F, 0.1F, 0.7F, 0.5F, 0.3F, 0.8F, 0.4F};
  const float initial_error = autoencoder.execute(input);
  for (int i = 0; i < 3'000; ++i) autoencoder.train(input, 0.1F);
  const float final_error = autoencoder.execute(input);
  CHECK(final_error < initial_error);
  CHECK(final_error < 0.05F);
}

TEST_CASE("analytic gradients match numerical differentiation") {
  constexpr std::size_t dim = 6;
  std::vector<float> parameters(Autoencoder::parameter_count(dim));
  Autoencoder reference(dim, parameters, Autoencoder::RandomInit{7});
  std::uint64_t state = 99;
  std::array<float, dim> input{};
  for (float& value : input) value = next_unit(state);

  const auto loss_of = [&](const std::vector<float>& candidate) {
    std::vector<float> copy = candidate;
    const Autoencoder probe(dim, copy, Autoencoder::FromExisting{});
    const float rmse = probe.execute(input);
    return rmse * rmse;
  };

  std::vector<float> before = parameters;
  const float learning_rate = 1.0F;
  reference.train(input, learning_rate);
  for (const std::size_t index :
       {std::size_t{0}, std::size_t{13}, std::size_t{40}, parameters.size() - 1}) {
    const float analytic_gradient = (before[index] - parameters[index]) / learning_rate;
    const float step = 1e-2F;
    std::vector<float> plus = before;
    std::vector<float> minus = before;
    plus[index] += step;
    minus[index] -= step;
    const float numerical_gradient = (loss_of(plus) - loss_of(minus)) / (2.0F * step);
    CHECK(analytic_gradient == doctest::Approx(numerical_gradient).epsilon(0.05).scale(1e-4));
  }
}

TEST_CASE("execute does not modify parameters") {
  std::vector<float> parameters(Autoencoder::parameter_count(5));
  const Autoencoder autoencoder(5, parameters, Autoencoder::RandomInit{3});
  const std::vector<float> snapshot = parameters;
  const std::array<float, 5> input{0.1F, 0.2F, 0.3F, 0.4F, 0.5F};
  CHECK(autoencoder.execute(input) >= 0.0F);
  CHECK(parameters == snapshot);
}

TEST_CASE("identical seeds produce identical models") {
  std::vector<float> first_params(Autoencoder::parameter_count(7));
  std::vector<float> second_params(Autoencoder::parameter_count(7));
  Autoencoder first(7, first_params, Autoencoder::RandomInit{11});
  Autoencoder second(7, second_params, Autoencoder::RandomInit{11});
  CHECK(first_params == second_params);
}

}  // namespace
