#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "core/mapper.hpp"

namespace {

using watchdog::FeatureMapper;

float next_unit(std::uint64_t& state) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return static_cast<float>(state >> 40) * 0x1.0p-24F;
}

std::size_t group_of(const FeatureMapper& mapper, std::uint16_t feature) {
  for (std::size_t g = 0; g < mapper.group_count(); ++g) {
    for (const std::uint16_t member : mapper.group(g)) {
      if (member == feature) return g;
    }
  }
  return SIZE_MAX;
}

TEST_CASE("correlated features cluster together and independent ones apart") {
  FeatureMapper mapper(6, 3);
  std::uint64_t state = 2024;
  for (int sample = 0; sample < 5'000; ++sample) {
    const float shared_a = next_unit(state);
    const float shared_b = next_unit(state);
    const std::array<float, 6> features{
        shared_a, 0.8F * shared_a + 0.01F * next_unit(state), 1.0F - shared_a,
        shared_b, 0.5F * shared_b + 0.01F * next_unit(state), next_unit(state)};
    mapper.accumulate(features);
  }
  mapper.freeze();
  CHECK(mapper.group_count() >= 2);
  CHECK(group_of(mapper, 0) == group_of(mapper, 1));
  CHECK(group_of(mapper, 0) == group_of(mapper, 2));
  CHECK(group_of(mapper, 3) == group_of(mapper, 4));
  CHECK(group_of(mapper, 0) != group_of(mapper, 3));
  CHECK(group_of(mapper, 5) != group_of(mapper, 0));
}

TEST_CASE("no group exceeds the size cap and every feature is assigned once") {
  constexpr std::size_t feature_count = 115;
  constexpr std::size_t cap = 10;
  FeatureMapper mapper(feature_count, cap);
  std::uint64_t state = 5;
  std::array<float, feature_count> features{};
  for (int sample = 0; sample < 2'000; ++sample) {
    const float shared = next_unit(state);
    for (std::size_t i = 0; i < feature_count; ++i) {
      features[i] = (i % 3 == 0) ? shared : next_unit(state);
    }
    mapper.accumulate(features);
  }
  mapper.freeze();
  std::vector<int> seen(feature_count, 0);
  for (std::size_t g = 0; g < mapper.group_count(); ++g) {
    CHECK(mapper.group(g).size() <= cap);
    CHECK(mapper.group(g).size() >= 1);
    for (const std::uint16_t member : mapper.group(g)) seen[member] += 1;
  }
  for (const int count : seen) CHECK(count == 1);
}

TEST_CASE("constant features do not poison clustering") {
  FeatureMapper mapper(4, 2);
  std::uint64_t state = 31;
  for (int sample = 0; sample < 1'000; ++sample) {
    const float value = next_unit(state);
    const std::array<float, 4> features{value, value, 0.5F, 0.5F};
    mapper.accumulate(features);
  }
  mapper.freeze();
  CHECK(group_of(mapper, 0) == group_of(mapper, 1));
}

TEST_CASE("restored groups match the originals") {
  FeatureMapper original(8, 4);
  std::uint64_t state = 9;
  std::array<float, 8> features{};
  for (int sample = 0; sample < 500; ++sample) {
    for (float& value : features) value = next_unit(state);
    original.accumulate(features);
  }
  original.freeze();
  FeatureMapper restored(8, 4);
  restored.restore_groups(original.members(), original.group_offsets());
  CHECK(restored.group_count() == original.group_count());
  for (std::size_t g = 0; g < original.group_count(); ++g) {
    CHECK(std::vector(restored.group(g).begin(), restored.group(g).end()) ==
          std::vector(original.group(g).begin(), original.group(g).end()));
  }
}

}  // namespace
