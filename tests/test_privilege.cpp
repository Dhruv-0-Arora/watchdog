#include <doctest/doctest.h>
#include <unistd.h>

#include "platform/privilege.hpp"

namespace {

using watchdog::drop_privileges;
using watchdog::PrivilegeDrop;

TEST_CASE("dropping privileges is a silent no-op for an unprivileged user" *
          doctest::skip(::geteuid() == 0)) {
  const PrivilegeDrop result = drop_privileges();
  CHECK(!result.attempted);
  CHECK(!result.succeeded);
  CHECK(result.error.empty());
  CHECK(::geteuid() != 0);
}

}  // namespace
