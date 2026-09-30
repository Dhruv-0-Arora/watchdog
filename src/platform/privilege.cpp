#include "platform/privilege.hpp"

#include <grp.h>
#include <pwd.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>

namespace watchdog {

namespace {

bool read_id(const char* variable, unsigned& value) {
  const char* text = std::getenv(variable);
  if (text == nullptr || *text == '\0') return false;
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(text, &end, 10);
  if (end == text || *end != '\0' || parsed == 0) return false;
  value = static_cast<unsigned>(parsed);
  return true;
}

}  // namespace

PrivilegeDrop drop_privileges() {
  PrivilegeDrop result;
  if (::geteuid() != 0) return result;
  unsigned target_uid = 0;
  unsigned target_gid = 0;
  if (!read_id("SUDO_UID", target_uid) || !read_id("SUDO_GID", target_gid)) {
    result.error = "running as root with no SUDO_UID to return to";
    return result;
  }
  result.attempted = true;
  const passwd* account = ::getpwuid(target_uid);
  result.account = account == nullptr ? std::to_string(target_uid) : account->pw_name;
  if (account != nullptr) ::initgroups(account->pw_name, static_cast<int>(target_gid));
  if (::setgid(static_cast<gid_t>(target_gid)) != 0) {
    result.error = std::string("setgid: ") + std::strerror(errno);
    return result;
  }
  if (::setuid(static_cast<uid_t>(target_uid)) != 0) {
    result.error = std::string("setuid: ") + std::strerror(errno);
    return result;
  }
  if (::setuid(0) == 0) {
    result.error = "root privileges could be regained after dropping them";
    return result;
  }
  result.succeeded = true;
  return result;
}

}  // namespace watchdog
