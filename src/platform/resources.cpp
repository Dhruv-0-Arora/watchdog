#include "platform/resources.hpp"

#include <dirent.h>
#include <unistd.h>

#include <array>
#include <cstddef>
#include <memory>

#ifdef __APPLE__
#include <libproc.h>
#include <mach/mach.h>
#else
#include <cstdio>
#endif

namespace watchdog {

namespace {

struct DirectoryCloser {
  void operator()(DIR* directory) const { ::closedir(directory); }
};

std::size_t count_directory_entries(const char* path) {
  const std::unique_ptr<DIR, DirectoryCloser> directory(::opendir(path));
  if (!directory) return 0;
  std::size_t entries = 0;
  while (const dirent* entry = ::readdir(directory.get())) {
    if (entry->d_name[0] != '.') entries += 1;
  }
  return entries;
}

}  // namespace

#ifdef __APPLE__

std::size_t resident_bytes() {
  mach_task_basic_info info{};
  mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
  const kern_return_t status = task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                                         reinterpret_cast<task_info_t>(&info), &count);
  return status == KERN_SUCCESS ? static_cast<std::size_t>(info.resident_size) : 0;
}

std::size_t open_descriptor_count() {
  std::array<proc_fdinfo, 512> descriptors{};
  const int bytes = ::proc_pidinfo(::getpid(), PROC_PIDLISTFDS, 0, descriptors.data(),
                                   static_cast<int>(sizeof descriptors));
  if (bytes <= 0) return count_directory_entries("/dev/fd");
  return static_cast<std::size_t>(bytes) / sizeof(proc_fdinfo);
}

#else

std::size_t resident_bytes() {
  std::FILE* statm = std::fopen("/proc/self/statm", "r");
  if (statm == nullptr) return 0;
  unsigned long total_pages = 0;
  unsigned long resident_pages = 0;
  const int matched = std::fscanf(statm, "%lu %lu", &total_pages, &resident_pages);
  std::fclose(statm);
  if (matched != 2) return 0;
  return resident_pages * static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
}

std::size_t open_descriptor_count() { return count_directory_entries("/proc/self/fd"); }

#endif

}  // namespace watchdog
