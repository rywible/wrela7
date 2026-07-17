#include "lld/Common/Driver.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

LLD_HAS_DRIVER(coff)

extern "C" {

struct WrelaLldResult {
  std::int32_t status;
  std::uint8_t can_run_again;
  std::uint8_t reserved[3];
  std::size_t captured_bytes;
  std::size_t total_bytes;
};

}

namespace {

class BoundedStream final : public llvm::raw_ostream {
public:
  BoundedStream(char *buffer, std::size_t capacity) noexcept
      : buffer_(buffer), capacity_(capacity) {
    SetUnbuffered();
  }

  std::size_t capturedBytes() const noexcept { return captured_; }
  std::size_t totalBytes() const noexcept { return total_; }

private:
  void write_impl(const char *data, std::size_t bytes) override {
    const std::size_t available = capacity_ - captured_;
    const std::size_t copied = bytes < available ? bytes : available;
    if (copied != 0 && buffer_ != nullptr) {
      std::memcpy(buffer_ + captured_, data, copied);
      captured_ += copied;
    }
    if (bytes > std::numeric_limits<std::size_t>::max() - total_) {
      total_ = std::numeric_limits<std::size_t>::max();
    } else {
      total_ += bytes;
    }
  }

  std::uint64_t current_pos() const override {
    return static_cast<std::uint64_t>(total_);
  }

  char *buffer_;
  std::size_t capacity_;
  std::size_t captured_ = 0;
  std::size_t total_ = 0;
};

bool asciiCaseEqual(char actual, char expected_lowercase) noexcept {
  return actual == expected_lowercase ||
         actual == static_cast<char>(expected_lowercase - 'a' + 'A');
}

const char *directOutputPath(const char *const *arguments,
                             std::size_t argument_count) noexcept {
  const char *output_path = nullptr;
  for (std::size_t index = 0; index < argument_count; ++index) {
    const char *argument = arguments[index];
    if (argument == nullptr || std::strlen(argument) <= 5 ||
        (argument[0] != '/' && argument[0] != '-') ||
        !asciiCaseEqual(argument[1], 'o') ||
        !asciiCaseEqual(argument[2], 'u') ||
        !asciiCaseEqual(argument[3], 't') || argument[4] != ':' ||
        argument[5] == '\0') {
      continue;
    }
    if (output_path != nullptr) {
      return nullptr;
    }
    output_path = argument + 5;
  }
  return output_path;
}

// LLD marks PE executables as host-executable files on Unix. The PE execution
// contract lives in the authenticated image bytes, not in ambient host mode
// bits. Seal the direct output before reporting success so every caller,
// including standalone distribution smoke drivers, receives one private,
// non-executable regular file.
bool sealDirectOutput(const char *output_path,
                      BoundedStream &diagnostics) noexcept {
  const int descriptor = ::open(output_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    static constexpr char message[] =
        "cannot open successful LLD output without following links";
    diagnostics.write(message, sizeof(message) - 1);
    return false;
  }

  struct stat before {};
  struct stat after {};
  struct stat path_after {};
  const bool inspected = ::fstat(descriptor, &before) == 0 &&
                         S_ISREG(before.st_mode) && before.st_nlink == 1;
  const bool restricted =
      inspected && ::fchmod(descriptor, S_IRUSR | S_IWUSR) == 0;
  const bool verified =
      restricted && ::fstat(descriptor, &after) == 0 &&
      S_ISREG(after.st_mode) && after.st_nlink == 1 &&
      before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
      (after.st_mode &
       (S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX)) ==
          (S_IRUSR | S_IWUSR);
  const bool path_verified =
      verified && ::lstat(output_path, &path_after) == 0 &&
      S_ISREG(path_after.st_mode) && path_after.st_nlink == 1 &&
      path_after.st_dev == after.st_dev && path_after.st_ino == after.st_ino &&
      (path_after.st_mode &
       (S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX)) ==
          (S_IRUSR | S_IWUSR);
  const bool closed = ::close(descriptor) == 0;
  if (!path_verified || !closed) {
    static constexpr char message[] =
        "cannot seal successful LLD output as one private regular file";
    diagnostics.write(message, sizeof(message) - 1);
    return false;
  }
  return true;
}

} // namespace

extern "C" WrelaLldResult
wrela_lld_link_coff(const char *const *arguments, std::size_t argument_count,
                    char *diagnostics,
                    std::size_t diagnostic_capacity) noexcept {
  BoundedStream output(diagnostics, diagnostic_capacity);
  if (arguments == nullptr || argument_count == 0) {
    static constexpr char message[] = "invalid empty LLD argument vector";
    output.write(message, sizeof(message) - 1);
    return {-2, 1, {0, 0, 0}, output.capturedBytes(), output.totalBytes()};
  }
  const char *output_path = directOutputPath(arguments, argument_count);
  if (output_path == nullptr) {
    static constexpr char message[] =
        "LLD invocation requires exactly one direct /out: path";
    output.write(message, sizeof(message) - 1);
    output.flush();
    return {-2, 1, {0, 0, 0}, output.capturedBytes(), output.totalBytes()};
  }
  const lld::DriverDef driver{lld::WinLink, &lld::coff::link};
  const llvm::ArrayRef<const char *> args(arguments, argument_count);
  const llvm::ArrayRef<lld::DriverDef> drivers(&driver, 1);
  const lld::Result result = lld::lldMain(args, output, output, drivers);
  std::int32_t status = static_cast<std::int32_t>(result.retCode);
  if (status == 0 && !sealDirectOutput(output_path, output)) {
    status = -3;
  }
  output.flush();
  return {status,
          static_cast<std::uint8_t>(result.canRunAgain),
          {0, 0, 0},
          output.capturedBytes(),
          output.totalBytes()};
}
