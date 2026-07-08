#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <utility>

namespace wrela::source {

class LoadResult;

class SourceBuffer {
public:
  SourceBuffer(std::string path, std::string text);

  [[nodiscard]] std::string_view path() const;
  [[nodiscard]] std::string_view text() const;

  static LoadResult loadFile(const std::filesystem::path& path);

private:
  std::string path_;
  std::string text_;
};

class LoadResult {
public:
  LoadResult(SourceBuffer buffer);
  LoadResult(std::string error);

  [[nodiscard]] bool has_value() const;
  [[nodiscard]] const SourceBuffer& value() const;
  [[nodiscard]] const std::string& error() const;

  [[nodiscard]] const SourceBuffer* operator->() const;
  [[nodiscard]] const SourceBuffer& operator*() const;

private:
  bool hasValue_ = false;
  SourceBuffer buffer_{"", ""};
  std::string error_;
};

} // namespace wrela::source
