#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace wrela::diagnostics {

enum class Severity { Note, Warning, Error };

struct SourceLocation {
  std::string path;
  std::size_t line = 1;
  std::size_t column = 1;
};

struct Entry {
  Severity severity = Severity::Error;
  SourceLocation location;
  std::string message;

  [[nodiscard]] std::string format() const;
};

class Engine {
public:
  void report(Severity severity, SourceLocation location, std::string message);

  [[nodiscard]] bool hasErrors() const;
  [[nodiscard]] std::size_t errorCount() const;
  [[nodiscard]] const std::vector<Entry>& entries() const;

private:
  std::vector<Entry> entries_;
  std::size_t errorCount_ = 0;
};

std::string_view severityName(Severity severity);

} // namespace wrela::diagnostics
