#include "wrela/Diagnostics/Diagnostic.h"

#include <sstream>
#include <utility>

namespace wrela::diagnostics {

std::string_view severityName(Severity severity) {
  switch (severity) {
  case Severity::Note:
    return "note";
  case Severity::Warning:
    return "warning";
  case Severity::Error:
    return "error";
  }
  return "error";
}

std::string Entry::format() const {
  std::ostringstream out;
  out << location.path << ':' << location.line << ':' << location.column << ": "
      << severityName(severity) << ": " << message;
  return out.str();
}

void Engine::report(Severity severity, SourceLocation location, std::string message) {
  if (severity == Severity::Error) {
    ++errorCount_;
  }

  entries_.push_back(Entry{
      .severity = severity,
      .location = std::move(location),
      .message = std::move(message),
  });
}

bool Engine::hasErrors() const { return errorCount_ != 0; }

std::size_t Engine::errorCount() const { return errorCount_; }

const std::vector<Entry>& Engine::entries() const { return entries_; }

} // namespace wrela::diagnostics
