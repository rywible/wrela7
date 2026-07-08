#include "wrela/Source/SourceBuffer.h"

#include <fstream>
#include <sstream>
#include <utility>

namespace wrela::source {

SourceBuffer::SourceBuffer(std::string path, std::string text)
    : path_(std::move(path)), text_(std::move(text)) {}

std::string_view SourceBuffer::path() const { return path_; }

std::string_view SourceBuffer::text() const { return text_; }

LoadResult SourceBuffer::loadFile(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    return {"failed to read source file: " + path.string()};
  }

  std::ostringstream buffer;
  buffer << input.rdbuf();
  return {SourceBuffer(path.string(), buffer.str())};
}

LoadResult::LoadResult(SourceBuffer buffer) : hasValue_(true), buffer_(std::move(buffer)) {}

LoadResult::LoadResult(std::string error) : error_(std::move(error)) {}

bool LoadResult::has_value() const { return hasValue_; }

const SourceBuffer& LoadResult::value() const { return buffer_; }

const std::string& LoadResult::error() const { return error_; }

const SourceBuffer* LoadResult::operator->() const { return &buffer_; }

const SourceBuffer& LoadResult::operator*() const { return buffer_; }

} // namespace wrela::source
