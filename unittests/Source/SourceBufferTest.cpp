#include "wrela/Source/SourceBuffer.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string_view>

TEST(SourceBufferTest, LoadsAFileWithStablePathAndText) {
  const auto path = std::filesystem::temp_directory_path() / "wrela-source-buffer-test.wrela";
  {
    std::ofstream out(path);
    out << "fn main() -> i32 { return 42; }\n";
  }

  auto loaded = wrela::source::SourceBuffer::loadFile(path);

  ASSERT_TRUE(loaded.has_value()) << loaded.error();
  EXPECT_EQ(loaded->path(), path.string());
  EXPECT_EQ(loaded->text(), std::string_view("fn main() -> i32 { return 42; }\n"));
  std::filesystem::remove(path);
}

TEST(SourceBufferTest, ReportsMissingFiles) {
  auto loaded = wrela::source::SourceBuffer::loadFile("/tmp/wrela-definitely-missing.wrela");

  ASSERT_FALSE(loaded.has_value());
  EXPECT_NE(loaded.error().find("failed to read source file"), std::string_view::npos);
}
