#include "wrela/Diagnostics/Diagnostic.h"

#include <gtest/gtest.h>
#include <string_view>

TEST(DiagnosticEngineTest, CountsErrorsAndFormatsLocation) {
  wrela::diagnostics::Engine diagnostics;

  diagnostics.report(
      wrela::diagnostics::Severity::Error,
      wrela::diagnostics::SourceLocation{.path = "sample.wrela", .line = 3, .column = 14},
      "expected expression");

  EXPECT_TRUE(diagnostics.hasErrors());
  EXPECT_EQ(diagnostics.errorCount(), 1U);
  ASSERT_EQ(diagnostics.entries().size(), 1U);
  EXPECT_EQ(diagnostics.entries().front().format(),
            std::string_view("sample.wrela:3:14: error: expected expression"));
}
