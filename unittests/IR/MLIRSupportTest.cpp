#include "wrela/IR/MLIRSupport.h"

#include <gtest/gtest.h>

TEST(MLIRSupportTest, CreatesAnEmptyModule) {
  const auto moduleText = wrela::ir::createEmptyModuleForTesting("unit");

  EXPECT_NE(moduleText.find("module"), std::string::npos);
}
