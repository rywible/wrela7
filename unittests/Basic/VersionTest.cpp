#include "wrela/Basic/Version.h"

#include <gtest/gtest.h>
#include <string_view>

TEST(VersionTest, ExposesProjectIdentity) {
  EXPECT_EQ(wrela::version::projectName(), std::string_view("wrela"));
  EXPECT_EQ(wrela::version::versionString(), std::string_view("0.1.0"));
}
