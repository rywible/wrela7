#pragma once

#include <string_view>

namespace wrela::version {

std::string_view projectName();
std::string_view versionString();
std::string_view fullVersionString();

} // namespace wrela::version
