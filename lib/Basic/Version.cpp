#include "wrela/Basic/Version.h"

#ifndef WRELA_VERSION
#define WRELA_VERSION "0.0.0"
#endif

namespace wrela::version {

std::string_view projectName() { return "wrela"; }

std::string_view versionString() { return WRELA_VERSION; }

std::string_view fullVersionString() { return "wrela " WRELA_VERSION; }

} // namespace wrela::version
