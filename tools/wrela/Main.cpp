#include "wrela/Driver/Driver.h"

#include <exception>
#include <iostream>
#include <string_view>
#include <vector>

int main(int argc, char** argv) {
  try {
    std::vector<std::string_view> args;
    args.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
    for (int index = 1; index < argc; ++index) {
      args.emplace_back(argv[index]);
    }

    return wrela::driver::run(args, std::cout, std::cerr);
  } catch (const std::exception& error) {
    std::cerr << "fatal: " << error.what() << '\n';
    return 1;
  }
}
