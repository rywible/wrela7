#include "wrela/Driver/Driver.h"

#include "wrela/Basic/Version.h"
#include "wrela/IR/MLIRSupport.h"
#include "wrela/Lex/Lexer.h"
#include "wrela/Source/SourceBuffer.h"

#include <iostream>
#include <span>
#include <string_view>

namespace wrela::driver {
namespace {

void printUsage(std::ostream& out) { out << "usage: wrela [--version] [check <file>]\n"; }

int checkFile(std::string_view path, std::ostream& out, std::ostream& err) {
  const auto loaded = source::SourceBuffer::loadFile(std::string(path));
  if (!loaded.has_value()) {
    err << loaded.error() << '\n';
    return 1;
  }

  const auto tokens = lex::lexAll(loaded->text());
  if (tokens.empty()) {
    err << "internal error: lexer produced no tokens\n";
    return 1;
  }

  static_cast<void>(ir::createEmptyModuleForTesting("check"));
  out << "ok\n";
  return 0;
}

} // namespace

int run(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
  if (args.empty()) {
    printUsage(out);
    return 0;
  }

  if (args.front() == "--version") {
    out << version::fullVersionString() << '\n';
    return 0;
  }

  if (args.front() == "--help" || args.front() == "-h") {
    printUsage(out);
    return 0;
  }

  if (args.front() == "check") {
    if (args.size() != 2) {
      err << "error: check expects exactly one input file\n";
      return 1;
    }
    return checkFile(args.back(), out, err);
  }

  err << "error: unknown command '" << args.front() << "'\n";
  printUsage(err);
  return 1;
}

} // namespace wrela::driver
