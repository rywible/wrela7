#pragma once

#include "wrela/Lex/Token.h"

#include <string_view>
#include <vector>

namespace wrela::lex {

class Lexer {
public:
  explicit Lexer(std::string_view input);

  [[nodiscard]] Token next();

private:
  [[nodiscard]] bool isAtEnd() const;
  [[nodiscard]] char peek() const;
  [[nodiscard]] char peekNext() const;
  char advance();

  void skipWhitespace();
  [[nodiscard]] Token makeToken(TokenKind kind, std::size_t start, std::size_t column);
  [[nodiscard]] Token identifier(std::size_t start, std::size_t column);
  [[nodiscard]] Token integer(std::size_t start, std::size_t column);

  std::string_view input_;
  std::size_t offset_ = 0;
  std::size_t line_ = 1;
  std::size_t column_ = 1;
};

std::vector<Token> lexAll(std::string_view input);

} // namespace wrela::lex
