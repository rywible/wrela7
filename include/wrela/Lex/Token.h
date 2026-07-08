#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace wrela::lex {

enum class TokenKind {
  Identifier,
  Integer,
  KwFn,
  KwReturn,
  LParen,
  RParen,
  LBrace,
  RBrace,
  Arrow,
  Semicolon,
  Unknown,
  EndOfFile,
};

struct Token {
  TokenKind kind = TokenKind::Unknown;
  std::string lexeme;
  std::size_t line = 1;
  std::size_t column = 1;
};

std::string_view tokenKindName(TokenKind kind);

} // namespace wrela::lex
