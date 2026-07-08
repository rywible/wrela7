#include "wrela/Lex/Lexer.h"

#include <cctype>

namespace wrela::lex {

std::string_view tokenKindName(TokenKind kind) {
  switch (kind) {
  case TokenKind::Identifier:
    return "identifier";
  case TokenKind::Integer:
    return "integer";
  case TokenKind::KwFn:
    return "fn";
  case TokenKind::KwReturn:
    return "return";
  case TokenKind::LParen:
    return "(";
  case TokenKind::RParen:
    return ")";
  case TokenKind::LBrace:
    return "{";
  case TokenKind::RBrace:
    return "}";
  case TokenKind::Arrow:
    return "->";
  case TokenKind::Semicolon:
    return ";";
  case TokenKind::Unknown:
    return "unknown";
  case TokenKind::EndOfFile:
    return "eof";
  }
  return "unknown";
}

Lexer::Lexer(std::string_view input) : input_(input) {}

Token Lexer::next() {
  skipWhitespace();

  const std::size_t start = offset_;
  const std::size_t tokenColumn = column_;

  if (isAtEnd()) {
    return Token{.kind = TokenKind::EndOfFile, .lexeme = "", .line = line_, .column = column_};
  }

  const char current = advance();
  const auto unsignedCurrent = static_cast<unsigned char>(current);

  if (std::isalpha(unsignedCurrent) != 0 || current == '_') {
    return identifier(start, tokenColumn);
  }

  if (std::isdigit(unsignedCurrent) != 0) {
    return integer(start, tokenColumn);
  }

  switch (current) {
  case '(':
    return makeToken(TokenKind::LParen, start, tokenColumn);
  case ')':
    return makeToken(TokenKind::RParen, start, tokenColumn);
  case '{':
    return makeToken(TokenKind::LBrace, start, tokenColumn);
  case '}':
    return makeToken(TokenKind::RBrace, start, tokenColumn);
  case ';':
    return makeToken(TokenKind::Semicolon, start, tokenColumn);
  case '-':
    if (peek() == '>') {
      advance();
      return makeToken(TokenKind::Arrow, start, tokenColumn);
    }
    break;
  default:
    break;
  }

  return makeToken(TokenKind::Unknown, start, tokenColumn);
}

bool Lexer::isAtEnd() const { return offset_ >= input_.size(); }

char Lexer::peek() const {
  if (isAtEnd()) {
    return '\0';
  }
  return input_.at(offset_);
}

char Lexer::peekNext() const {
  const std::size_t nextOffset = offset_ + 1;
  if (nextOffset >= input_.size()) {
    return '\0';
  }
  return input_.at(nextOffset);
}

char Lexer::advance() {
  const char current = input_.at(offset_);
  ++offset_;
  if (current == '\n') {
    ++line_;
    column_ = 1;
  } else {
    ++column_;
  }
  return current;
}

void Lexer::skipWhitespace() {
  while (!isAtEnd()) {
    const char current = peek();
    if (current == ' ' || current == '\r' || current == '\t' || current == '\n') {
      advance();
      continue;
    }

    if (current == '/' && peekNext() == '/') {
      while (!isAtEnd() && peek() != '\n') {
        advance();
      }
      continue;
    }

    return;
  }
}

Token Lexer::makeToken(TokenKind kind, std::size_t start, std::size_t column) {
  return Token{
      .kind = kind,
      .lexeme = std::string(input_.substr(start, offset_ - start)),
      .line = line_,
      .column = column,
  };
}

Token Lexer::identifier(std::size_t start, std::size_t column) {
  while (!isAtEnd()) {
    const char current = peek();
    const auto unsignedCurrent = static_cast<unsigned char>(current);
    if (std::isalnum(unsignedCurrent) == 0 && current != '_') {
      break;
    }
    advance();
  }

  const std::string_view lexeme = input_.substr(start, offset_ - start);
  if (lexeme == "fn") {
    return makeToken(TokenKind::KwFn, start, column);
  }
  if (lexeme == "return") {
    return makeToken(TokenKind::KwReturn, start, column);
  }
  return makeToken(TokenKind::Identifier, start, column);
}

Token Lexer::integer(std::size_t start, std::size_t column) {
  while (!isAtEnd() && std::isdigit(static_cast<unsigned char>(peek())) != 0) {
    advance();
  }
  return makeToken(TokenKind::Integer, start, column);
}

std::vector<Token> lexAll(std::string_view input) {
  Lexer lexer(input);
  std::vector<Token> tokens;

  while (true) {
    Token token = lexer.next();
    const bool done = token.kind == TokenKind::EndOfFile;
    tokens.push_back(std::move(token));
    if (done) {
      break;
    }
  }

  return tokens;
}

} // namespace wrela::lex
