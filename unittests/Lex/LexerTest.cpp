#include "wrela/Lex/Lexer.h"

#include <gtest/gtest.h>

#include <vector>

TEST(LexerTest, TokenizesFunctionSkeleton) {
  const auto tokens = wrela::lex::lexAll("fn main() -> i32 { return 42; }");

  const std::vector<wrela::lex::TokenKind> kinds = {
      wrela::lex::TokenKind::KwFn,    wrela::lex::TokenKind::Identifier,
      wrela::lex::TokenKind::LParen,  wrela::lex::TokenKind::RParen,
      wrela::lex::TokenKind::Arrow,   wrela::lex::TokenKind::Identifier,
      wrela::lex::TokenKind::LBrace,  wrela::lex::TokenKind::KwReturn,
      wrela::lex::TokenKind::Integer, wrela::lex::TokenKind::Semicolon,
      wrela::lex::TokenKind::RBrace,  wrela::lex::TokenKind::EndOfFile,
  };

  ASSERT_EQ(tokens.size(), kinds.size());
  for (std::size_t index = 0; index < kinds.size(); ++index) {
    EXPECT_EQ(tokens.at(index).kind, kinds.at(index)) << "token index " << index;
  }
  EXPECT_EQ(tokens.at(1).lexeme, "main");
  EXPECT_EQ(tokens.at(8).lexeme, "42");
}

TEST(LexerTest, PreservesUnknownCharactersForDiagnostics) {
  const auto tokens = wrela::lex::lexAll("@");

  ASSERT_GE(tokens.size(), 2U);
  EXPECT_EQ(tokens.at(0).kind, wrela::lex::TokenKind::Unknown);
  EXPECT_EQ(tokens.at(0).lexeme, "@");
  EXPECT_EQ(tokens.at(0).line, 1U);
  EXPECT_EQ(tokens.at(0).column, 1U);
}
