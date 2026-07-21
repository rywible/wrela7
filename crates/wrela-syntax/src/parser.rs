//! Production scanner and revision-0.1 parser vertical.

use unicode_ident::{is_xid_continue, is_xid_start};
use unicode_normalization::UnicodeNormalization;
use wrela_diagnostics::{Category, Diagnostic};
use wrela_source::{FileId, SourceFile, Span, TextRange};

use super::*;

/// Unicode data revision fixed by Wrela language revision 0.1.
pub const UNICODE_DATA_VERSION: &str = "16.0.0";

/// Maximum scanner/parser work units between cancellation polls.
pub const CANCELLATION_POLL_INTERVAL: u32 = 256;

/// The production revision-0.1 Wrela scanner/parser.
#[derive(Debug, Default, Clone, Copy)]
pub struct WrelaSyntaxParser;

impl WrelaSyntaxParser {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SyntaxParser for WrelaSyntaxParser {
    fn parse(
        &self,
        request: ParseRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ParseOutput, ParseFailure> {
        request.limits.validate()?;
        if is_cancelled() {
            return Err(ParseFailure::Cancelled);
        }
        let source = request
            .sources
            .get(request.file)
            .ok_or(ParseFailure::UnknownSource(request.file))?;
        let mut diagnostics = DiagnosticSink::new(source.id(), request.limits);
        let lexical =
            Scanner::new(source, request.limits, &mut diagnostics, is_cancelled).scan()?;
        let ast = {
            let mut parser = Parser::new(
                source,
                &lexical,
                request.limits,
                &mut diagnostics,
                is_cancelled,
            )?;
            parser.parse_file()?
        };
        let candidate = ParsedFileCandidate {
            file: source.id(),
            source_digest: source.digest(),
            lexical,
            ast,
            recovery_complete: true,
        };
        seal_parse_output(
            &request,
            candidate,
            diagnostics.into_diagnostics(),
            is_cancelled,
        )
    }

    fn parse_fragment(
        &self,
        request: FragmentParseRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<FragmentParseOutput, ParseFailure> {
        request.limits.validate()?;
        if is_cancelled() {
            return Err(ParseFailure::Cancelled);
        }
        let source = request
            .sources
            .get(request.parsed.file)
            .ok_or(ParseFailure::UnknownSource(request.parsed.file))?;
        if request.parsed.source_digest != source.digest() {
            return Err(ParseFailure::StaleOutput(request.parsed.file));
        }
        let (argument_meta, tokens) = match request.argument {
            BracketArgument::UnclassifiedTypeOrExpression { meta, tokens } => (*meta, *tokens),
            BracketArgument::BoundedCapacity { meta, .. } => {
                return Err(ParseFailure::InvalidFragmentRange {
                    first: meta.tokens.first.0,
                    end: meta.tokens.end.0,
                });
            }
            BracketArgument::Error(error) => {
                return Err(ParseFailure::InvalidFragmentRange {
                    first: error.meta.tokens.first.0,
                    end: error.meta.tokens.end.0,
                });
            }
        };
        let start = tokens.first.0 as usize;
        let end = tokens.end.0 as usize;
        let token_count = request.parsed.lexical.tokens.len();
        if start >= end || end >= token_count || argument_meta.tokens != tokens {
            return Err(ParseFailure::InvalidFragmentRange {
                first: tokens.first.0,
                end: tokens.end.0,
            });
        }
        if end - start > request.limits.tokens as usize {
            return Err(ParseFailure::ResourceLimit {
                resource: "fragment tokens",
                limit: u64::from(request.limits.tokens),
            });
        }
        let mut literal_bytes = 0u64;
        for token in &request.parsed.lexical.tokens[start..end] {
            if is_literal_token(token.kind) {
                let bytes = token.spelling.as_ref().map_or(0usize, String::len);
                literal_bytes = literal_bytes
                    .checked_add(
                        u64::try_from(bytes).map_err(|_| ParseFailure::ResourceLimit {
                            resource: "literal bytes",
                            limit: request.limits.literal_bytes,
                        })?,
                    )
                    .ok_or(ParseFailure::ResourceLimit {
                        resource: "literal bytes",
                        limit: request.limits.literal_bytes,
                    })?;
            }
        }
        if literal_bytes > request.limits.literal_bytes {
            return Err(ParseFailure::ResourceLimit {
                resource: "literal bytes",
                limit: request.limits.literal_bytes,
            });
        }
        let mut diagnostics = DiagnosticSink::new(source.id(), request.limits);
        let fragment = {
            let mut parser = Parser::new(
                source,
                &request.parsed.lexical,
                request.limits,
                &mut diagnostics,
                is_cancelled,
            )?;
            parser.position = start;
            parser.expression_end = Some(end);
            let fragment = match request.kind {
                FragmentKind::Type => SyntaxFragment::Type(parser.parse_type(1)?),
                FragmentKind::Expression => SyntaxFragment::Expression(parser.parse_expression(1)?),
            };
            if parser.position != end {
                let diagnostic_start = parser.current().span.range.start as usize;
                parser.diagnostics.error(
                    "syntax-fragment-trailing-tokens",
                    diagnostic_start,
                    parser.token_end(end),
                    "contextual syntax fragment was not consumed exactly".to_owned(),
                )?;
                while parser.position < end {
                    parser.bump()?;
                }
            }
            fragment
        };
        let meta = NodeMeta {
            id: AstId(0),
            span: argument_meta.span,
            tokens,
        };
        seal_fragment_output(
            &request,
            meta,
            fragment,
            diagnostics.into_diagnostics(),
            is_cancelled,
        )
    }
}

struct CancellationPoller<'a> {
    callback: &'a dyn Fn() -> bool,
    work: u32,
}

impl<'a> CancellationPoller<'a> {
    fn new(callback: &'a dyn Fn() -> bool) -> Self {
        Self { callback, work: 0 }
    }

    fn work(&mut self) -> Result<(), ParseFailure> {
        self.work += 1;
        if self.work == CANCELLATION_POLL_INTERVAL {
            self.work = 0;
            if (self.callback)() {
                return Err(ParseFailure::Cancelled);
            }
        }
        Ok(())
    }

    fn checkpoint(&self) -> Result<(), ParseFailure> {
        if (self.callback)() {
            Err(ParseFailure::Cancelled)
        } else {
            Ok(())
        }
    }
}

struct DiagnosticSink {
    file: FileId,
    limits: ParseLimits,
    bytes: u64,
    diagnostics: Vec<Diagnostic>,
}

impl DiagnosticSink {
    fn new(file: FileId, limits: ParseLimits) -> Self {
        Self {
            file,
            limits,
            bytes: 0,
            diagnostics: Vec::new(),
        }
    }

    fn error(
        &mut self,
        code: &'static str,
        start: usize,
        end: usize,
        message: String,
    ) -> Result<(), ParseFailure> {
        if self.diagnostics.len() >= self.limits.diagnostics as usize {
            return Err(ParseFailure::ResourceLimit {
                resource: "diagnostics",
                limit: u64::from(self.limits.diagnostics),
            });
        }
        let added =
            u64::try_from(code.len() + message.len()).map_err(|_| ParseFailure::ResourceLimit {
                resource: "diagnostic bytes",
                limit: self.limits.diagnostic_bytes,
            })?;
        let next = self
            .bytes
            .checked_add(added)
            .ok_or(ParseFailure::ResourceLimit {
                resource: "diagnostic bytes",
                limit: self.limits.diagnostic_bytes,
            })?;
        if next > self.limits.diagnostic_bytes {
            return Err(ParseFailure::ResourceLimit {
                resource: "diagnostic bytes",
                limit: self.limits.diagnostic_bytes,
            });
        }
        self.diagnostics
            .try_reserve(1)
            .map_err(|_| ParseFailure::ResourceLimit {
                resource: "diagnostics",
                limit: u64::from(self.limits.diagnostics),
            })?;
        let mut diagnostic = Diagnostic::error(
            Category::SYNTAX,
            Span {
                file: self.file,
                range: TextRange {
                    start: start as u32,
                    end: end as u32,
                },
            },
            message,
        );
        diagnostic.code = Some(code.to_owned());
        self.bytes = next;
        self.diagnostics.push(diagnostic);
        Ok(())
    }

    fn into_diagnostics(self) -> Vec<Diagnostic> {
        self.diagnostics
    }
}

struct Scanner<'a, 'diag> {
    source: &'a SourceFile,
    text: &'a str,
    limits: ParseLimits,
    diagnostics: &'diag mut DiagnosticSink,
    cancellation: CancellationPoller<'a>,
    position: usize,
    at_line_start: bool,
    prepared_dedent_at: Option<usize>,
    hanging_header_at: Option<usize>,
    hanging_header_continuation: bool,
    indentation: Vec<usize>,
    delimiters: Vec<(char, usize)>,
    tokens: Vec<Token>,
    trivia: Vec<Trivia>,
    order: Vec<LexicalElement>,
    literal_bytes: u64,
    interpolation_depth: u32,
}

struct SignificantLine {
    indentation: usize,
    prefix_start: usize,
    prefix_end: usize,
    code_offset: Option<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MemberContext {
    /// A direct member of a `struct` declaration's own suite; the only
    /// context in which `init` may appear.
    TypeSuite,
    OtherType,
    Implementation,
}

impl<'a, 'diag> Scanner<'a, 'diag> {
    fn new(
        source: &'a SourceFile,
        limits: ParseLimits,
        diagnostics: &'diag mut DiagnosticSink,
        is_cancelled: &'a dyn Fn() -> bool,
    ) -> Self {
        Self {
            source,
            text: source.text(),
            limits,
            diagnostics,
            cancellation: CancellationPoller::new(is_cancelled),
            position: 0,
            at_line_start: true,
            prepared_dedent_at: None,
            hanging_header_at: None,
            hanging_header_continuation: false,
            indentation: vec![0],
            delimiters: Vec::new(),
            tokens: Vec::new(),
            trivia: Vec::new(),
            order: Vec::new(),
            literal_bytes: 0,
            interpolation_depth: 0,
        }
    }

    fn scan(mut self) -> Result<LosslessLexicalTable, ParseFailure> {
        self.preflight_forbidden_characters()?;
        while self.position < self.text.len() {
            self.cancellation.work()?;
            if self.at_line_start && self.scan_line_prefix()? {
                continue;
            }
            if self.position >= self.text.len() {
                break;
            }
            let start = self.position;
            let character = self.current_char()?;
            match character {
                ' ' | '\t' => self.scan_horizontal_space()?,
                '#' => self.scan_comment()?,
                '\n' => self.scan_newline(1)?,
                '\r' if self.remaining().starts_with("\r\n") => self.scan_newline(2)?,
                'b' if self.remaining().starts_with("b\"") => {
                    self.scan_quoted(TokenKind::ByteStringLiteral, 1, true, false)?;
                }
                'f' if self.remaining().starts_with("f\"") => {
                    self.scan_interpolated()?;
                }
                '\"' => self.scan_quoted(TokenKind::StringLiteral, 0, false, false)?,
                '\'' => self.scan_character_literal()?,
                '0'..='9' => self.scan_number()?,
                '_' => self.scan_identifier()?,
                value if is_xid_start(value) => self.scan_identifier()?,
                value if is_forbidden_raw_character(value) => {
                    self.position += value.len_utf8();
                    self.push_physical(TokenKind::Error, start, self.position, None, true)?;
                }
                _ => self.scan_punctuation_or_error()?,
            }
        }
        self.finish_layout()?;
        self.cancellation.checkpoint()?;
        Ok(LosslessLexicalTable {
            tokens: self.tokens,
            trivia: self.trivia,
            order: self.order,
        })
    }

    fn preflight_forbidden_characters(&mut self) -> Result<(), ParseFailure> {
        for (offset, character) in self.text.char_indices() {
            self.cancellation.work()?;
            if is_forbidden_raw_character(character) {
                self.diagnostics.error(
                    "syntax-forbidden-code-point",
                    offset,
                    offset + character.len_utf8(),
                    format!(
                        "raw Unicode code point U+{:04X} is forbidden; use an explicit escape inside strings or comments",
                        character as u32
                    ),
                )?;
            }
        }
        Ok(())
    }

    /// Returns true when the entire current physical line was trivia.
    fn scan_line_prefix(&mut self) -> Result<bool, ParseFailure> {
        let start = self.position;
        let mut indentation = 0usize;
        let mut first_tab = None;
        while let Some(byte) = self.text.as_bytes().get(self.position) {
            match *byte {
                b' ' => {
                    indentation += 1;
                    self.position += 1;
                }
                b'\t' => {
                    first_tab.get_or_insert(self.position);
                    indentation = (indentation / 4 + 1) * 4;
                    self.position += 1;
                }
                _ => break,
            }
        }
        if self.position > start {
            self.push_trivia(TriviaKind::Spaces, start, self.position)?;
        }
        if let Some(tab) = first_tab {
            self.diagnostics.error(
                "syntax-leading-tab",
                tab,
                tab + 1,
                "tabs are forbidden in leading indentation".to_owned(),
            )?;
        }
        if self.position == self.text.len() {
            return Ok(true);
        }
        if self.remaining().starts_with('\n') {
            let newline = self.position;
            self.position += 1;
            self.push_trivia(TriviaKind::BlankLine, newline, self.position)?;
            return Ok(true);
        }
        if self.remaining().starts_with("\r\n") {
            let newline = self.position;
            self.position += 2;
            self.push_trivia(TriviaKind::BlankLine, newline, self.position)?;
            return Ok(true);
        }
        if self.remaining().starts_with('#') {
            self.scan_comment()?;
            if self.position < self.text.len() {
                if self.remaining().starts_with("\r\n") {
                    let newline = self.position;
                    self.position += 2;
                    self.push_trivia(TriviaKind::BlankLine, newline, self.position)?;
                } else if self.remaining().starts_with('\n') {
                    let newline = self.position;
                    self.position += 1;
                    self.push_trivia(TriviaKind::BlankLine, newline, self.position)?;
                }
            }
            return Ok(true);
        }
        if self.hanging_header_at == Some(self.position) {
            self.hanging_header_at = None;
        } else if self.prepared_dedent_at == Some(self.position) {
            self.prepared_dedent_at = None;
        } else if self.delimiters.is_empty() {
            self.prepared_dedent_at = None;
            self.apply_indentation(indentation)?;
        }
        self.at_line_start = false;
        Ok(false)
    }

    fn apply_indentation(&mut self, indentation: usize) -> Result<(), ParseFailure> {
        let current = self.current_indentation()?;
        if indentation > current {
            if indentation != current + 4 {
                self.diagnostics.error(
                    "syntax-invalid-indentation",
                    self.position.saturating_sub(indentation),
                    self.position,
                    format!(
                        "indentation must increase by exactly four spaces from column {}",
                        current + 1
                    ),
                )?;
            }
            if self.indentation.len() as u32 >= self.limits.nesting_depth {
                return Err(ParseFailure::ResourceLimit {
                    resource: "scanner nesting depth",
                    limit: u64::from(self.limits.nesting_depth),
                });
            }
            self.indentation
                .try_reserve(1)
                .map_err(|_| ParseFailure::ResourceLimit {
                    resource: "scanner nesting depth",
                    limit: u64::from(self.limits.nesting_depth),
                })?;
            self.indentation.push(indentation);
            self.push_synthetic(TokenKind::Indent, self.position, None)?;
        } else if indentation < current {
            while self.indentation.len() > 1 && self.current_indentation()? > indentation {
                self.indentation.pop();
                self.push_synthetic(TokenKind::Dedent, self.position, None)?;
            }
            if self.current_indentation()? != indentation {
                self.diagnostics.error(
                    "syntax-inconsistent-dedent",
                    self.position.saturating_sub(indentation),
                    self.position,
                    "dedent does not match an earlier indentation level".to_owned(),
                )?;
            }
        }
        Ok(())
    }

    fn current_indentation(&self) -> Result<usize, ParseFailure> {
        self.indentation.last().copied().ok_or_else(|| {
            ParseFailure::InternalInvariant("scanner lost its root indentation".to_owned())
        })
    }

    fn scan_horizontal_space(&mut self) -> Result<(), ParseFailure> {
        let start = self.position;
        while matches!(self.text.as_bytes().get(self.position), Some(b' ' | b'\t')) {
            self.position += 1;
        }
        self.push_trivia(TriviaKind::Spaces, start, self.position)
    }

    fn scan_comment(&mut self) -> Result<(), ParseFailure> {
        let start = self.position;
        while self.position < self.text.len()
            && !matches!(self.text.as_bytes()[self.position], b'\n' | b'\r')
        {
            let character = self.current_char()?;
            self.position += character.len_utf8();
            self.cancellation.work()?;
        }
        self.push_trivia(TriviaKind::Comment, start, self.position)
    }

    fn scan_newline(&mut self, width: usize) -> Result<(), ParseFailure> {
        let start = self.position;
        let end = start + width;
        if self.delimiters.is_empty() {
            let next_line = self.next_significant_line(end)?;
            let current = self.current_indentation()?;
            let hanging_header = !self.hanging_header_continuation
                && next_line.indentation > current
                && next_line
                    .code_offset
                    .is_some_and(|offset| self.text.as_bytes()[offset..].starts_with(b"->"))
                && self.tokens.last().map(|token| token.kind)
                    == Some(TokenKind::Punctuation(Punctuation::RightParen))
                && self.current_line_starts_declaration_header()?;
            if hanging_header {
                self.position = end;
                self.push_trivia(TriviaKind::SuppressedPhysicalNewline, start, end)?;
                self.hanging_header_at = next_line.code_offset;
                self.hanging_header_continuation = true;
            } else if next_line.indentation < current {
                self.hanging_header_continuation = false;
                let mut closed_levels = 0usize;
                while self.indentation.len() > 1
                    && self.current_indentation()? > next_line.indentation
                {
                    self.indentation.pop();
                    closed_levels += 1;
                }
                if self.current_indentation()? != next_line.indentation {
                    self.diagnostics.error(
                        "syntax-inconsistent-dedent",
                        next_line.prefix_start,
                        next_line.prefix_end,
                        "dedent does not match an earlier indentation level".to_owned(),
                    )?;
                }
                for level in 0..closed_levels {
                    let position = if level == 0 { start } else { end };
                    self.push_synthetic(TokenKind::Dedent, position, None)?;
                    if level == 0 {
                        self.position = end;
                        self.push_physical(
                            TokenKind::Newline,
                            start,
                            end,
                            Some(NewlineOrigin::Physical),
                            false,
                        )?;
                    } else {
                        self.push_synthetic(
                            TokenKind::Newline,
                            end,
                            Some(NewlineOrigin::Physical),
                        )?;
                    }
                }
                self.prepared_dedent_at = next_line.code_offset;
            } else {
                self.hanging_header_continuation = false;
                self.position = end;
                self.push_physical(
                    TokenKind::Newline,
                    start,
                    end,
                    Some(NewlineOrigin::Physical),
                    false,
                )?;
            }
        } else {
            self.position = end;
            self.push_trivia(TriviaKind::SuppressedPhysicalNewline, start, end)?;
        }
        self.at_line_start = true;
        Ok(())
    }

    fn current_line_starts_declaration_header(&mut self) -> Result<bool, ParseFailure> {
        let mut start = self.tokens.len();
        while start > 0 {
            self.cancellation.work()?;
            if matches!(
                self.tokens[start - 1].kind,
                TokenKind::Newline | TokenKind::Indent | TokenKind::Dedent
            ) {
                break;
            }
            start -= 1;
        }
        if self.tokens.get(start).map(|token| token.kind) == Some(TokenKind::Keyword(Keyword::Pub))
        {
            start += 1;
        }
        let first = self.tokens.get(start).map(|token| token.kind);
        if matches!(
            first,
            Some(TokenKind::Keyword(
                Keyword::Projection | Keyword::Scope | Keyword::Fn | Keyword::Init
            ))
        ) {
            return Ok(true);
        }
        Ok(matches!(
            first,
            Some(TokenKind::Keyword(
                Keyword::Async | Keyword::Isr | Keyword::Comptime
            ))
        ) && self.tokens.get(start + 1).map(|token| token.kind)
            == Some(TokenKind::Keyword(Keyword::Fn)))
    }

    fn next_significant_line(
        &mut self,
        after_newline: usize,
    ) -> Result<SignificantLine, ParseFailure> {
        let bytes = self.text.as_bytes();
        let mut cursor = after_newline;
        loop {
            let prefix_start = cursor;
            let mut indentation = 0usize;
            while cursor < bytes.len() {
                self.cancellation.work()?;
                match bytes[cursor] {
                    b' ' => {
                        indentation += 1;
                        cursor += 1;
                    }
                    b'\t' => {
                        indentation = (indentation / 4 + 1) * 4;
                        cursor += 1;
                    }
                    _ => break,
                }
            }
            let prefix_end = cursor;
            if cursor == bytes.len() {
                return Ok(SignificantLine {
                    indentation: 0,
                    prefix_start,
                    prefix_end,
                    code_offset: None,
                });
            }
            if bytes[cursor] == b'\n' {
                cursor += 1;
                continue;
            }
            if bytes[cursor] == b'\r' && bytes.get(cursor + 1) == Some(&b'\n') {
                cursor += 2;
                continue;
            }
            if bytes[cursor] == b'#' {
                while cursor < bytes.len() && !matches!(bytes[cursor], b'\n' | b'\r') {
                    cursor += 1;
                    self.cancellation.work()?;
                }
                if cursor == bytes.len() {
                    return Ok(SignificantLine {
                        indentation: 0,
                        prefix_start,
                        prefix_end,
                        code_offset: None,
                    });
                }
                if bytes[cursor] == b'\r' && bytes.get(cursor + 1) == Some(&b'\n') {
                    cursor += 2;
                } else {
                    cursor += 1;
                }
                continue;
            }
            return Ok(SignificantLine {
                indentation,
                prefix_start,
                prefix_end,
                code_offset: Some(cursor),
            });
        }
    }

    fn scan_identifier(&mut self) -> Result<(), ParseFailure> {
        let start = self.position;
        let first = self.current_char()?;
        self.position += first.len_utf8();
        while self.position < self.text.len() {
            let character = self.current_char()?;
            if is_xid_continue(character) || character == '_' {
                self.position += character.len_utf8();
                self.cancellation.work()?;
            } else {
                break;
            }
        }
        let spelling = &self.text[start..self.position];
        if spelling != "_" && first == '_' {
            self.diagnostics.error(
                "syntax-invalid-identifier-start",
                start,
                start + 1,
                "an identifier must begin with a Unicode XID_Start character".to_owned(),
            )?;
        }
        if !spelling.chars().nfc().eq(spelling.chars()) {
            self.diagnostics.error(
                "syntax-non-nfc-identifier",
                start,
                self.position,
                "identifier spelling is not Unicode NFC".to_owned(),
            )?;
        }
        let kind = keyword(spelling).map_or(TokenKind::Identifier, TokenKind::Keyword);
        self.push_physical(
            kind,
            start,
            self.position,
            None,
            matches!(kind, TokenKind::Identifier),
        )
    }

    fn scan_number(&mut self) -> Result<(), ParseFailure> {
        let start = self.position;
        let bytes = self.text.as_bytes();
        let mut kind = TokenKind::IntegerLiteral;
        let mut digits_start = start;
        if bytes.get(start) == Some(&b'0') {
            if let Some(prefix) = bytes.get(start + 1) {
                let base = match *prefix {
                    b'x' | b'X' => 16,
                    b'o' | b'O' => 8,
                    b'b' | b'B' => 2,
                    _ => 10,
                };
                if base != 10 {
                    self.position += 2;
                    digits_start = self.position;
                    while self.position < bytes.len()
                        && (digit_value(bytes[self.position]).is_some_and(|value| value < base)
                            || bytes[self.position] == b'_')
                    {
                        self.position += 1;
                        self.cancellation.work()?;
                    }
                    self.validate_digit_run(digits_start, self.position, base)?;
                    return self.push_physical(kind, start, self.position, None, true);
                }
            }
        }
        while self.position < bytes.len()
            && (bytes[self.position].is_ascii_digit() || bytes[self.position] == b'_')
        {
            self.position += 1;
            self.cancellation.work()?;
        }
        self.validate_digit_run(digits_start, self.position, 10)?;
        if bytes.get(self.position) == Some(&b'.')
            && bytes.get(self.position + 1).is_some_and(u8::is_ascii_digit)
        {
            kind = TokenKind::FloatLiteral;
            self.position += 1;
            let fraction = self.position;
            while self.position < bytes.len()
                && (bytes[self.position].is_ascii_digit() || bytes[self.position] == b'_')
            {
                self.position += 1;
                self.cancellation.work()?;
            }
            self.validate_digit_run(fraction, self.position, 10)?;
        }
        if matches!(bytes.get(self.position), Some(b'e' | b'E')) {
            kind = TokenKind::FloatLiteral;
            self.position += 1;
            if matches!(bytes.get(self.position), Some(b'+' | b'-')) {
                self.position += 1;
            }
            let exponent = self.position;
            while self.position < bytes.len()
                && (bytes[self.position].is_ascii_digit() || bytes[self.position] == b'_')
            {
                self.position += 1;
                self.cancellation.work()?;
            }
            self.validate_digit_run(exponent, self.position, 10)?;
        }
        self.push_physical(kind, start, self.position, None, true)
    }

    fn validate_digit_run(
        &mut self,
        start: usize,
        end: usize,
        base: u8,
    ) -> Result<(), ParseFailure> {
        let bytes = self.text.as_bytes();
        let valid_digit = |byte: u8| digit_value(byte).is_some_and(|value| value < base);
        let valid = start < end
            && (start..end).all(|index| {
                let byte = bytes[index];
                valid_digit(byte)
                    || (byte == b'_'
                        && index > start
                        && index + 1 < end
                        && valid_digit(bytes[index - 1])
                        && valid_digit(bytes[index + 1]))
            });
        if !valid {
            self.diagnostics.error(
                "syntax-invalid-number",
                start,
                end,
                format!("numeric literal has an invalid base-{base} digit or underscore"),
            )?;
        }
        Ok(())
    }

    fn scan_interpolated(&mut self) -> Result<(), ParseFailure> {
        if self.interpolation_depth >= self.limits.nesting_depth {
            return Err(ParseFailure::ResourceLimit {
                resource: "scanner nesting depth",
                limit: u64::from(self.limits.nesting_depth),
            });
        }
        self.interpolation_depth += 1;
        let result = self.scan_interpolated_inner();
        self.interpolation_depth -= 1;
        result
    }

    fn scan_interpolated_inner(&mut self) -> Result<(), ParseFailure> {
        let literal_start = self.position;
        self.position += 2;
        self.push_physical(
            TokenKind::InterpolatedStringStart,
            literal_start,
            self.position,
            None,
            true,
        )?;
        let mut text_start = self.position;
        let mut terminated = false;
        while self.position < self.text.len() {
            self.cancellation.work()?;
            let character = self.current_char()?;
            if matches!(character, '\n' | '\r') {
                break;
            }
            if character == '"' {
                self.push_interpolation_text(text_start, self.position)?;
                let quote = self.position;
                self.position += 1;
                self.push_physical(
                    TokenKind::InterpolatedStringEnd,
                    quote,
                    self.position,
                    None,
                    true,
                )?;
                text_start = self.position;
                terminated = true;
                break;
            }
            if character == '\\' {
                self.scan_escape(false)?;
                continue;
            }
            if character == '{' {
                if self.remaining().starts_with("{{") {
                    self.position += 2;
                    continue;
                }
                self.push_interpolation_text(text_start, self.position)?;
                let opening = self.position;
                self.position += 1;
                self.push_physical(
                    TokenKind::Punctuation(Punctuation::LeftBrace),
                    opening,
                    self.position,
                    None,
                    false,
                )?;
                self.scan_interpolation_value(opening)?;
                text_start = self.position;
                continue;
            }
            if character == '}' && !self.remaining().starts_with("}}") {
                self.diagnostics.error(
                    "syntax-unmatched-interpolation-brace",
                    self.position,
                    self.position + 1,
                    "unmatched closing brace in interpolated string".to_owned(),
                )?;
            }
            if character == '}' && self.remaining().starts_with("}}") {
                self.position += 2;
            } else {
                self.position += character.len_utf8();
            }
        }
        self.push_interpolation_text(text_start, self.position)?;
        if !terminated {
            self.diagnostics.error(
                "syntax-unterminated-literal",
                literal_start,
                self.position,
                "literal is not terminated before the physical newline or end of file".to_owned(),
            )?;
        }
        Ok(())
    }

    fn push_interpolation_text(&mut self, start: usize, end: usize) -> Result<(), ParseFailure> {
        if start < end {
            self.push_physical(TokenKind::InterpolatedStringText, start, end, None, true)?;
        }
        Ok(())
    }

    fn scan_interpolation_value(&mut self, opening: usize) -> Result<(), ParseFailure> {
        let delimiter_base = self.delimiters.len();
        let expression_token_start = self.tokens.len();
        let mut base_pipe_count = 0u8;
        while self.position < self.text.len() {
            self.cancellation.work()?;
            let character = self.current_char()?;
            if matches!(character, '\n' | '\r') {
                break;
            }
            if self.delimiters.len() == delimiter_base && character == '}' {
                let closing = self.position;
                self.position += 1;
                self.push_physical(
                    TokenKind::Punctuation(Punctuation::RightBrace),
                    closing,
                    self.position,
                    None,
                    false,
                )?;
                return Ok(());
            }
            if self.delimiters.len() == delimiter_base
                && character == ':'
                && self.interpolation_colon_starts_format(expression_token_start, base_pipe_count)
            {
                let colon = self.position;
                self.position += 1;
                self.push_physical(
                    TokenKind::Punctuation(Punctuation::Colon),
                    colon,
                    self.position,
                    None,
                    false,
                )?;
                self.scan_interpolation_format(opening)?;
                return Ok(());
            }
            let token_count = self.tokens.len();
            self.scan_interpolation_expression_token(delimiter_base)?;
            if self.delimiters.len() == delimiter_base
                && self.tokens.len() > token_count
                && self.tokens.last().map(|token| token.kind)
                    == Some(TokenKind::Punctuation(Punctuation::Pipe))
            {
                base_pipe_count = (base_pipe_count + 1).min(2);
            }
        }
        self.delimiters.truncate(delimiter_base);
        self.diagnostics.error(
            "syntax-unmatched-interpolation-brace",
            opening,
            self.position,
            "interpolated string has an unmatched opening brace".to_owned(),
        )
    }

    fn interpolation_colon_starts_format(
        &self,
        expression_token_start: usize,
        base_pipe_count: u8,
    ) -> bool {
        let tokens = &self.tokens[expression_token_start..];
        let closure_prefix = match tokens.first().map(|token| token.kind) {
            Some(TokenKind::Punctuation(Punctuation::Pipe)) => true,
            Some(TokenKind::Keyword(Keyword::Take | Keyword::Async))
                if tokens.get(1).map(|token| token.kind)
                    == Some(TokenKind::Punctuation(Punctuation::Pipe)) =>
            {
                true
            }
            Some(TokenKind::Keyword(Keyword::Async))
                if tokens.get(1).map(|token| token.kind)
                    == Some(TokenKind::Keyword(Keyword::Take))
                    && tokens.get(2).map(|token| token.kind)
                        == Some(TokenKind::Punctuation(Punctuation::Pipe)) =>
            {
                true
            }
            _ => false,
        };
        !closure_prefix || base_pipe_count >= 2
    }

    fn scan_interpolation_format(&mut self, opening: usize) -> Result<(), ParseFailure> {
        let start = self.position;
        while self.position < self.text.len() {
            self.cancellation.work()?;
            let character = self.current_char()?;
            if character == '}' {
                break;
            }
            if matches!(character, '\n' | '\r' | '"') {
                break;
            }
            if character == '{' {
                self.diagnostics.error(
                    "syntax-interpolation-format-brace",
                    self.position,
                    self.position + 1,
                    "interpolation format specifications cannot contain braces".to_owned(),
                )?;
            }
            if !character.is_ascii() {
                self.diagnostics.error(
                    "syntax-interpolation-format-ascii",
                    self.position,
                    self.position + character.len_utf8(),
                    "interpolation format specifications must be ASCII".to_owned(),
                )?;
            }
            self.position += character.len_utf8();
        }
        if start == self.position {
            self.diagnostics.error(
                "syntax-empty-interpolation-format",
                start,
                start,
                "interpolation format specifications cannot be empty".to_owned(),
            )?;
        } else {
            self.push_physical(
                TokenKind::InterpolationFormat,
                start,
                self.position,
                None,
                true,
            )?;
        }
        if self.position < self.text.len() && self.current_char()? == '}' {
            let closing = self.position;
            self.position += 1;
            self.push_physical(
                TokenKind::Punctuation(Punctuation::RightBrace),
                closing,
                self.position,
                None,
                false,
            )?;
            Ok(())
        } else {
            self.diagnostics.error(
                "syntax-unmatched-interpolation-brace",
                opening,
                self.position,
                "interpolated string has an unmatched opening brace".to_owned(),
            )
        }
    }

    fn scan_interpolation_expression_token(
        &mut self,
        delimiter_base: usize,
    ) -> Result<(), ParseFailure> {
        let start = self.position;
        let character = self.current_char()?;
        if self.delimiters.len() == delimiter_base && matches!(character, ')' | ']') {
            self.position += 1;
            self.diagnostics.error(
                "syntax-unmatched-delimiter",
                start,
                self.position,
                format!("closing delimiter {character:?} has no matching opener"),
            )?;
            let punctuation = if character == ')' {
                Punctuation::RightParen
            } else {
                Punctuation::RightBracket
            };
            return self.push_physical(
                TokenKind::Punctuation(punctuation),
                start,
                self.position,
                None,
                false,
            );
        }
        match character {
            ' ' | '\t' => self.scan_horizontal_space(),
            '#' => self.scan_comment(),
            'b' if self.remaining().starts_with("b\"") => {
                self.scan_quoted(TokenKind::ByteStringLiteral, 1, true, false)
            }
            'f' if self.remaining().starts_with("f\"") => self.scan_interpolated(),
            '"' => self.scan_quoted(TokenKind::StringLiteral, 0, false, false),
            '\'' => self.scan_character_literal(),
            '0'..='9' => self.scan_number(),
            '_' => self.scan_identifier(),
            value if is_xid_start(value) => self.scan_identifier(),
            value if is_forbidden_raw_character(value) => {
                self.position += value.len_utf8();
                self.push_physical(TokenKind::Error, start, self.position, None, true)
            }
            _ => self.scan_punctuation_or_error(),
        }
    }

    fn scan_character_literal(&mut self) -> Result<(), ParseFailure> {
        self.scan_quoted(TokenKind::CharacterLiteral, 0, false, false)
    }

    fn scan_quoted(
        &mut self,
        kind: TokenKind,
        prefix_bytes: usize,
        byte_string: bool,
        interpolated: bool,
    ) -> Result<(), ParseFailure> {
        let start = self.position;
        let quote = if kind == TokenKind::CharacterLiteral {
            '\''
        } else {
            '\"'
        };
        self.position += prefix_bytes + 1;
        let mut decoded_scalars = 0usize;
        let mut interpolation_depth = 0u32;
        let mut terminated = false;
        while self.position < self.text.len() {
            self.cancellation.work()?;
            let character = self.current_char()?;
            if character == quote && interpolation_depth == 0 {
                self.position += character.len_utf8();
                terminated = true;
                break;
            }
            if matches!(character, '\n' | '\r') {
                break;
            }
            if character == '\\' {
                decoded_scalars += 1;
                self.scan_escape(byte_string)?;
                continue;
            }
            if interpolated {
                if character == '{' {
                    if self.remaining().starts_with("{{") {
                        self.position += 2;
                        decoded_scalars += 1;
                        continue;
                    }
                    interpolation_depth += 1;
                } else if character == '}' {
                    if self.remaining().starts_with("}}") && interpolation_depth == 0 {
                        self.position += 2;
                        decoded_scalars += 1;
                        continue;
                    }
                    if interpolation_depth == 0 {
                        self.diagnostics.error(
                            "syntax-unmatched-interpolation-brace",
                            self.position,
                            self.position + 1,
                            "unmatched closing brace in interpolated string".to_owned(),
                        )?;
                    } else {
                        interpolation_depth -= 1;
                    }
                }
            }
            if byte_string && !character.is_ascii() {
                self.diagnostics.error(
                    "syntax-non-ascii-byte-string",
                    self.position,
                    self.position + character.len_utf8(),
                    "byte strings permit only ASCII source characters and escapes".to_owned(),
                )?;
            }
            decoded_scalars += 1;
            self.position += character.len_utf8();
        }
        if !terminated {
            self.diagnostics.error(
                "syntax-unterminated-literal",
                start,
                self.position,
                "literal is not terminated before the physical newline or end of file".to_owned(),
            )?;
        }
        if interpolation_depth != 0 {
            self.diagnostics.error(
                "syntax-unmatched-interpolation-brace",
                start,
                self.position,
                "interpolated string has an unmatched opening brace".to_owned(),
            )?;
        }
        if kind == TokenKind::CharacterLiteral && decoded_scalars != 1 {
            self.diagnostics.error(
                "syntax-invalid-character-literal",
                start,
                self.position,
                "a character literal must decode to exactly one Unicode scalar".to_owned(),
            )?;
        }
        self.push_physical(kind, start, self.position, None, true)
    }

    fn scan_escape(&mut self, byte_string: bool) -> Result<(), ParseFailure> {
        let start = self.position;
        let decoded = decode_escape(self.text, start, byte_string);
        self.position = decoded.end;
        if let Some(diagnostic) = decoded.diagnostic {
            self.diagnostics.error(
                diagnostic.code,
                start,
                self.position,
                diagnostic.message.to_owned(),
            )?;
        }
        Ok(())
    }

    fn scan_punctuation_or_error(&mut self) -> Result<(), ParseFailure> {
        let start = self.position;
        let remaining = self.remaining();
        let multi = [
            (">>=", TokenKind::Operator(Operator::ShiftRightAssign)),
            ("<<=", TokenKind::Operator(Operator::ShiftLeftAssign)),
            ("..=", TokenKind::Operator(Operator::RangeInclusive)),
            ("->", TokenKind::Punctuation(Punctuation::Arrow)),
            ("==", TokenKind::Operator(Operator::Equal)),
            ("!=", TokenKind::Operator(Operator::NotEqual)),
            ("<=", TokenKind::Operator(Operator::LessEqual)),
            (">=", TokenKind::Operator(Operator::GreaterEqual)),
            ("+=", TokenKind::Operator(Operator::AddAssign)),
            ("-=", TokenKind::Operator(Operator::SubtractAssign)),
            ("*=", TokenKind::Operator(Operator::MultiplyAssign)),
            ("/=", TokenKind::Operator(Operator::DivideAssign)),
            ("%=", TokenKind::Operator(Operator::RemainderAssign)),
            ("&=", TokenKind::Operator(Operator::BitAndAssign)),
            ("|=", TokenKind::Operator(Operator::BitOrAssign)),
            ("^=", TokenKind::Operator(Operator::BitXorAssign)),
            ("<<", TokenKind::Operator(Operator::ShiftLeft)),
            (">>", TokenKind::Operator(Operator::ShiftRight)),
            ("+%", TokenKind::Operator(Operator::AddWrapping)),
            ("-%", TokenKind::Operator(Operator::SubtractWrapping)),
            ("*%", TokenKind::Operator(Operator::MultiplyWrapping)),
            ("..", TokenKind::Operator(Operator::Range)),
        ];
        if let Some((spelling, kind)) = multi
            .into_iter()
            .find(|(spelling, _)| remaining.starts_with(spelling))
        {
            self.position += spelling.len();
            return self.push_physical(kind, start, self.position, None, false);
        }
        let character = self.current_char()?;
        self.position += character.len_utf8();
        let kind = match character {
            '@' => TokenKind::Punctuation(Punctuation::At),
            '.' => TokenKind::Punctuation(Punctuation::Dot),
            ',' => TokenKind::Punctuation(Punctuation::Comma),
            ':' => TokenKind::Punctuation(Punctuation::Colon),
            ';' if self.delimiters.is_empty() => {
                return self.push_physical(
                    TokenKind::Newline,
                    start,
                    self.position,
                    Some(NewlineOrigin::Semicolon),
                    false,
                );
            }
            ';' => TokenKind::Punctuation(Punctuation::Semicolon),
            '(' => TokenKind::Punctuation(Punctuation::LeftParen),
            ')' => TokenKind::Punctuation(Punctuation::RightParen),
            '[' => TokenKind::Punctuation(Punctuation::LeftBracket),
            ']' => TokenKind::Punctuation(Punctuation::RightBracket),
            '{' => TokenKind::Punctuation(Punctuation::LeftBrace),
            '}' => TokenKind::Punctuation(Punctuation::RightBrace),
            '?' => TokenKind::Punctuation(Punctuation::Question),
            '|' => TokenKind::Punctuation(Punctuation::Pipe),
            '=' => TokenKind::Operator(Operator::Assign),
            '+' => TokenKind::Operator(Operator::Add),
            '-' => TokenKind::Operator(Operator::Subtract),
            '*' => TokenKind::Operator(Operator::Multiply),
            '/' => TokenKind::Operator(Operator::Divide),
            '%' => TokenKind::Operator(Operator::Remainder),
            '&' => TokenKind::Operator(Operator::BitAnd),
            '^' => TokenKind::Operator(Operator::BitXor),
            '<' => TokenKind::Operator(Operator::Less),
            '>' => TokenKind::Operator(Operator::Greater),
            '~' => TokenKind::Operator(Operator::BitNot),
            _ => {
                self.diagnostics.error(
                    "syntax-unexpected-character",
                    start,
                    self.position,
                    format!("unexpected source character U+{:04X}", character as u32),
                )?;
                TokenKind::Error
            }
        };
        self.update_delimiters(character, start)?;
        self.push_physical(
            kind,
            start,
            self.position,
            None,
            matches!(kind, TokenKind::Error),
        )
    }

    fn update_delimiters(&mut self, character: char, start: usize) -> Result<(), ParseFailure> {
        match character {
            '(' | '[' | '{' => {
                if self.delimiters.len() as u32 >= self.limits.nesting_depth {
                    return Err(ParseFailure::ResourceLimit {
                        resource: "scanner nesting depth",
                        limit: u64::from(self.limits.nesting_depth),
                    });
                }
                self.delimiters
                    .try_reserve(1)
                    .map_err(|_| ParseFailure::ResourceLimit {
                        resource: "scanner nesting depth",
                        limit: u64::from(self.limits.nesting_depth),
                    })?;
                self.delimiters.push((character, start));
            }
            ')' | ']' | '}' => {
                let expected = match character {
                    ')' => '(',
                    ']' => '[',
                    '}' => '{',
                    _ => {
                        return Err(ParseFailure::InternalInvariant(
                            "delimiter closer classification diverged".to_owned(),
                        ));
                    }
                };
                if self.delimiters.last().map(|value| value.0) == Some(expected) {
                    self.delimiters.pop();
                } else {
                    self.diagnostics.error(
                        "syntax-unmatched-delimiter",
                        start,
                        self.position,
                        format!("closing delimiter {character:?} has no matching opener"),
                    )?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn finish_layout(&mut self) -> Result<(), ParseFailure> {
        for (delimiter, start) in self.delimiters.clone() {
            self.diagnostics.error(
                "syntax-unclosed-delimiter",
                start,
                start + delimiter.len_utf8(),
                format!("opening delimiter {delimiter:?} is not closed"),
            )?;
        }
        let eof = self.text.len();
        if self.indentation.len() > 1 {
            while self.indentation.len() > 1 {
                self.indentation.pop();
                self.push_synthetic(TokenKind::Dedent, eof, None)?;
                self.push_synthetic(TokenKind::Newline, eof, Some(NewlineOrigin::EndOfFile))?;
            }
        } else if !matches!(
            self.tokens.last().map(|token| token.kind),
            Some(TokenKind::Newline)
        ) {
            self.push_synthetic(TokenKind::Newline, eof, Some(NewlineOrigin::EndOfFile))?;
        }
        self.push_synthetic(TokenKind::EndOfFile, eof, None)
    }

    fn push_physical(
        &mut self,
        kind: TokenKind,
        start: usize,
        end: usize,
        newline_origin: Option<NewlineOrigin>,
        spelling: bool,
    ) -> Result<(), ParseFailure> {
        self.check_token_capacity()?;
        let raw = if spelling {
            if is_literal_token(kind) {
                let length =
                    u64::try_from(end - start).map_err(|_| ParseFailure::ResourceLimit {
                        resource: "literal bytes",
                        limit: self.limits.literal_bytes,
                    })?;
                let next =
                    self.literal_bytes
                        .checked_add(length)
                        .ok_or(ParseFailure::ResourceLimit {
                            resource: "literal bytes",
                            limit: self.limits.literal_bytes,
                        })?;
                if next > self.limits.literal_bytes {
                    return Err(ParseFailure::ResourceLimit {
                        resource: "literal bytes",
                        limit: self.limits.literal_bytes,
                    });
                }
                self.literal_bytes = next;
            }
            Some(self.text[start..end].to_owned())
        } else {
            None
        };
        let id = TokenId(self.tokens.len() as u32);
        self.tokens.push(Token {
            id,
            kind,
            span: self.span(start, end),
            newline_origin,
            spelling: raw,
            synthetic: false,
        });
        self.order.push(LexicalElement::Token(id));
        Ok(())
    }

    fn push_synthetic(
        &mut self,
        kind: TokenKind,
        position: usize,
        newline_origin: Option<NewlineOrigin>,
    ) -> Result<(), ParseFailure> {
        self.check_token_capacity()?;
        let id = TokenId(self.tokens.len() as u32);
        self.tokens.push(Token {
            id,
            kind,
            span: self.span(position, position),
            newline_origin,
            spelling: None,
            synthetic: true,
        });
        self.order.push(LexicalElement::Token(id));
        Ok(())
    }

    fn check_token_capacity(&mut self) -> Result<(), ParseFailure> {
        if self.tokens.len() >= self.limits.tokens as usize {
            return Err(ParseFailure::ResourceLimit {
                resource: "tokens",
                limit: u64::from(self.limits.tokens),
            });
        }
        self.tokens
            .try_reserve(1)
            .map_err(|_| ParseFailure::ResourceLimit {
                resource: "tokens",
                limit: u64::from(self.limits.tokens),
            })?;
        self.order
            .try_reserve(1)
            .map_err(|_| ParseFailure::ResourceLimit {
                resource: "lexical elements",
                limit: u64::from(self.limits.tokens),
            })
    }

    fn push_trivia(
        &mut self,
        kind: TriviaKind,
        start: usize,
        end: usize,
    ) -> Result<(), ParseFailure> {
        debug_assert!(start < end);
        self.trivia
            .try_reserve(1)
            .map_err(|_| ParseFailure::ResourceLimit {
                resource: "lexical trivia",
                limit: u64::from(self.limits.tokens),
            })?;
        self.order
            .try_reserve(1)
            .map_err(|_| ParseFailure::ResourceLimit {
                resource: "lexical elements",
                limit: u64::from(self.limits.tokens),
            })?;
        let id = TriviaId(self.trivia.len() as u32);
        self.trivia.push(Trivia {
            id,
            kind,
            span: self.span(start, end),
        });
        self.order.push(LexicalElement::Trivia(id));
        Ok(())
    }

    fn span(&self, start: usize, end: usize) -> Span {
        Span {
            file: self.source.id(),
            range: TextRange {
                start: start as u32,
                end: end as u32,
            },
        }
    }

    fn current_char(&self) -> Result<char, ParseFailure> {
        self.remaining().chars().next().ok_or_else(|| {
            ParseFailure::InternalInvariant(
                "scanner requested a character at end of input".to_owned(),
            )
        })
    }

    fn remaining(&self) -> &str {
        &self.text[self.position..]
    }
}

fn digit_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum EscapeValue {
    Scalar(char),
    Byte(u8),
}

#[derive(Clone, Copy)]
struct EscapeDiagnostic {
    code: &'static str,
    message: &'static str,
}

struct DecodedEscape {
    end: usize,
    value: Option<EscapeValue>,
    diagnostic: Option<EscapeDiagnostic>,
}

fn decode_escape(text: &str, start: usize, byte_string: bool) -> DecodedEscape {
    let mut position = start.saturating_add(1).min(text.len());
    let Some(escaped) = text.get(position..).and_then(|tail| tail.chars().next()) else {
        return DecodedEscape {
            end: position,
            value: None,
            diagnostic: Some(EscapeDiagnostic {
                code: "syntax-invalid-escape",
                message: "incomplete escape sequence",
            }),
        };
    };
    position += escaped.len_utf8();
    let simple = match escaped {
        '\\' => Some('\\'),
        '"' => Some('"'),
        '\'' => Some('\''),
        'n' => Some('\n'),
        'r' => Some('\r'),
        't' => Some('\t'),
        '0' => Some('\0'),
        _ => None,
    };
    if let Some(value) = simple {
        return DecodedEscape {
            end: position,
            value: Some(if byte_string {
                EscapeValue::Byte(value as u8)
            } else {
                EscapeValue::Scalar(value)
            }),
            diagnostic: None,
        };
    }
    if escaped == 'x' && byte_string {
        let digits = position;
        for _ in 0..2 {
            if text
                .as_bytes()
                .get(position)
                .is_some_and(u8::is_ascii_hexdigit)
            {
                position += 1;
            }
        }
        let valid = position - digits == 2;
        let value = valid
            .then(|| u8::from_str_radix(&text[digits..position], 16).ok())
            .flatten()
            .map(EscapeValue::Byte);
        return DecodedEscape {
            end: position,
            value,
            diagnostic: (!valid).then_some(EscapeDiagnostic {
                code: "syntax-invalid-escape",
                message: "a byte escape must contain exactly two hexadecimal digits",
            }),
        };
    }
    if escaped == 'u' && !byte_string {
        if text.as_bytes().get(position) != Some(&b'{') {
            return DecodedEscape {
                end: position,
                value: None,
                diagnostic: Some(EscapeDiagnostic {
                    code: "syntax-invalid-unicode-escape",
                    message: "Unicode escape must use the form \\u{H...}",
                }),
            };
        }
        position += 1;
        let digits_start = position;
        while position < text.len()
            && text.as_bytes()[position].is_ascii_hexdigit()
            && position - digits_start < 7
        {
            position += 1;
        }
        let digits = &text[digits_start..position];
        let closed = text.as_bytes().get(position) == Some(&b'}');
        if closed {
            position += 1;
        }
        let scalar = u32::from_str_radix(digits, 16)
            .ok()
            .and_then(char::from_u32);
        let valid = !digits.is_empty() && digits.len() <= 6 && closed && scalar.is_some();
        return DecodedEscape {
            end: position,
            value: valid.then_some(scalar).flatten().map(EscapeValue::Scalar),
            diagnostic: (!valid).then_some(EscapeDiagnostic {
                code: "syntax-invalid-unicode-escape",
                message: "Unicode escape must contain one to six digits naming a scalar value",
            }),
        };
    }
    DecodedEscape {
        end: position,
        value: None,
        diagnostic: Some(EscapeDiagnostic {
            code: "syntax-invalid-escape",
            message: "escape is not part of Wrela revision 0.1",
        }),
    }
}

pub(super) fn decode_literal_spelling(
    kind: LiteralKind,
    spelling: &str,
    literal_bytes: u64,
    work: &mut dyn FnMut() -> Result<(), ParseFailure>,
) -> Result<LiteralValue, ParseFailure> {
    match kind {
        LiteralKind::Integer => Ok(LiteralValue::IntegerSpelling),
        LiteralKind::Float => Ok(LiteralValue::FloatSpelling),
        LiteralKind::Boolean => Ok(match spelling {
            "true" => LiteralValue::Boolean(true),
            "false" => LiteralValue::Boolean(false),
            _ => LiteralValue::Invalid,
        }),
        LiteralKind::Unit => Ok(if spelling == "unit" {
            LiteralValue::Unit
        } else {
            LiteralValue::Invalid
        }),
        LiteralKind::String => {
            let Some(body) = spelling
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
            else {
                return Ok(LiteralValue::Invalid);
            };
            Ok(decode_text_body(body, literal_bytes, work)?
                .map_or(LiteralValue::Invalid, LiteralValue::Text))
        }
        LiteralKind::ByteString => {
            let Some(body) = spelling
                .strip_prefix("b\"")
                .and_then(|value| value.strip_suffix('"'))
            else {
                return Ok(LiteralValue::Invalid);
            };
            Ok(decode_byte_body(body, literal_bytes, work)?
                .map_or(LiteralValue::Invalid, LiteralValue::Bytes))
        }
        LiteralKind::Character => {
            let Some(body) = spelling
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
            else {
                return Ok(LiteralValue::Invalid);
            };
            let Some(decoded) = decode_text_body(body, literal_bytes, work)? else {
                return Ok(LiteralValue::Invalid);
            };
            let mut scalars = decoded.chars();
            let Some(value) = scalars.next() else {
                return Ok(LiteralValue::Invalid);
            };
            Ok(if scalars.next().is_none() {
                LiteralValue::Character(value)
            } else {
                LiteralValue::Invalid
            })
        }
    }
}

fn decode_text_body(
    body: &str,
    literal_bytes: u64,
    work: &mut dyn FnMut() -> Result<(), ParseFailure>,
) -> Result<Option<String>, ParseFailure> {
    let mut decoded = String::new();
    decoded
        .try_reserve(body.len())
        .map_err(|_| ParseFailure::ResourceLimit {
            resource: "literal bytes",
            limit: literal_bytes,
        })?;
    let mut position = 0usize;
    let mut valid = true;
    while position < body.len() {
        work()?;
        let character = body[position..].chars().next().ok_or_else(|| {
            ParseFailure::InternalInvariant("literal cursor split UTF-8".to_owned())
        })?;
        if character == '\\' {
            let escape = decode_escape(body, position, false);
            match escape.value {
                Some(EscapeValue::Scalar(value)) if escape.diagnostic.is_none() => {
                    decoded.push(value);
                }
                _ => valid = false,
            }
            position = escape.end.max(position + 1);
        } else {
            decoded.push(character);
            position += character.len_utf8();
        }
    }
    Ok(valid.then_some(decoded))
}

fn decode_byte_body(
    body: &str,
    literal_bytes: u64,
    work: &mut dyn FnMut() -> Result<(), ParseFailure>,
) -> Result<Option<Vec<u8>>, ParseFailure> {
    let mut decoded = Vec::new();
    decoded
        .try_reserve(body.len())
        .map_err(|_| ParseFailure::ResourceLimit {
            resource: "literal bytes",
            limit: literal_bytes,
        })?;
    let mut position = 0usize;
    let mut valid = true;
    while position < body.len() {
        work()?;
        let character = body[position..].chars().next().ok_or_else(|| {
            ParseFailure::InternalInvariant("literal cursor split UTF-8".to_owned())
        })?;
        if character == '\\' {
            let escape = decode_escape(body, position, true);
            match escape.value {
                Some(EscapeValue::Byte(value)) if escape.diagnostic.is_none() => {
                    decoded.push(value);
                }
                _ => valid = false,
            }
            position = escape.end.max(position + 1);
        } else {
            if character.is_ascii() {
                decoded.push(character as u8);
            } else {
                valid = false;
            }
            position += character.len_utf8();
        }
    }
    Ok(valid.then_some(decoded))
}

fn is_literal_token(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::IntegerLiteral
            | TokenKind::FloatLiteral
            | TokenKind::StringLiteral
            | TokenKind::ByteStringLiteral
            | TokenKind::CharacterLiteral
            | TokenKind::InterpolatedStringStart
            | TokenKind::InterpolatedStringText
            | TokenKind::InterpolationFormat
            | TokenKind::InterpolatedStringEnd
    )
}

fn is_forbidden_raw_character(character: char) -> bool {
    let value = character as u32;
    matches!(
        value,
        0x00ad
            | 0x034f
            | 0x061c
            | 0x115f..=0x1160
            | 0x17b4..=0x17b5
            | 0x180b..=0x180f
            | 0x200b..=0x200f
            | 0x202a..=0x202e
            | 0x2060..=0x206f
            | 0x3164
            | 0xfe00..=0xfe0f
            | 0xfeff
            | 0xffa0
            | 0xfff0..=0xfff8
            | 0x1bca0..=0x1bca3
            | 0x1d173..=0x1d17a
            | 0xe0000..=0xe0fff
    )
}

fn keyword(spelling: &str) -> Option<Keyword> {
    Some(match spelling {
        "module" => Keyword::Module,
        "pub" => Keyword::Pub,
        "import" => Keyword::Import,
        "from" => Keyword::From,
        "as" => Keyword::As,
        "const" => Keyword::Const,
        "brand" => Keyword::Brand,
        "fn" => Keyword::Fn,
        "init" => Keyword::Init,
        "async" => Keyword::Async,
        "isr" => Keyword::Isr,
        "comptime" => Keyword::Comptime,
        "struct" => Keyword::Struct,
        "enum" => Keyword::Enum,
        "interface" => Keyword::Iface,
        "impl" => Keyword::Impl,
        "for" => Keyword::For,
        "projection" => Keyword::Projection,
        "scope" => Keyword::Scope,
        "implements" => Keyword::Implements,
        "deriving" => Keyword::Deriving,
        "region" => Keyword::Region,
        "view" => Keyword::View,
        "mut" => Keyword::Mut,
        "iso" => Keyword::Iso,
        "read" => Keyword::Read,
        "take" => Keyword::Take,
        "self" => Keyword::SelfValue,
        "if" => Keyword::If,
        "elif" => Keyword::Elif,
        "else" => Keyword::Else,
        "match" => Keyword::Match,
        "case" => Keyword::Case,
        "in" => Keyword::In,
        "not" => Keyword::Not,
        "while" => Keyword::While,
        "loop" => Keyword::Loop,
        "with" => Keyword::With,
        "enter" => Keyword::Enter,
        "abort" => Keyword::Abort,
        "exit" => Keyword::Exit,
        "shadow" => Keyword::Shadow,
        "return" => Keyword::Return,
        "break" => Keyword::Break,
        "continue" => Keyword::Continue,
        "pass" => Keyword::Pass,
        "assert" => Keyword::Assert,
        "send" => Keyword::Send,
        "try" => Keyword::Try,
        "yield" => Keyword::Yield,
        "await" => Keyword::Await,
        "copy" => Keyword::Copy,
        "true" => Keyword::True,
        "false" => Keyword::False,
        "unit" => Keyword::Unit,
        "or" => Keyword::Or,
        "and" => Keyword::And,
        "is" => Keyword::Is,
        _ => return None,
    })
}

struct Parser<'a, 'diag> {
    source: &'a SourceFile,
    lexical: &'a LosslessLexicalTable,
    eof: &'a Token,
    limits: ParseLimits,
    diagnostics: &'diag mut DiagnosticSink,
    cancellation: CancellationPoller<'a>,
    position: usize,
    /// An exclusive token boundary used by productions with a contextual
    /// expression terminator (currently the binding `as` in `with`).
    expression_end: Option<usize>,
    next_ast_id: u32,
}

impl<'a, 'diag> Parser<'a, 'diag> {
    fn new(
        source: &'a SourceFile,
        lexical: &'a LosslessLexicalTable,
        limits: ParseLimits,
        diagnostics: &'diag mut DiagnosticSink,
        is_cancelled: &'a dyn Fn() -> bool,
    ) -> Result<Self, ParseFailure> {
        let eof = lexical
            .tokens
            .last()
            .filter(|token| token.kind == TokenKind::EndOfFile)
            .ok_or_else(|| {
                ParseFailure::InternalInvariant(
                    "parser requires a lexical table ending in EOF".to_owned(),
                )
            })?;
        Ok(Self {
            source,
            lexical,
            eof,
            limits,
            diagnostics,
            cancellation: CancellationPoller::new(is_cancelled),
            position: 0,
            expression_end: None,
            next_ast_id: 1,
        })
    }

    fn parse_file(&mut self) -> Result<AstFile, ParseFailure> {
        if self.limits.ast_nodes < 1 {
            return Err(ParseFailure::ResourceLimit {
                resource: "AST nodes",
                limit: u64::from(self.limits.ast_nodes),
            });
        }
        self.cancellation.checkpoint()?;
        while self.at(TokenKind::Newline) {
            self.bump()?;
        }
        let mut recovery_nodes = Vec::new();
        let module = if self.at_keyword(Keyword::Module) {
            self.parse_module(2)?
        } else {
            self.error_here(
                "syntax-missing-module",
                "every Wrela source file must begin with a module declaration",
            )?;
            let recovery =
                self.recovery_error(self.position, self.position, "module declaration", 2)?;
            push_ast_value(&mut recovery_nodes, recovery, self.limits.ast_nodes)?;
            None
        };
        self.consume_required_line_end("syntax-expected-newline", "module declaration")?;

        let mut imports = Vec::new();
        loop {
            while self.at(TokenKind::Newline) {
                self.bump()?;
            }
            if self.starts_import() {
                if let Some(import) = self.parse_import(2)? {
                    push_ast_value(&mut imports, import, self.limits.ast_nodes)?;
                }
                self.consume_required_line_end("syntax-expected-newline", "import declaration")?;
            } else {
                break;
            }
        }

        let mut declarations = Vec::new();
        while !self.at(TokenKind::EndOfFile) {
            while self.at(TokenKind::Newline) || self.at(TokenKind::Dedent) {
                self.bump()?;
            }
            if self.at(TokenKind::EndOfFile) {
                break;
            }
            let declaration = self.parse_top_level(2)?;
            push_ast_value(&mut declarations, declaration, self.limits.ast_nodes)?;
            if self.at(TokenKind::Newline) {
                if self.current().newline_origin == Some(NewlineOrigin::Semicolon) {
                    self.error_here(
                        "syntax-semicolon-declaration",
                        "a semicolon cannot separate top-level declarations",
                    )?;
                }
                self.bump()?;
            } else if !self.at(TokenKind::EndOfFile) && !self.at(TokenKind::Dedent) {
                self.error_here(
                    "syntax-expected-newline",
                    "expected a logical newline after the top-level declaration",
                )?;
                self.recover_to_line_end()?;
            }
        }
        while !self.at(TokenKind::EndOfFile) {
            self.bump()?;
        }
        if self.at(TokenKind::EndOfFile) {
            self.bump()?;
        }
        self.cancellation.checkpoint()?;
        Ok(AstFile {
            meta: NodeMeta {
                id: AstId(0),
                span: self.source.full_span(),
                tokens: TokenRange {
                    first: TokenId(0),
                    end: TokenId(self.lexical.tokens.len() as u32),
                },
            },
            module,
            imports,
            declarations,
            recovery_nodes,
        })
    }

    fn parse_module(&mut self, depth: u32) -> Result<Option<ModuleDeclaration>, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        self.bump()?;
        let Some(path) = self.parse_qualified_name(depth + 1, false)? else {
            self.error_here(
                "syntax-expected-module-path",
                "expected a dotted identifier path after `module`",
            )?;
            self.recover_to_line_end()?;
            return Ok(None);
        };
        let meta = self.meta(start, self.position)?;
        Ok(Some(ModuleDeclaration { meta, path }))
    }

    fn starts_import(&self) -> bool {
        self.at_keyword(Keyword::Import)
            || self.at_keyword(Keyword::From)
            || (self.at_keyword(Keyword::Pub)
                && matches!(
                    self.nth_kind(1),
                    Some(TokenKind::Keyword(Keyword::Import | Keyword::From))
                ))
    }

    fn parse_import(&mut self, depth: u32) -> Result<Option<ImportDeclaration>, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        let public = self.eat_keyword(Keyword::Pub)?;
        if self.eat_keyword(Keyword::Import)? {
            let Some(path) = self.parse_qualified_name(depth + 1, false)? else {
                self.error_here(
                    "syntax-expected-import-path",
                    "expected a module path after `import`",
                )?;
                self.recover_to_line_end()?;
                return Ok(None);
            };
            let alias = if self.eat_keyword(Keyword::As)? {
                self.parse_identifier(depth + 1)?
            } else {
                None
            };
            let meta = self.meta(start, self.position)?;
            return Ok(Some(ImportDeclaration {
                meta,
                public,
                items: ImportItems::Module { path, alias },
            }));
        }
        if self.eat_keyword(Keyword::From)? {
            let Some(module) = self.parse_qualified_name(depth + 1, false)? else {
                self.error_here(
                    "syntax-expected-import-path",
                    "expected a module path after `from`",
                )?;
                self.recover_to_line_end()?;
                return Ok(None);
            };
            if !self.eat_keyword(Keyword::Import)? {
                self.error_here(
                    "syntax-expected-import-keyword",
                    "expected `import` after the source module path",
                )?;
            }
            let parenthesized = self.eat_punctuation(Punctuation::LeftParen)?;
            let mut names = Vec::new();
            while !(self.at(TokenKind::EndOfFile)
                || self.at(TokenKind::Newline)
                || parenthesized && self.at_punctuation(Punctuation::RightParen))
            {
                let name_start = self.position;
                let Some(name) = self.parse_identifier(depth + 2)? else {
                    self.error_here(
                        "syntax-expected-import-name",
                        "expected an imported identifier",
                    )?;
                    self.recover_list_item(parenthesized)?;
                    if self.eat_punctuation(Punctuation::Comma)? {
                        continue;
                    }
                    break;
                };
                let alias = if self.eat_keyword(Keyword::As)? {
                    self.parse_identifier(depth + 2)?
                } else {
                    None
                };
                let imported = ImportedName {
                    meta: self.meta(name_start, self.position)?,
                    name,
                    alias,
                };
                push_ast_value(&mut names, imported, self.limits.ast_nodes)?;
                if !self.eat_punctuation(Punctuation::Comma)? {
                    break;
                }
            }
            if parenthesized && !self.eat_punctuation(Punctuation::RightParen)? {
                self.error_here(
                    "syntax-unclosed-import-list",
                    "expected `)` to close the import list",
                )?;
            }
            if names.is_empty() && !parenthesized {
                self.error_here(
                    "syntax-empty-import-list",
                    "an unparenthesized from-import requires at least one name",
                )?;
            }
            let meta = self.meta(start, self.position)?;
            return Ok(Some(ImportDeclaration {
                meta,
                public,
                items: ImportItems::Names {
                    module,
                    names,
                    parenthesized,
                },
            }));
        }
        self.error_here("syntax-expected-import", "expected an import declaration")?;
        Ok(None)
    }

    fn parse_top_level(&mut self, depth: u32) -> Result<TopLevelDeclaration, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        let mut attributes = Vec::new();
        while self.at_punctuation(Punctuation::At) {
            if let Some(attribute) = self.parse_attribute(depth + 1)? {
                push_ast_value(&mut attributes, attribute, self.limits.ast_nodes)?;
            }
            self.consume_required_line_end("syntax-attribute-line", "attribute")?;
            while self.at(TokenKind::Newline) {
                self.bump()?;
            }
        }
        let public = self.eat_keyword(Keyword::Pub)?;
        let kind = if self.starts_removed_initializer_spelling() {
            let error_start = self.position;
            self.error_here(
                "syntax-removed-initializer-spelling",
                "`fn __init__` was removed; declare a struct initializer with `init`",
            )?;
            self.recover_to_line_end()?;
            Some(DeclarationKind::Error(self.recovery_error(
                error_start,
                self.position,
                "`init` struct initializer",
                depth + 1,
            )?))
        } else if self.starts_comptime_fn_spelling() {
            let error_start = self.position;
            self.error_here(
                "syntax-legacy-comptime-fn-color",
                "`comptime` before `fn` is a legacy spelling; functions are phase-neutral",
            )?;
            self.recover_to_line_end()?;
            Some(DeclarationKind::Error(self.recovery_error(
                error_start,
                self.position,
                "revision-0.1 declaration",
                depth + 1,
            )?))
        } else if self.starts_function() {
            self.parse_function(depth + 1, true)?
                .map(DeclarationKind::Function)
        } else if self.at_linear_struct() {
            self.parse_type_declaration(depth + 1, true, false)?
                .map(DeclarationKind::Structure)
        } else if self.at_copy_struct() {
            self.parse_type_declaration(depth + 1, false, true)?
                .map(DeclarationKind::Structure)
        } else {
            match self.kind() {
                TokenKind::Keyword(Keyword::Const) => self
                    .parse_constant_declaration(depth + 1)?
                    .map(DeclarationKind::Constant),
                TokenKind::Keyword(Keyword::Brand) => self
                    .parse_brand_declaration(depth + 1)?
                    .map(DeclarationKind::Brand),
                TokenKind::Keyword(Keyword::Struct) => self
                    .parse_type_declaration(depth + 1, false, false)?
                    .map(DeclarationKind::Structure),
                TokenKind::Keyword(Keyword::Enum) => self
                    .parse_enum_declaration(depth + 1)?
                    .map(DeclarationKind::Enumeration),
                TokenKind::Keyword(Keyword::Iface) => self
                    .parse_interface_declaration(depth + 1)?
                    .map(DeclarationKind::Interface),
                TokenKind::Keyword(Keyword::Impl) => Some(DeclarationKind::Implementation(
                    self.parse_implementation_declaration(depth + 1)?,
                )),
                TokenKind::Keyword(Keyword::Projection) => self
                    .parse_projection_declaration(depth + 1, true)?
                    .map(DeclarationKind::Projection),
                TokenKind::Keyword(Keyword::Scope) => self
                    .parse_scope_declaration(depth + 1)?
                    .map(DeclarationKind::Scope),
                TokenKind::Keyword(Keyword::Comptime)
                    if self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::If)) =>
                {
                    Some(DeclarationKind::ComptimeIf(
                        self.parse_comptime_top_if(depth + 1)?,
                    ))
                }
                _ => None,
            }
        };
        let kind = if let Some(kind) = kind {
            kind
        } else {
            let unsupported_start = self.position;
            let description = self.current_description();
            self.error_here(
                "syntax-unsupported-declaration",
                &format!("{description} does not begin a representable revision-0.1 declaration"),
            )?;
            self.recover_to_line_end()?;
            DeclarationKind::Error(self.recovery_error(
                unsupported_start,
                self.position,
                "revision-0.1 declaration",
                depth + 1,
            )?)
        };
        Ok(TopLevelDeclaration {
            meta: self.meta(start, self.position)?,
            attributes,
            public,
            kind,
        })
    }

    fn starts_function(&self) -> bool {
        self.at_keyword(Keyword::Fn)
            || (matches!(
                self.kind(),
                TokenKind::Keyword(Keyword::Async | Keyword::Isr | Keyword::Comptime)
            ) && self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::Fn)))
    }

    /// `linear` is a contextual keyword: it is only a modifier when it
    /// spells the current identifier token and is immediately followed by
    /// `struct`. Anywhere else `linear` remains an ordinary identifier.
    fn at_linear_struct(&self) -> bool {
        self.kind() == TokenKind::Identifier
            && self.token_text(self.position) == "linear"
            && self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::Struct))
    }

    /// `copy struct` uses the reserved `copy` keyword as a declaration modifier.
    fn at_copy_struct(&self) -> bool {
        self.at_keyword(Keyword::Copy)
            && self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::Struct))
    }

    /// `comptime fn` is a legacy color spelling: revision 0.1 has only
    /// `fn`/`async fn`/`isr fn`, and a plain `fn` is phase-neutral.
    fn starts_comptime_fn_spelling(&self) -> bool {
        self.at_keyword(Keyword::Comptime)
            && self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::Fn))
    }

    fn starts_removed_initializer_spelling(&self) -> bool {
        let mut offset = usize::from(matches!(
            self.kind(),
            TokenKind::Keyword(Keyword::Async | Keyword::Isr | Keyword::Comptime)
        ));
        if self.nth_kind(offset) != Some(TokenKind::Keyword(Keyword::Fn)) {
            return false;
        }
        offset += 1;
        self.lexical
            .tokens
            .get(self.position + offset)
            .is_some_and(|token| {
                token.kind == TokenKind::Identifier && token.spelling.as_deref() == Some("__init__")
            })
    }

    fn parse_attribute(&mut self, depth: u32) -> Result<Option<Attribute>, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        self.bump()?;
        let Some(name) = self.parse_qualified_name(depth + 1, false)? else {
            self.error_here(
                "syntax-expected-attribute-name",
                "expected a qualified attribute name after `@`",
            )?;
            self.recover_to_line_end()?;
            return Ok(None);
        };
        let mut arguments = Vec::new();
        if self.eat_punctuation(Punctuation::LeftParen)? {
            while !self.at_punctuation(Punctuation::RightParen)
                && !self.at(TokenKind::EndOfFile)
                && !self.at(TokenKind::Newline)
            {
                let argument_start = self.position;
                let named = self.at(TokenKind::Identifier)
                    && self.nth_kind(1) == Some(TokenKind::Operator(Operator::Assign));
                let argument_name = if named {
                    let name = self.parse_identifier(depth + 2)?;
                    self.bump()?;
                    name
                } else {
                    None
                };
                let value = self.parse_expression(depth + 2)?;
                let argument = AttributeArgument {
                    meta: self.meta(argument_start, self.position)?,
                    name: argument_name,
                    value,
                };
                push_ast_value(&mut arguments, argument, self.limits.ast_nodes)?;
                if !self.eat_punctuation(Punctuation::Comma)? {
                    break;
                }
            }
            if !self.eat_punctuation(Punctuation::RightParen)? {
                self.error_here(
                    "syntax-unclosed-attribute",
                    "expected `)` to close attribute arguments",
                )?;
            }
        }
        Ok(Some(Attribute {
            meta: self.meta(start, self.position)?,
            name,
            arguments,
        }))
    }

    fn parse_function(
        &mut self,
        depth: u32,
        body_required: bool,
    ) -> Result<Option<FunctionDeclaration>, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        let color = match self.kind() {
            TokenKind::Keyword(Keyword::Async) => {
                self.bump()?;
                FunctionColor::Async
            }
            TokenKind::Keyword(Keyword::Isr) => {
                self.bump()?;
                FunctionColor::Isr
            }
            _ => FunctionColor::Sync,
        };
        if !self.eat_keyword(Keyword::Fn)? {
            self.error_here("syntax-expected-fn", "expected `fn` after function color")?;
            return Ok(None);
        }
        let Some(name) = self.parse_identifier(depth + 1)? else {
            self.error_here(
                "syntax-expected-function-name",
                "expected an identifier after `fn`",
            )?;
            return Ok(None);
        };
        let generics = self.parse_generic_parameters(depth + 1)?;
        let mut parameters = Vec::new();
        if self.eat_punctuation(Punctuation::LeftParen)? {
            while !self.at_punctuation(Punctuation::RightParen)
                && !self.at(TokenKind::EndOfFile)
                && !self.at(TokenKind::Newline)
            {
                if let Some(parameter) = self.parse_parameter(depth + 1)? {
                    push_ast_value(&mut parameters, parameter, self.limits.ast_nodes)?;
                } else {
                    self.recover_list_item(true)?;
                }
                if !self.eat_punctuation(Punctuation::Comma)? {
                    break;
                }
            }
            if !self.eat_punctuation(Punctuation::RightParen)? {
                self.error_here(
                    "syntax-unclosed-parameters",
                    "expected `)` to close function parameters",
                )?;
            }
        } else {
            self.error_here(
                "syntax-expected-parameters",
                "expected `(` after the function name",
            )?;
        }
        let return_type = if self.eat_punctuation(Punctuation::Arrow)? {
            Some(self.parse_type(depth + 1)?)
        } else {
            None
        };
        let body = if body_required {
            if !self.eat_punctuation(Punctuation::Colon)? {
                self.error_here(
                    "syntax-expected-suite-colon",
                    "expected `:` before the function suite",
                )?;
            }
            Some(self.parse_suite(depth + 1)?)
        } else {
            None
        };
        Ok(Some(FunctionDeclaration {
            meta: self.meta(start, self.position)?,
            color,
            name,
            generics,
            parameters,
            return_type,
            body,
        }))
    }

    fn parse_constant_declaration(
        &mut self,
        depth: u32,
    ) -> Result<Option<ConstantDeclaration>, ParseFailure> {
        let start = self.position;
        self.bump()?;
        let Some(name) = self.parse_identifier(depth + 1)? else {
            self.error_here(
                "syntax-expected-constant-name",
                "expected an identifier after `const`",
            )?;
            return Ok(None);
        };
        let ty = if self.eat_punctuation(Punctuation::Colon)? {
            Some(self.parse_type(depth + 1)?)
        } else {
            None
        };
        if !self.eat_operator(Operator::Assign)? {
            self.error_here(
                "syntax-constant-assignment",
                "constant declarations require `=` before their value",
            )?;
        }
        let value = self.parse_expression(depth + 1)?;
        Ok(Some(ConstantDeclaration {
            meta: self.meta(start, self.position)?,
            name,
            ty,
            value,
        }))
    }

    fn parse_brand_declaration(
        &mut self,
        depth: u32,
    ) -> Result<Option<BrandDeclaration>, ParseFailure> {
        let start = self.position;
        self.bump()?;
        let Some(name) = self.parse_identifier(depth + 1)? else {
            self.error_here(
                "syntax-expected-brand-name",
                "expected an identifier after `brand`",
            )?;
            return Ok(None);
        };
        Ok(Some(BrandDeclaration {
            meta: self.meta(start, self.position)?,
            name,
        }))
    }

    fn parse_type_declaration(
        &mut self,
        depth: u32,
        linear: bool,
        copy: bool,
    ) -> Result<Option<TypeDeclaration>, ParseFailure> {
        let start = self.position;
        if linear || copy {
            self.bump()?; // consume `linear` identifier or `copy` keyword
        }
        self.bump()?; // consume `struct`
        let Some(name) = self.parse_identifier(depth + 1)? else {
            self.error_here(
                "syntax-expected-type-name",
                "expected a declaration name after `struct`",
            )?;
            return Ok(None);
        };
        let generics = self.parse_generic_parameters(depth + 1)?;
        let implements = if self.eat_keyword(Keyword::Implements)? {
            self.parse_type_list(depth + 1, Punctuation::Colon)?
        } else {
            Vec::new()
        };
        let deriving = self.parse_deriving_list(depth + 1)?;
        if !self.eat_punctuation(Punctuation::Colon)? {
            self.error_here(
                "syntax-expected-suite-colon",
                "expected `:` before the type declaration suite",
            )?;
        }
        self.enter_indented_declaration_suite("type declaration")?;
        let mut explicit_pass = false;
        let mut members = Vec::new();
        if self.at_keyword(Keyword::Pass) {
            explicit_pass = true;
            self.bump()?;
            if self.at(TokenKind::Newline) {
                self.bump()?;
            }
            if !self.at(TokenKind::Dedent) {
                self.error_here(
                    "syntax-pass-with-members",
                    "a struct suite containing `pass` cannot also declare members",
                )?;
            }
        }
        while !self.at(TokenKind::Dedent) && !self.at(TokenKind::EndOfFile) {
            while self.at(TokenKind::Newline) {
                self.bump()?;
            }
            if self.at(TokenKind::Dedent) || self.at(TokenKind::EndOfFile) {
                break;
            }
            let member = self.parse_member_declaration(depth + 1, MemberContext::TypeSuite)?;
            if matches!(member.kind, MemberKind::Initializer(_))
                && members.iter().any(|member: &MemberDeclaration| {
                    matches!(member.kind, MemberKind::Initializer(_))
                })
            {
                self.error_here(
                    "syntax-duplicate-initializer",
                    "a struct may declare exactly one direct `init` member",
                )?;
            }
            push_ast_value(&mut members, member, self.limits.ast_nodes)?;
            if self.at(TokenKind::Newline) {
                self.bump()?;
            }
        }
        if !explicit_pass && members.is_empty() {
            self.error_here(
                "syntax-empty-struct-suite",
                "struct declarations require members or an explicit `pass`",
            )?;
        }
        self.leave_indented_declaration_suite("type declaration")?;
        Ok(Some(TypeDeclaration {
            meta: self.meta(start, self.position)?,
            name,
            generics,
            implements,
            members,
            explicit_pass,
            linear,
            copy,
            deriving,
        }))
    }

    fn parse_deriving_list(&mut self, depth: u32) -> Result<Vec<Identifier>, ParseFailure> {
        self.check_depth(depth)?;
        if !self.eat_keyword(Keyword::Deriving)? {
            return Ok(Vec::new());
        }
        if !self.eat_punctuation(Punctuation::LeftParen)? {
            self.error_here(
                "syntax-expected-deriving-list",
                "expected `(` after `deriving`",
            )?;
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        while !self.at_punctuation(Punctuation::RightParen)
            && !self.at(TokenKind::EndOfFile)
            && !self.at(TokenKind::Newline)
        {
            let Some(name) = self.parse_identifier(depth + 1)? else {
                self.error_here(
                    "syntax-expected-deriving-name",
                    "expected a deriving trait name",
                )?;
                break;
            };
            push_ast_value(&mut names, name, self.limits.ast_nodes)?;
            if !self.eat_punctuation(Punctuation::Comma)? {
                break;
            }
        }
        if !self.eat_punctuation(Punctuation::RightParen)? {
            self.error_here(
                "syntax-unclosed-deriving-list",
                "expected `)` to close the deriving list",
            )?;
        }
        Ok(names)
    }

    fn parse_type_list(
        &mut self,
        depth: u32,
        terminator: Punctuation,
    ) -> Result<Vec<TypeExpression>, ParseFailure> {
        let mut types = Vec::new();
        loop {
            let ty = self.parse_type(depth + 1)?;
            push_ast_value(&mut types, ty, self.limits.ast_nodes)?;
            if !self.eat_punctuation(Punctuation::Comma)? {
                break;
            }
            if self.at_punctuation(terminator) {
                break;
            }
        }
        Ok(types)
    }

    fn parse_member_declaration(
        &mut self,
        depth: u32,
        context: MemberContext,
    ) -> Result<MemberDeclaration, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        let mut attributes = Vec::new();
        let mut inline_attribute = false;
        while self.at_punctuation(Punctuation::At) {
            if let Some(attribute) = self.parse_attribute(depth + 1)? {
                push_ast_value(&mut attributes, attribute, self.limits.ast_nodes)?;
            }
            if self.at(TokenKind::Newline) {
                self.bump()?;
                while self.at(TokenKind::Newline) {
                    self.bump()?;
                }
            } else {
                inline_attribute = true;
            }
        }
        let inline_attribute_before_public = inline_attribute;
        let public = self.eat_keyword(Keyword::Pub)?;
        if inline_attribute_before_public && public {
            self.error_here(
                "syntax-inline-attribute-order",
                "same-line field attributes must follow `pub`",
            )?;
        }
        while self.at_punctuation(Punctuation::At) {
            inline_attribute = true;
            if let Some(attribute) = self.parse_attribute(depth + 1)? {
                push_ast_value(&mut attributes, attribute, self.limits.ast_nodes)?;
            }
        }
        if inline_attribute && !self.at(TokenKind::Identifier) {
            self.error_here(
                "syntax-inline-attribute-target",
                "same-line member attributes are permitted only on fields",
            )?;
        }
        if context == MemberContext::Implementation && public {
            self.error_here(
                "syntax-implementation-member-pub",
                "implementation members cannot be marked `pub`",
            )?;
        }
        let implementation_rejects = context == MemberContext::Implementation
            && !self.starts_function()
            && !self.at_keyword(Keyword::Projection);
        let kind = if self.starts_removed_initializer_spelling() {
            let error_start = self.position;
            self.error_here(
                "syntax-removed-initializer-spelling",
                "`fn __init__` was removed; declare a struct initializer with `init`",
            )?;
            self.recover_to_line_end()?;
            Some(MemberKind::Error(self.recovery_error(
                error_start,
                self.position,
                "`init` struct initializer",
                depth + 1,
            )?))
        } else if self.starts_comptime_fn_spelling() {
            let error_start = self.position;
            self.error_here(
                "syntax-legacy-comptime-fn-color",
                "`comptime` before `fn` is a legacy spelling; functions are phase-neutral",
            )?;
            self.recover_to_line_end()?;
            Some(MemberKind::Error(self.recovery_error(
                error_start,
                self.position,
                "revision-0.1 declaration",
                depth + 1,
            )?))
        } else if self.at_keyword(Keyword::Init) {
            if context != MemberContext::TypeSuite {
                let error_start = self.position;
                self.error_here(
                    "syntax-initializer-context",
                    "`init` is permitted only as a direct struct member",
                )?;
                self.recover_to_line_end()?;
                Some(MemberKind::Error(self.recovery_error(
                    error_start,
                    self.position,
                    "struct initializer",
                    depth + 1,
                )?))
            } else {
                if !attributes.is_empty() {
                    self.error_here(
                        "syntax-initializer-attribute",
                        "attributes on `init` are not supported by revision 0.1",
                    )?;
                }
                if public {
                    self.error_here(
                        "syntax-initializer-visibility",
                        "struct initializers cannot be marked `pub`",
                    )?;
                }
                Some(MemberKind::Initializer(self.parse_initializer(depth + 1)?))
            }
        } else if implementation_rejects {
            let error_start = self.position;
            self.error_here(
                "syntax-implementation-member",
                "implementation suites permit only functions and projections",
            )?;
            self.recover_to_line_end()?;
            Some(MemberKind::Error(self.recovery_error(
                error_start,
                self.position,
                "implementation function or projection",
                depth + 1,
            )?))
        } else if self.starts_function() {
            self.parse_function(depth + 1, true)?
                .map(MemberKind::Function)
        } else {
            match self.kind() {
                TokenKind::Identifier => {
                    Some(MemberKind::Field(self.parse_field_declaration(depth + 1)?))
                }
                TokenKind::Keyword(Keyword::Const) => self
                    .parse_constant_declaration(depth + 1)?
                    .map(MemberKind::Constant),
                TokenKind::Keyword(Keyword::Projection) => self
                    .parse_projection_declaration(depth + 1, true)?
                    .map(MemberKind::Projection),
                TokenKind::Keyword(Keyword::Scope) => self
                    .parse_scope_declaration(depth + 1)?
                    .map(MemberKind::Scope),
                TokenKind::Keyword(Keyword::Comptime)
                    if self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::If)) =>
                {
                    Some(MemberKind::ComptimeIf(
                        self.parse_comptime_member_if(depth + 1)?,
                    ))
                }
                _ => None,
            }
        };
        let kind = if let Some(kind) = kind {
            kind
        } else {
            let error_start = self.position;
            self.error_here(
                "syntax-unsupported-member",
                "expected a field, function, projection, scope, constant, or comptime member",
            )?;
            self.recover_to_line_end()?;
            MemberKind::Error(self.recovery_error(
                error_start,
                self.position,
                "member declaration",
                depth + 1,
            )?)
        };
        Ok(MemberDeclaration {
            meta: self.meta(start, self.position)?,
            attributes,
            public,
            kind,
        })
    }

    fn parse_field_declaration(&mut self, depth: u32) -> Result<FieldDeclaration, ParseFailure> {
        let start = self.position;
        let name = self
            .parse_identifier(depth + 1)?
            .ok_or_else(|| ParseFailure::InternalInvariant("field lost its name".to_owned()))?;
        if !self.eat_punctuation(Punctuation::Colon)? {
            self.error_here("syntax-field-type", "field declarations require `: Type`")?;
        }
        let ty = self.parse_type(depth + 1)?;
        let default = if self.eat_operator(Operator::Assign)? {
            Some(self.parse_expression(depth + 1)?)
        } else {
            None
        };
        Ok(FieldDeclaration {
            meta: self.meta(start, self.position)?,
            name,
            ty,
            default,
        })
    }

    fn parse_initializer(&mut self, depth: u32) -> Result<InitializerDeclaration, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        self.bump()?;
        let mut parameters = Vec::new();
        if self.eat_punctuation(Punctuation::LeftParen)? {
            while !self.at_punctuation(Punctuation::RightParen)
                && !self.at(TokenKind::EndOfFile)
                && !self.at(TokenKind::Newline)
            {
                if let Some(parameter) = self.parse_parameter(depth + 1)? {
                    push_ast_value(&mut parameters, parameter, self.limits.ast_nodes)?;
                } else {
                    self.recover_list_item(true)?;
                }
                if !self.eat_punctuation(Punctuation::Comma)? {
                    break;
                }
            }
            if !self.eat_punctuation(Punctuation::RightParen)? {
                self.error_here(
                    "syntax-unclosed-parameters",
                    "expected `)` to close initializer parameters",
                )?;
            }
        } else {
            self.error_here("syntax-expected-parameters", "expected `(` after `init`")?;
        }
        if !parameters.first().is_some_and(|parameter| {
            parameter.receiver && parameter.access == AccessMode::Mutate && parameter.ty.is_none()
        }) || parameters
            .iter()
            .skip(1)
            .any(|parameter| parameter.receiver)
        {
            self.error_here(
                "syntax-initializer-receiver",
                "an initializer must begin with exactly one `mut self` receiver",
            )?;
        }
        let return_type = if self.eat_punctuation(Punctuation::Arrow)? {
            Some(self.parse_type(depth + 1)?)
        } else {
            None
        };
        if !self.eat_punctuation(Punctuation::Colon)? {
            self.error_here(
                "syntax-expected-suite-colon",
                "expected `:` before the initializer suite",
            )?;
        }
        let body = self.parse_suite(depth + 1)?;
        Ok(InitializerDeclaration {
            meta: self.meta(start, self.position)?,
            parameters,
            return_type,
            body,
        })
    }

    fn enter_indented_declaration_suite(
        &mut self,
        construct: &'static str,
    ) -> Result<(), ParseFailure> {
        if self.at(TokenKind::Newline) {
            if self.current().newline_origin == Some(NewlineOrigin::Semicolon) {
                self.error_here(
                    "syntax-semicolon-before-suite",
                    "a semicolon cannot introduce an indented declaration suite",
                )?;
            }
            self.bump()?;
        } else {
            self.error_here(
                "syntax-expected-suite-newline",
                &format!("expected a physical newline before the {construct} suite"),
            )?;
        }
        if !self.eat(TokenKind::Indent)? {
            self.error_here(
                "syntax-expected-indent",
                &format!("expected a four-space indentation for the {construct} suite"),
            )?;
        }
        Ok(())
    }

    fn leave_indented_declaration_suite(
        &mut self,
        construct: &'static str,
    ) -> Result<(), ParseFailure> {
        if !self.eat(TokenKind::Dedent)? {
            self.error_here(
                "syntax-expected-dedent",
                &format!("expected the closing dedent for the {construct} suite"),
            )?;
        }
        Ok(())
    }

    fn parse_enum_declaration(
        &mut self,
        depth: u32,
    ) -> Result<Option<EnumDeclaration>, ParseFailure> {
        let start = self.position;
        self.bump()?;
        let Some(name) = self.parse_identifier(depth + 1)? else {
            self.error_here(
                "syntax-expected-enum-name",
                "expected an identifier after `enum`",
            )?;
            return Ok(None);
        };
        let generics = self.parse_generic_parameters(depth + 1)?;
        let deriving = self.parse_deriving_list(depth + 1)?;
        if !self.eat_punctuation(Punctuation::Colon)? {
            self.error_here(
                "syntax-expected-suite-colon",
                "expected `:` before the enum suite",
            )?;
        }
        self.enter_indented_declaration_suite("enum")?;
        let mut variants = Vec::new();
        while !self.at(TokenKind::Dedent) && !self.at(TokenKind::EndOfFile) {
            while self.at(TokenKind::Newline) {
                self.bump()?;
            }
            if self.at(TokenKind::Dedent) || self.at(TokenKind::EndOfFile) {
                break;
            }
            if let Some(variant) = self.parse_enum_variant(depth + 1)? {
                push_ast_value(&mut variants, variant, self.limits.ast_nodes)?;
            } else {
                self.recover_to_line_end()?;
            }
            if self.at(TokenKind::Newline) {
                self.bump()?;
            }
        }
        if variants.is_empty() {
            self.error_here(
                "syntax-empty-enum-suite",
                "enum declarations require at least one variant",
            )?;
        }
        self.leave_indented_declaration_suite("enum")?;
        Ok(Some(EnumDeclaration {
            meta: self.meta(start, self.position)?,
            name,
            generics,
            variants,
            deriving,
        }))
    }

    fn parse_enum_variant(&mut self, depth: u32) -> Result<Option<EnumVariant>, ParseFailure> {
        let start = self.position;
        let Some(name) = self.parse_identifier(depth + 1)? else {
            self.error_here(
                "syntax-expected-enum-variant",
                "expected an enum variant identifier",
            )?;
            return Ok(None);
        };
        let payload = if self.eat_punctuation(Punctuation::LeftParen)? {
            if self.eat_punctuation(Punctuation::RightParen)? {
                EnumPayload::None
            } else if self.at(TokenKind::Identifier)
                && self.nth_kind(1) == Some(TokenKind::Punctuation(Punctuation::Colon))
            {
                let mut fields = Vec::new();
                loop {
                    let field_start = self.position;
                    let Some(field_name) = self.parse_identifier(depth + 2)? else {
                        self.error_here(
                            "syntax-enum-payload-field",
                            "expected a named enum payload field",
                        )?;
                        break;
                    };
                    if !self.eat_punctuation(Punctuation::Colon)? {
                        self.error_here(
                            "syntax-enum-payload-field",
                            "named enum payload fields require `: Type`",
                        )?;
                    }
                    let ty = self.parse_type(depth + 2)?;
                    let field = VariantField {
                        meta: self.meta(field_start, self.position)?,
                        name: field_name,
                        ty,
                    };
                    push_ast_value(&mut fields, field, self.limits.ast_nodes)?;
                    if !self.eat_punctuation(Punctuation::Comma)?
                        || self.at_punctuation(Punctuation::RightParen)
                    {
                        break;
                    }
                }
                if !self.eat_punctuation(Punctuation::RightParen)? {
                    self.error_here(
                        "syntax-unclosed-enum-payload",
                        "expected `)` after the named enum payload",
                    )?;
                }
                EnumPayload::Named(fields)
            } else {
                let mut types = Vec::new();
                loop {
                    let ty = self.parse_type(depth + 2)?;
                    push_ast_value(&mut types, ty, self.limits.ast_nodes)?;
                    if !self.eat_punctuation(Punctuation::Comma)?
                        || self.at_punctuation(Punctuation::RightParen)
                    {
                        break;
                    }
                }
                if !self.eat_punctuation(Punctuation::RightParen)? {
                    self.error_here(
                        "syntax-unclosed-enum-payload",
                        "expected `)` after the positional enum payload",
                    )?;
                }
                EnumPayload::Positional(types)
            }
        } else {
            EnumPayload::None
        };
        Ok(Some(EnumVariant {
            meta: self.meta(start, self.position)?,
            name,
            payload,
        }))
    }

    fn parse_interface_declaration(
        &mut self,
        depth: u32,
    ) -> Result<Option<InterfaceDeclaration>, ParseFailure> {
        let start = self.position;
        self.bump()?;
        let Some(name) = self.parse_identifier(depth + 1)? else {
            self.error_here(
                "syntax-expected-interface-name",
                "expected an identifier after `interface`",
            )?;
            return Ok(None);
        };
        let generics = self.parse_generic_parameters(depth + 1)?;
        if !self.eat_punctuation(Punctuation::Colon)? {
            self.error_here(
                "syntax-expected-suite-colon",
                "expected `:` before the interface suite",
            )?;
        }
        self.enter_indented_declaration_suite("interface")?;
        let mut members = Vec::new();
        while !self.at(TokenKind::Dedent) && !self.at(TokenKind::EndOfFile) {
            while self.at(TokenKind::Newline) {
                self.bump()?;
            }
            if self.at(TokenKind::Dedent) || self.at(TokenKind::EndOfFile) {
                break;
            }
            let member = self.parse_interface_member(depth + 1)?;
            push_ast_value(&mut members, member, self.limits.ast_nodes)?;
            if self.at(TokenKind::Newline) {
                self.bump()?;
            }
        }
        if members.is_empty() {
            self.error_here(
                "syntax-empty-interface-suite",
                "interface declarations require at least one member",
            )?;
        }
        self.leave_indented_declaration_suite("interface")?;
        Ok(Some(InterfaceDeclaration {
            meta: self.meta(start, self.position)?,
            name,
            generics,
            members,
        }))
    }

    fn parse_interface_member(&mut self, depth: u32) -> Result<InterfaceMember, ParseFailure> {
        let start = self.position;
        if self.at_punctuation(Punctuation::At)
            && !self.interface_member_supported_after_attributes()?
        {
            self.error_here(
                "syntax-interface-member",
                "attributes must precede a function or projection interface member",
            )?;
            self.recover_to_line_end()?;
            return Ok(InterfaceMember::Error(self.recovery_error(
                start,
                self.position,
                "interface function or projection",
                depth + 1,
            )?));
        }
        let mut attributes = Vec::new();
        while self.at_punctuation(Punctuation::At) {
            if let Some(attribute) = self.parse_attribute(depth + 1)? {
                push_ast_value(&mut attributes, attribute, self.limits.ast_nodes)?;
            }
            self.consume_required_line_end("syntax-attribute-line", "interface attribute")?;
            while self.at(TokenKind::Newline) {
                self.bump()?;
            }
        }
        if self.starts_removed_initializer_spelling() {
            self.error_here(
                "syntax-removed-initializer-spelling",
                "`fn __init__` was removed; declare a struct initializer with `init`",
            )?;
            self.recover_to_line_end()?;
            return Ok(InterfaceMember::Error(self.recovery_error(
                start,
                self.position,
                "interface function or projection",
                depth + 1,
            )?));
        }
        if self.starts_comptime_fn_spelling() {
            self.error_here(
                "syntax-legacy-comptime-fn-color",
                "`comptime` before `fn` is a legacy spelling; functions are phase-neutral",
            )?;
            self.recover_to_line_end()?;
            return Ok(InterfaceMember::Error(self.recovery_error(
                start,
                self.position,
                "interface function or projection",
                depth + 1,
            )?));
        }
        if self.starts_function() {
            if let Some(declaration) = self.parse_function(depth + 1, false)? {
                return Ok(InterfaceMember::Function {
                    attributes,
                    declaration,
                });
            }
        } else if self.at_keyword(Keyword::Projection)
            && let Some(declaration) = self.parse_projection_declaration(depth + 1, false)?
        {
            return Ok(InterfaceMember::Projection {
                attributes,
                declaration,
            });
        }
        self.error_here(
            "syntax-interface-member",
            "interface suites permit only function and projection signatures",
        )?;
        self.recover_to_line_end()?;
        Ok(InterfaceMember::Error(self.recovery_error(
            start,
            self.position,
            "interface function or projection",
            depth + 1,
        )?))
    }

    fn interface_member_supported_after_attributes(&mut self) -> Result<bool, ParseFailure> {
        let mut cursor = self.position;
        while self.lexical.tokens.get(cursor).map(|token| token.kind)
            == Some(TokenKind::Punctuation(Punctuation::At))
        {
            while cursor < self.lexical.tokens.len()
                && self.lexical.tokens[cursor].kind != TokenKind::Newline
            {
                cursor += 1;
                self.cancellation.work()?;
            }
            if self.lexical.tokens.get(cursor).map(|token| token.kind) == Some(TokenKind::Newline) {
                cursor += 1;
            }
        }
        let kind = self.lexical.tokens.get(cursor).map(|token| token.kind);
        if matches!(
            kind,
            Some(TokenKind::Keyword(
                Keyword::Async | Keyword::Isr | Keyword::Comptime
            ))
        ) {
            cursor += 1;
            if self.lexical.tokens.get(cursor).map(|token| token.kind)
                != Some(TokenKind::Keyword(Keyword::Fn))
            {
                return Ok(false);
            }
        } else if kind != Some(TokenKind::Keyword(Keyword::Fn))
            && kind != Some(TokenKind::Keyword(Keyword::Projection))
        {
            return Ok(false);
        }
        cursor += 1;
        Ok(self.lexical.tokens.get(cursor).map(|token| token.kind) == Some(TokenKind::Identifier))
    }

    fn parse_implementation_declaration(
        &mut self,
        depth: u32,
    ) -> Result<ImplementationDeclaration, ParseFailure> {
        let start = self.position;
        self.bump()?;
        let interface = self.parse_type(depth + 1)?;
        if !self.eat_keyword(Keyword::For)? {
            self.error_here(
                "syntax-implementation-for",
                "expected `for` between the interface and implementing type",
            )?;
        }
        let implementing_type = self.parse_type(depth + 1)?;
        if !self.eat_punctuation(Punctuation::Colon)? {
            self.error_here(
                "syntax-expected-suite-colon",
                "expected `:` before the implementation suite",
            )?;
        }
        self.enter_indented_declaration_suite("implementation")?;
        let mut members = Vec::new();
        while !self.at(TokenKind::Dedent) && !self.at(TokenKind::EndOfFile) {
            while self.at(TokenKind::Newline) {
                self.bump()?;
            }
            if self.at(TokenKind::Dedent) || self.at(TokenKind::EndOfFile) {
                break;
            }
            let member = self.parse_member_declaration(depth + 1, MemberContext::Implementation)?;
            push_ast_value(&mut members, member, self.limits.ast_nodes)?;
            if self.at(TokenKind::Newline) {
                self.bump()?;
            }
        }
        if members.is_empty() {
            self.error_here(
                "syntax-empty-implementation-suite",
                "implementation declarations require at least one member",
            )?;
        }
        self.leave_indented_declaration_suite("implementation")?;
        Ok(ImplementationDeclaration {
            meta: self.meta(start, self.position)?,
            interface,
            implementing_type,
            members,
        })
    }

    fn parse_projection_declaration(
        &mut self,
        depth: u32,
        body_required: bool,
    ) -> Result<Option<ProjectionDeclaration>, ParseFailure> {
        let start = self.position;
        self.bump()?;
        let Some(name) = self.parse_identifier(depth + 1)? else {
            self.error_here(
                "syntax-expected-projection-name",
                "expected an identifier after `projection`",
            )?;
            return Ok(None);
        };
        let generics = self.parse_generic_parameters(depth + 1)?;
        let parameters = self.parse_parameter_list(depth + 1, "projection")?;
        if !self.eat_punctuation(Punctuation::Arrow)? {
            self.error_here(
                "syntax-projection-arrow",
                "expected `->` before the projection carrier",
            )?;
        }
        let carrier = self.parse_projection_carrier(depth + 1)?;
        let body = if body_required {
            if !self.eat_punctuation(Punctuation::Colon)? {
                self.error_here(
                    "syntax-expected-suite-colon",
                    "expected `:` before the projection suite",
                )?;
            }
            Some(self.parse_suite(depth + 1)?)
        } else {
            None
        };
        Ok(Some(ProjectionDeclaration {
            meta: self.meta(start, self.position)?,
            name,
            generics,
            parameters,
            carrier,
            body,
        }))
    }

    fn parse_parameter_list(
        &mut self,
        depth: u32,
        construct: &'static str,
    ) -> Result<Vec<Parameter>, ParseFailure> {
        let mut parameters = Vec::new();
        if !self.eat_punctuation(Punctuation::LeftParen)? {
            self.error_here(
                "syntax-expected-parameters",
                &format!("expected `(` before {construct} parameters"),
            )?;
            return Ok(parameters);
        }
        while !self.at_punctuation(Punctuation::RightParen)
            && !self.at(TokenKind::EndOfFile)
            && !self.at(TokenKind::Newline)
        {
            if let Some(parameter) = self.parse_parameter(depth + 1)? {
                push_ast_value(&mut parameters, parameter, self.limits.ast_nodes)?;
            } else {
                self.recover_list_item(true)?;
            }
            if !self.eat_punctuation(Punctuation::Comma)? {
                break;
            }
        }
        if !self.eat_punctuation(Punctuation::RightParen)? {
            self.error_here(
                "syntax-unclosed-parameters",
                &format!("expected `)` after {construct} parameters"),
            )?;
        }
        Ok(parameters)
    }

    /// Parses a bare view leaf (`view T` / `mut view T`), returning `None`
    /// when the current token does not start one.
    fn parse_projection_view_leaf(
        &mut self,
        depth: u32,
    ) -> Result<Option<ProjectionCarrier>, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        if self.eat_keyword(Keyword::View)? {
            let ty = self.parse_type(depth + 1)?;
            return Ok(Some(ProjectionCarrier::View {
                meta: self.meta(start, self.position)?,
                mutable: false,
                ty: Box::new(ty),
            }));
        }
        if self.at_keyword(Keyword::Mut)
            && self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::View))
        {
            self.bump()?;
            self.bump()?;
            let ty = self.parse_type(depth + 1)?;
            return Ok(Some(ProjectionCarrier::View {
                meta: self.meta(start, self.position)?,
                mutable: true,
                ty: Box::new(ty),
            }));
        }
        Ok(None)
    }

    /// Parses the leaf required inside `Option[..]`/`Result[.., E]`; emits a
    /// diagnostic and an error node when the leaf is missing.
    fn parse_projection_leaf_or_error(
        &mut self,
        depth: u32,
        wrapper: &'static str,
    ) -> Result<ProjectionCarrier, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        if let Some(leaf) = self.parse_projection_view_leaf(depth + 1)? {
            return Ok(leaf);
        }
        self.error_here(
            "syntax-projection-carrier-leaf",
            &format!(
                "expected a `view` or `mut view` leaf inside a `{wrapper}` projection carrier"
            ),
        )?;
        if !self.is_type_terminator() {
            self.bump()?;
        }
        Ok(ProjectionCarrier::Error(self.recovery_error(
            start,
            self.position,
            "projection carrier leaf",
            depth + 1,
        )?))
    }

    /// A projection carrier is exactly one view leaf, or that leaf wrapped
    /// in a single `Option[..]` or `Result[.., E]` layer — no tuples and no
    /// nested wrapping.
    fn parse_projection_carrier(&mut self, depth: u32) -> Result<ProjectionCarrier, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        if let Some(leaf) = self.parse_projection_view_leaf(depth + 1)? {
            return Ok(leaf);
        }
        if self.at(TokenKind::Identifier) && self.token_text(self.position) == "Option" {
            self.bump()?;
            if !self.eat_punctuation(Punctuation::LeftBracket)? {
                self.error_here(
                    "syntax-option-carrier",
                    "expected `[` after `Option` projection carrier",
                )?;
            }
            let carrier = self.parse_projection_leaf_or_error(depth + 1, "Option")?;
            if !self.eat_punctuation(Punctuation::RightBracket)? {
                self.error_here(
                    "syntax-option-carrier",
                    "expected `]` after `Option` projection carrier",
                )?;
            }
            return Ok(ProjectionCarrier::Option {
                meta: self.meta(start, self.position)?,
                carrier: Box::new(carrier),
            });
        }
        if self.at(TokenKind::Identifier) && self.token_text(self.position) == "Result" {
            self.bump()?;
            if !self.eat_punctuation(Punctuation::LeftBracket)? {
                self.error_here(
                    "syntax-result-carrier",
                    "expected `[` after `Result` projection carrier",
                )?;
            }
            let carrier = self.parse_projection_leaf_or_error(depth + 1, "Result")?;
            if !self.eat_punctuation(Punctuation::Comma)? {
                self.error_here(
                    "syntax-result-carrier",
                    "expected `,` before the Result carrier error type",
                )?;
            }
            let error = self.parse_type(depth + 1)?;
            if !self.eat_punctuation(Punctuation::RightBracket)? {
                self.error_here(
                    "syntax-result-carrier",
                    "expected `]` after the Result projection carrier",
                )?;
            }
            return Ok(ProjectionCarrier::Result {
                meta: self.meta(start, self.position)?,
                carrier: Box::new(carrier),
                error: Box::new(error),
            });
        }
        self.error_here(
            "syntax-projection-carrier",
            "expected a view, Option[view], or Result[view, Error] projection carrier",
        )?;
        if !self.is_type_terminator() {
            self.bump()?;
        }
        Ok(ProjectionCarrier::Error(self.recovery_error(
            start,
            self.position,
            "projection carrier",
            depth + 1,
        )?))
    }

    fn parse_scope_declaration(
        &mut self,
        depth: u32,
    ) -> Result<Option<ScopeDeclaration>, ParseFailure> {
        let start = self.position;
        self.bump()?;
        let Some(name) = self.parse_identifier(depth + 1)? else {
            self.error_here(
                "syntax-expected-scope-name",
                "expected an identifier after `scope`",
            )?;
            return Ok(None);
        };
        let parameters = self.parse_parameter_list(depth + 1, "scope")?;
        if !self.eat_punctuation(Punctuation::Arrow)? {
            self.error_here(
                "syntax-scope-arrow",
                "expected `->` before the scope return type",
            )?;
        }
        let return_type = self.parse_type(depth + 1)?;
        if !self.eat_punctuation(Punctuation::Colon)? {
            self.error_here(
                "syntax-expected-suite-colon",
                "expected `:` before the scope suite",
            )?;
        }
        self.enter_indented_declaration_suite("scope")?;
        let mut setup = Vec::new();
        let mut semicolon_boundary: Option<(Span, bool)> = None;
        while !self.at_keyword(Keyword::Enter)
            && !self.at_keyword(Keyword::Exit)
            && !self.at(TokenKind::Dedent)
            && !self.at(TokenKind::EndOfFile)
        {
            while self.at(TokenKind::Newline) {
                if let Some((span, _)) = semicolon_boundary.take() {
                    self.report_invalid_semicolon_boundary(span)?;
                }
                self.bump()?;
            }
            if self.at_keyword(Keyword::Enter)
                || self.at_keyword(Keyword::Exit)
                || self.at(TokenKind::Dedent)
                || self.at(TokenKind::EndOfFile)
            {
                break;
            }
            let statement = self.parse_statement(depth + 1)?;
            let simple = Self::is_simple_statement_kind(&statement.kind);
            if let Some((span, left_simple)) = semicolon_boundary.take() {
                if !left_simple || !simple {
                    self.report_invalid_semicolon_boundary(span)?;
                }
            }
            push_ast_value(&mut setup, statement, self.limits.ast_nodes)?;
            if self.at(TokenKind::Newline) {
                if self.current().newline_origin == Some(NewlineOrigin::Semicolon) {
                    semicolon_boundary = Some((self.current().span, simple));
                }
                self.bump()?;
            }
        }
        if let Some((span, _)) = semicolon_boundary {
            self.report_invalid_semicolon_boundary(span)?;
        }
        let enter = if self.eat_keyword(Keyword::Enter)? {
            self.parse_expression(depth + 1)?
        } else {
            self.error_here(
                "syntax-scope-enter",
                "scope suites require `enter expression`",
            )?;
            self.error_expression(self.position, self.position, depth + 1)?
        };
        if self.at(TokenKind::Newline) {
            self.bump()?;
        } else if !self.at_keyword(Keyword::Exit) && !self.at_keyword(Keyword::Abort) {
            self.error_here(
                "syntax-scope-enter-newline",
                "expected a newline after the scope enter expression",
            )?;
            self.recover_to_line_end()?;
            self.eat(TokenKind::Newline)?;
        }
        let abort = if self.eat_keyword(Keyword::Abort)? {
            if !self.eat_punctuation(Punctuation::Colon)? {
                self.error_here(
                    "syntax-scope-abort-colon",
                    "expected `:` before the scope abort suite",
                )?;
            }
            let suite = self.parse_suite(depth + 1)?;
            if self.at(TokenKind::Newline) {
                self.bump()?;
            }
            Some(suite)
        } else {
            None
        };
        let exit_keyword = if self.at_keyword(Keyword::Exit) {
            let keyword = self.position;
            self.bump()?;
            keyword
        } else {
            self.error_here(
                "syntax-scope-exit",
                "scope suites require an `exit binding: suite` clause",
            )?;
            start
        };
        let exit_binding = if let Some(identifier) = self.parse_identifier(depth + 1)? {
            identifier
        } else {
            self.error_here(
                "syntax-scope-exit-binding",
                "expected a binding name after `exit`",
            )?;
            self.identifier_from_token(exit_keyword, depth + 1)?
        };
        if !self.eat_punctuation(Punctuation::Colon)? {
            self.error_here(
                "syntax-scope-exit-colon",
                "expected `:` before the scope exit suite",
            )?;
        }
        let exit = self.parse_suite(depth + 1)?;
        if self.at(TokenKind::Newline) {
            self.bump()?;
        }
        self.leave_indented_declaration_suite("scope")?;
        Ok(Some(ScopeDeclaration {
            meta: self.meta(start, self.position)?,
            name,
            parameters,
            return_type,
            setup,
            enter,
            abort,
            exit_binding,
            exit,
        }))
    }

    fn parse_comptime_top_if(&mut self, depth: u32) -> Result<ComptimeDeclarationIf, ParseFailure> {
        let start = self.position;
        self.bump()?;
        self.bump()?;
        let condition = self.parse_expression(depth + 1)?;
        if !self.eat_punctuation(Punctuation::Colon)? {
            self.error_here(
                "syntax-comptime-if-colon",
                "expected `:` before the comptime declaration branch",
            )?;
        }
        let then_declarations = self.parse_top_declaration_suite(depth + 1)?;
        let else_declarations = if self.newline_precedes_comptime_else() {
            self.bump()?;
            self.bump()?;
            self.bump()?;
            if !self.eat_punctuation(Punctuation::Colon)? {
                self.error_here(
                    "syntax-comptime-else-colon",
                    "expected `:` before the comptime else declaration branch",
                )?;
            }
            self.parse_top_declaration_suite(depth + 1)?
        } else {
            Vec::new()
        };
        Ok(ComptimeDeclarationIf {
            meta: self.meta(start, self.position)?,
            condition,
            then_declarations,
            else_declarations,
        })
    }

    fn parse_top_declaration_suite(
        &mut self,
        depth: u32,
    ) -> Result<Vec<TopLevelDeclaration>, ParseFailure> {
        self.enter_indented_declaration_suite("comptime declaration branch")?;
        let mut declarations = Vec::new();
        while !self.at(TokenKind::Dedent) && !self.at(TokenKind::EndOfFile) {
            while self.at(TokenKind::Newline) {
                self.bump()?;
            }
            if self.at(TokenKind::Dedent) || self.at(TokenKind::EndOfFile) {
                break;
            }
            let declaration = self.parse_top_level(depth + 1)?;
            push_ast_value(&mut declarations, declaration, self.limits.ast_nodes)?;
            if self.at(TokenKind::Newline) {
                self.bump()?;
            }
        }
        if declarations.is_empty() {
            self.error_here(
                "syntax-empty-comptime-branch",
                "comptime declaration branches require at least one declaration",
            )?;
        }
        self.leave_indented_declaration_suite("comptime declaration branch")?;
        Ok(declarations)
    }

    fn parse_comptime_member_if(&mut self, depth: u32) -> Result<ComptimeMemberIf, ParseFailure> {
        let start = self.position;
        self.bump()?;
        self.bump()?;
        let condition = self.parse_expression(depth + 1)?;
        if !self.eat_punctuation(Punctuation::Colon)? {
            self.error_here(
                "syntax-comptime-if-colon",
                "expected `:` before the comptime member branch",
            )?;
        }
        let then_members = self.parse_member_declaration_suite(depth + 1)?;
        let else_members = if self.newline_precedes_comptime_else() {
            self.bump()?;
            self.bump()?;
            self.bump()?;
            if !self.eat_punctuation(Punctuation::Colon)? {
                self.error_here(
                    "syntax-comptime-else-colon",
                    "expected `:` before the comptime else member branch",
                )?;
            }
            self.parse_member_declaration_suite(depth + 1)?
        } else {
            Vec::new()
        };
        Ok(ComptimeMemberIf {
            meta: self.meta(start, self.position)?,
            condition,
            then_members,
            else_members,
        })
    }

    fn parse_member_declaration_suite(
        &mut self,
        depth: u32,
    ) -> Result<Vec<MemberDeclaration>, ParseFailure> {
        self.enter_indented_declaration_suite("comptime member branch")?;
        let mut members = Vec::new();
        while !self.at(TokenKind::Dedent) && !self.at(TokenKind::EndOfFile) {
            while self.at(TokenKind::Newline) {
                self.bump()?;
            }
            if self.at(TokenKind::Dedent) || self.at(TokenKind::EndOfFile) {
                break;
            }
            let member = self.parse_member_declaration(depth + 1, MemberContext::OtherType)?;
            push_ast_value(&mut members, member, self.limits.ast_nodes)?;
            if self.at(TokenKind::Newline) {
                self.bump()?;
            }
        }
        if members.is_empty() {
            self.error_here(
                "syntax-empty-comptime-branch",
                "comptime member branches require at least one member",
            )?;
        }
        self.leave_indented_declaration_suite("comptime member branch")?;
        Ok(members)
    }

    fn newline_precedes_comptime_else(&self) -> bool {
        self.at(TokenKind::Newline)
            && self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::Comptime))
            && self.nth_kind(2) == Some(TokenKind::Keyword(Keyword::Else))
    }

    fn parse_parameter(&mut self, depth: u32) -> Result<Option<Parameter>, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        let access = self.parse_access_mode()?;
        let receiver = self.at_keyword(Keyword::SelfValue);
        let positional_only = if !receiver
            && self.at(TokenKind::Identifier)
            && self.token_text(self.position) == "_"
            && self.nth_kind(1) == Some(TokenKind::Identifier)
        {
            self.bump()?;
            true
        } else {
            false
        };
        let name = if receiver {
            self.identifier_from_current(depth + 1)?.ok_or_else(|| {
                ParseFailure::InternalInvariant(
                    "receiver keyword did not produce an identifier".to_owned(),
                )
            })?
        } else if let Some(identifier) = self.parse_identifier(depth + 1)? {
            identifier
        } else {
            self.error_here(
                "syntax-expected-parameter-name",
                "expected a parameter identifier",
            )?;
            return Ok(None);
        };
        let ty = if receiver {
            None
        } else if self.eat_punctuation(Punctuation::Colon)? {
            Some(self.parse_type(depth + 1)?)
        } else {
            self.error_here(
                "syntax-expected-parameter-type",
                "non-receiver parameters require `: Type`",
            )?;
            Some(self.error_type(self.position, self.position, depth + 1)?)
        };
        Ok(Some(Parameter {
            meta: self.meta(start, self.position)?,
            access,
            name,
            ty,
            receiver,
            positional_only,
        }))
    }

    fn parse_access_mode(&mut self) -> Result<AccessMode, ParseFailure> {
        let access = match self.kind() {
            TokenKind::Keyword(Keyword::Read) => AccessMode::Read,
            TokenKind::Keyword(Keyword::Mut) => AccessMode::Mutate,
            TokenKind::Keyword(Keyword::Take) => AccessMode::Take,
            _ => return Ok(AccessMode::Value),
        };
        self.bump()?;
        Ok(access)
    }

    fn parse_generic_parameters(
        &mut self,
        depth: u32,
    ) -> Result<Vec<GenericParameter>, ParseFailure> {
        self.check_depth(depth)?;
        if !self.eat_punctuation(Punctuation::LeftBracket)? {
            return Ok(Vec::new());
        }
        let mut parameters = Vec::new();
        if self.at_punctuation(Punctuation::RightBracket) {
            self.error_here(
                "syntax-empty-generic-parameters",
                "generic parameter lists require at least one parameter",
            )?;
        }
        while !self.at_punctuation(Punctuation::RightBracket)
            && !self.at(TokenKind::EndOfFile)
            && !self.at(TokenKind::Newline)
        {
            let start = self.position;
            let parameter = if self.eat_keyword(Keyword::Const)? {
                if let Some(name) = self.parse_identifier(depth + 1)? {
                    if !self.eat_punctuation(Punctuation::Colon)? {
                        self.error_here(
                            "syntax-generic-const-type",
                            "constant generic parameters require `: Type`",
                        )?;
                    }
                    let ty = self.parse_type(depth + 1)?;
                    Some(GenericParameter::Constant {
                        meta: self.meta(start, self.position)?,
                        name,
                        ty,
                    })
                } else {
                    self.error_here(
                        "syntax-generic-parameter-name",
                        "expected a name after `const`",
                    )?;
                    None
                }
            } else if self.eat_keyword(Keyword::Region)? {
                if let Some(name) = self.parse_identifier(depth + 1)? {
                    Some(GenericParameter::Region {
                        meta: self.meta(start, self.position)?,
                        name,
                    })
                } else {
                    self.error_here(
                        "syntax-generic-parameter-name",
                        "expected a name after `region`",
                    )?;
                    None
                }
            } else if let Some(name) = self.parse_identifier(depth + 1)? {
                let bound = if self.eat_punctuation(Punctuation::Colon)? {
                    Some(self.parse_type(depth + 1)?)
                } else {
                    None
                };
                Some(GenericParameter::Type {
                    meta: self.meta(start, self.position)?,
                    name,
                    bound,
                })
            } else {
                self.error_here(
                    "syntax-generic-parameter",
                    "expected a type, constant, or region generic parameter",
                )?;
                None
            };
            if let Some(parameter) = parameter {
                push_ast_value(&mut parameters, parameter, self.limits.ast_nodes)?;
            } else {
                while !self.at_punctuation(Punctuation::Comma)
                    && !self.at_punctuation(Punctuation::RightBracket)
                    && !self.at(TokenKind::Newline)
                    && !self.at(TokenKind::EndOfFile)
                {
                    self.bump()?;
                }
            }
            if !self.eat_punctuation(Punctuation::Comma)? {
                break;
            }
        }
        if !self.eat_punctuation(Punctuation::RightBracket)? {
            self.error_here(
                "syntax-unclosed-generic-parameters",
                "expected `]` to close generic parameters",
            )?;
        }
        Ok(parameters)
    }

    fn parse_suite(&mut self, depth: u32) -> Result<Suite, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        if self.at(TokenKind::Newline) {
            if self.current().newline_origin == Some(NewlineOrigin::Semicolon) {
                self.error_here(
                    "syntax-semicolon-before-suite",
                    "a semicolon cannot provide the newline required before a suite",
                )?;
            }
            self.bump()?;
        } else {
            self.error_here(
                "syntax-expected-suite-newline",
                "expected a physical newline before the indented suite",
            )?;
        }
        if !self.eat(TokenKind::Indent)? {
            self.error_here(
                "syntax-expected-indent",
                "expected a four-space indentation for the suite",
            )?;
        }
        let mut statements = Vec::new();
        let mut semicolon_boundary: Option<(Span, bool)> = None;
        while !self.at(TokenKind::Dedent) && !self.at(TokenKind::EndOfFile) {
            while self.at(TokenKind::Newline) {
                if let Some((span, _)) = semicolon_boundary.take() {
                    self.report_invalid_semicolon_boundary(span)?;
                }
                self.bump()?;
            }
            if self.at(TokenKind::Dedent) || self.at(TokenKind::EndOfFile) {
                break;
            }
            let statement = self.parse_statement(depth + 1)?;
            let simple = Self::is_simple_statement_kind(&statement.kind);
            if let Some((span, left_simple)) = semicolon_boundary.take() {
                if !left_simple || !simple {
                    self.report_invalid_semicolon_boundary(span)?;
                }
            }
            push_ast_value(&mut statements, statement, self.limits.ast_nodes)?;
            if self.at(TokenKind::Newline) {
                if self.current().newline_origin == Some(NewlineOrigin::Semicolon) {
                    semicolon_boundary = Some((self.current().span, simple));
                }
                self.bump()?;
            } else if !self.at(TokenKind::Dedent) && !self.at(TokenKind::EndOfFile) {
                self.error_here(
                    "syntax-expected-newline",
                    "expected a logical newline after the statement",
                )?;
                self.recover_to_line_end()?;
            }
        }
        if let Some((span, _)) = semicolon_boundary {
            self.report_invalid_semicolon_boundary(span)?;
        }
        if statements.is_empty() {
            self.error_here(
                "syntax-empty-suite",
                "a function suite requires at least one statement; write `pass` explicitly",
            )?;
        }
        self.eat(TokenKind::Dedent)?;
        Ok(Suite {
            meta: self.meta(start, self.position)?,
            statements,
        })
    }

    fn is_simple_statement_kind(kind: &StatementKind) -> bool {
        !matches!(
            kind,
            StatementKind::If(_)
                | StatementKind::Match { .. }
                | StatementKind::For { .. }
                | StatementKind::While { .. }
                | StatementKind::Loop(_)
                | StatementKind::With { .. }
                | StatementKind::ComptimeIf { .. }
        )
    }

    fn report_invalid_semicolon_boundary(&mut self, span: Span) -> Result<(), ParseFailure> {
        self.diagnostics.error(
            "syntax-semicolon-statement-boundary",
            span.range.start as usize,
            span.range.end as usize,
            "a semicolon must have a simple statement immediately on both sides".to_owned(),
        )
    }

    fn parse_statement(&mut self, depth: u32) -> Result<Statement, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        let mut attributes = Vec::new();
        while self.at_punctuation(Punctuation::At) {
            if let Some(attribute) = self.parse_attribute(depth + 1)? {
                push_ast_value(&mut attributes, attribute, self.limits.ast_nodes)?;
            }
            if self.at(TokenKind::Newline) {
                if self.current().newline_origin == Some(NewlineOrigin::Semicolon) {
                    self.error_here(
                        "syntax-statement-attribute-newline",
                        "statement attributes require a physical newline",
                    )?;
                }
                self.bump()?;
            } else {
                self.error_here(
                    "syntax-statement-attribute-newline",
                    "expected a newline after the statement attribute",
                )?;
                self.recover_to_line_end()?;
                self.eat(TokenKind::Newline)?;
            }
        }
        let kind = match self.kind() {
            TokenKind::Keyword(Keyword::Return) => {
                self.bump()?;
                let value = if self.is_statement_terminator() {
                    None
                } else {
                    Some(self.parse_expression(depth + 1)?)
                };
                StatementKind::Return(value)
            }
            TokenKind::Keyword(Keyword::Pass) => {
                self.bump()?;
                StatementKind::Pass
            }
            TokenKind::Keyword(Keyword::Break) => {
                self.bump()?;
                StatementKind::Break
            }
            TokenKind::Keyword(Keyword::Continue) => {
                self.bump()?;
                StatementKind::Continue
            }
            TokenKind::Keyword(Keyword::Send) => {
                self.bump()?;
                let value = self.parse_expression(depth + 1)?;
                if !matches!(value.kind, ExpressionKind::Call { .. }) {
                    self.diagnostics.error(
                        "syntax-send-call",
                        value.meta.span.range.start as usize,
                        value.meta.span.range.end as usize,
                        "`send` requires a call expression".to_owned(),
                    )?;
                }
                StatementKind::Send(value)
            }
            TokenKind::Keyword(Keyword::Yield) => {
                self.bump()?;
                StatementKind::Yield(self.parse_expression(depth + 1)?)
            }
            TokenKind::Keyword(Keyword::Assert) => self.parse_assert(depth + 1, false)?,
            TokenKind::Keyword(Keyword::Comptime)
                if self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::Assert)) =>
            {
                self.bump()?;
                self.parse_assert(depth + 1, true)?
            }
            TokenKind::Keyword(Keyword::If) => self.parse_if_statement(depth + 1)?,
            TokenKind::Keyword(Keyword::Match) => self.parse_match_statement(depth + 1)?,
            TokenKind::Keyword(Keyword::For) => self.parse_for_statement(depth + 1)?,
            TokenKind::Keyword(Keyword::While) => self.parse_while_statement(depth + 1)?,
            TokenKind::Keyword(Keyword::Loop) => self.parse_loop_statement(depth + 1)?,
            TokenKind::Keyword(Keyword::With) => self.parse_with_statement(depth + 1)?,
            TokenKind::Keyword(Keyword::Comptime)
                if self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::If)) =>
            {
                self.parse_comptime_statement_if(depth + 1)?
            }
            TokenKind::Keyword(Keyword::Shadow) => self.parse_local_assignment(depth + 1, true)?,
            TokenKind::Identifier if self.starts_local_assignment() => {
                self.parse_local_assignment(depth + 1, false)?
            }
            _ => {
                let mut expression = self.parse_expression(depth + 1)?;
                if let Some(operator) = self.assignment_operator() {
                    Self::anchor_missing_assignment_target(
                        &mut expression,
                        self.current().span.range.start,
                    );
                    self.bump()?;
                    let value = self.parse_expression(depth + 1)?;
                    StatementKind::PlaceAssignment {
                        target: self.assignment_target_from_expression(expression)?,
                        operator,
                        value,
                    }
                } else {
                    StatementKind::Expression(expression)
                }
            }
        };
        Ok(Statement {
            meta: self.meta(start, self.position)?,
            attributes,
            kind,
        })
    }

    fn anchor_missing_assignment_target(expression: &mut Expression, offset: u32) {
        if expression.meta.tokens.first == expression.meta.tokens.end
            && let ExpressionKind::Error(error) = &mut expression.kind
        {
            let range = TextRange {
                start: offset,
                end: offset,
            };
            expression.meta.span.range = range;
            error.meta.span.range = range;
        }
    }

    fn assignment_target_from_expression(
        &mut self,
        expression: Expression,
    ) -> Result<AssignmentTarget, ParseFailure> {
        match expression {
            Expression {
                meta,
                kind: ExpressionKind::Tuple(values),
            } => {
                let mut elements = Vec::new();
                for value in values {
                    let element = self.assignment_target_from_expression(value)?;
                    push_ast_value(&mut elements, element, self.limits.ast_nodes)?;
                }
                Ok(AssignmentTarget::Tuple { meta, elements })
            }
            expression => {
                if !Self::is_place_expression(&expression) {
                    self.diagnostics.error(
                        "syntax-assignment-target",
                        expression.meta.span.range.start as usize,
                        expression.meta.span.range.end as usize,
                        "assignment targets must be places or tuples of places".to_owned(),
                    )?;
                }
                Ok(AssignmentTarget::Place(expression))
            }
        }
    }

    fn is_place_expression(expression: &Expression) -> bool {
        match &expression.kind {
            ExpressionKind::Name(_) => true,
            ExpressionKind::Field { base, .. } | ExpressionKind::Index { base, .. } => {
                Self::is_place_expression(base)
            }
            ExpressionKind::Parenthesized(inner) => Self::is_place_expression(inner),
            _ => false,
        }
    }

    fn parse_if_statement(&mut self, depth: u32) -> Result<StatementKind, ParseFailure> {
        self.bump()?;
        let condition = self.parse_expression(depth + 1)?;
        self.expect_suite_colon("if")?;
        let then_suite = self.parse_suite(depth + 1)?;
        let mut elif = Vec::new();
        while self.newline_precedes_keyword(Keyword::Elif) {
            self.bump()?;
            self.bump()?;
            let condition = self.parse_expression(depth + 1)?;
            self.expect_suite_colon("elif")?;
            let suite = self.parse_suite(depth + 1)?;
            push_ast_value(&mut elif, (condition, suite), self.limits.ast_nodes)?;
        }
        let else_suite = if self.newline_precedes_keyword(Keyword::Else) {
            self.bump()?;
            self.bump()?;
            self.expect_suite_colon("else")?;
            Some(self.parse_suite(depth + 1)?)
        } else {
            None
        };
        Ok(StatementKind::If(IfStatement {
            condition,
            then_suite,
            elif,
            else_suite,
        }))
    }

    fn parse_match_statement(&mut self, depth: u32) -> Result<StatementKind, ParseFailure> {
        self.bump()?;
        let scrutinee = self.parse_expression(depth + 1)?;
        self.expect_suite_colon("match")?;
        self.enter_indented_declaration_suite("match")?;
        let mut arms = Vec::new();
        while !self.at(TokenKind::Dedent) && !self.at(TokenKind::EndOfFile) {
            while self.at(TokenKind::Newline) {
                if self.current().newline_origin == Some(NewlineOrigin::Semicolon) {
                    self.error_here(
                        "syntax-semicolon-match-arm",
                        "match arms require physical newlines",
                    )?;
                }
                self.bump()?;
            }
            if self.at(TokenKind::Dedent) || self.at(TokenKind::EndOfFile) {
                break;
            }
            if self.eat_keyword(Keyword::Case)? {
                let arm_start = self.position.saturating_sub(1);
                let pattern = self.parse_pattern(depth + 1)?;
                let guard = if self.eat_keyword(Keyword::If)? {
                    Some(self.parse_expression(depth + 1)?)
                } else {
                    None
                };
                self.expect_suite_colon("match arm")?;
                let body = self.parse_suite(depth + 1)?;
                let arm = MatchArm {
                    meta: self.meta(arm_start, self.position)?,
                    pattern,
                    guard,
                    body,
                };
                push_ast_value(&mut arms, arm, self.limits.ast_nodes)?;
            } else {
                self.error_here(
                    "syntax-match-arm",
                    "expected `case pattern: suite` in the match body",
                )?;
                self.recover_to_line_end()?;
            }
        }
        if arms.is_empty() {
            self.error_here(
                "syntax-empty-match",
                "match statements require at least one case arm",
            )?;
        }
        self.leave_indented_declaration_suite("match")?;
        Ok(StatementKind::Match { scrutinee, arms })
    }

    fn parse_pattern(&mut self, depth: u32) -> Result<Pattern, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        let first = self.parse_primary_pattern(depth + 1)?;
        let mut alternatives = Vec::new();
        push_ast_value(&mut alternatives, first, self.limits.ast_nodes)?;
        while self.eat_punctuation(Punctuation::Pipe)? || self.eat_operator(Operator::BitOr)? {
            let alternative = self.parse_primary_pattern(depth + 1)?;
            push_ast_value(&mut alternatives, alternative, self.limits.ast_nodes)?;
        }
        Ok(Pattern {
            meta: self.meta(start, self.position)?,
            alternatives,
        })
    }

    fn parse_primary_pattern(&mut self, depth: u32) -> Result<PrimaryPattern, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        if self.at(TokenKind::Identifier) && self.token_text(self.position) == "_" {
            self.bump()?;
            return Ok(PrimaryPattern::Wildcard(self.meta(start, self.position)?));
        }
        if self.eat_punctuation(Punctuation::Dot)? {
            let Some(name) = self.parse_identifier(depth + 1)? else {
                self.error_here(
                    "syntax-expected-dot-variant-name",
                    "expected an identifier after `.`",
                )?;
                return Ok(PrimaryPattern::Error(self.recovery_error(
                    start,
                    self.position,
                    "dot-variant pattern",
                    depth + 1,
                )?));
            };
            let arguments = if self.eat_punctuation(Punctuation::LeftParen)? {
                let arguments = self.parse_pattern_arguments(depth + 1, Punctuation::RightParen)?;
                if !self.eat_punctuation(Punctuation::RightParen)? {
                    self.error_here(
                        "syntax-unclosed-pattern-constructor",
                        "expected `)` to close the constructor pattern",
                    )?;
                }
                arguments
            } else {
                Vec::new()
            };
            return Ok(PrimaryPattern::DotVariant {
                meta: self.meta(start, self.position)?,
                name,
                arguments,
            });
        }
        if self.at(TokenKind::Operator(Operator::Subtract)) {
            self.bump()?;
            if matches!(
                self.kind(),
                TokenKind::IntegerLiteral | TokenKind::FloatLiteral
            ) {
                return Ok(PrimaryPattern::Literal {
                    negative: true,
                    literal: self.parse_literal_node(depth + 1)?,
                });
            }
            self.error_here(
                "syntax-negative-pattern-literal",
                "`-` in a pattern must precede an integer or floating literal",
            )?;
            if !self.is_pattern_terminator() {
                self.bump()?;
            }
            return Ok(PrimaryPattern::Error(self.recovery_error(
                start,
                self.position,
                "negative numeric literal pattern",
                depth + 1,
            )?));
        }
        if matches!(
            self.kind(),
            TokenKind::IntegerLiteral
                | TokenKind::FloatLiteral
                | TokenKind::StringLiteral
                | TokenKind::ByteStringLiteral
                | TokenKind::CharacterLiteral
                | TokenKind::Keyword(Keyword::True | Keyword::False | Keyword::Unit)
        ) {
            return Ok(PrimaryPattern::Literal {
                negative: false,
                literal: self.parse_literal_node(depth + 1)?,
            });
        }
        if self.at(TokenKind::Identifier)
            && self.nth_kind(1) != Some(TokenKind::Punctuation(Punctuation::Dot))
        {
            // A bare identifier (no qualifying dot follows) is always a
            // binding now; unqualified variant-with-payload patterns
            // require a leading dot. Parsed directly as an `Identifier`
            // rather than through `parse_qualified_name` so no separate,
            // immediately-discarded `QualifiedName` AST id is allocated.
            if self.nth_kind(1) == Some(TokenKind::Punctuation(Punctuation::LeftParen)) {
                // Legacy unqualified constructor-with-payload spelling. The
                // name and its parenthesized payload are discarded during
                // recovery, so they are skipped as raw tokens rather than
                // parsed into AST nodes that would then go unreferenced.
                self.error_here(
                    "syntax-legacy-variant-pattern",
                    "unqualified variant patterns require a leading dot, e.g. `.Name(...)`",
                )?;
                self.bump()?; // the identifier
                self.bump()?; // `(`
                let mut nesting: u32 = 1;
                while nesting > 0
                    && !self.at(TokenKind::EndOfFile)
                    && !self.at(TokenKind::Newline)
                    && !self.at(TokenKind::Dedent)
                {
                    if self.at_punctuation(Punctuation::LeftParen) {
                        nesting += 1;
                    } else if self.at_punctuation(Punctuation::RightParen) {
                        nesting -= 1;
                        if nesting == 0 {
                            break;
                        }
                    }
                    self.bump()?;
                }
                if !self.eat_punctuation(Punctuation::RightParen)? {
                    self.error_here(
                        "syntax-unclosed-pattern-constructor",
                        "expected `)` to close the constructor pattern",
                    )?;
                }
                return Ok(PrimaryPattern::Error(self.recovery_error(
                    start,
                    self.position,
                    "dot-variant pattern",
                    depth + 1,
                )?));
            }
            let identifier = self.parse_identifier(depth + 1)?.ok_or_else(|| {
                ParseFailure::InternalInvariant(
                    "pattern name token did not form an identifier".to_owned(),
                )
            })?;
            return Ok(PrimaryPattern::Bind(identifier));
        }
        if self.at(TokenKind::Identifier) {
            // A qualifying dot follows: this is `Enum.variant(...)`.
            let name = self
                .parse_qualified_name(depth + 1, false)?
                .ok_or_else(|| {
                    ParseFailure::InternalInvariant(
                        "pattern name token did not form a qualified name".to_owned(),
                    )
                })?;
            let arguments = if self.eat_punctuation(Punctuation::LeftParen)? {
                let arguments = self.parse_pattern_arguments(depth + 1, Punctuation::RightParen)?;
                if !self.eat_punctuation(Punctuation::RightParen)? {
                    self.error_here(
                        "syntax-unclosed-pattern-constructor",
                        "expected `)` to close the constructor pattern",
                    )?;
                }
                arguments
            } else {
                Vec::new()
            };
            return Ok(PrimaryPattern::Constructor { name, arguments });
        }
        if self.eat_punctuation(Punctuation::LeftParen)? {
            if self.at_punctuation(Punctuation::RightParen) {
                self.error_here(
                    "syntax-empty-tuple-pattern",
                    "tuple patterns require at least one element",
                )?;
                self.bump()?;
                return Ok(PrimaryPattern::Error(self.recovery_error(
                    start,
                    self.position,
                    "tuple pattern",
                    depth + 1,
                )?));
            }
            let first_start = self.position;
            let first = self.parse_pattern(depth + 1)?;
            let first_argument = PatternArgument {
                meta: self.meta(first_start, self.position)?,
                take: false,
                pattern: first,
            };
            if !self.eat_punctuation(Punctuation::Comma)? {
                self.error_here(
                    "syntax-tuple-pattern-comma",
                    "a tuple pattern requires a comma after its first element",
                )?;
            }
            let mut elements = Vec::new();
            push_ast_value(&mut elements, first_argument, self.limits.ast_nodes)?;
            if !self.at_punctuation(Punctuation::RightParen) {
                for argument in self.parse_pattern_arguments(depth + 1, Punctuation::RightParen)? {
                    push_ast_value(&mut elements, argument, self.limits.ast_nodes)?;
                }
            }
            if !self.eat_punctuation(Punctuation::RightParen)? {
                self.error_here(
                    "syntax-unclosed-tuple-pattern",
                    "expected `)` to close the tuple pattern",
                )?;
            }
            return Ok(PrimaryPattern::Tuple {
                meta: self.meta(start, self.position)?,
                elements,
            });
        }
        if self.eat_punctuation(Punctuation::LeftBracket)? {
            let elements = self.parse_pattern_arguments(depth + 1, Punctuation::RightBracket)?;
            if !self.eat_punctuation(Punctuation::RightBracket)? {
                self.error_here(
                    "syntax-unclosed-array-pattern",
                    "expected `]` to close the array pattern",
                )?;
            }
            return Ok(PrimaryPattern::Array {
                meta: self.meta(start, self.position)?,
                elements,
            });
        }
        self.error_here(
            "syntax-expected-pattern",
            "expected a wildcard, literal, constructor, binding, tuple, or array pattern",
        )?;
        if !self.is_pattern_terminator() {
            self.bump()?;
        }
        Ok(PrimaryPattern::Error(self.recovery_error(
            start,
            self.position,
            "pattern",
            depth + 1,
        )?))
    }

    fn parse_pattern_arguments(
        &mut self,
        depth: u32,
        closing: Punctuation,
    ) -> Result<Vec<PatternArgument>, ParseFailure> {
        let mut arguments = Vec::new();
        while !self.at_punctuation(closing)
            && !self.at(TokenKind::Newline)
            && !self.at(TokenKind::Dedent)
            && !self.at(TokenKind::EndOfFile)
        {
            let start = self.position;
            let take = self.eat_keyword(Keyword::Take)?;
            let pattern = self.parse_pattern(depth + 1)?;
            let argument = PatternArgument {
                meta: self.meta(start, self.position)?,
                take,
                pattern,
            };
            push_ast_value(&mut arguments, argument, self.limits.ast_nodes)?;
            if !self.eat_punctuation(Punctuation::Comma)? {
                break;
            }
        }
        Ok(arguments)
    }

    fn is_pattern_terminator(&self) -> bool {
        matches!(
            self.kind(),
            TokenKind::Punctuation(
                Punctuation::Pipe
                    | Punctuation::Comma
                    | Punctuation::Colon
                    | Punctuation::RightParen
                    | Punctuation::RightBracket
                    | Punctuation::RightBrace
            ) | TokenKind::Keyword(Keyword::If | Keyword::And | Keyword::Or)
                | TokenKind::Newline
                | TokenKind::Dedent
                | TokenKind::EndOfFile
        )
    }

    fn parse_for_statement(&mut self, depth: u32) -> Result<StatementKind, ParseFailure> {
        let start = self.position;
        self.bump()?;
        let take_binding = self.eat_keyword(Keyword::Take)?;
        let binding = if let Some(binding) = self.parse_identifier(depth + 1)? {
            binding
        } else {
            self.error_here("syntax-for-binding", "expected a loop binding name")?;
            self.identifier_from_token(start, depth + 1)?
        };
        if !self.eat_keyword(Keyword::In)? {
            self.error_here("syntax-for-in", "expected `in` after the loop binding")?;
        }
        let take_iterable = self.eat_keyword(Keyword::Take)?;
        let iterable = self.parse_expression(depth + 1)?;
        self.expect_suite_colon("for")?;
        let body = self.parse_suite(depth + 1)?;
        Ok(StatementKind::For {
            take_binding,
            binding,
            take_iterable,
            iterable,
            body,
        })
    }

    fn parse_while_statement(&mut self, depth: u32) -> Result<StatementKind, ParseFailure> {
        self.bump()?;
        let condition = self.parse_expression(depth + 1)?;
        self.expect_suite_colon("while")?;
        let body = self.parse_suite(depth + 1)?;
        Ok(StatementKind::While { condition, body })
    }

    fn parse_loop_statement(&mut self, depth: u32) -> Result<StatementKind, ParseFailure> {
        self.bump()?;
        self.expect_suite_colon("loop")?;
        Ok(StatementKind::Loop(self.parse_suite(depth + 1)?))
    }

    fn parse_with_statement(&mut self, depth: u32) -> Result<StatementKind, ParseFailure> {
        self.bump()?;
        let binding_separator = self.find_with_binding_separator()?;
        let previous_end = self.expression_end;
        if let Some(separator) = binding_separator {
            self.expression_end = Some(separator);
        }
        let value = self.parse_expression(depth + 1)?;
        self.expression_end = previous_end;
        let binding = if self.eat_keyword(Keyword::As)? {
            let start = self.position;
            if let Some(name) = self.parse_identifier(depth + 1)? {
                let region = if self.eat_punctuation(Punctuation::LeftBracket)? {
                    if !self.eat_keyword(Keyword::Region)? {
                        self.error_here(
                            "syntax-with-region",
                            "expected `region` in the with binding",
                        )?;
                    }
                    let region = self.parse_identifier(depth + 1)?;
                    if region.is_none() {
                        self.error_here("syntax-with-region", "expected a lexical region name")?;
                    }
                    if !self.eat_punctuation(Punctuation::RightBracket)? {
                        self.error_here(
                            "syntax-with-region",
                            "expected `]` after the lexical region name",
                        )?;
                    }
                    region
                } else {
                    None
                };
                Some(WithBinding {
                    meta: self.meta(start, self.position)?,
                    name,
                    region,
                })
            } else {
                self.error_here("syntax-with-binding", "expected a with binding name")?;
                None
            }
        } else {
            None
        };
        self.expect_suite_colon("with")?;
        let body = self.parse_suite(depth + 1)?;
        Ok(StatementKind::With {
            value,
            binding,
            body,
        })
    }

    fn find_with_binding_separator(&mut self) -> Result<Option<usize>, ParseFailure> {
        let mut nesting = 0u32;
        let mut index = self.position;
        while let Some(token) = self.lexical.tokens.get(index) {
            self.cancellation.work()?;
            match token.kind {
                TokenKind::Punctuation(
                    Punctuation::LeftParen | Punctuation::LeftBracket | Punctuation::LeftBrace,
                ) => {
                    nesting = nesting.checked_add(1).ok_or(ParseFailure::ResourceLimit {
                        resource: "parser nesting depth",
                        limit: u64::from(self.limits.nesting_depth),
                    })?;
                    if nesting > self.limits.nesting_depth {
                        return Err(ParseFailure::ResourceLimit {
                            resource: "parser nesting depth",
                            limit: u64::from(self.limits.nesting_depth),
                        });
                    }
                }
                TokenKind::Punctuation(
                    Punctuation::RightParen | Punctuation::RightBracket | Punctuation::RightBrace,
                ) => {
                    nesting = nesting.saturating_sub(1);
                }
                TokenKind::Keyword(Keyword::As)
                    if nesting == 0 && self.is_with_binding_tail(index + 1) =>
                {
                    return Ok(Some(index));
                }
                TokenKind::Newline | TokenKind::Dedent | TokenKind::EndOfFile => return Ok(None),
                _ => {}
            }
            index += 1;
        }
        Ok(None)
    }

    fn is_with_binding_tail(&self, start: usize) -> bool {
        if self.lexical.tokens.get(start).map(|token| token.kind) != Some(TokenKind::Identifier) {
            return false;
        }
        let mut index = start + 1;
        if self.lexical.tokens.get(index).map(|token| token.kind)
            == Some(TokenKind::Punctuation(Punctuation::LeftBracket))
        {
            if self.lexical.tokens.get(index + 1).map(|token| token.kind)
                != Some(TokenKind::Keyword(Keyword::Region))
                || self.lexical.tokens.get(index + 2).map(|token| token.kind)
                    != Some(TokenKind::Identifier)
                || self.lexical.tokens.get(index + 3).map(|token| token.kind)
                    != Some(TokenKind::Punctuation(Punctuation::RightBracket))
            {
                return false;
            }
            index += 4;
        }
        self.lexical.tokens.get(index).map(|token| token.kind)
            == Some(TokenKind::Punctuation(Punctuation::Colon))
    }

    fn parse_comptime_statement_if(&mut self, depth: u32) -> Result<StatementKind, ParseFailure> {
        self.bump()?;
        self.bump()?;
        let condition = self.parse_expression(depth + 1)?;
        self.expect_suite_colon("comptime if")?;
        let then_suite = self.parse_suite(depth + 1)?;
        let else_suite = if self.newline_precedes_comptime_else() {
            self.bump()?;
            self.bump()?;
            self.bump()?;
            self.expect_suite_colon("comptime else")?;
            Some(self.parse_suite(depth + 1)?)
        } else {
            None
        };
        Ok(StatementKind::ComptimeIf {
            condition,
            then_suite,
            else_suite,
        })
    }

    fn expect_suite_colon(&mut self, construct: &'static str) -> Result<(), ParseFailure> {
        if !self.eat_punctuation(Punctuation::Colon)? {
            self.error_here(
                "syntax-expected-suite-colon",
                &format!("expected `:` before the {construct} suite"),
            )?;
        }
        Ok(())
    }

    fn newline_precedes_keyword(&self, keyword: Keyword) -> bool {
        self.at(TokenKind::Newline) && self.nth_kind(1) == Some(TokenKind::Keyword(keyword))
    }

    fn parse_assert(&mut self, depth: u32, comptime: bool) -> Result<StatementKind, ParseFailure> {
        if !comptime {
            self.bump()?;
        } else if !self.eat_keyword(Keyword::Assert)? {
            self.error_here(
                "syntax-expected-assert",
                "expected `assert` after `comptime`",
            )?;
        }
        let condition = self.parse_expression(depth)?;
        let message = if self.eat_punctuation(Punctuation::Comma)? {
            if self.at(TokenKind::StringLiteral) {
                Some(self.parse_literal_node(depth + 1)?)
            } else {
                self.error_here(
                    "syntax-assert-message",
                    "assert messages must be plain string literals",
                )?;
                self.skip_to_statement_terminator()?;
                None
            }
        } else {
            None
        };
        Ok(if comptime {
            StatementKind::ComptimeAssert { condition, message }
        } else {
            StatementKind::Assert { condition, message }
        })
    }

    fn starts_local_assignment(&self) -> bool {
        matches!(
            self.nth_kind(1),
            Some(
                TokenKind::Operator(Operator::Assign) | TokenKind::Punctuation(Punctuation::Colon)
            )
        )
    }

    fn parse_local_assignment(
        &mut self,
        depth: u32,
        shadow: bool,
    ) -> Result<StatementKind, ParseFailure> {
        if shadow {
            self.bump()?;
        }
        let Some(name) = self.parse_identifier(depth + 1)? else {
            let error = self.error_expression(self.position, self.position, depth + 1)?;
            self.error_here(
                "syntax-expected-local-name",
                "expected an identifier in the local assignment",
            )?;
            return Ok(StatementKind::Expression(error));
        };
        let ty = if self.eat_punctuation(Punctuation::Colon)? {
            Some(self.parse_type(depth + 1)?)
        } else {
            None
        };
        if !self.eat_operator(Operator::Assign)? {
            self.error_here(
                "syntax-expected-assignment",
                "expected `=` in the local assignment",
            )?;
        }
        let value = self.parse_expression(depth + 1)?;
        Ok(StatementKind::LocalAssignment {
            shadow,
            name,
            ty,
            value,
        })
    }

    fn assignment_operator(&self) -> Option<AssignmentOperator> {
        Some(match self.kind() {
            TokenKind::Operator(Operator::Assign) => AssignmentOperator::Assign,
            TokenKind::Operator(Operator::AddAssign) => AssignmentOperator::Add,
            TokenKind::Operator(Operator::SubtractAssign) => AssignmentOperator::Subtract,
            TokenKind::Operator(Operator::MultiplyAssign) => AssignmentOperator::Multiply,
            TokenKind::Operator(Operator::DivideAssign) => AssignmentOperator::Divide,
            TokenKind::Operator(Operator::RemainderAssign) => AssignmentOperator::Remainder,
            TokenKind::Operator(Operator::BitAndAssign) => AssignmentOperator::BitAnd,
            TokenKind::Operator(Operator::BitOrAssign) => AssignmentOperator::BitOr,
            TokenKind::Operator(Operator::BitXorAssign) => AssignmentOperator::BitXor,
            TokenKind::Operator(Operator::ShiftLeftAssign) => AssignmentOperator::ShiftLeft,
            TokenKind::Operator(Operator::ShiftRightAssign) => AssignmentOperator::ShiftRight,
            _ => return None,
        })
    }

    fn parse_type(&mut self, depth: u32) -> Result<TypeExpression, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        match self.kind() {
            TokenKind::Identifier | TokenKind::Keyword(Keyword::Unit) => {
                let accepts_unit = self.at_keyword(Keyword::Unit);
                let name = self
                    .parse_qualified_name(depth + 1, accepts_unit)?
                    .ok_or_else(|| {
                        ParseFailure::InternalInvariant(
                            "named type token did not produce a qualified name".to_owned(),
                        )
                    })?;
                let arguments = if self.eat_punctuation(Punctuation::LeftBracket)? {
                    self.parse_unclassified_type_arguments(depth + 1)?
                } else {
                    Vec::new()
                };
                Ok(TypeExpression {
                    meta: self.meta(start, self.position)?,
                    kind: TypeExpressionKind::Named { name, arguments },
                })
            }
            TokenKind::Punctuation(Punctuation::LeftBracket) => {
                self.bump()?;
                let element = self.parse_type(depth + 1)?;
                if !self.eat_punctuation(Punctuation::Semicolon)? {
                    self.error_here(
                        "syntax-array-type-semicolon",
                        "expected `;` between the array element type and length",
                    )?;
                }
                let length = self.parse_expression(depth + 1)?;
                if !self.eat_punctuation(Punctuation::RightBracket)? {
                    self.error_here(
                        "syntax-unclosed-array-type",
                        "expected `]` to close the array type",
                    )?;
                }
                Ok(TypeExpression {
                    meta: self.meta(start, self.position)?,
                    kind: TypeExpressionKind::Array {
                        element: Box::new(element),
                        length: Box::new(length),
                    },
                })
            }
            TokenKind::Punctuation(Punctuation::LeftParen) => {
                self.bump()?;
                let first = self.parse_type(depth + 1)?;
                if !self.eat_punctuation(Punctuation::Comma)? {
                    self.error_here(
                        "syntax-tuple-type-comma",
                        "tuple types require a comma; grouping is not a type form",
                    )?;
                }
                let mut elements = Vec::new();
                push_ast_value(&mut elements, first, self.limits.ast_nodes)?;
                while !self.at_punctuation(Punctuation::RightParen)
                    && !self.at(TokenKind::EndOfFile)
                    && !self.at(TokenKind::Newline)
                {
                    let element = self.parse_type(depth + 1)?;
                    push_ast_value(&mut elements, element, self.limits.ast_nodes)?;
                    if !self.eat_punctuation(Punctuation::Comma)? {
                        break;
                    }
                }
                if !self.eat_punctuation(Punctuation::RightParen)? {
                    self.error_here(
                        "syntax-unclosed-tuple-type",
                        "expected `)` to close the tuple type",
                    )?;
                }
                Ok(TypeExpression {
                    meta: self.meta(start, self.position)?,
                    kind: TypeExpressionKind::Tuple(elements),
                })
            }
            TokenKind::Keyword(Keyword::View) => {
                self.bump()?;
                let target = self.parse_type(depth + 1)?;
                Ok(TypeExpression {
                    meta: self.meta(start, self.position)?,
                    kind: TypeExpressionKind::View {
                        mutable: false,
                        target: Box::new(target),
                    },
                })
            }
            TokenKind::Keyword(Keyword::Mut)
                if self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::View)) =>
            {
                self.bump()?;
                self.bump()?;
                let target = self.parse_type(depth + 1)?;
                Ok(TypeExpression {
                    meta: self.meta(start, self.position)?,
                    kind: TypeExpressionKind::View {
                        mutable: true,
                        target: Box::new(target),
                    },
                })
            }
            TokenKind::Keyword(Keyword::Iso) => {
                self.bump()?;
                if !self.eat_punctuation(Punctuation::LeftBracket)? {
                    self.error_here("syntax-iso-brand", "expected `[` before the iso brand type")?;
                }
                let brand = self.parse_type(depth + 1)?;
                if !self.eat_punctuation(Punctuation::RightBracket)? {
                    self.error_here("syntax-iso-brand", "expected `]` after the iso brand type")?;
                }
                let payload = self.parse_type(depth + 1)?;
                Ok(TypeExpression {
                    meta: self.meta(start, self.position)?,
                    kind: TypeExpressionKind::Iso {
                        brand: Box::new(brand),
                        payload: Box::new(payload),
                    },
                })
            }
            TokenKind::Keyword(Keyword::Fn) | TokenKind::Keyword(Keyword::Async)
                if self.at_keyword(Keyword::Fn)
                    || self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::Fn)) =>
            {
                self.parse_function_type(depth, start)
            }
            _ => {
                self.error_here(
                    "syntax-expected-type",
                    "expected a named, array, tuple, view, iso, or function type",
                )?;
                if !self.is_type_terminator() {
                    self.bump()?;
                }
                self.error_type(start, self.position, depth)
            }
        }
    }

    fn parse_function_type(
        &mut self,
        depth: u32,
        start: usize,
    ) -> Result<TypeExpression, ParseFailure> {
        let asynchronous = self.eat_keyword(Keyword::Async)?;
        if !self.eat_keyword(Keyword::Fn)? {
            self.error_here(
                "syntax-function-type-fn",
                "expected `fn` in the function type",
            )?;
        }
        if !self.eat_punctuation(Punctuation::LeftParen)? {
            self.error_here(
                "syntax-function-type-parameters",
                "expected `(` before function-type parameters",
            )?;
        }
        let mut parameters = Vec::new();
        while !self.at_punctuation(Punctuation::RightParen)
            && !self.at(TokenKind::EndOfFile)
            && !self.at(TokenKind::Newline)
        {
            let parameter_start = self.position;
            let access = self.parse_access_mode()?;
            let ty = self.parse_type(depth + 1)?;
            let parameter = FunctionTypeParameter {
                meta: self.meta(parameter_start, self.position)?,
                access,
                ty,
            };
            push_ast_value(&mut parameters, parameter, self.limits.ast_nodes)?;
            if !self.eat_punctuation(Punctuation::Comma)? {
                break;
            }
        }
        if !self.eat_punctuation(Punctuation::RightParen)? {
            self.error_here(
                "syntax-function-type-parameters",
                "expected `)` after function-type parameters",
            )?;
        }
        if !self.eat_punctuation(Punctuation::Arrow)? {
            self.error_here(
                "syntax-function-type-arrow",
                "expected `->` before the function result type",
            )?;
        }
        let result = self.parse_type(depth + 1)?;
        Ok(TypeExpression {
            meta: self.meta(start, self.position)?,
            kind: TypeExpressionKind::Function {
                asynchronous,
                parameters,
                result: Box::new(result),
            },
        })
    }

    fn parse_unclassified_type_arguments(
        &mut self,
        depth: u32,
    ) -> Result<Vec<BracketArgument>, ParseFailure> {
        let mut arguments = Vec::new();
        let mut item_start = self.position;
        let mut nesting = 0u32;
        while !self.at(TokenKind::EndOfFile) && !self.at(TokenKind::Newline) {
            if self.at_punctuation(Punctuation::RightBracket) && nesting == 0 {
                if item_start < self.position {
                    let argument = self.parse_type_argument(item_start, depth)?;
                    push_ast_value(&mut arguments, argument, self.limits.ast_nodes)?;
                } else if arguments.is_empty() {
                    self.error_here(
                        "syntax-empty-type-arguments",
                        "type argument lists require at least one argument",
                    )?;
                }
                self.bump()?;
                return Ok(arguments);
            }
            if self.at_punctuation(Punctuation::Comma) && nesting == 0 {
                if item_start < self.position {
                    let argument = self.parse_type_argument(item_start, depth)?;
                    push_ast_value(&mut arguments, argument, self.limits.ast_nodes)?;
                } else {
                    self.error_here(
                        "syntax-empty-type-argument",
                        "expected a type or constant argument before `,`",
                    )?;
                }
                self.bump()?;
                item_start = self.position;
                continue;
            }
            match self.kind() {
                TokenKind::Punctuation(
                    Punctuation::LeftParen | Punctuation::LeftBracket | Punctuation::LeftBrace,
                ) => nesting += 1,
                TokenKind::Punctuation(
                    Punctuation::RightParen | Punctuation::RightBracket | Punctuation::RightBrace,
                ) if nesting > 0 => nesting -= 1,
                _ => {}
            }
            self.bump()?;
        }
        self.error_here(
            "syntax-unclosed-type-arguments",
            "expected `]` to close type arguments",
        )?;
        if item_start < self.position {
            let argument = self.parse_type_argument(item_start, depth)?;
            push_ast_value(&mut arguments, argument, self.limits.ast_nodes)?;
        }
        Ok(arguments)
    }

    fn parse_type_argument(
        &mut self,
        start: usize,
        depth: u32,
    ) -> Result<BracketArgument, ParseFailure> {
        let end = self.position;
        if self.lexical.tokens.get(start).map(|token| token.kind)
            == Some(TokenKind::Operator(Operator::Range))
        {
            let saved = self.position;
            self.position = start;
            self.bump()?;
            let maximum = self.parse_expression(depth + 1)?;
            if self.position != end {
                self.diagnostics.error(
                    "syntax-bounded-capacity-argument",
                    self.current().span.range.start as usize,
                    self.token_end(end),
                    "bounded-capacity argument must contain exactly one expression after `..`"
                        .to_owned(),
                )?;
                self.position = end;
            }
            let argument = BracketArgument::BoundedCapacity {
                meta: self.meta(start, end)?,
                maximum,
            };
            self.position = saved;
            Ok(argument)
        } else {
            self.unclassified_argument(start, end, depth)
        }
    }

    fn unclassified_argument(
        &mut self,
        start: usize,
        end: usize,
        _depth: u32,
    ) -> Result<BracketArgument, ParseFailure> {
        Ok(BracketArgument::UnclassifiedTypeOrExpression {
            meta: self.meta(start, end)?,
            tokens: TokenRange {
                first: TokenId(start as u32),
                end: TokenId(end as u32),
            },
        })
    }

    fn error_type(
        &mut self,
        start: usize,
        end: usize,
        depth: u32,
    ) -> Result<TypeExpression, ParseFailure> {
        let error = self.recovery_error(start, end, "qualified or primitive type", depth + 1)?;
        Ok(TypeExpression {
            meta: self.meta(start, end)?,
            kind: TypeExpressionKind::Error(error),
        })
    }

    fn parse_expression(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        self.check_depth(depth)?;
        if self.starts_closure_expression() {
            self.parse_closure_expression(depth + 1)
        } else if self.at_keyword(Keyword::If) {
            self.parse_if_expression(depth + 1)
        } else {
            self.parse_or(depth + 1)
        }
    }

    fn parse_if_expression(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        self.bump()?; // if
        let condition = Box::new(self.parse_expression(depth + 1)?);
        if !self.eat_punctuation(Punctuation::Colon)? {
            self.error_here(
                "syntax-expected-if-expression-colon",
                "expected `:` after the inline `if` condition",
            )?;
        }
        let then_branch = Box::new(self.parse_if_expression_arm(depth + 1)?);
        let mut elif_branches = Vec::new();
        while self.eat_expression_elif()? {
            let elif_condition = self.parse_expression(depth + 1)?;
            if !self.eat_punctuation(Punctuation::Colon)? {
                self.error_here(
                    "syntax-expected-if-expression-colon",
                    "expected `:` after the inline `elif` condition",
                )?;
            }
            let elif_branch = self.parse_if_expression_arm(depth + 1)?;
            push_ast_value(
                &mut elif_branches,
                (elif_condition, elif_branch),
                self.limits.ast_nodes,
            )?;
        }
        if !self.eat_expression_else()? {
            self.error_here(
                "syntax-expected-if-expression-else",
                "an inline `if` expression requires a mandatory `else` branch",
            )?;
        }
        if !self.eat_punctuation(Punctuation::Colon)? {
            self.error_here(
                "syntax-expected-if-expression-colon",
                "expected `:` after `else` in an inline `if` expression",
            )?;
        }
        let else_branch = Box::new(self.parse_if_expression_arm(depth + 1)?);
        Ok(Expression {
            meta: self.meta(start, self.position)?,
            kind: ExpressionKind::If {
                condition,
                then_branch,
                elif_branches,
                else_branch,
            },
        })
    }

    /// Tail-position / inline arm: either a single expression or a one-statement
    /// suite whose sole statement is a bare expression (chapter 2 §7.1).
    fn parse_if_expression_arm(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        self.check_depth(depth)?;
        if self.at(TokenKind::Newline) {
            let suite = self.parse_suite(depth + 1)?;
            return self.expression_from_tail_suite(suite, depth + 1);
        }
        self.parse_expression(depth + 1)
    }

    fn expression_from_tail_suite(
        &mut self,
        suite: Suite,
        depth: u32,
    ) -> Result<Expression, ParseFailure> {
        self.check_depth(depth)?;
        let [statement] = suite.statements.as_slice() else {
            let span = suite.meta.span;
            self.diagnostics.error(
                "syntax-tail-if-suite",
                span.range.start as usize,
                span.range.end as usize,
                "a tail-position `if` arm suite must contain exactly one expression statement"
                    .to_owned(),
            )?;
            return self.error_expression(self.position, self.position, depth + 1);
        };
        match &statement.kind {
            StatementKind::Expression(expression) => Ok(expression.clone()),
            _ => {
                let span = statement.meta.span;
                self.diagnostics.error(
                    "syntax-tail-if-suite",
                    span.range.start as usize,
                    span.range.end as usize,
                    "a tail-position `if` arm suite must end in a bare expression value"
                        .to_owned(),
                )?;
                self.error_expression(self.position, self.position, depth + 1)
            }
        }
    }

    fn starts_closure_expression(&self) -> bool {
        self.at_punctuation(Punctuation::Pipe)
            || (self.at_keyword(Keyword::Take)
                && self.nth_kind(1) == Some(TokenKind::Punctuation(Punctuation::Pipe)))
            || (self.at_keyword(Keyword::Async)
                && (self.nth_kind(1) == Some(TokenKind::Punctuation(Punctuation::Pipe))
                    || (self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::Take))
                        && self.nth_kind(2) == Some(TokenKind::Punctuation(Punctuation::Pipe)))))
    }

    fn parse_closure_expression(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        let asynchronous = self.eat_keyword(Keyword::Async)?;
        let take_captures = self.eat_keyword(Keyword::Take)?;
        if !self.eat_punctuation(Punctuation::Pipe)? {
            self.error_here(
                "syntax-closure-open",
                "expected `|` before closure parameters",
            )?;
        }
        let mut parameters = Vec::new();
        while !self.at_punctuation(Punctuation::Pipe)
            && !self.at(TokenKind::Newline)
            && !self.at(TokenKind::EndOfFile)
        {
            let parameter_start = self.position;
            let access = self.parse_access_mode()?;
            let Some(name) = self.parse_identifier(depth + 1)? else {
                self.error_here(
                    "syntax-closure-parameter-name",
                    "expected a closure parameter name",
                )?;
                self.recover_list_item(true)?;
                if !self.eat_punctuation(Punctuation::Comma)? {
                    break;
                }
                continue;
            };
            if !self.eat_punctuation(Punctuation::Colon)? {
                self.error_here(
                    "syntax-closure-parameter-type",
                    "closure parameters require `: Type`",
                )?;
            }
            let ty = self.parse_type(depth + 1)?;
            let parameter = Parameter {
                meta: self.meta(parameter_start, self.position)?,
                access,
                name,
                ty: Some(ty),
                receiver: false,
                positional_only: false,
            };
            push_ast_value(&mut parameters, parameter, self.limits.ast_nodes)?;
            if !self.eat_punctuation(Punctuation::Comma)? {
                break;
            }
        }
        if !self.eat_punctuation(Punctuation::Pipe)? {
            self.error_here(
                "syntax-closure-close",
                "expected `|` after closure parameters",
            )?;
        }
        let body = if self.eat_punctuation(Punctuation::Colon)? {
            ClosureBody::Suite(self.parse_suite(depth + 1)?)
        } else {
            ClosureBody::Expression(Box::new(self.parse_expression(depth + 1)?))
        };
        Ok(Expression {
            meta: self.meta(start, self.position)?,
            kind: ExpressionKind::Closure {
                asynchronous,
                take_captures,
                parameters,
                body,
            },
        })
    }

    fn parse_or(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let mut expression = self.parse_and(depth + 1)?;
        while self.eat_keyword(Keyword::Or)? {
            let start = expression.meta.tokens.first.0 as usize;
            let right = self.parse_and(depth + 1)?;
            expression = Expression {
                meta: self.meta(start, self.position)?,
                kind: ExpressionKind::Binary {
                    operator: BinaryOperator::LogicalOr,
                    left: Box::new(expression),
                    right: Box::new(right),
                },
            };
        }
        Ok(expression)
    }

    fn parse_and(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let mut expression = self.parse_not(depth + 1)?;
        while self.eat_keyword(Keyword::And)? {
            let start = expression.meta.tokens.first.0 as usize;
            let right = self.parse_not(depth + 1)?;
            expression = Expression {
                meta: self.meta(start, self.position)?,
                kind: ExpressionKind::Binary {
                    operator: BinaryOperator::LogicalAnd,
                    left: Box::new(expression),
                    right: Box::new(right),
                },
            };
        }
        Ok(expression)
    }

    fn parse_not(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        self.check_depth(depth)?;
        if self.at_keyword(Keyword::Not) {
            let start = self.position;
            self.bump()?;
            let operand = self.parse_not(depth + 1)?;
            return Ok(Expression {
                meta: self.meta(start, self.position)?,
                kind: ExpressionKind::Unary {
                    operator: UnaryOperator::BoolNot,
                    operand: Box::new(operand),
                },
            });
        }
        self.parse_comparison(depth + 1)
    }

    fn parse_comparison(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let first = self.parse_range(depth + 1)?;
        if self.eat_keyword(Keyword::Is)? {
            let start = first.meta.tokens.first.0 as usize;
            let negated = self.eat_keyword(Keyword::Not)?;
            let pattern = self.parse_pattern(depth + 1)?;
            let mut expression = Expression {
                meta: self.meta(start, self.position)?,
                kind: ExpressionKind::IsPattern {
                    value: Box::new(first),
                    negated,
                    pattern: Box::new(pattern),
                },
            };
            if self.comparison_operator().is_some() || self.at_keyword(Keyword::Is) {
                self.error_here(
                    "syntax-comparison-chain",
                    "comparison operators do not chain; combine comparisons explicitly with `and`",
                )?;
                self.skip_expression_tail()?;
                expression.meta = self.meta_without_id(expression.meta.id, start, self.position);
            }
            return Ok(expression);
        }
        let Some(operator) = self.comparison_operator() else {
            return Ok(first);
        };
        let start = first.meta.tokens.first.0 as usize;
        self.consume_comparison_operator(operator)?;
        let right = self.parse_range(depth + 1)?;
        let mut tails = Vec::new();
        push_ast_value(
            &mut tails,
            ComparisonTail { operator, right },
            self.limits.ast_nodes,
        )?;
        let mut expression = Expression {
            meta: self.meta(start, self.position)?,
            kind: ExpressionKind::Comparison {
                first: Box::new(first),
                tails,
            },
        };
        if self.comparison_operator().is_some() || self.at_keyword(Keyword::Is) {
            self.error_here(
                "syntax-comparison-chain",
                "comparison operators do not chain; combine comparisons explicitly with `and`",
            )?;
            self.skip_expression_tail()?;
            expression.meta = self.meta_without_id(expression.meta.id, start, self.position);
        }
        Ok(expression)
    }

    fn comparison_operator(&self) -> Option<ComparisonOperator> {
        Some(match self.kind() {
            TokenKind::Operator(Operator::Equal) => ComparisonOperator::Equal,
            TokenKind::Operator(Operator::NotEqual) => ComparisonOperator::NotEqual,
            TokenKind::Operator(Operator::Less) => ComparisonOperator::Less,
            TokenKind::Operator(Operator::LessEqual) => ComparisonOperator::LessEqual,
            TokenKind::Operator(Operator::Greater) => ComparisonOperator::Greater,
            TokenKind::Operator(Operator::GreaterEqual) => ComparisonOperator::GreaterEqual,
            TokenKind::Keyword(Keyword::In) => ComparisonOperator::In,
            TokenKind::Keyword(Keyword::Not)
                if self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::In)) =>
            {
                ComparisonOperator::NotIn
            }
            _ => return None,
        })
    }

    fn consume_comparison_operator(
        &mut self,
        operator: ComparisonOperator,
    ) -> Result<(), ParseFailure> {
        self.bump()?;
        if operator == ComparisonOperator::NotIn {
            self.bump()?;
        }
        Ok(())
    }

    fn parse_range(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let start = self.position;
        let expression = self.parse_bit_or(depth + 1)?;
        let inclusive = if self.eat_operator(Operator::RangeInclusive)? {
            Some(true)
        } else if self.eat_operator(Operator::Range)? {
            Some(false)
        } else {
            None
        };
        if let Some(inclusive) = inclusive {
            let end = self.parse_bit_or(depth + 1)?;
            Ok(Expression {
                meta: self.meta(start, self.position)?,
                kind: ExpressionKind::Range {
                    start: Box::new(expression),
                    end: Box::new(end),
                    inclusive,
                },
            })
        } else {
            Ok(expression)
        }
    }

    fn parse_bit_or(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let mut expression = self.parse_bit_xor(depth + 1)?;
        while self.eat_operator(Operator::BitOr)? || self.eat_punctuation(Punctuation::Pipe)? {
            expression = self.binary(
                expression,
                BinaryOperator::BitOr,
                Self::parse_bit_xor,
                depth + 1,
            )?;
        }
        Ok(expression)
    }

    fn parse_bit_xor(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let mut expression = self.parse_bit_and(depth + 1)?;
        while self.eat_operator(Operator::BitXor)? {
            expression = self.binary(
                expression,
                BinaryOperator::BitXor,
                Self::parse_bit_and,
                depth + 1,
            )?;
        }
        Ok(expression)
    }

    fn parse_bit_and(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let mut expression = self.parse_shift(depth + 1)?;
        while self.eat_operator(Operator::BitAnd)? {
            expression = self.binary(
                expression,
                BinaryOperator::BitAnd,
                Self::parse_shift,
                depth + 1,
            )?;
        }
        Ok(expression)
    }

    fn parse_shift(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let mut expression = self.parse_additive(depth + 1)?;
        loop {
            let operator = match self.kind() {
                TokenKind::Operator(Operator::ShiftLeft) => BinaryOperator::ShiftLeft,
                TokenKind::Operator(Operator::ShiftRight) => BinaryOperator::ShiftRight,
                _ => break,
            };
            self.bump()?;
            expression = self.binary(expression, operator, Self::parse_additive, depth + 1)?;
        }
        Ok(expression)
    }

    fn parse_additive(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let mut expression = self.parse_multiplicative(depth + 1)?;
        loop {
            let operator = match self.kind() {
                TokenKind::Operator(Operator::Add) => BinaryOperator::Add,
                TokenKind::Operator(Operator::AddWrapping) => BinaryOperator::AddWrapping,
                TokenKind::Operator(Operator::Subtract) => BinaryOperator::Subtract,
                TokenKind::Operator(Operator::SubtractWrapping) => BinaryOperator::SubtractWrapping,
                _ => break,
            };
            self.bump()?;
            expression =
                self.binary(expression, operator, Self::parse_multiplicative, depth + 1)?;
        }
        Ok(expression)
    }

    fn parse_multiplicative(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let mut expression = self.parse_cast(depth + 1)?;
        loop {
            let operator = match self.kind() {
                TokenKind::Operator(Operator::Multiply) => BinaryOperator::Multiply,
                TokenKind::Operator(Operator::MultiplyWrapping) => BinaryOperator::MultiplyWrapping,
                TokenKind::Operator(Operator::Divide) => BinaryOperator::Divide,
                TokenKind::Operator(Operator::Remainder) => BinaryOperator::Remainder,
                _ => break,
            };
            self.bump()?;
            expression = self.binary(expression, operator, Self::parse_cast, depth + 1)?;
        }
        Ok(expression)
    }

    fn binary(
        &mut self,
        left: Expression,
        operator: BinaryOperator,
        parse_right: fn(&mut Self, u32) -> Result<Expression, ParseFailure>,
        depth: u32,
    ) -> Result<Expression, ParseFailure> {
        let start = left.meta.tokens.first.0 as usize;
        let right = parse_right(self, depth)?;
        Ok(Expression {
            meta: self.meta(start, self.position)?,
            kind: ExpressionKind::Binary {
                operator,
                left: Box::new(left),
                right: Box::new(right),
            },
        })
    }

    fn parse_cast(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let mut expression = self.parse_try(depth + 1)?;
        while self.eat_keyword(Keyword::As)? {
            let start = expression.meta.tokens.first.0 as usize;
            let ty = self.parse_type(depth + 1)?;
            expression = Expression {
                meta: self.meta(start, self.position)?,
                kind: ExpressionKind::Cast {
                    value: Box::new(expression),
                    ty: Box::new(ty),
                },
            };
        }
        Ok(expression)
    }

    fn parse_try(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let mut expression = self.parse_unary(depth + 1)?;
        while self.eat_punctuation(Punctuation::Question)? {
            let start = expression.meta.tokens.first.0 as usize;
            expression = Expression {
                meta: self.meta(start, self.position)?,
                kind: ExpressionKind::Try(Box::new(expression)),
            };
        }
        Ok(expression)
    }

    fn parse_unary(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        self.check_depth(depth)?;
        let operator = match self.kind() {
            TokenKind::Operator(Operator::Subtract) => UnaryOperator::Negate,
            TokenKind::Operator(Operator::BitNot) => UnaryOperator::BitNot,
            TokenKind::Keyword(Keyword::Await) => UnaryOperator::Await,
            TokenKind::Keyword(Keyword::Take) => UnaryOperator::Take,
            TokenKind::Keyword(Keyword::Copy) => UnaryOperator::Copy,
            TokenKind::Keyword(Keyword::Comptime) => UnaryOperator::Comptime,
            _ => return self.parse_postfix(depth + 1),
        };
        let start = self.position;
        self.bump()?;
        let operand = self.parse_unary(depth + 1)?;
        Ok(Expression {
            meta: self.meta(start, self.position)?,
            kind: ExpressionKind::Unary {
                operator,
                operand: Box::new(operand),
            },
        })
    }

    fn parse_postfix(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let mut expression = self.parse_primary(depth + 1)?;
        loop {
            if self.eat_punctuation(Punctuation::Dot)? {
                let Some(field) = self.parse_identifier(depth + 1)? else {
                    self.error_here("syntax-expected-field", "expected an identifier after `.`")?;
                    break;
                };
                let start = expression.meta.tokens.first.0 as usize;
                expression = Expression {
                    meta: self.meta(start, self.position)?,
                    kind: ExpressionKind::Field {
                        base: Box::new(expression),
                        field,
                    },
                };
            } else if self.eat_punctuation(Punctuation::LeftParen)? {
                let start = expression.meta.tokens.first.0 as usize;
                let arguments = self.parse_arguments(depth + 1)?;
                expression = Expression {
                    meta: self.meta(start, self.position)?,
                    kind: ExpressionKind::Call {
                        callee: Box::new(expression),
                        arguments,
                    },
                };
            } else if self.eat_punctuation(Punctuation::LeftBracket)? {
                let start = expression.meta.tokens.first.0 as usize;
                let index = self.parse_expression(depth + 1)?;
                if !self.eat_punctuation(Punctuation::RightBracket)? {
                    self.error_here(
                        "syntax-unclosed-index",
                        "expected `]` to close the index expression",
                    )?;
                }
                expression = Expression {
                    meta: self.meta(start, self.position)?,
                    kind: ExpressionKind::Index {
                        base: Box::new(expression),
                        index: Box::new(index),
                    },
                };
            } else {
                break;
            }
        }
        Ok(expression)
    }

    fn parse_arguments(&mut self, depth: u32) -> Result<Vec<Argument>, ParseFailure> {
        let mut arguments = Vec::new();
        while !self.at_punctuation(Punctuation::RightParen)
            && !self.at(TokenKind::EndOfFile)
            && !self.at(TokenKind::Newline)
        {
            let start = self.position;
            let named = self.at(TokenKind::Identifier)
                && self.nth_kind(1) == Some(TokenKind::Operator(Operator::Assign));
            let name = if named {
                let name = self.parse_identifier(depth + 1)?;
                self.bump()?;
                name
            } else {
                None
            };
            let exclusive = match self.kind() {
                TokenKind::Keyword(Keyword::Mut) => {
                    self.bump()?;
                    Some(ExclusiveAccess::Mutate)
                }
                TokenKind::Keyword(Keyword::Take) => {
                    self.bump()?;
                    Some(ExclusiveAccess::Take)
                }
                _ => None,
            };
            let expression = self.parse_expression(depth + 1)?;
            let value = if let Some(access) = exclusive {
                if !Self::is_place_expression(&expression) {
                    self.diagnostics.error(
                        "syntax-access-place",
                        expression.meta.span.range.start as usize,
                        expression.meta.span.range.end as usize,
                        "`mut` and `take` call operands must be places".to_owned(),
                    )?;
                    ArgumentValue::InvalidExclusive { access, expression }
                } else {
                    ArgumentValue::Exclusive {
                        access,
                        place: expression,
                    }
                }
            } else {
                ArgumentValue::Value(expression)
            };
            let argument = Argument {
                meta: self.meta(start, self.position)?,
                name,
                value,
            };
            push_ast_value(&mut arguments, argument, self.limits.ast_nodes)?;
            if !self.eat_punctuation(Punctuation::Comma)? {
                break;
            }
        }
        if !self.eat_punctuation(Punctuation::RightParen)? {
            self.error_here(
                "syntax-unclosed-call",
                "expected `)` to close call arguments",
            )?;
        }
        Ok(arguments)
    }

    fn parse_primary(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        match self.kind() {
            TokenKind::IntegerLiteral
            | TokenKind::FloatLiteral
            | TokenKind::StringLiteral
            | TokenKind::ByteStringLiteral
            | TokenKind::CharacterLiteral
            | TokenKind::Keyword(Keyword::True | Keyword::False | Keyword::Unit) => {
                let literal = self.parse_literal_node(depth + 1)?;
                Ok(Expression {
                    meta: self.meta(start, self.position)?,
                    kind: ExpressionKind::Literal(literal),
                })
            }
            TokenKind::InterpolatedStringStart => self.parse_interpolated(depth + 1),
            TokenKind::Identifier | TokenKind::Keyword(Keyword::SelfValue) => {
                let identifier = self.identifier_from_current(depth + 2)?.ok_or_else(|| {
                    ParseFailure::InternalInvariant(
                        "name token could not form an identifier node".to_owned(),
                    )
                })?;
                let mut segments = Vec::new();
                push_ast_value(&mut segments, identifier, self.limits.ast_nodes)?;
                let name = QualifiedName {
                    meta: self.meta(start, self.position)?,
                    segments,
                };
                Ok(Expression {
                    meta: self.meta(start, self.position)?,
                    kind: ExpressionKind::Name(name),
                })
            }
            TokenKind::Punctuation(Punctuation::Dot) => {
                self.bump()?;
                let Some(name) = self.parse_identifier(depth + 1)? else {
                    self.error_here(
                        "syntax-expected-dot-variant-name",
                        "expected an identifier after `.`",
                    )?;
                    return self.error_expression(start, self.position, depth);
                };
                Ok(Expression {
                    meta: self.meta(start, self.position)?,
                    kind: ExpressionKind::DotName {
                        meta: self.meta(start, self.position)?,
                        name,
                    },
                })
            }
            TokenKind::Punctuation(Punctuation::LeftParen) => {
                self.bump()?;
                if self.at_punctuation(Punctuation::RightParen) {
                    self.error_here(
                        "syntax-empty-parentheses",
                        "empty parentheses are not a value; write `unit`",
                    )?;
                    self.bump()?;
                    return self.error_expression(start, self.position, depth);
                }
                let first = self.parse_expression(depth + 1)?;
                if self.eat_punctuation(Punctuation::Comma)? {
                    let mut values = Vec::new();
                    push_ast_value(&mut values, first, self.limits.ast_nodes)?;
                    while !self.at_punctuation(Punctuation::RightParen)
                        && !self.at(TokenKind::EndOfFile)
                    {
                        let value = self.parse_expression(depth + 1)?;
                        push_ast_value(&mut values, value, self.limits.ast_nodes)?;
                        if !self.eat_punctuation(Punctuation::Comma)? {
                            break;
                        }
                    }
                    if !self.eat_punctuation(Punctuation::RightParen)? {
                        self.error_here(
                            "syntax-unclosed-tuple",
                            "expected `)` to close tuple expression",
                        )?;
                    }
                    Ok(Expression {
                        meta: self.meta(start, self.position)?,
                        kind: ExpressionKind::Tuple(values),
                    })
                } else {
                    if !self.eat_punctuation(Punctuation::RightParen)? {
                        self.error_here(
                            "syntax-unclosed-parentheses",
                            "expected `)` to close parenthesized expression",
                        )?;
                    }
                    Ok(Expression {
                        meta: self.meta(start, self.position)?,
                        kind: ExpressionKind::Parenthesized(Box::new(first)),
                    })
                }
            }
            TokenKind::Punctuation(Punctuation::LeftBracket) => {
                self.bump()?;
                let mut values = Vec::new();
                while !self.at_punctuation(Punctuation::RightBracket)
                    && !self.at(TokenKind::EndOfFile)
                {
                    let value = self.parse_expression(depth + 1)?;
                    push_ast_value(&mut values, value, self.limits.ast_nodes)?;
                    if !self.eat_punctuation(Punctuation::Comma)? {
                        break;
                    }
                }
                if !self.eat_punctuation(Punctuation::RightBracket)? {
                    self.error_here(
                        "syntax-unclosed-array",
                        "expected `]` to close array expression",
                    )?;
                }
                Ok(Expression {
                    meta: self.meta(start, self.position)?,
                    kind: ExpressionKind::Array(values),
                })
            }
            TokenKind::Keyword(Keyword::Try)
                if self.nth_kind(1) == Some(TokenKind::Keyword(Keyword::Send)) =>
            {
                self.parse_try_send_expression(depth + 1)
            }
            _ => {
                self.error_here(
                    "syntax-expected-expression",
                    "expected a literal, name, or delimited expression",
                )?;
                if !self.is_expression_terminator() {
                    self.bump()?;
                }
                self.error_expression(start, self.position, depth)
            }
        }
    }

    fn parse_try_send_expression(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        self.bump()?;
        self.bump()?;
        let call = self.parse_postfix(depth + 1)?;
        if !matches!(call.kind, ExpressionKind::Call { .. }) {
            self.diagnostics.error(
                "syntax-try-send-call",
                call.meta.span.range.start as usize,
                call.meta.span.range.end as usize,
                "`try send` requires a call expression".to_owned(),
            )?;
        }
        Ok(Expression {
            meta: self.meta(start, self.position)?,
            kind: ExpressionKind::TrySend(Box::new(call)),
        })
    }

    fn parse_literal_node(&mut self, _depth: u32) -> Result<Literal, ParseFailure> {
        let start = self.position;
        let kind = match self.kind() {
            TokenKind::IntegerLiteral => LiteralKind::Integer,
            TokenKind::FloatLiteral => LiteralKind::Float,
            TokenKind::StringLiteral => LiteralKind::String,
            TokenKind::ByteStringLiteral => LiteralKind::ByteString,
            TokenKind::CharacterLiteral => LiteralKind::Character,
            TokenKind::Keyword(Keyword::True | Keyword::False) => LiteralKind::Boolean,
            TokenKind::Keyword(Keyword::Unit) => LiteralKind::Unit,
            _ => {
                return Err(ParseFailure::InternalInvariant(
                    "literal parser called on a non-literal token".to_owned(),
                ));
            }
        };
        let spelling = self.token_text(self.position).to_owned();
        let literal_bytes = self.limits.literal_bytes;
        let value = decode_literal_spelling(kind, &spelling, literal_bytes, &mut || {
            self.cancellation.work()
        })?;
        self.bump()?;
        Ok(Literal {
            meta: self.meta(start, self.position)?,
            kind,
            spelling,
            value,
        })
    }

    fn parse_interpolated(&mut self, depth: u32) -> Result<Expression, ParseFailure> {
        let start = self.position;
        self.bump()?;
        let mut parts = Vec::new();
        while !matches!(
            self.kind(),
            TokenKind::InterpolatedStringEnd
                | TokenKind::Newline
                | TokenKind::Dedent
                | TokenKind::EndOfFile
        ) {
            if self.at(TokenKind::InterpolatedStringText) {
                let span = self.current().span;
                let raw = self.token_text(self.position).to_owned();
                let decoded = self.decode_interpolation_text(&raw)?;
                self.bump()?;
                push_ast_value(
                    &mut parts,
                    InterpolationPart::Text { span, decoded },
                    self.limits.ast_nodes,
                )?;
                continue;
            }
            if self.eat_punctuation(Punctuation::LeftBrace)? {
                let expression = self.parse_expression(depth + 1)?;
                let (format, format_span) = if self.eat_punctuation(Punctuation::Colon)? {
                    if self.at(TokenKind::InterpolationFormat) {
                        let span = self.current().span;
                        let value = self.token_text(self.position).to_owned();
                        self.bump()?;
                        (Some(value), Some(span))
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                };
                if !self.eat_punctuation(Punctuation::RightBrace)? {
                    self.error_here(
                        "syntax-unmatched-interpolation-brace",
                        "expected `}` after the interpolation value",
                    )?;
                    while !matches!(
                        self.kind(),
                        TokenKind::InterpolatedStringEnd
                            | TokenKind::Newline
                            | TokenKind::Dedent
                            | TokenKind::EndOfFile
                    ) && !self.at_punctuation(Punctuation::RightBrace)
                    {
                        self.bump()?;
                    }
                    self.eat_punctuation(Punctuation::RightBrace)?;
                }
                push_ast_value(
                    &mut parts,
                    InterpolationPart::Value {
                        expression,
                        format,
                        format_span,
                    },
                    self.limits.ast_nodes,
                )?;
                continue;
            }
            self.error_here(
                "syntax-interpolation-token",
                "expected interpolation text or a `{ expression }` value",
            )?;
            self.bump()?;
        }
        self.eat(TokenKind::InterpolatedStringEnd)?;
        Ok(Expression {
            meta: self.meta(start, self.position)?,
            kind: ExpressionKind::Interpolated(parts),
        })
    }

    fn decode_interpolation_text(&mut self, raw: &str) -> Result<String, ParseFailure> {
        let mut decoded = String::new();
        decoded
            .try_reserve(raw.len())
            .map_err(|_| ParseFailure::ResourceLimit {
                resource: "literal bytes",
                limit: self.limits.literal_bytes,
            })?;
        let mut position = 0usize;
        while position < raw.len() {
            self.cancellation.work()?;
            let character = raw[position..].chars().next().ok_or_else(|| {
                ParseFailure::InternalInvariant("interpolation cursor split UTF-8".to_owned())
            })?;
            match character {
                '{' if raw[position..].starts_with("{{") => {
                    decoded.push('{');
                    position += 2;
                }
                '}' if raw[position..].starts_with("}}") => {
                    decoded.push('}');
                    position += 2;
                }
                '\\' => {
                    let escape = decode_escape(raw, position, false);
                    if let Some(EscapeValue::Scalar(value)) = escape.value {
                        decoded.push(value);
                    } else {
                        decoded.push('\u{fffd}');
                    }
                    position = escape.end.max(position + 1);
                }
                other => {
                    decoded.push(other);
                    position += other.len_utf8();
                }
            }
        }
        Ok(decoded)
    }

    fn error_expression(
        &mut self,
        start: usize,
        end: usize,
        depth: u32,
    ) -> Result<Expression, ParseFailure> {
        let error = self.recovery_error(start, end, "expression", depth + 1)?;
        Ok(Expression {
            meta: self.meta(start, end)?,
            kind: ExpressionKind::Error(error),
        })
    }

    fn parse_qualified_name(
        &mut self,
        depth: u32,
        allow_unit: bool,
    ) -> Result<Option<QualifiedName>, ParseFailure> {
        self.check_depth(depth)?;
        let start = self.position;
        let first =
            if self.at(TokenKind::Identifier) || (allow_unit && self.at_keyword(Keyword::Unit)) {
                self.identifier_from_current(depth + 1)?
            } else {
                None
            };
        let Some(first) = first else {
            return Ok(None);
        };
        let mut segments = Vec::new();
        push_ast_value(&mut segments, first, self.limits.ast_nodes)?;
        while self.at_punctuation(Punctuation::Dot) {
            if self.nth_kind(1) != Some(TokenKind::Identifier) {
                self.bump()?;
                self.error_here(
                    "syntax-expected-name-segment",
                    "expected an identifier after `.` in the qualified name",
                )?;
                break;
            }
            self.bump()?;
            if let Some(segment) = self.parse_identifier(depth + 1)? {
                push_ast_value(&mut segments, segment, self.limits.ast_nodes)?;
            }
        }
        Ok(Some(QualifiedName {
            meta: self.meta(start, self.position)?,
            segments,
        }))
    }

    fn parse_identifier(&mut self, depth: u32) -> Result<Option<Identifier>, ParseFailure> {
        if !self.at(TokenKind::Identifier) {
            return Ok(None);
        }
        self.identifier_from_current(depth)
    }

    fn identifier_from_current(&mut self, depth: u32) -> Result<Option<Identifier>, ParseFailure> {
        self.check_depth(depth)?;
        if self.at(TokenKind::EndOfFile) {
            return Ok(None);
        }
        let start = self.position;
        let spelling = self.token_text(start).to_owned();
        if spelling.is_empty() {
            return Ok(None);
        }
        self.bump()?;
        Ok(Some(Identifier {
            meta: self.meta(start, self.position)?,
            spelling,
        }))
    }

    fn identifier_from_token(
        &mut self,
        token: usize,
        depth: u32,
    ) -> Result<Identifier, ParseFailure> {
        self.check_depth(depth)?;
        let spelling = self.token_text(token).to_owned();
        if spelling.is_empty() {
            return Err(ParseFailure::InternalInvariant(
                "cannot recover an identifier from an empty token".to_owned(),
            ));
        }
        Ok(Identifier {
            meta: self.meta(token, token.saturating_add(1))?,
            spelling,
        })
    }

    fn recovery_error(
        &mut self,
        start: usize,
        end: usize,
        expected: &'static str,
        depth: u32,
    ) -> Result<ErrorNode, ParseFailure> {
        self.check_depth(depth)?;
        Ok(ErrorNode {
            meta: self.meta(start, end)?,
            expected: vec![expected.to_owned()],
        })
    }

    fn meta(&mut self, start: usize, end: usize) -> Result<NodeMeta, ParseFailure> {
        if self.next_ast_id >= self.limits.ast_nodes {
            return Err(ParseFailure::ResourceLimit {
                resource: "AST nodes",
                limit: u64::from(self.limits.ast_nodes),
            });
        }
        let id = AstId(self.next_ast_id);
        self.next_ast_id += 1;
        Ok(self.meta_without_id(id, start, end))
    }

    fn meta_without_id(&self, id: AstId, start: usize, end: usize) -> NodeMeta {
        let token_count = self.lexical.tokens.len();
        let start = start.min(token_count.saturating_sub(1));
        let end = end.min(token_count);
        let (span_start, span_end) = if start < end {
            (
                self.lexical.tokens[start].span.range.start,
                self.lexical.tokens[end - 1].span.range.end,
            )
        } else {
            // A missing child after trailing trivia belongs at the end of the
            // last consumed token. Anchoring it at the next layout token can
            // otherwise place the zero-width child beyond its parent's span.
            let offset = start
                .checked_sub(1)
                .and_then(|previous| self.lexical.tokens.get(previous))
                .map(|token| token.span.range.end)
                .or_else(|| {
                    self.lexical
                        .tokens
                        .get(start)
                        .map(|token| token.span.range.start)
                })
                .unwrap_or(self.source.text().len() as u32);
            (offset, offset)
        };
        NodeMeta {
            id,
            span: Span {
                file: self.source.id(),
                range: TextRange {
                    start: span_start,
                    end: span_end,
                },
            },
            tokens: TokenRange {
                first: TokenId(start as u32),
                end: TokenId(end as u32),
            },
        }
    }

    fn error_here(&mut self, code: &'static str, message: &str) -> Result<(), ParseFailure> {
        let span = self.current().span.range;
        self.diagnostics.error(
            code,
            span.start as usize,
            span.end as usize,
            message.to_owned(),
        )
    }

    fn consume_required_line_end(
        &mut self,
        code: &'static str,
        construct: &'static str,
    ) -> Result<(), ParseFailure> {
        if self.at(TokenKind::Newline) {
            if self.current().newline_origin == Some(NewlineOrigin::Semicolon) {
                self.error_here(
                    "syntax-semicolon-declaration",
                    "semicolons may separate only simple statements inside a suite",
                )?;
            }
            self.bump()?;
        } else if !self.at(TokenKind::EndOfFile) {
            self.error_here(
                code,
                &format!("expected a logical newline after {construct}"),
            )?;
            self.recover_to_line_end()?;
            self.eat(TokenKind::Newline)?;
        }
        Ok(())
    }

    fn recover_to_line_end(&mut self) -> Result<(), ParseFailure> {
        while !matches!(
            self.kind(),
            TokenKind::Newline | TokenKind::Dedent | TokenKind::EndOfFile
        ) {
            self.bump()?;
        }
        Ok(())
    }

    fn recover_list_item(&mut self, parenthesized: bool) -> Result<(), ParseFailure> {
        while !(self.at(TokenKind::EndOfFile)
            || self.at(TokenKind::Newline)
            || self.at_punctuation(Punctuation::Comma)
            || parenthesized && self.at_punctuation(Punctuation::RightParen))
        {
            self.bump()?;
        }
        Ok(())
    }

    fn skip_to_statement_terminator(&mut self) -> Result<(), ParseFailure> {
        while !self.is_statement_terminator() {
            self.bump()?;
        }
        Ok(())
    }

    fn skip_expression_tail(&mut self) -> Result<(), ParseFailure> {
        while !self.is_expression_terminator() {
            self.bump()?;
        }
        Ok(())
    }

    fn is_statement_terminator(&self) -> bool {
        matches!(
            self.kind(),
            TokenKind::Newline | TokenKind::Dedent | TokenKind::EndOfFile
        )
    }

    fn is_expression_terminator(&self) -> bool {
        self.is_statement_terminator()
            || matches!(
                self.kind(),
                TokenKind::Punctuation(
                    Punctuation::Comma
                        | Punctuation::Colon
                        | Punctuation::RightParen
                        | Punctuation::RightBracket
                        | Punctuation::RightBrace
                ) | TokenKind::Operator(
                    Operator::Assign
                        | Operator::AddAssign
                        | Operator::SubtractAssign
                        | Operator::MultiplyAssign
                        | Operator::DivideAssign
                        | Operator::RemainderAssign
                        | Operator::BitAndAssign
                        | Operator::BitOrAssign
                        | Operator::BitXorAssign
                        | Operator::ShiftLeftAssign
                        | Operator::ShiftRightAssign
                )
            )
    }

    fn is_type_terminator(&self) -> bool {
        self.is_statement_terminator()
            || matches!(
                self.kind(),
                TokenKind::Punctuation(
                    Punctuation::Comma
                        | Punctuation::Colon
                        | Punctuation::RightParen
                        | Punctuation::RightBracket
                )
            )
    }

    fn current_description(&self) -> String {
        match self.kind() {
            TokenKind::Keyword(keyword) => format!("keyword {keyword:?}"),
            TokenKind::Identifier => format!("identifier {:?}", self.token_text(self.position)),
            kind => format!("token {kind:?}"),
        }
    }

    fn token_text(&self, index: usize) -> &str {
        self.lexical
            .tokens
            .get(index)
            .and_then(|token| self.source.slice(token.span.range))
            .unwrap_or_default()
    }

    fn token_end(&self, exclusive: usize) -> usize {
        exclusive
            .checked_sub(1)
            .and_then(|index| self.lexical.tokens.get(index))
            .map_or(self.source.text().len(), |token| {
                token.span.range.end as usize
            })
    }

    fn current(&self) -> &Token {
        self.lexical.tokens.get(self.position).unwrap_or(self.eof)
    }

    fn kind(&self) -> TokenKind {
        if self.expression_end == Some(self.position) {
            TokenKind::Newline
        } else {
            self.current().kind
        }
    }

    fn nth_kind(&self, offset: usize) -> Option<TokenKind> {
        let index = self.position.checked_add(offset)?;
        if let Some(end) = self.expression_end {
            if index == end {
                return Some(TokenKind::Newline);
            }
            if index > end {
                return None;
            }
        }
        self.lexical.tokens.get(index).map(|token| token.kind)
    }

    fn at(&self, kind: TokenKind) -> bool {
        self.kind() == kind
    }

    fn at_keyword(&self, keyword: Keyword) -> bool {
        self.at(TokenKind::Keyword(keyword))
    }

    fn at_punctuation(&self, punctuation: Punctuation) -> bool {
        self.at(TokenKind::Punctuation(punctuation))
    }

    fn bump(&mut self) -> Result<(), ParseFailure> {
        self.cancellation.work()?;
        if self.position < self.lexical.tokens.len() {
            self.position += 1;
        }
        Ok(())
    }

    fn eat(&mut self, kind: TokenKind) -> Result<bool, ParseFailure> {
        if self.at(kind) {
            self.bump()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn eat_keyword(&mut self, keyword: Keyword) -> Result<bool, ParseFailure> {
        self.eat(TokenKind::Keyword(keyword))
    }

    fn eat_expression_elif(&mut self) -> Result<bool, ParseFailure> {
        if self.newline_precedes_keyword(Keyword::Elif) {
            self.bump()?;
            self.bump()?;
            return Ok(true);
        }
        self.eat_keyword(Keyword::Elif)
    }

    fn eat_expression_else(&mut self) -> Result<bool, ParseFailure> {
        if self.newline_precedes_keyword(Keyword::Else) {
            self.bump()?;
            self.bump()?;
            return Ok(true);
        }
        self.eat_keyword(Keyword::Else)
    }

    fn eat_punctuation(&mut self, punctuation: Punctuation) -> Result<bool, ParseFailure> {
        self.eat(TokenKind::Punctuation(punctuation))
    }

    fn eat_operator(&mut self, operator: Operator) -> Result<bool, ParseFailure> {
        self.eat(TokenKind::Operator(operator))
    }

    fn check_depth(&self, depth: u32) -> Result<(), ParseFailure> {
        if depth > self.limits.nesting_depth {
            Err(ParseFailure::ResourceLimit {
                resource: "parser nesting depth",
                limit: u64::from(self.limits.nesting_depth),
            })
        } else {
            Ok(())
        }
    }
}

fn push_ast_value<T>(values: &mut Vec<T>, value: T, limit: u32) -> Result<(), ParseFailure> {
    if values.len() >= limit as usize {
        return Err(ParseFailure::ResourceLimit {
            resource: "AST nodes",
            limit: u64::from(limit),
        });
    }
    values
        .try_reserve(1)
        .map_err(|_| ParseFailure::ResourceLimit {
            resource: "AST nodes",
            limit: u64::from(limit),
        })?;
    values.push(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeSet;

    use wrela_build_model::Sha256Digest;
    use wrela_source::{SourceDatabase, SourceInput};

    use super::*;

    const REPRESENTATIVE: &str =
        include_str!("../../../tests/contracts/syntax/v3/representative.wr");
    const IMPORTS_TRIVIA: &str =
        include_str!("../../../tests/contracts/syntax/v3/imports-trivia.wr");
    const PRECEDENCE: &str = include_str!("../../../tests/contracts/syntax/v3/precedence.wr");
    const UNICODE: &str = include_str!("../../../tests/contracts/syntax/v3/unicode.wr");
    const LITERALS: &str = include_str!("../../../tests/contracts/syntax/v3/literals.wr");
    const LAYOUT: &str = include_str!("../../../tests/contracts/syntax/v3/layout.wr");
    const LAYOUT_DEDENT: &str = include_str!("../../../tests/contracts/syntax/v3/layout-dedent.wr");
    const LAYOUT_NESTED_DEDENT: &str =
        include_str!("../../../tests/contracts/syntax/v3/layout-nested-dedent.wr");
    const MALFORMED: &str = include_str!("../../../tests/contracts/syntax/v3/malformed.wr");
    const DECLARATIONS_TYPES: &str =
        include_str!("../../../tests/contracts/syntax/v3/declarations-types.wr");
    const DECLARATIONS_TYPES_MALFORMED: &str =
        include_str!("../../../tests/contracts/syntax/v3/declarations-types-malformed.wr");
    const INITIALIZERS_MALFORMED: &str =
        include_str!("../../../tests/contracts/syntax/v3/initializers-malformed.wr");
    const STATEMENTS_EXPRESSIONS: &str =
        include_str!("../../../tests/contracts/syntax/v3/statements-expressions.wr");
    const STATEMENTS_EXPRESSIONS_MALFORMED: &str =
        include_str!("../../../tests/contracts/syntax/v3/statements-expressions-malformed.wr");

    fn database(text: &str) -> (SourceDatabase, FileId) {
        let mut sources = SourceDatabase::default();
        let file = sources
            .add(SourceInput {
                path: "src/contracts.wr".to_owned(),
                text: text.to_owned(),
                digest: Sha256Digest::from_bytes([0x51; 32]),
            })
            .expect("fixture source is valid");
        (sources, file)
    }

    fn parse_with_limits(text: &str, limits: ParseLimits) -> Result<ParseOutput, ParseFailure> {
        let (sources, file) = database(text);
        WrelaSyntaxParser::new().parse(
            ParseRequest {
                sources: &sources,
                file,
                limits,
            },
            &|| false,
        )
    }

    fn parse_clean(text: &str) -> ParseOutput {
        let output = parse_with_limits(text, ParseLimits::standard()).expect("parse seals");
        assert_eq!(output.diagnostics(), &[], "unexpected diagnostics");
        output
    }

    fn scan_only(text: &str) -> (LosslessLexicalTable, Vec<Diagnostic>) {
        let (sources, file) = database(text);
        let source = sources.get(file).expect("fixture source");
        let limits = ParseLimits::standard();
        let mut diagnostics = DiagnosticSink::new(file, limits);
        let lexical = Scanner::new(source, limits, &mut diagnostics, &|| false)
            .scan()
            .expect("scanner completes");
        (lexical, diagnostics.into_diagnostics())
    }

    #[test]
    fn init_is_a_dedicated_struct_member_and_keyword() {
        assert_eq!(SYNTAX_CONTRACT_VERSION, 3);
        let output = parse_clean(
            "module contracts.initializer\nstruct Cache:\n    value: u64\n    init(mut self, value: u64):\n        self.value = value\n",
        );
        assert!(
            output
                .parsed()
                .lexical()
                .tokens
                .iter()
                .any(|token| { token.kind == TokenKind::Keyword(Keyword::Init) })
        );
        let DeclarationKind::Structure(structure) = &output.parsed().ast().declarations[0].kind
        else {
            panic!("expected struct declaration");
        };
        let MemberKind::Initializer(initializer) = &structure.members[1].kind else {
            panic!("expected dedicated initializer member");
        };
        assert_eq!(initializer.parameters.len(), 2);
        assert!(initializer.parameters[0].receiver);
        assert_eq!(initializer.parameters[0].access, AccessMode::Mutate);
        assert!(initializer.return_type.is_none());
    }

    #[test]
    fn removed_dunder_initializer_never_becomes_a_function() {
        let output = parse_with_limits(
            "module contracts.initializer\nstruct Cache:\n    fn __init__(mut self):\n        pass\n",
            ParseLimits::standard(),
        )
        .expect("removed spelling recovers");
        assert!(output.diagnostics().iter().any(|diagnostic| {
            diagnostic.code.as_deref() == Some("syntax-removed-initializer-spelling")
        }));
        let DeclarationKind::Structure(structure) = &output.parsed().ast().declarations[0].kind
        else {
            panic!("expected struct declaration");
        };
        assert!(matches!(structure.members[0].kind, MemberKind::Error(_)));
        assert!(
            !structure
                .members
                .iter()
                .any(|member| matches!(member.kind, MemberKind::Function(_)))
        );
    }

    #[test]
    fn initializer_shape_and_context_fail_explicitly() {
        for (source, code) in [
            (
                "module contracts.initializer\nstruct Cache:\n    init(self):\n        pass\n",
                "syntax-initializer-receiver",
            ),
            (
                "module contracts.initializer\nstruct Cache:\n    comptime if true:\n        init(mut self):\n            pass\n",
                "syntax-initializer-context",
            ),
            (
                "module contracts.initializer\nstruct Cache:\n    pub init(mut self):\n        pass\n",
                "syntax-initializer-visibility",
            ),
            (
                "module contracts.initializer\nstruct Cache:\n    @budget(bound=1)\n    init(mut self):\n        pass\n",
                "syntax-initializer-attribute",
            ),
            (
                "module contracts.initializer\nstruct Cache:\n    init(mut self):\n        pass\n    init(mut self):\n        pass\n",
                "syntax-duplicate-initializer",
            ),
        ] {
            let output = parse_with_limits(source, ParseLimits::standard())
                .expect("initializer rejection recovers");
            assert!(
                output
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic.code.as_deref() == Some(code)),
                "missing {code}: {:?}",
                output.diagnostics()
            );
        }
    }

    fn first_function(output: &ParseOutput) -> &FunctionDeclaration {
        let declaration = output
            .parsed()
            .ast()
            .declarations
            .first()
            .expect("fixture function");
        match &declaration.kind {
            DeclarationKind::Function(function) => function,
            other => panic!("expected function, got {other:?}"),
        }
    }

    fn first_constant_type_arguments(output: &ParseOutput) -> &[BracketArgument] {
        let declaration = output
            .parsed()
            .ast()
            .declarations
            .first()
            .expect("fixture constant");
        let DeclarationKind::Constant(constant) = &declaration.kind else {
            panic!("expected constant, got {:?}", declaration.kind);
        };
        let Some(TypeExpression {
            kind: TypeExpressionKind::Named { arguments, .. },
            ..
        }) = &constant.ty
        else {
            panic!("expected named constant type");
        };
        arguments
    }

    fn local_literal<'a>(function: &'a FunctionDeclaration, name: &str) -> &'a Literal {
        let statement = function
            .body
            .as_ref()
            .expect("function body")
            .statements
            .iter()
            .find(|statement| {
                matches!(
                    &statement.kind,
                    StatementKind::LocalAssignment { name: local, .. }
                        if local.spelling == name
                )
            })
            .unwrap_or_else(|| panic!("missing local literal {name}"));
        let StatementKind::LocalAssignment { value, .. } = &statement.kind else {
            unreachable!("predicate selected a local assignment");
        };
        let ExpressionKind::Literal(literal) = &value.kind else {
            panic!("local {name} does not contain a literal");
        };
        literal
    }

    fn local_value<'a>(function: &'a FunctionDeclaration, name: &str) -> &'a Expression {
        let statement = function
            .body
            .as_ref()
            .expect("function body")
            .statements
            .iter()
            .find(|statement| {
                matches!(
                    &statement.kind,
                    StatementKind::LocalAssignment { name: local, .. }
                        if local.spelling == name
                )
            })
            .unwrap_or_else(|| panic!("missing local value {name}"));
        let StatementKind::LocalAssignment { value, .. } = &statement.kind else {
            unreachable!("predicate selected a local assignment");
        };
        value
    }

    #[test]
    fn parses_representative_phase_one_file() {
        let output = parse_clean(REPRESENTATIVE);
        assert_eq!(output.parsed().ast().imports.len(), 2);
        let function = first_function(&output);
        assert_eq!(function.color, FunctionColor::Async);
        assert_eq!(function.parameters.len(), 2);
        assert_eq!(function.body.as_ref().expect("body").statements.len(), 4);
    }

    #[test]
    fn parses_complete_normative_statement_pattern_and_expression_fixture() {
        let output = parse_clean(STATEMENTS_EXPRESSIONS);
        assert_eq!(output.parsed().ast().declarations.len(), 2);
        let function = first_function(&output);
        assert!(
            function
                .body
                .as_ref()
                .expect("complete function body")
                .statements
                .len()
                > 50
        );
    }

    #[test]
    fn parses_positional_only_parameter_marker() {
        let output = parse_clean(
            "module contracts.labels\n\nfn hash(_ data: u64) -> u64:\n    return data\n\nfn pair(_ a: u64, b: u64) -> u64:\n    return a\n",
        );
        let declarations = &output.parsed().ast().declarations;
        assert_eq!(declarations.len(), 2);
        let DeclarationKind::Function(hash) = &declarations[0].kind else {
            panic!("expected hash function");
        };
        assert!(hash.parameters[0].positional_only);
        assert_eq!(hash.parameters[0].name.spelling, "data");
        let DeclarationKind::Function(pair) = &declarations[1].kind else {
            panic!("expected pair function");
        };
        assert!(pair.parameters[0].positional_only);
        assert!(!pair.parameters[1].positional_only);
    }

    #[test]
    fn statement_pattern_expression_recovery_is_structured() {
        let output = parse_with_limits(STATEMENTS_EXPRESSIONS_MALFORMED, ParseLimits::standard())
            .expect("malformed phase-three fixture remains recoverable");
        assert!(output.parsed().recovery_complete());
        let codes = output
            .diagnostics()
            .iter()
            .filter_map(|diagnostic| diagnostic.code.as_deref())
            .collect::<Vec<_>>();
        for expected in [
            "syntax-semicolon-statement-boundary",
            "syntax-semicolon-before-suite",
            "syntax-negative-pattern-literal",
            "syntax-tuple-pattern-comma",
            "syntax-send-call",
            "syntax-legacy-variant-pattern",
            "syntax-expected-dot-variant-name",
            "syntax-try-send-call",
            "syntax-closure-parameter-type",
            "syntax-empty-interpolation-format",
            "syntax-interpolation-format-ascii",
            "syntax-unmatched-interpolation-brace",
            "syntax-access-place",
        ] {
            assert!(codes.contains(&expected), "missing {expected}: {codes:?}");
        }
        let exclusive_place_diagnostics = output
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code.as_deref() == Some("syntax-access-place"))
            .collect::<Vec<_>>();
        assert_eq!(exclusive_place_diagnostics.len(), 3);
        assert!(exclusive_place_diagnostics.iter().all(|diagnostic| {
            diagnostic.message == "`mut` and `take` call operands must be places"
        }));
    }

    #[test]
    fn interpolation_parts_retain_nested_expressions_decoding_and_exact_format_spans() {
        let output = parse_clean(STATEMENTS_EXPRESSIONS);
        let function = first_function(&output);
        let Expression {
            meta,
            kind: ExpressionKind::Interpolated(parts),
        } = local_value(function, "formatted")
        else {
            panic!("formatted local is interpolated");
        };
        assert_eq!(parts.len(), 4);
        let InterpolationPart::Text { span, decoded } = &parts[0] else {
            panic!("leading interpolation text");
        };
        assert_eq!(decoded, "escaped {brace} ");
        let source = output
            .parsed()
            .lexical()
            .tokens
            .first()
            .expect("tokens")
            .span
            .file;
        assert_eq!(span.file, source);
        let InterpolationPart::Value {
            expression,
            format,
            format_span,
        } = &parts[1]
        else {
            panic!("formatted value");
        };
        assert!(matches!(expression.kind, ExpressionKind::Name(_)));
        assert_eq!(format.as_deref(), Some("08x"));
        let format_span = format_span.expect("exact format span");
        let start = format_span.range.start as usize;
        let end = format_span.range.end as usize;
        assert_eq!(&STATEMENTS_EXPRESSIONS[start..end], "08x");
        assert_eq!(&STATEMENTS_EXPRESSIONS[start - 1..start], ":");
        assert_eq!(&STATEMENTS_EXPRESSIONS[end..end + 1], "}");
        let InterpolationPart::Value {
            expression,
            format,
            format_span,
        } = &parts[3]
        else {
            panic!("unformatted value");
        };
        assert!(matches!(expression.kind, ExpressionKind::Binary { .. }));
        assert_eq!(format, &None);
        assert_eq!(format_span, &None);
        assert_eq!(
            &STATEMENTS_EXPRESSIONS[meta.span.range.start as usize..meta.span.range.end as usize],
            "f\"escaped {{brace}} {left:08x} {right + 1}\""
        );

        let Expression {
            kind: ExpressionKind::Interpolated(parts),
            ..
        } = local_value(function, "nested")
        else {
            panic!("nested local is interpolated");
        };
        let InterpolationPart::Value { expression, .. } = &parts[1] else {
            panic!("nested interpolation value");
        };
        assert!(matches!(expression.kind, ExpressionKind::Interpolated(_)));

        let Expression {
            kind: ExpressionKind::Interpolated(parts),
            ..
        } = local_value(function, "closure_formatted")
        else {
            panic!("closure interpolation");
        };
        let InterpolationPart::Value { expression, .. } = &parts[1] else {
            panic!("closure interpolation value");
        };
        assert!(matches!(expression.kind, ExpressionKind::Closure { .. }));
    }

    #[test]
    fn phase_three_fixture_reaches_every_non_recovery_ast_surface() {
        #[derive(Default)]
        struct SurfaceFlags {
            has_alternative: bool,
            has_take: bool,
            has_tuple_target: bool,
        }

        fn collect_pattern(
            pattern: &Pattern,
            patterns: &mut BTreeSet<&'static str>,
            expressions: &mut BTreeSet<&'static str>,
            flags: &mut SurfaceFlags,
        ) {
            flags.has_alternative |= pattern.alternatives.len() > 1;
            for alternative in &pattern.alternatives {
                let arguments = match alternative {
                    PrimaryPattern::Wildcard(_) => {
                        patterns.insert("wildcard");
                        continue;
                    }
                    PrimaryPattern::Literal { .. } => {
                        patterns.insert("literal");
                        continue;
                    }
                    PrimaryPattern::Constructor { arguments, .. } => {
                        patterns.insert("constructor");
                        arguments
                    }
                    PrimaryPattern::DotVariant { arguments, .. } => {
                        patterns.insert("dot_variant");
                        arguments
                    }
                    PrimaryPattern::Bind(_) => {
                        patterns.insert("bind");
                        continue;
                    }
                    PrimaryPattern::Tuple { elements, .. } => {
                        patterns.insert("tuple");
                        elements
                    }
                    PrimaryPattern::Array { elements, .. } => {
                        patterns.insert("array");
                        elements
                    }
                    PrimaryPattern::Error(_) => {
                        patterns.insert("error");
                        continue;
                    }
                };
                for argument in arguments {
                    flags.has_take |= argument.take;
                    collect_pattern(&argument.pattern, patterns, expressions, flags);
                }
            }
            let _ = expressions;
        }

        fn collect_expression(
            expression: &Expression,
            expressions: &mut BTreeSet<&'static str>,
            patterns: &mut BTreeSet<&'static str>,
            flags: &mut SurfaceFlags,
            statements: &mut BTreeSet<&'static str>,
            operators: &mut BTreeSet<&'static str>,
        ) {
            let tag = match &expression.kind {
                ExpressionKind::Literal(_) => "literal",
                ExpressionKind::Name(_) => "name",
                ExpressionKind::Closure { body, .. } => {
                    match body {
                        ClosureBody::Expression(value) => collect_expression(
                            value,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        ),
                        ClosureBody::Suite(suite) => collect_suite(
                            suite,
                            statements,
                            expressions,
                            patterns,
                            operators,
                            flags,
                        ),
                    }
                    "closure"
                }
                ExpressionKind::Unary { operand, .. } => {
                    collect_expression(
                        operand,
                        expressions,
                        patterns,
                        flags,
                        statements,
                        operators,
                    );
                    "unary"
                }
                ExpressionKind::Binary { left, right, .. } => {
                    for value in [left.as_ref(), right.as_ref()] {
                        collect_expression(
                            value,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                    }
                    "binary"
                }
                ExpressionKind::Comparison { first, tails } => {
                    collect_expression(first, expressions, patterns, flags, statements, operators);
                    for tail in tails {
                        collect_expression(
                            &tail.right,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                    }
                    "comparison"
                }
                ExpressionKind::IsPattern { value, pattern, .. } => {
                    collect_expression(value, expressions, patterns, flags, statements, operators);
                    collect_pattern(pattern, patterns, expressions, flags);
                    "is-pattern"
                }
                ExpressionKind::Range { start, end, .. } => {
                    for value in [start.as_ref(), end.as_ref()] {
                        collect_expression(
                            value,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                    }
                    "range"
                }
                ExpressionKind::Cast { value, .. } => {
                    collect_expression(value, expressions, patterns, flags, statements, operators);
                    "cast"
                }
                ExpressionKind::Try(value) => {
                    collect_expression(value, expressions, patterns, flags, statements, operators);
                    "try"
                }
                ExpressionKind::Field { base, .. } => {
                    collect_expression(base, expressions, patterns, flags, statements, operators);
                    "field"
                }
                ExpressionKind::Call { callee, arguments } => {
                    collect_expression(callee, expressions, patterns, flags, statements, operators);
                    for argument in arguments {
                        let value = match &argument.value {
                            ArgumentValue::Value(value) => value,
                            ArgumentValue::Exclusive { place, .. } => place,
                            ArgumentValue::InvalidExclusive { expression, .. } => expression,
                        };
                        collect_expression(
                            value,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                    }
                    "call"
                }
                ExpressionKind::Index { base, index } => {
                    for value in [base.as_ref(), index.as_ref()] {
                        collect_expression(
                            value,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                    }
                    "index"
                }
                ExpressionKind::Parenthesized(value) => {
                    collect_expression(value, expressions, patterns, flags, statements, operators);
                    "parenthesized"
                }
                ExpressionKind::Tuple(values) => {
                    collect_expressions(
                        values,
                        expressions,
                        patterns,
                        flags,
                        statements,
                        operators,
                    );
                    "tuple"
                }
                ExpressionKind::Array(values) => {
                    collect_expressions(
                        values,
                        expressions,
                        patterns,
                        flags,
                        statements,
                        operators,
                    );
                    "array"
                }
                ExpressionKind::DotName { .. } => "dot-name",
                ExpressionKind::TrySend(value) => {
                    collect_expression(value, expressions, patterns, flags, statements, operators);
                    "try-send"
                }
                ExpressionKind::Interpolated(parts) => {
                    for part in parts {
                        if let InterpolationPart::Value { expression, .. } = part {
                            collect_expression(
                                expression,
                                expressions,
                                patterns,
                                flags,
                                statements,
                                operators,
                            );
                        }
                    }
                    "interpolated"
                }
                ExpressionKind::If {
                    condition,
                    then_branch,
                    elif_branches,
                    else_branch,
                } => {
                    collect_expression(
                        condition,
                        expressions,
                        patterns,
                        flags,
                        statements,
                        operators,
                    );
                    collect_expression(
                        then_branch,
                        expressions,
                        patterns,
                        flags,
                        statements,
                        operators,
                    );
                    for (elif_condition, elif_branch) in elif_branches {
                        collect_expression(
                            elif_condition,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        collect_expression(
                            elif_branch,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                    }
                    collect_expression(
                        else_branch,
                        expressions,
                        patterns,
                        flags,
                        statements,
                        operators,
                    );
                    "if"
                }
                ExpressionKind::Error(_) => "error",
            };
            expressions.insert(tag);
        }

        fn collect_expressions(
            values: &[Expression],
            expressions: &mut BTreeSet<&'static str>,
            patterns: &mut BTreeSet<&'static str>,
            flags: &mut SurfaceFlags,
            statements: &mut BTreeSet<&'static str>,
            operators: &mut BTreeSet<&'static str>,
        ) {
            for value in values {
                collect_expression(value, expressions, patterns, flags, statements, operators);
            }
        }

        fn collect_target(
            target: &AssignmentTarget,
            expressions: &mut BTreeSet<&'static str>,
            patterns: &mut BTreeSet<&'static str>,
            flags: &mut SurfaceFlags,
            statements: &mut BTreeSet<&'static str>,
            operators: &mut BTreeSet<&'static str>,
        ) {
            match target {
                AssignmentTarget::Place(value) => {
                    collect_expression(value, expressions, patterns, flags, statements, operators)
                }
                AssignmentTarget::Tuple { elements, .. } => {
                    flags.has_tuple_target = true;
                    for element in elements {
                        collect_target(
                            element,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                    }
                }
                AssignmentTarget::Error(_) => {}
            }
        }

        fn collect_suite(
            suite: &Suite,
            statements: &mut BTreeSet<&'static str>,
            expressions: &mut BTreeSet<&'static str>,
            patterns: &mut BTreeSet<&'static str>,
            operators: &mut BTreeSet<&'static str>,
            flags: &mut SurfaceFlags,
        ) {
            for statement in &suite.statements {
                let tag = match &statement.kind {
                    StatementKind::LocalAssignment { value, .. } => {
                        collect_expression(
                            value,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        "local-assignment"
                    }
                    StatementKind::PlaceAssignment {
                        target,
                        operator,
                        value,
                    } => {
                        operators.insert(match operator {
                            AssignmentOperator::Assign => "=",
                            AssignmentOperator::Add => "+=",
                            AssignmentOperator::Subtract => "-=",
                            AssignmentOperator::Multiply => "*=",
                            AssignmentOperator::Divide => "/=",
                            AssignmentOperator::Remainder => "%=",
                            AssignmentOperator::BitAnd => "&=",
                            AssignmentOperator::BitOr => "|=",
                            AssignmentOperator::BitXor => "^=",
                            AssignmentOperator::ShiftLeft => "<<=",
                            AssignmentOperator::ShiftRight => ">>=",
                        });
                        collect_target(target, expressions, patterns, flags, statements, operators);
                        collect_expression(
                            value,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        "place-assignment"
                    }
                    StatementKind::Return(value) => {
                        if let Some(value) = value {
                            collect_expression(
                                value,
                                expressions,
                                patterns,
                                flags,
                                statements,
                                operators,
                            );
                        }
                        "return"
                    }
                    StatementKind::Break => "break",
                    StatementKind::Continue => "continue",
                    StatementKind::Pass => "pass",
                    StatementKind::Assert { condition, .. } => {
                        collect_expression(
                            condition,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        "assert"
                    }
                    StatementKind::Send(value) => {
                        collect_expression(
                            value,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        "send"
                    }
                    StatementKind::Yield(value) => {
                        collect_expression(
                            value,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        "yield"
                    }
                    StatementKind::ComptimeAssert { condition, .. } => {
                        collect_expression(
                            condition,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        "comptime-assert"
                    }
                    StatementKind::Expression(value) => {
                        collect_expression(
                            value,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        "expression"
                    }
                    StatementKind::If(value) => {
                        collect_expression(
                            &value.condition,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        collect_suite(
                            &value.then_suite,
                            statements,
                            expressions,
                            patterns,
                            operators,
                            flags,
                        );
                        for (condition, suite) in &value.elif {
                            collect_expression(
                                condition,
                                expressions,
                                patterns,
                                flags,
                                statements,
                                operators,
                            );
                            collect_suite(
                                suite,
                                statements,
                                expressions,
                                patterns,
                                operators,
                                flags,
                            );
                        }
                        if let Some(suite) = &value.else_suite {
                            collect_suite(
                                suite,
                                statements,
                                expressions,
                                patterns,
                                operators,
                                flags,
                            );
                        }
                        "if"
                    }
                    StatementKind::Match { scrutinee, arms } => {
                        collect_expression(
                            scrutinee,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        for arm in arms {
                            collect_pattern(&arm.pattern, patterns, expressions, flags);
                            if let Some(guard) = &arm.guard {
                                collect_expression(
                                    guard,
                                    expressions,
                                    patterns,
                                    flags,
                                    statements,
                                    operators,
                                );
                            }
                            collect_suite(
                                &arm.body,
                                statements,
                                expressions,
                                patterns,
                                operators,
                                flags,
                            );
                        }
                        "match"
                    }
                    StatementKind::For { iterable, body, .. } => {
                        collect_expression(
                            iterable,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        collect_suite(body, statements, expressions, patterns, operators, flags);
                        "for"
                    }
                    StatementKind::While { condition, body } => {
                        collect_expression(
                            condition,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        collect_suite(body, statements, expressions, patterns, operators, flags);
                        "while"
                    }
                    StatementKind::Loop(body) => {
                        collect_suite(body, statements, expressions, patterns, operators, flags);
                        "loop"
                    }
                    StatementKind::With { value, body, .. } => {
                        collect_expression(
                            value,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        collect_suite(body, statements, expressions, patterns, operators, flags);
                        "with"
                    }
                    StatementKind::ComptimeIf {
                        condition,
                        then_suite,
                        else_suite,
                    } => {
                        collect_expression(
                            condition,
                            expressions,
                            patterns,
                            flags,
                            statements,
                            operators,
                        );
                        collect_suite(
                            then_suite,
                            statements,
                            expressions,
                            patterns,
                            operators,
                            flags,
                        );
                        if let Some(suite) = else_suite {
                            collect_suite(
                                suite,
                                statements,
                                expressions,
                                patterns,
                                operators,
                                flags,
                            );
                        }
                        "comptime-if"
                    }
                    StatementKind::Error(_) => "error",
                };
                statements.insert(tag);
            }
        }

        let output = parse_clean(STATEMENTS_EXPRESSIONS);
        let mut statements = BTreeSet::new();
        let mut expressions = BTreeSet::new();
        let mut patterns = BTreeSet::new();
        let mut operators = BTreeSet::new();
        let mut flags = SurfaceFlags::default();
        collect_suite(
            first_function(&output).body.as_ref().expect("body"),
            &mut statements,
            &mut expressions,
            &mut patterns,
            &mut operators,
            &mut flags,
        );
        assert_eq!(
            statements,
            BTreeSet::from([
                "assert",
                "break",
                "comptime-assert",
                "comptime-if",
                "continue",
                "expression",
                "for",
                "if",
                "local-assignment",
                "loop",
                "match",
                "pass",
                "place-assignment",
                "return",
                "send",
                "while",
                "with",
                "yield",
            ])
        );
        assert_eq!(
            expressions,
            BTreeSet::from([
                "array",
                "binary",
                "call",
                "cast",
                "closure",
                "comparison",
                "dot-name",
                "field",
                "index",
                "interpolated",
                "is-pattern",
                "literal",
                "name",
                "parenthesized",
                "range",
                "try",
                "try-send",
                "tuple",
                "unary",
            ])
        );
        assert_eq!(
            patterns,
            BTreeSet::from([
                "array",
                "bind",
                "constructor",
                "dot_variant",
                "literal",
                "tuple",
                "wildcard"
            ])
        );
        assert_eq!(
            operators,
            BTreeSet::from([
                "%=", "&=", "*=", "+=", "-=", "/=", "<<=", ">>=", "=", "^=", "|="
            ])
        );
        assert!(flags.has_alternative);
        assert!(flags.has_take);
        assert!(flags.has_tuple_target);
    }

    #[test]
    fn contextual_generic_fragments_resolve_name_ambiguity_and_nested_brackets() {
        let text = "module x\nconst value: Outer[Thing, Nested[Inner[u64]], item +] = unit\n";
        let (sources, file) = database(text);
        let parser = WrelaSyntaxParser::new();
        let output = parser
            .parse(
                ParseRequest {
                    sources: &sources,
                    file,
                    limits: ParseLimits::standard(),
                },
                &|| false,
            )
            .expect("file parse");
        assert_eq!(output.diagnostics(), &[]);
        let file_arguments = first_constant_type_arguments(&output);
        assert_eq!(file_arguments.len(), 3);

        let as_type = parser
            .parse_fragment(
                FragmentParseRequest {
                    sources: &sources,
                    parsed: output.parsed(),
                    argument: &file_arguments[0],
                    kind: FragmentKind::Type,
                    limits: ParseLimits::standard(),
                },
                &|| false,
            )
            .expect("name reparses as type");
        assert_eq!(as_type.diagnostics(), &[]);
        let SyntaxFragment::Type(TypeExpression {
            kind: TypeExpressionKind::Named { name, .. },
            meta,
        }) = as_type.parsed().fragment()
        else {
            panic!("expected named type fragment");
        };
        assert_eq!(name.segments[0].spelling, "Thing");
        assert_eq!(meta.span, as_type.parsed().meta().span);

        let as_expression = parser
            .parse_fragment(
                FragmentParseRequest {
                    sources: &sources,
                    parsed: output.parsed(),
                    argument: &file_arguments[0],
                    kind: FragmentKind::Expression,
                    limits: ParseLimits::standard(),
                },
                &|| false,
            )
            .expect("name reparses as expression");
        assert_eq!(as_expression.diagnostics(), &[]);
        assert!(matches!(
            as_expression.parsed().fragment(),
            SyntaxFragment::Expression(Expression {
                kind: ExpressionKind::Name(_),
                ..
            })
        ));

        let nested = parser
            .parse_fragment(
                FragmentParseRequest {
                    sources: &sources,
                    parsed: output.parsed(),
                    argument: &file_arguments[1],
                    kind: FragmentKind::Type,
                    limits: ParseLimits::standard(),
                },
                &|| false,
            )
            .expect("nested type fragment");
        let SyntaxFragment::Type(TypeExpression {
            kind:
                TypeExpressionKind::Named {
                    name,
                    arguments: nested_arguments,
                },
            ..
        }) = nested.parsed().fragment()
        else {
            panic!("expected nested named type");
        };
        assert_eq!(name.segments[0].spelling, "Nested");
        assert_eq!(nested_arguments.len(), 1);
        let BracketArgument::UnclassifiedTypeOrExpression { meta, tokens } = &nested_arguments[0]
        else {
            panic!("nested generic argument remains contextual");
        };
        assert_eq!(meta.tokens, *tokens);
        let source = sources.get(file).expect("source");
        assert_eq!(source.slice(meta.span.range), Some("Inner[u64]"));

        let malformed = parser
            .parse_fragment(
                FragmentParseRequest {
                    sources: &sources,
                    parsed: output.parsed(),
                    argument: &file_arguments[2],
                    kind: FragmentKind::Expression,
                    limits: ParseLimits::standard(),
                },
                &|| false,
            )
            .expect("malformed fragment recovers");
        assert!(malformed.diagnostics().iter().any(|diagnostic| {
            diagnostic.code.as_deref() == Some("syntax-expected-expression")
        }));
    }

    #[test]
    fn contextual_fragment_ranges_and_allocation_limits_are_enforced() {
        let text = "module x\nconst value: Outer[Thing, Nested[Inner[u64]], \"abc\"] = unit\n";
        let (sources, file) = database(text);
        let parser = WrelaSyntaxParser::new();
        let output = parser
            .parse(
                ParseRequest {
                    sources: &sources,
                    file,
                    limits: ParseLimits::standard(),
                },
                &|| false,
            )
            .expect("file parse");
        let arguments = first_constant_type_arguments(&output);

        let BracketArgument::UnclassifiedTypeOrExpression { meta, tokens } = arguments[0].clone()
        else {
            panic!("contextual argument");
        };
        let invalid = BracketArgument::UnclassifiedTypeOrExpression {
            meta,
            tokens: TokenRange {
                first: tokens.first,
                end: TokenId(u32::MAX),
            },
        };
        assert!(matches!(
            parser.parse_fragment(
                FragmentParseRequest {
                    sources: &sources,
                    parsed: output.parsed(),
                    argument: &invalid,
                    kind: FragmentKind::Type,
                    limits: ParseLimits::standard(),
                },
                &|| false,
            ),
            Err(ParseFailure::InvalidFragmentRange { .. })
        ));

        let BracketArgument::UnclassifiedTypeOrExpression { tokens, .. } = &arguments[1] else {
            panic!("nested argument");
        };
        let fragment_tokens = tokens.end.0 - tokens.first.0;
        let mut exact_tokens = ParseLimits::standard();
        exact_tokens.tokens = fragment_tokens;
        parser
            .parse_fragment(
                FragmentParseRequest {
                    sources: &sources,
                    parsed: output.parsed(),
                    argument: &arguments[1],
                    kind: FragmentKind::Type,
                    limits: exact_tokens,
                },
                &|| false,
            )
            .expect("exact fragment token limit");
        let mut over_tokens = exact_tokens;
        over_tokens.tokens -= 1;
        assert!(matches!(
            parser.parse_fragment(
                FragmentParseRequest {
                    sources: &sources,
                    parsed: output.parsed(),
                    argument: &arguments[1],
                    kind: FragmentKind::Type,
                    limits: over_tokens,
                },
                &|| false,
            ),
            Err(ParseFailure::ResourceLimit {
                resource: "fragment tokens",
                ..
            })
        ));

        let mut exact_nodes = ParseLimits::standard();
        exact_nodes.ast_nodes = 4;
        parser
            .parse_fragment(
                FragmentParseRequest {
                    sources: &sources,
                    parsed: output.parsed(),
                    argument: &arguments[0],
                    kind: FragmentKind::Type,
                    limits: exact_nodes,
                },
                &|| false,
            )
            .expect("exact fragment AST-node limit");
        let mut over_nodes = exact_nodes;
        over_nodes.ast_nodes -= 1;
        assert!(matches!(
            parser.parse_fragment(
                FragmentParseRequest {
                    sources: &sources,
                    parsed: output.parsed(),
                    argument: &arguments[0],
                    kind: FragmentKind::Type,
                    limits: over_nodes,
                },
                &|| false,
            ),
            Err(ParseFailure::ResourceLimit {
                resource: "AST nodes",
                ..
            })
        ));

        let mut exact_literal = ParseLimits::standard();
        exact_literal.literal_bytes = 5;
        parser
            .parse_fragment(
                FragmentParseRequest {
                    sources: &sources,
                    parsed: output.parsed(),
                    argument: &arguments[2],
                    kind: FragmentKind::Expression,
                    limits: exact_literal,
                },
                &|| false,
            )
            .expect("exact fragment literal-byte limit");
        let mut over_literal = exact_literal;
        over_literal.literal_bytes -= 1;
        assert!(matches!(
            parser.parse_fragment(
                FragmentParseRequest {
                    sources: &sources,
                    parsed: output.parsed(),
                    argument: &arguments[2],
                    kind: FragmentKind::Expression,
                    limits: over_literal,
                },
                &|| false,
            ),
            Err(ParseFailure::ResourceLimit {
                resource: "literal bytes",
                ..
            })
        ));
    }

    #[test]
    fn contextual_fragment_parsing_polls_cancellation_at_a_bounded_interval() {
        let expression = (0..300).map(|_| "value").collect::<Vec<_>>().join(" + ");
        let text = format!("module x\nconst value: Outer[{expression}] = unit\n");
        let (sources, file) = database(&text);
        let parser = WrelaSyntaxParser::new();
        let output = parser
            .parse(
                ParseRequest {
                    sources: &sources,
                    file,
                    limits: ParseLimits::standard(),
                },
                &|| false,
            )
            .expect("file parse");
        let arguments = first_constant_type_arguments(&output);
        let polls = Cell::new(0u32);
        let result = parser.parse_fragment(
            FragmentParseRequest {
                sources: &sources,
                parsed: output.parsed(),
                argument: &arguments[0],
                kind: FragmentKind::Expression,
                limits: ParseLimits::standard(),
            },
            &|| {
                polls.set(polls.get() + 1);
                polls.get() > 1
            },
        );
        assert_eq!(result, Err(ParseFailure::Cancelled));
        assert_eq!(polls.get(), 2);
    }

    #[test]
    fn parses_complete_normative_declaration_and_type_fixture() {
        let output = parse_clean(DECLARATIONS_TYPES);
        let declarations = &output.parsed().ast().declarations;
        assert_eq!(declarations.len(), 15);
        assert!(matches!(declarations[0].kind, DeclarationKind::Constant(_)));
        assert!(matches!(declarations[1].kind, DeclarationKind::Brand(_)));

        let DeclarationKind::Structure(empty) = &declarations[2].kind else {
            panic!("third declaration must be the empty struct");
        };
        assert!(empty.explicit_pass);
        assert!(empty.members.is_empty());

        let DeclarationKind::Structure(packet) = &declarations[3].kind else {
            panic!("fourth declaration must be Packet");
        };
        assert!(matches!(
            packet.generics[0],
            GenericParameter::Type { bound: Some(_), .. }
        ));
        assert!(matches!(
            packet.generics[1],
            GenericParameter::Constant { .. }
        ));
        assert!(matches!(
            packet.generics[2],
            GenericParameter::Region { .. }
        ));
        assert_eq!(packet.members.len(), 8);
        assert!(packet.members[0].public);
        assert_eq!(packet.members[0].attributes.len(), 2);
        let field_type = |index: usize| match &packet.members[index].kind {
            MemberKind::Field(field) => &field.ty,
            other => panic!("Packet member {index} is not a field: {other:?}"),
        };
        assert!(matches!(
            field_type(0).kind,
            TypeExpressionKind::Array { .. }
        ));
        let TypeExpressionKind::Named { arguments, .. } = &field_type(1).kind else {
            panic!("bounded field must use a named type");
        };
        assert!(matches!(
            arguments[0],
            BracketArgument::BoundedCapacity { .. }
        ));
        assert!(
            matches!(field_type(2).kind, TypeExpressionKind::Tuple(ref values) if values.len() == 2)
        );
        let TypeExpressionKind::Function {
            asynchronous,
            parameters,
            ..
        } = &field_type(3).kind
        else {
            panic!("callback field must use a function type");
        };
        assert!(!asynchronous);
        assert_eq!(
            parameters
                .iter()
                .map(|parameter| parameter.access)
                .collect::<Vec<_>>(),
            vec![AccessMode::Read, AccessMode::Mutate, AccessMode::Take]
        );
        let TypeExpressionKind::Named { arguments, .. } = &parameters[2].ty.kind else {
            panic!("third callback parameter must be Packet arguments");
        };
        assert_eq!(arguments.len(), 3);
        assert!(arguments.iter().all(|argument| matches!(
            argument,
            BracketArgument::UnclassifiedTypeOrExpression { .. }
        )));
        assert!(matches!(
            field_type(4).kind,
            TypeExpressionKind::Function {
                asynchronous: true,
                ..
            }
        ));
        assert!(matches!(
            field_type(5).kind,
            TypeExpressionKind::View { mutable: false, .. }
        ));
        assert!(matches!(
            field_type(6).kind,
            TypeExpressionKind::View { mutable: true, .. }
        ));
        assert!(matches!(field_type(7).kind, TypeExpressionKind::Iso { .. }));

        let DeclarationKind::Structure(service) = &declarations[4].kind else {
            panic!("fifth declaration must be Service");
        };
        assert_eq!(declarations[4].attributes.len(), 1);
        assert!(service.linear);
        assert_eq!(service.implements.len(), 2);
        assert_eq!(service.members.len(), 7);
        assert!(matches!(
            service.members[1].kind,
            MemberKind::Initializer(_)
        ));
        assert!(service.members[2].public);
        assert!(matches!(service.members[2].kind, MemberKind::Function(_)));
        assert!(matches!(
            service.members[3].kind,
            MemberKind::Function(FunctionDeclaration {
                color: FunctionColor::Async,
                ..
            })
        ));
        assert!(matches!(service.members[4].kind, MemberKind::Constant(_)));
        assert!(matches!(service.members[5].kind, MemberKind::Projection(_)));
        assert!(matches!(service.members[6].kind, MemberKind::ComptimeIf(_)));

        let DeclarationKind::Enumeration(enumeration) = &declarations[5].kind else {
            panic!("sixth declaration must be Outcome");
        };
        assert_eq!(enumeration.variants.len(), 5);
        assert!(matches!(enumeration.variants[0].payload, EnumPayload::None));
        assert!(
            matches!(enumeration.variants[2].payload, EnumPayload::Positional(ref values) if values.len() == 1)
        );
        assert!(
            matches!(enumeration.variants[4].payload, EnumPayload::Named(ref fields) if fields.len() == 2)
        );

        let DeclarationKind::Interface(interface) = &declarations[6].kind else {
            panic!("seventh declaration must be Reader");
        };
        assert_eq!(interface.members.len(), 5);
        let InterfaceMember::Function {
            attributes,
            declaration,
        } = &interface.members[0]
        else {
            panic!("first interface member must be a function");
        };
        assert_eq!(attributes.len(), 1);
        assert!(declaration.body.is_none());
        assert!(matches!(
            interface.members[4],
            InterfaceMember::Projection { .. }
        ));

        let DeclarationKind::Implementation(implementation) = &declarations[7].kind else {
            panic!("eighth declaration must be an implementation");
        };
        assert_eq!(implementation.members.len(), 2);
        assert!(matches!(
            implementation.members[0].kind,
            MemberKind::Function(_)
        ));
        assert!(matches!(
            implementation.members[1].kind,
            MemberKind::Projection(_)
        ));

        let DeclarationKind::Projection(projection) = &declarations[8].kind else {
            panic!("ninth declaration must be locate");
        };
        assert_eq!(projection.generics.len(), 1);
        assert!(matches!(
            projection.carrier,
            ProjectionCarrier::Result { ref carrier, .. }
                if matches!(carrier.as_ref(), ProjectionCarrier::View { .. })
        ));
        assert!(matches!(
            projection
                .body
                .as_ref()
                .expect("projection body")
                .statements[0]
                .kind,
            StatementKind::Yield(_)
        ));

        let DeclarationKind::Scope(scope) = &declarations[9].kind else {
            panic!("tenth declaration must be replace");
        };
        assert_eq!(scope.parameters.len(), 2);
        assert_eq!(scope.setup.len(), 1);
        assert!(matches!(
            scope.setup[0].kind,
            StatementKind::LocalAssignment { .. }
        ));
        assert!(scope.abort.is_some());
        assert_eq!(scope.exit_binding.spelling, "replacement");

        for (index, color) in [
            FunctionColor::Sync,
            FunctionColor::Async,
            FunctionColor::Isr,
            // `capacity` was historically `comptime fn`; a plain `fn` is
            // phase-neutral, so it now parses with `FunctionColor::Sync`.
            FunctionColor::Sync,
        ]
        .into_iter()
        .enumerate()
        {
            let DeclarationKind::Function(function) = &declarations[10 + index].kind else {
                panic!("expected a function color fixture");
            };
            assert_eq!(function.color, color);
        }
        let DeclarationKind::ComptimeIf(comptime) = &declarations[14].kind else {
            panic!("last declaration must be a comptime top-level branch");
        };
        assert!(matches!(
            comptime.then_declarations[0].kind,
            DeclarationKind::Constant(_)
        ));
        assert!(matches!(
            comptime.else_declarations[0].kind,
            DeclarationKind::Brand(_)
        ));

        for needle in [")\n    -> Result", ")\n    -> u64"] {
            let newline = DECLARATIONS_TYPES
                .find(needle)
                .expect("hanging declaration header")
                + 1;
            assert!(output.parsed().lexical().trivia.iter().any(|trivia| {
                trivia.kind == TriviaKind::SuppressedPhysicalNewline
                    && trivia.span.range.start == newline as u32
            }));
        }
    }

    #[test]
    fn hanging_arrow_continuation_is_limited_to_declaration_headers() {
        let text = "module x\nfn f():\n    value = call()\n        -> u64:\n        pass\n";
        let (lexical, diagnostics) = scan_only(text);
        assert!(diagnostics.is_empty());
        let newline = text.find("call()\n").expect("call newline") + "call()".len();
        assert!(lexical.tokens.iter().any(|token| {
            token.kind == TokenKind::Newline
                && token.newline_origin == Some(NewlineOrigin::Physical)
                && token.span.range.start == newline as u32
        }));
        assert!(!lexical.trivia.iter().any(|trivia| {
            trivia.kind == TriviaKind::SuppressedPhysicalNewline
                && trivia.span.range.start == newline as u32
        }));
    }

    #[test]
    fn declaration_and_type_recovery_seals_without_lossy_fallbacks() {
        let output = parse_with_limits(DECLARATIONS_TYPES_MALFORMED, ParseLimits::standard())
            .expect("malformed declaration/type fixture remains recoverable");
        assert!(output.parsed().recovery_complete());
        let codes: Vec<_> = output
            .diagnostics()
            .iter()
            .filter_map(|diagnostic| diagnostic.code.as_deref())
            .collect();
        for expected in [
            "syntax-unsupported-declaration",
            "syntax-generic-const-type",
            "syntax-generic-parameter-name",
            "syntax-inline-attribute-order",
            "syntax-empty-type-arguments",
            "syntax-array-type-semicolon",
            "syntax-tuple-type-comma",
            "syntax-iso-brand",
            "syntax-function-type-arrow",
            "syntax-interface-member",
            "syntax-implementation-member",
            "syntax-implementation-member-pub",
            "syntax-projection-carrier",
            "syntax-projection-carrier-leaf",
            "syntax-scope-exit-binding",
        ] {
            assert!(
                codes.contains(&expected),
                "missing {expected}; got {codes:?}"
            );
        }
        assert_eq!(
            codes
                .iter()
                .filter(|code| **code == "syntax-unsupported-declaration")
                .count(),
            4
        );
    }

    #[test]
    fn initializer_malformed_fixture_covers_the_removed_and_invalid_surface() {
        let output = parse_with_limits(INITIALIZERS_MALFORMED, ParseLimits::standard())
            .expect("malformed initializer fixture remains recoverable");
        assert!(output.parsed().recovery_complete());
        let codes = output
            .diagnostics()
            .iter()
            .filter_map(|diagnostic| diagnostic.code.as_deref())
            .collect::<BTreeSet<_>>();
        for expected in [
            "syntax-initializer-attribute",
            "syntax-initializer-visibility",
            "syntax-initializer-receiver",
            "syntax-duplicate-initializer",
            "syntax-removed-initializer-spelling",
            "syntax-initializer-context",
        ] {
            assert!(
                codes.contains(expected),
                "missing {expected}; got {codes:?}"
            );
        }
    }

    #[test]
    fn comptime_fn_legacy_color_is_diagnosed_at_every_function_site() {
        let text = "module x\n\ncomptime fn top() -> unit:\n    pass\n\nstruct S:\n    comptime fn member() -> unit:\n        pass\n\ninterface I:\n    comptime fn signature() -> unit\n";
        let output = parse_with_limits(text, ParseLimits::standard())
            .expect("legacy comptime-fn spellings remain recoverable");
        assert!(output.parsed().recovery_complete());
        let codes = output
            .diagnostics()
            .iter()
            .filter_map(|diagnostic| diagnostic.code.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(
            codes
                .iter()
                .filter(|code| **code == "syntax-legacy-comptime-fn-color")
                .count(),
            3,
            "expected the legacy comptime-fn diagnostic at the top-level, member, and interface \
             sites; got {codes:?}"
        );
    }

    #[test]
    fn declaration_type_nodes_and_unsupported_spellings_have_exact_spans() {
        let output = parse_clean(DECLARATIONS_TYPES);
        let DeclarationKind::Structure(packet) = &output.parsed().ast().declarations[3].kind else {
            panic!("Packet declaration");
        };
        let MemberKind::Field(array_field) = &packet.members[0].kind else {
            panic!("array field");
        };
        let array_range = array_field.ty.meta.span.range;
        assert_eq!(
            &DECLARATIONS_TYPES[array_range.start as usize..array_range.end as usize],
            "[u8; N + 1]"
        );
        let MemberKind::Field(bounded_field) = &packet.members[1].kind else {
            panic!("bounded field");
        };
        let TypeExpressionKind::Named { arguments, .. } = &bounded_field.ty.kind else {
            panic!("bounded named type");
        };
        let BracketArgument::BoundedCapacity { meta, maximum } = &arguments[0] else {
            panic!("bounded-capacity argument");
        };
        let bounded_range = meta.span.range;
        assert_eq!(
            &DECLARATIONS_TYPES[bounded_range.start as usize..bounded_range.end as usize],
            "..N"
        );
        let maximum_range = maximum.meta.span.range;
        assert_eq!(
            &DECLARATIONS_TYPES[maximum_range.start as usize..maximum_range.end as usize],
            "N"
        );

        let malformed = parse_with_limits(DECLARATIONS_TYPES_MALFORMED, ParseLimits::standard())
            .expect("recoverable malformed fixture");
        let unsupported = malformed
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_deref() == Some("syntax-unsupported-declaration"))
            .expect("unsupported declaration diagnostic");
        let start = DECLARATIONS_TYPES_MALFORMED
            .find("type Alias")
            .expect("type alias spelling");
        assert_eq!(unsupported.primary.range.start, start as u32);
        assert_eq!(unsupported.primary.range.end, (start + "type".len()) as u32);
    }

    #[test]
    fn short_and_unmatched_interpolated_literals_never_panic() {
        for literal in ["f\"", "f\"{", "f\"{{", "f\"}\""] {
            let text = format!("module x\nfn f():\n    {literal}\n");
            let output = parse_with_limits(&text, ParseLimits::standard())
                .expect("short interpolated literal remains recoverable");
            assert!(output.parsed().recovery_complete());
            assert!(!output.diagnostics().is_empty());
        }

        let text = "module x\nfn f():\n    f\"\n";
        let output = parse_with_limits(text, ParseLimits::standard()).expect("recoverable parse");
        let diagnostic = output
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_deref() == Some("syntax-unterminated-literal"))
            .expect("unterminated literal diagnostic");
        let start = text.find("f\"").expect("literal offset");
        assert_eq!(diagnostic.primary.range.start, start as u32);
        assert_eq!(diagnostic.primary.range.end, (start + 2) as u32);
    }

    #[test]
    fn truncated_phase_two_prefixes_remain_recoverable() {
        for end in 0..=DECLARATIONS_TYPES.len() {
            let prefix = &DECLARATIONS_TYPES[..end];
            let output = parse_with_limits(prefix, ParseLimits::standard())
                .unwrap_or_else(|failure| panic!("prefix ending at byte {end} failed: {failure}"));
            assert!(output.parsed().recovery_complete());
        }
    }

    #[test]
    fn truncated_phase_three_prefixes_remain_recoverable() {
        for end in 0..=STATEMENTS_EXPRESSIONS.len() {
            let prefix = &STATEMENTS_EXPRESSIONS[..end];
            let output = parse_with_limits(prefix, ParseLimits::standard())
                .unwrap_or_else(|failure| panic!("prefix ending at byte {end} failed: {failure}"));
            assert!(output.parsed().recovery_complete());
        }
    }

    #[test]
    fn missing_match_guard_operand_anchors_recovery_inside_the_assignment_statement() {
        let text = "module x\nfn f():\n    match x:\n        case unit if left =";
        let output = parse_with_limits(text, ParseLimits::standard())
            .expect("guard truncated at assignment operator seals");
        assert!(output.parsed().recovery_complete());
        assert!(output.diagnostics().iter().any(|diagnostic| {
            diagnostic.code.as_deref() == Some("syntax-expected-suite-colon")
        }));
    }

    #[test]
    fn phase_two_fixture_honors_exact_token_and_ast_node_limits() {
        let baseline = parse_clean(DECLARATIONS_TYPES);
        let token_count = baseline.parsed().lexical().tokens.len() as u32;
        let node_count = baseline.parsed().node_ranges.len() as u32;
        let mut exact = ParseLimits::standard();
        exact.tokens = token_count;
        exact.ast_nodes = node_count;
        parse_with_limits(DECLARATIONS_TYPES, exact).expect("exact phase-two limits pass");

        let mut over_tokens = exact;
        over_tokens.tokens -= 1;
        assert!(matches!(
            parse_with_limits(DECLARATIONS_TYPES, over_tokens),
            Err(ParseFailure::ResourceLimit {
                resource: "tokens",
                limit
            }) if limit == u64::from(token_count - 1)
        ));

        let mut over_nodes = exact;
        over_nodes.ast_nodes -= 1;
        assert!(matches!(
            parse_with_limits(DECLARATIONS_TYPES, over_nodes),
            Err(ParseFailure::ResourceLimit {
                resource: "AST nodes",
                limit
            }) if limit == u64::from(node_count - 1)
        ));
    }

    #[test]
    fn phase_three_fixture_honors_exact_token_node_and_literal_limits() {
        let baseline = parse_clean(STATEMENTS_EXPRESSIONS);
        let token_count = baseline.parsed().lexical().tokens.len() as u32;
        let node_count = baseline.parsed().node_ranges.len() as u32;
        let literal_bytes = baseline
            .parsed()
            .lexical()
            .tokens
            .iter()
            .filter(|token| is_literal_token(token.kind))
            .map(|token| {
                token
                    .spelling
                    .as_ref()
                    .map_or(0u64, |value| value.len() as u64)
            })
            .sum::<u64>();
        let mut exact = ParseLimits::standard();
        exact.tokens = token_count;
        exact.ast_nodes = node_count;
        exact.literal_bytes = literal_bytes;
        parse_with_limits(STATEMENTS_EXPRESSIONS, exact).expect("exact phase-three limits pass");

        let mut over_tokens = exact;
        over_tokens.tokens -= 1;
        assert!(matches!(
            parse_with_limits(STATEMENTS_EXPRESSIONS, over_tokens),
            Err(ParseFailure::ResourceLimit {
                resource: "tokens",
                ..
            })
        ));
        let mut over_nodes = exact;
        over_nodes.ast_nodes -= 1;
        assert!(matches!(
            parse_with_limits(STATEMENTS_EXPRESSIONS, over_nodes),
            Err(ParseFailure::ResourceLimit {
                resource: "AST nodes",
                ..
            })
        ));
        let mut over_literals = exact;
        over_literals.literal_bytes -= 1;
        assert!(matches!(
            parse_with_limits(STATEMENTS_EXPRESSIONS, over_literals),
            Err(ParseFailure::ResourceLimit {
                resource: "literal bytes",
                ..
            })
        ));
    }

    #[test]
    fn preserves_imports_comments_spaces_and_source_bytes_losslessly() {
        let output = parse_clean(IMPORTS_TRIVIA);
        assert_eq!(output.parsed().ast().imports.len(), 3);
        let lexical = output.parsed().lexical();
        assert!(
            lexical
                .trivia
                .iter()
                .any(|trivia| trivia.kind == TriviaKind::Comment)
        );
        let (sources, file) = database(IMPORTS_TRIVIA);
        let source = sources.get(file).expect("fixture source");
        let reconstructed = lexical
            .order
            .iter()
            .fold(String::new(), |mut text, element| {
                let span = match element {
                    LexicalElement::Token(id) => lexical.tokens[id.0 as usize].span,
                    LexicalElement::Trivia(id) => lexical.trivia[id.0 as usize].span,
                };
                text.push_str(source.slice(span.range).expect("validated span"));
                text
            });
        assert_eq!(reconstructed, IMPORTS_TRIVIA);
    }

    #[test]
    fn builds_the_normative_precedence_shape() {
        let output = parse_clean(PRECEDENCE);
        let statements = &first_function(&output)
            .body
            .as_ref()
            .expect("body")
            .statements;
        let StatementKind::LocalAssignment { value, .. } = &statements[0].kind else {
            panic!("first statement is a local assignment");
        };
        assert!(matches!(
            value.kind,
            ExpressionKind::Binary {
                operator: BinaryOperator::LogicalOr,
                ..
            }
        ));
        let StatementKind::LocalAssignment { value, .. } = &statements[1].kind else {
            panic!("second statement is a local assignment");
        };
        assert!(matches!(value.kind, ExpressionKind::Cast { .. }));
    }

    #[test]
    fn accepts_unicode_16_xid_nfc_and_rejects_decomposed_spelling() {
        parse_clean(UNICODE);
        let text = "module contracts.unicode\nfn cafe\u{301}():\n    pass\n";
        let output = parse_with_limits(text, ParseLimits::standard()).expect("recoverable parse");
        let diagnostic = output
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_deref() == Some("syntax-non-nfc-identifier"))
            .expect("NFC diagnostic");
        let start = text.find("cafe").expect("identifier offset");
        assert_eq!(diagnostic.primary.range.start, start as u32);
        assert_eq!(
            diagnostic.primary.range.end,
            (start + "cafe\u{301}".len()) as u32
        );
    }

    #[test]
    fn scans_every_literal_class_and_valid_escape_family() {
        let output = parse_clean(LITERALS);
        let kinds: Vec<_> = output
            .parsed()
            .lexical()
            .tokens
            .iter()
            .map(|token| token.kind)
            .collect();
        for expected in [
            TokenKind::IntegerLiteral,
            TokenKind::FloatLiteral,
            TokenKind::StringLiteral,
            TokenKind::ByteStringLiteral,
            TokenKind::CharacterLiteral,
            TokenKind::InterpolatedStringStart,
        ] {
            assert!(kinds.contains(&expected), "missing {expected:?}");
        }
    }

    #[test]
    fn literal_values_are_decoded_once_by_syntax_without_losing_spelling() {
        let output = parse_clean(LITERALS);
        let function = first_function(&output);
        assert_eq!(
            local_literal(function, "decimal").value,
            LiteralValue::IntegerSpelling
        );
        assert_eq!(
            local_literal(function, "fraction").value,
            LiteralValue::FloatSpelling
        );
        assert_eq!(
            local_literal(function, "text").value,
            LiteralValue::Text(
                "slash\\ quote\" apostrophe' newline\n return\r tab\t zero\0 scalar🙂".to_owned()
            )
        );
        assert_eq!(
            local_literal(function, "bytes").value,
            LiteralValue::Bytes(vec![b'A', b'B', b'\\', b'"', b'\'', b'\n', b'\r', b'\t', 0])
        );
        assert_eq!(
            local_literal(function, "scalar").value,
            LiteralValue::Character('🙂')
        );
        assert_eq!(
            local_literal(function, "truth").value,
            LiteralValue::Boolean(true)
        );
        assert_eq!(local_literal(function, "nothing").value, LiteralValue::Unit);
        assert_eq!(local_literal(function, "hexadecimal").spelling, "0xCA_FE");
    }

    #[test]
    fn malformed_literal_decoding_is_explicit_and_recoverable() {
        let text = concat!(
            "module x\n",
            "fn f():\n",
            "    bad_text = \"\\q\"\n",
            "    bad_bytes = b\"é\"\n",
            "    bad_character = 'ab'\n",
            "    bad_scalar = '\\u{D800}'\n",
        );
        let output = parse_with_limits(text, ParseLimits::standard()).expect("recoverable parse");
        let function = first_function(&output);
        for name in ["bad_text", "bad_bytes", "bad_character", "bad_scalar"] {
            assert_eq!(local_literal(function, name).value, LiteralValue::Invalid);
        }
        let codes = output
            .diagnostics()
            .iter()
            .filter_map(|diagnostic| diagnostic.code.as_deref())
            .collect::<Vec<_>>();
        for expected in [
            "syntax-invalid-escape",
            "syntax-non-ascii-byte-string",
            "syntax-invalid-character-literal",
            "syntax-invalid-unicode-escape",
        ] {
            assert!(codes.contains(&expected), "missing {expected}: {codes:?}");
        }
    }

    #[test]
    fn records_layout_suppression_semicolon_origin_and_eof_layout() {
        let output = parse_clean(LAYOUT);
        let lexical = output.parsed().lexical();
        assert!(
            lexical
                .trivia
                .iter()
                .any(|trivia| { trivia.kind == TriviaKind::SuppressedPhysicalNewline })
        );
        assert!(lexical.tokens.iter().any(|token| {
            token.kind == TokenKind::Newline
                && token.newline_origin == Some(NewlineOrigin::Semicolon)
        }));
        assert_eq!(
            lexical.tokens.last().map(|token| token.kind),
            Some(TokenKind::EndOfFile)
        );
        assert!(
            lexical
                .tokens
                .iter()
                .any(|token| token.kind == TokenKind::Indent)
        );
        assert!(
            lexical
                .tokens
                .iter()
                .any(|token| token.kind == TokenKind::Dedent)
        );
    }

    #[test]
    fn normal_dedent_emits_exact_pair_before_a_second_top_level_declaration() {
        let output = parse_clean(LAYOUT_DEDENT);
        assert_eq!(output.parsed().ast().declarations.len(), 2);
        let tokens = &output.parsed().lexical().tokens;
        let pass = tokens
            .iter()
            .position(|token| token.kind == TokenKind::Keyword(Keyword::Pass))
            .expect("first function pass token");
        assert_eq!(
            tokens[pass + 1..pass + 4]
                .iter()
                .map(|token| token.kind)
                .collect::<Vec<_>>(),
            vec![
                TokenKind::Dedent,
                TokenKind::Newline,
                TokenKind::Keyword(Keyword::Fn),
            ]
        );
        assert!(tokens[pass + 1].synthetic);
        assert_eq!(
            tokens[pass + 1].span.range.start,
            tokens[pass].span.range.end
        );
        assert_eq!(
            tokens[pass + 2].newline_origin,
            Some(NewlineOrigin::Physical)
        );
        assert!(!tokens[pass + 2].synthetic);
        assert_eq!(
            tokens[pass + 2].span.range.start,
            tokens[pass + 1].span.range.start
        );
    }

    #[test]
    fn nested_dedent_emits_one_exact_pair_per_closed_level() {
        let (lexical, diagnostics) = scan_only(LAYOUT_NESTED_DEDENT);
        assert_eq!(diagnostics, []);
        let tokens = &lexical.tokens;
        let pass = tokens
            .iter()
            .position(|token| token.kind == TokenKind::Keyword(Keyword::Pass))
            .expect("nested pass token");
        assert_eq!(
            tokens[pass + 1..pass + 6]
                .iter()
                .map(|token| token.kind)
                .collect::<Vec<_>>(),
            vec![
                TokenKind::Dedent,
                TokenKind::Newline,
                TokenKind::Dedent,
                TokenKind::Newline,
                TokenKind::Keyword(Keyword::Fn),
            ]
        );
        assert_eq!(
            tokens[pass + 2].newline_origin,
            Some(NewlineOrigin::Physical)
        );
        assert!(!tokens[pass + 2].synthetic);
        assert_eq!(
            tokens[pass + 4].newline_origin,
            Some(NewlineOrigin::Physical)
        );
        assert!(tokens[pass + 4].synthetic);
        assert_eq!(tokens[pass + 3].span.range, tokens[pass + 4].span.range);
        assert_eq!(
            tokens[pass + 4].span.range.start,
            tokens[pass + 2].span.range.end
        );
    }

    #[test]
    fn eof_without_physical_newline_emits_only_closing_pairs_then_eof() {
        let text = "module x\nfn only():\n    pass";
        let (lexical, diagnostics) = scan_only(text);
        assert_eq!(diagnostics, []);
        let tail = &lexical.tokens[lexical.tokens.len() - 4..];
        assert_eq!(
            tail.iter().map(|token| token.kind).collect::<Vec<_>>(),
            vec![
                TokenKind::Keyword(Keyword::Pass),
                TokenKind::Dedent,
                TokenKind::Newline,
                TokenKind::EndOfFile,
            ]
        );
        assert!(tail[1].synthetic);
        assert!(tail[2].synthetic);
        assert_eq!(tail[2].newline_origin, Some(NewlineOrigin::EndOfFile));
    }

    #[test]
    fn recovers_from_malformed_input_across_supported_statements() {
        let output =
            parse_with_limits(MALFORMED, ParseLimits::standard()).expect("recoverable parse");
        assert!(output.parsed().recovery_complete());
        let codes: Vec<_> = output
            .diagnostics()
            .iter()
            .filter_map(|diagnostic| diagnostic.code.as_deref())
            .collect();
        assert!(codes.contains(&"syntax-invalid-indentation"));
        assert!(codes.contains(&"syntax-comparison-chain"));
        assert!(codes.contains(&"syntax-unterminated-literal"));
        assert!(!codes.iter().any(|code| code.contains("unsupported")));
    }

    #[test]
    fn comparison_chain_diagnostic_has_the_second_operator_span() {
        let text = "module x\nfn f():\n    value = 1 < 2 < 3\n";
        let output = parse_with_limits(text, ParseLimits::standard()).expect("recoverable parse");
        let diagnostic = output
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_deref() == Some("syntax-comparison-chain"))
            .expect("chain diagnostic");
        let second = text.rfind('<').expect("second comparison");
        assert_eq!(diagnostic.primary.range.start, second as u32);
        assert_eq!(diagnostic.primary.range.end, (second + 1) as u32);
    }

    #[test]
    fn enforces_exact_and_over_resource_limits() {
        let minimal = "module x\n";
        let mut exact = ParseLimits::standard();
        exact.tokens = 4;
        exact.ast_nodes = 4;
        exact.literal_bytes = 0;
        exact.diagnostics = 0;
        exact.diagnostic_bytes = 0;
        let minimal_output =
            parse_with_limits(minimal, exact).expect("exact token/node limits pass");
        assert_eq!(minimal_output.usage().tokens(), 4);
        assert_eq!(minimal_output.usage().ast_nodes(), 4);
        assert_eq!(minimal_output.usage().literal_bytes(), 0);
        assert_eq!(minimal_output.usage().diagnostics(), 0);
        assert_eq!(minimal_output.usage().diagnostic_bytes(), 0);
        let remaining = exact
            .remaining_after(minimal_output.usage())
            .expect("sealed usage fits exact limits");
        assert_eq!(remaining.tokens, 0);
        assert_eq!(remaining.ast_nodes, 0);
        assert_eq!(remaining.literal_bytes, 0);
        assert_eq!(remaining.diagnostics, 0);
        assert_eq!(remaining.diagnostic_bytes, 0);

        let mut over_tokens = exact;
        over_tokens.tokens = 3;
        assert!(matches!(
            parse_with_limits(minimal, over_tokens),
            Err(ParseFailure::ResourceLimit {
                resource: "tokens",
                limit: 3
            })
        ));
        let mut over_nodes = exact;
        over_nodes.ast_nodes = 3;
        assert!(matches!(
            parse_with_limits(minimal, over_nodes),
            Err(ParseFailure::ResourceLimit {
                resource: "AST nodes",
                limit: 3
            })
        ));

        let literal = "module x\nfn f():\n    return \"x\"\n";
        let mut literal_exact = ParseLimits::standard();
        literal_exact.literal_bytes = 3;
        let literal_output =
            parse_with_limits(literal, literal_exact).expect("exact literal limit passes");
        assert_eq!(literal_output.usage().literal_bytes(), 3);
        literal_exact.literal_bytes = 2;
        assert!(matches!(
            parse_with_limits(literal, literal_exact),
            Err(ParseFailure::ResourceLimit {
                resource: "literal bytes",
                limit: 2
            })
        ));

        let malformed = "module x\n$\n";
        let baseline =
            parse_with_limits(malformed, ParseLimits::standard()).expect("baseline diagnostics");
        let count = baseline.diagnostics().len() as u32;
        assert!(count > 1);
        assert_eq!(baseline.usage().diagnostics(), count);
        assert!(baseline.usage().diagnostic_bytes() > 0);
        let mut diagnostic_exact = ParseLimits::standard();
        diagnostic_exact.diagnostics = count;
        parse_with_limits(malformed, diagnostic_exact).expect("exact diagnostic limit passes");
        diagnostic_exact.diagnostics = count - 1;
        assert!(matches!(
            parse_with_limits(malformed, diagnostic_exact),
            Err(ParseFailure::ResourceLimit {
                resource: "diagnostics",
                ..
            })
        ));
    }

    #[test]
    fn rejects_stale_candidate_identity_at_the_sealed_boundary() {
        let (sources, file) = database(DECLARATIONS_TYPES);
        let request = ParseRequest {
            sources: &sources,
            file,
            limits: ParseLimits::standard(),
        };
        let output = WrelaSyntaxParser::new()
            .parse(
                ParseRequest {
                    sources: &sources,
                    file,
                    limits: ParseLimits::standard(),
                },
                &|| false,
            )
            .expect("parse");
        let candidate = ParsedFileCandidate {
            file,
            source_digest: Sha256Digest::from_bytes([0x99; 32]),
            lexical: output.parsed().lexical().clone(),
            ast: output.parsed().ast().clone(),
            recovery_complete: true,
        };
        assert!(matches!(
            seal_parse_output(&request, candidate, Vec::new(), &|| false),
            Err(ParseFailure::StaleOutput(id)) if id == file
        ));
    }

    #[test]
    fn sealed_boundary_rejects_a_literal_value_that_disagrees_with_spelling() {
        let (sources, file) = database(LITERALS);
        let request = ParseRequest {
            sources: &sources,
            file,
            limits: ParseLimits::standard(),
        };
        let output = WrelaSyntaxParser::new()
            .parse(
                ParseRequest {
                    sources: &sources,
                    file,
                    limits: ParseLimits::standard(),
                },
                &|| false,
            )
            .expect("parse");
        let mut ast = output.parsed().ast().clone();
        let DeclarationKind::Function(function) = &mut ast.declarations[0].kind else {
            panic!("literal fixture function");
        };
        let StatementKind::LocalAssignment { value, .. } = &mut function
            .body
            .as_mut()
            .expect("body")
            .statements
            .iter_mut()
            .find(|statement| {
                matches!(
                    &statement.kind,
                    StatementKind::LocalAssignment { name, .. } if name.spelling == "text"
                )
            })
            .expect("text literal")
            .kind
        else {
            panic!("text local assignment");
        };
        let ExpressionKind::Literal(literal) = &mut value.kind else {
            panic!("text literal expression");
        };
        literal.value = LiteralValue::Text("forged".to_owned());
        let candidate = ParsedFileCandidate {
            file,
            source_digest: output.parsed().source_digest(),
            lexical: output.parsed().lexical().clone(),
            ast,
            recovery_complete: true,
        };
        assert!(matches!(
            seal_parse_output(&request, candidate, Vec::new(), &|| false),
            Err(ParseFailure::InternalInvariant(message))
                if message.contains("decoded value differs")
        ));
    }

    #[test]
    fn cancellation_polling_is_bounded_and_deterministic() {
        let text = format!("# {}\nmodule x\n", "a".repeat(1_024));
        let run = || {
            let (sources, file) = database(&text);
            let polls = Cell::new(0u32);
            let result = WrelaSyntaxParser::new().parse(
                ParseRequest {
                    sources: &sources,
                    file,
                    limits: ParseLimits::standard(),
                },
                &|| {
                    let next = polls.get() + 1;
                    polls.set(next);
                    next >= 2
                },
            );
            (result, polls.get())
        };
        let (first, first_polls) = run();
        let (second, second_polls) = run();
        assert!(matches!(first, Err(ParseFailure::Cancelled)));
        assert!(matches!(second, Err(ParseFailure::Cancelled)));
        assert_eq!(first_polls, second_polls);
        assert_eq!(first_polls, 2);
    }

    #[test]
    fn phase_two_declaration_parsing_polls_cancellation_deterministically() {
        let mut text = "module x\n".to_owned();
        for index in 0..300 {
            text.push_str(&format!("const VALUE_{index}: usize = {index}\n"));
        }
        let run = || {
            let (sources, file) = database(&text);
            let source = sources.get(file).expect("fixture source");
            let limits = ParseLimits::standard();
            let mut scanner_diagnostics = DiagnosticSink::new(file, limits);
            let lexical = Scanner::new(source, limits, &mut scanner_diagnostics, &|| false)
                .scan()
                .expect("scanner completes before parser cancellation test");
            assert!(scanner_diagnostics.into_diagnostics().is_empty());

            let polls = Cell::new(0u32);
            let cancellation = || {
                let next = polls.get() + 1;
                polls.set(next);
                next >= 2
            };
            let mut parser_diagnostics = DiagnosticSink::new(file, limits);
            let result = Parser::new(
                source,
                &lexical,
                limits,
                &mut parser_diagnostics,
                &cancellation,
            )
            .and_then(|mut parser| parser.parse_file());
            (result, polls.get())
        };
        let (first, first_polls) = run();
        let (second, second_polls) = run();
        assert!(matches!(first, Err(ParseFailure::Cancelled)));
        assert!(matches!(second, Err(ParseFailure::Cancelled)));
        assert_eq!(first_polls, 2);
        assert_eq!(second_polls, first_polls);
    }

    #[test]
    fn forbidden_raw_controls_report_exact_utf8_spans() {
        let text = "module x\n# hidden\u{202e}text\nfn f():\n    pass\n";
        let output = parse_with_limits(text, ParseLimits::standard()).expect("recoverable parse");
        let diagnostic = output
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_deref() == Some("syntax-forbidden-code-point"))
            .expect("forbidden-control diagnostic");
        let offset = text.find('\u{202e}').expect("control offset");
        assert_eq!(diagnostic.primary.range.start, offset as u32);
        assert_eq!(
            diagnostic.primary.range.end,
            (offset + '\u{202e}'.len_utf8()) as u32
        );
    }

    #[test]
    fn scanner_and_parser_invariant_failures_are_structured() {
        let (sources, file) = database("module invariant\n");
        let source = sources.get(file).expect("fixture source");
        let limits = ParseLimits::standard();
        let cancelled = || false;

        let mut scanner_diagnostics = DiagnosticSink::new(file, limits);
        let mut scanner = Scanner::new(source, limits, &mut scanner_diagnostics, &cancelled);
        scanner.indentation.clear();
        assert!(matches!(
            scanner.current_indentation(),
            Err(ParseFailure::InternalInvariant(message))
                if message.contains("root indentation")
        ));
        scanner.position = source.text().len();
        assert!(matches!(
            scanner.current_char(),
            Err(ParseFailure::InternalInvariant(message))
                if message.contains("end of input")
        ));

        let (mut lexical, _) = scan_only("module invariant\n");
        lexical.tokens.pop();
        let mut parser_diagnostics = DiagnosticSink::new(file, limits);
        assert!(matches!(
            Parser::new(
                source,
                &lexical,
                limits,
                &mut parser_diagnostics,
                &cancelled,
            ),
            Err(ParseFailure::InternalInvariant(message))
                if message.contains("ending in EOF")
        ));
    }
}
