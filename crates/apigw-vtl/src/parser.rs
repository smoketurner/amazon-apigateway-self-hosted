//! A parser for Velocity 1.7 templates.
//!
//! The grammar and its lexical quirks follow Velocity 1.7 as observed against the real engine:
//! which characters continue an identifier, that `-1` is a single number token, that method
//! arguments are not full expressions, how backslashes escape references and directives, and
//! which whitespace around directives is swallowed.
//!
//! Velocity's lexer has states of its own that outlive the reference that entered them. After
//! `$a.b`, it stays in a reference state across `#set` and comments, so a following `(` opens an
//! argument list that nothing closes, and from then on only some characters lex. [`Lexer`]
//! follows those states for the text between directives and references.

use std::sync::Arc;

use crate::ast::{BinaryOp, Block, Define, Expr, Foreach, If, Node, Reference, Set, Step};
use crate::error::ParseError;
use crate::number::BigInt;
use crate::value::Value;

/// Deepest nesting of directives, expressions, collections, and interpolated strings.
pub(crate) const MAX_PARSE_DEPTH: usize = 64;

const fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

const fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// A character of a directive word, such as a macro name: `-` is not one.
const fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '@'
}

/// Why a block of nodes ended.
enum BlockEnd {
    Eof,
    End,
    Else,
    ElseIf(Expr),
}

/// The directives the lexer recognizes after a `#`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Directive {
    Set,
    If,
    ElseIf,
    Else,
    End,
    Foreach,
    Break,
    Stop,
    Define,
    /// `#macro`: API Gateway parses a definition and ignores it.
    Macro,
    /// `#parse` and `#include`.
    Unsupported,
}

/// A directive found at a `#`.
struct DirectiveToken {
    directive: Directive,
    /// The directive as written, such as `#if` or `#{if}`, for text that is not executed.
    text: String,
    /// Position just past the name.
    end: usize,
}

/// Velocity's lexical states for the text between tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Plain text.
    Default,
    /// Just after a reference that ended in its name, a method call, or an index.
    Reference,
    /// Just after a reference that ended in `.property`.
    RefModifier,
    /// Inside the argument list of a method call that never started: only identifiers,
    /// numbers, string literals, `.name`, references, and directives lex here.
    RefMod2,
}

/// Velocity's lexer state and the stack of states it returns to.
#[derive(Debug, Clone)]
struct Lexer {
    mode: Mode,
    saved: Vec<Mode>,
}

impl Lexer {
    const fn new() -> Self {
        Self {
            mode: Mode::Default,
            saved: Vec::new(),
        }
    }

    fn push(&mut self, next: Mode) {
        self.saved.push(self.mode);
        self.mode = next;
    }

    fn pop(&mut self) {
        self.mode = self.saved.pop().unwrap_or(Mode::Default);
    }

    /// The state a reference leaves the lexer in: after `.name` it is still reading
    /// modifiers, otherwise it is in the plain reference state. An index returns to the
    /// state before it.
    fn after_reference(&mut self, steps: &[Step]) {
        let property = steps
            .iter()
            .rev()
            .find(|step| !matches!(step, Step::Index(_)))
            .is_some_and(|step| matches!(step, Step::Property(_)));
        self.mode = if property {
            Mode::RefModifier
        } else {
            Mode::Reference
        };
    }

    const fn in_reference(&self) -> bool {
        matches!(self.mode, Mode::Reference | Mode::RefModifier)
    }
}

/// Accumulates the nodes of one block.
struct BlockBuilder {
    nodes: Vec<Node>,
    text: String,
    /// Whether the current text run started right after a token that is not text: a reference,
    /// a directive, or a comment. Whitespace alone in such a run before `#set` is dropped.
    after_token: bool,
}

impl BlockBuilder {
    const fn new(after_token: bool) -> Self {
        Self {
            nodes: Vec::new(),
            text: String::new(),
            after_token,
        }
    }

    fn flush(&mut self) {
        if !self.text.is_empty() {
            self.nodes.push(Node::Text(std::mem::take(&mut self.text)));
        }
    }

    fn push_node(&mut self, node: Node) {
        self.flush();
        self.nodes.push(node);
        self.after_token = true;
    }

    fn mark_token(&mut self) {
        self.flush();
        self.after_token = true;
    }

    fn drop_leading_space_for_set(&mut self) {
        if self.after_token
            && !self.text.is_empty()
            && self.text.chars().all(|c| c == ' ' || c == '\t')
        {
            self.text.clear();
        }
    }

    fn add_text(&mut self, text: &str) {
        self.text.push_str(text);
    }

    fn add_char(&mut self, c: char) {
        self.text.push(c);
    }

    fn finish(mut self) -> Block {
        self.flush();
        Block(self.nodes)
    }
}

/// What a `$` turned out to be.
enum Dollar {
    Reference(Reference),
    /// Text to output for a `$` that does not start a reference.
    Text,
}

/// An argument of a directive such as `#macro`: a bare word or a value.
enum DirectiveArg {
    Word,
    Value(Expr),
}

pub(crate) struct Parser {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
    first_line: usize,
    lex: Lexer,
}

impl Parser {
    /// Parses a template.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] for anything Velocity 1.7 rejects, for `#parse` and `#include`,
    /// and for templates nested beyond [`MAX_PARSE_DEPTH`].
    pub(crate) fn parse(source: &str) -> Result<Block, ParseError> {
        Self::parse_at(source, 0, 1)
    }

    fn parse_at(source: &str, depth: usize, first_line: usize) -> Result<Block, ParseError> {
        let mut parser = Self {
            chars: source.chars().collect(),
            pos: 0,
            depth,
            first_line,
            lex: Lexer::new(),
        };
        let (block, end) = parser.parse_block(false)?;
        match end {
            BlockEnd::Eof => Ok(block),
            BlockEnd::End => Err(parser.error("unexpected #end")),
            BlockEnd::Else => Err(parser.error("unexpected #else")),
            BlockEnd::ElseIf(_) => Err(parser.error("unexpected #elseif")),
        }
    }

    fn line(&self) -> usize {
        self.chars
            .iter()
            .take(self.pos)
            .filter(|c| **c == '\n')
            .count()
            .saturating_add(self.first_line)
    }

    fn error(&self, message: &str) -> ParseError {
        let column = self
            .chars
            .iter()
            .take(self.pos)
            .rev()
            .take_while(|c| **c != '\n')
            .count()
            .saturating_add(1);
        ParseError::Syntax {
            line: self.line(),
            column,
            message: message.to_owned(),
        }
    }

    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_PARSE_DEPTH {
            return Err(ParseError::TooDeep {
                limit: MAX_PARSE_DEPTH,
            });
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos.saturating_add(offset)).copied()
    }

    fn advance(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn eat(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: char) -> Result<(), ParseError> {
        if self.eat(expected) {
            Ok(())
        } else {
            Err(self.error(&format!("expected '{expected}'")))
        }
    }

    fn starts_with(&self, text: &str) -> bool {
        text.chars()
            .enumerate()
            .all(|(offset, c)| self.peek_at(offset) == Some(c))
    }

    fn eat_str(&mut self, text: &str) -> bool {
        if self.starts_with(text) {
            self.pos = self.pos.saturating_add(text.chars().count());
            true
        } else {
            false
        }
    }

    /// Consumes `word` when it is not the start of a longer identifier.
    fn eat_word(&mut self, word: &str) -> bool {
        let after = self.pos.saturating_add(word.chars().count());
        let boundary = self.chars.get(after).is_none_or(|c| !is_ident_char(*c));
        boundary && self.eat_str(word)
    }

    fn eat_word_ignoring_case(&mut self, word: &str) -> bool {
        let matches_word = word.chars().enumerate().all(|(offset, c)| {
            self.peek_at(offset)
                .is_some_and(|actual| actual.eq_ignore_ascii_case(&c))
        });
        let after = self.pos.saturating_add(word.chars().count());
        let boundary = self.chars.get(after).is_none_or(|c| !is_ident_char(*c));
        if matches_word && boundary {
            self.pos = after;
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\r' | '\n')) {
            self.advance();
        }
    }

    /// Consumes spaces and tabs and then one line break, if that is what follows; otherwise
    /// consumes nothing. This is how directives swallow the rest of their line.
    fn eat_line_end(&mut self) {
        let start = self.pos;
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.advance();
        }
        match self.peek() {
            Some('\r') => {
                self.advance();
                self.eat('\n');
            }
            Some('\n') => self.advance(),
            _ => self.pos = start,
        }
    }

    fn parse_identifier(&mut self) -> Option<String> {
        if !self.peek().is_some_and(is_ident_start) {
            return None;
        }
        let mut name = String::new();
        while let Some(c) = self.peek().filter(|c| is_ident_char(*c)) {
            name.push(c);
            self.advance();
        }
        Some(name)
    }

    fn source(&self, start: usize) -> String {
        self.chars
            .get(start..self.pos)
            .map_or_default(|slice| slice.iter().collect())
    }

    // ----- text, references, directives -----

    fn parse_block(&mut self, nested: bool) -> Result<(Block, BlockEnd), ParseError> {
        self.enter()?;
        let result = self.parse_block_inner(nested);
        self.leave();
        result
    }

    fn parse_block_inner(&mut self, nested: bool) -> Result<(Block, BlockEnd), ParseError> {
        let mut builder = BlockBuilder::new(nested);
        while let Some(c) = self.peek() {
            match c {
                '\\' => {
                    if let Some(end) = self.parse_backslashes(&mut builder)? {
                        return Ok((builder.finish(), end));
                    }
                }
                '$' => self.parse_dollar_in_text(&mut builder, 0)?,
                '#' => {
                    if let Some(end) = self.parse_hash(&mut builder, 0)? {
                        return Ok((builder.finish(), end));
                    }
                }
                other => self.parse_text_char(&mut builder, other)?,
            }
        }
        Ok((builder.finish(), BlockEnd::Eof))
    }

    /// One character of text, read in the lexer's current state.
    fn parse_text_char(&mut self, builder: &mut BlockBuilder, c: char) -> Result<(), ParseError> {
        if self.lex.mode == Mode::Default {
            builder.add_char(c);
            self.advance();
            return Ok(());
        }
        if matches!(c, ' ' | '\t') && self.set_after_blanks() {
            while matches!(self.peek(), Some(' ' | '\t')) {
                self.advance();
            }
            return Ok(());
        }
        if is_ident_start(c) {
            return self.parse_runt(builder);
        }
        let alpha_after = self
            .peek_at(1)
            .is_some_and(|next| next.is_ascii_alphabetic());
        match (self.lex.mode, c) {
            (_, '.') if alpha_after => {
                builder.add_char('.');
                self.advance();
                self.lex.mode = Mode::RefModifier;
            }
            (Mode::RefModifier, '(') => {
                builder.add_char('(');
                self.advance();
                self.lex.mode = Mode::RefMod2;
            }
            (Mode::Reference | Mode::RefModifier, '{') => {
                builder.add_char('{');
                self.advance();
            }
            (Mode::Reference | Mode::RefModifier, '}') => {
                builder.add_char('}');
                self.advance();
                self.lex.pop();
            }
            (Mode::Reference | Mode::RefModifier, '[') => {
                return Err(self.error("unexpected '[' after a reference"));
            }
            (Mode::Reference | Mode::RefModifier, _) => self.lex.pop(),
            (Mode::RefMod2, '\'' | '"') => self.parse_stray_string(builder)?,
            (Mode::RefMod2, _) if self.number_starts_here() => self.parse_stray_number(builder)?,
            (Mode::RefMod2 | Mode::Default, _) => {
                return Err(self.error("unexpected character in an unclosed method call"));
            }
        }
        Ok(())
    }

    /// Whether spaces and tabs from here lead to a `#set(`, which swallows them.
    fn set_after_blanks(&mut self) -> bool {
        let start = self.pos;
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.advance();
        }
        let set = self.peek() == Some('#')
            && self
                .directive_at(true)
                .is_some_and(|token| token.directive == Directive::Set);
        self.pos = start;
        set
    }

    /// An identifier where the lexer reads identifiers: Velocity parses it as a reference
    /// without a `$`, which renders as its own name, whatever follows it in the chain.
    fn parse_runt(&mut self, builder: &mut BlockBuilder) -> Result<(), ParseError> {
        let Some(name) = self.parse_identifier() else {
            return Ok(());
        };
        if name == "true" || name == "false" {
            return Err(self.error("unexpected boolean after a reference"));
        }
        if self.lex.mode == Mode::RefMod2 && self.peek() == Some('[') {
            return Err(self.error("unexpected '[' in an unclosed method call"));
        }
        let steps = self.parse_chain()?;
        builder.add_text(&name);
        builder.mark_token();
        if !steps.is_empty() {
            self.lex.after_reference(&steps);
        }
        Ok(())
    }

    /// A string literal where the lexer reads literals: it renders as written.
    fn parse_stray_string(&mut self, builder: &mut BlockBuilder) -> Result<(), ParseError> {
        let start = self.pos;
        let Some(quote) = self.peek() else {
            return Ok(());
        };
        self.advance();
        loop {
            match self.peek() {
                Some(c) if c == quote => {
                    self.advance();
                    if !self.eat(quote) {
                        break;
                    }
                }
                Some(_) => self.advance(),
                None => return Err(self.error("unterminated string")),
            }
        }
        builder.add_text(&self.source(start));
        builder.mark_token();
        Ok(())
    }

    /// A number where the lexer reads numbers: it renders as written.
    fn parse_stray_number(&mut self, builder: &mut BlockBuilder) -> Result<(), ParseError> {
        let start = self.pos;
        self.eat('-');
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.advance();
        }
        if self.starts_with("..") {
            return Err(self.error("unexpected '..' in an unclosed method call"));
        }
        if self.eat('.') {
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.advance();
            }
        }
        if self.peek().is_some_and(|c| c == 'e' || c == 'E') {
            let signed = matches!(self.peek_at(1), Some('+' | '-'));
            let digit_at = if signed { 2 } else { 1 };
            if self.peek_at(digit_at).is_some_and(|c| c.is_ascii_digit()) {
                self.pos = self.pos.saturating_add(digit_at);
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.advance();
                }
            }
        }
        builder.add_text(&self.source(start));
        builder.mark_token();
        Ok(())
    }

    fn parse_dollar_in_text(
        &mut self,
        builder: &mut BlockBuilder,
        backslashes: usize,
    ) -> Result<(), ParseError> {
        if self.lex.mode == Mode::Reference {
            self.lex.pop();
        }
        self.lex.push(Mode::Reference);
        match self.parse_dollar(backslashes)? {
            Dollar::Reference(reference) => {
                let formal =
                    reference.source.starts_with("${") || reference.source.starts_with("$!{");
                if formal {
                    self.lex.pop();
                } else {
                    self.lex.after_reference(&reference.steps);
                }
                builder.push_node(Node::Reference(reference));
            }
            Dollar::Text => {
                self.lex.pop();
                builder.add_char('$');
            }
        }
        Ok(())
    }

    /// Handles a run of backslashes, which escape a following reference or directive.
    fn parse_backslashes(
        &mut self,
        builder: &mut BlockBuilder,
    ) -> Result<Option<BlockEnd>, ParseError> {
        let mut count = 0_usize;
        while self.peek_at(count) == Some('\\') {
            count = count.saturating_add(1);
        }
        let before_dollar = self.peek_at(count) == Some('$');
        match self.lex.mode {
            Mode::Reference | Mode::RefModifier if !before_dollar => {
                self.lex.pop();
                return Ok(None);
            }
            Mode::RefMod2 if !before_dollar => {
                return Err(self.error("unexpected '\\' in an unclosed method call"));
            }
            Mode::Default | Mode::Reference | Mode::RefModifier | Mode::RefMod2 => {}
        }
        self.pos = self.pos.saturating_add(count);
        match self.peek() {
            Some('$') => {
                self.parse_dollar_in_text(builder, count)?;
                Ok(None)
            }
            Some('#') => {
                let before = self.pos;
                let end = self.parse_hash(builder, count)?;
                if self.pos == before {
                    builder.add_text(&"\\".repeat(count));
                }
                Ok(end)
            }
            _ => {
                builder.add_text(&"\\".repeat(count));
                Ok(None)
            }
        }
    }

    /// Parses what follows a `$`.
    fn parse_dollar(&mut self, backslashes: usize) -> Result<Dollar, ParseError> {
        let start = self.pos;
        self.advance();
        let quiet = self.eat('!');
        let formal = self.peek() == Some('{');
        if formal {
            self.advance();
        }
        let Some(head) = self.parse_identifier() else {
            if self.peek().is_none() && !formal {
                return Err(self.error("a template cannot end with '$'"));
            }
            if quiet && !formal {
                return Ok(Dollar::Text);
            }
            self.pos = start.saturating_add(1);
            return Ok(Dollar::Text);
        };
        let steps = self.parse_chain()?;
        if formal && !self.eat('}') {
            return Err(self.error("expected '}' to close ${...}"));
        }
        let source = self.source(start);
        Ok(Dollar::Reference(Reference {
            head: head.into(),
            steps,
            quiet,
            source,
            backslashes,
        }))
    }

    /// Whether the `(` under the cursor starts text rather than a method call. Velocity looks
    /// three tokens ahead to tell a method call from a property, and a directive, a comment,
    /// or `.name` cannot start an argument, so the `(` is then plain text, read in the state of
    /// an argument list that never closes.
    fn paren_is_text(&self) -> bool {
        match self.peek_at(1) {
            Some('#') => true,
            Some('.') => self.peek_at(2).is_some_and(|c| c.is_ascii_alphabetic()),
            _ => false,
        }
    }

    /// Parses `.name`, `.name(args)`, and `[index]` steps.
    fn parse_chain(&mut self) -> Result<Vec<Step>, ParseError> {
        let mut steps = Vec::new();
        loop {
            match self.peek() {
                Some('.') if self.peek_at(1).is_some_and(is_ident_start) => {
                    self.advance();
                    let Some(name) = self.parse_identifier() else {
                        break;
                    };
                    if self.peek() == Some('(') && self.paren_is_text() {
                        steps.push(Step::Property(name.into()));
                        break;
                    }
                    if self.peek() == Some('(') {
                        let before = self.pos;
                        match self.parse_arguments() {
                            Ok(args) => steps.push(Step::Method(name.into(), args)),
                            Err(ParseError::TooDeep { limit }) => {
                                return Err(ParseError::TooDeep { limit });
                            }
                            Err(err) => {
                                if self.pos < self.chars.len() {
                                    return Err(err);
                                }
                                self.pos = before;
                                steps.push(Step::Property(name.into()));
                                break;
                            }
                        }
                    } else {
                        steps.push(Step::Property(name.into()));
                    }
                }
                Some('[') => {
                    let index = self.parse_index()?;
                    steps.push(Step::Index(Box::new(index)));
                }
                _ => break,
            }
        }
        Ok(steps)
    }

    fn parse_index(&mut self) -> Result<Expr, ParseError> {
        self.expect('[')?;
        self.skip_whitespace();
        let index = self.parse_parameter()?;
        if matches!(
            index,
            Expr::Literal(Value::Double(_)) | Expr::List(_) | Expr::Map(_) | Expr::Range(..)
        ) {
            return Err(self.error("an index must be an integer, a string, or a reference"));
        }
        self.skip_whitespace();
        self.expect(']')?;
        Ok(index)
    }

    /// A method argument: a parameter, or a bare word, which Velocity passes as `null`.
    fn parse_argument(&mut self) -> Result<Expr, ParseError> {
        if self.peek().is_some_and(is_ident_start)
            && !self.word_ahead("true")
            && !self.word_ahead("false")
        {
            self.parse_identifier();
            return Ok(Expr::Literal(Value::Null));
        }
        self.parse_parameter()
    }

    fn word_ahead(&self, word: &str) -> bool {
        self.starts_with(word)
            && self
                .peek_at(word.chars().count())
                .is_none_or(|c| !is_ident_char(c))
    }

    fn parse_arguments(&mut self) -> Result<Vec<Expr>, ParseError> {
        self.enter()?;
        let result = self.parse_arguments_inner();
        self.leave();
        result
    }

    fn parse_arguments_inner(&mut self) -> Result<Vec<Expr>, ParseError> {
        self.expect('(')?;
        let mut args = Vec::new();
        self.skip_whitespace();
        if self.eat(')') {
            return Ok(args);
        }
        loop {
            args.push(self.parse_argument()?);
            self.skip_whitespace();
            if self.eat(',') {
                self.skip_whitespace();
            } else {
                self.expect(')')?;
                return Ok(args);
            }
        }
    }

    /// Parses what follows a `#`; returns the end of the block when the directive closes it.
    fn parse_hash(
        &mut self,
        builder: &mut BlockBuilder,
        backslashes: usize,
    ) -> Result<Option<BlockEnd>, ParseError> {
        if backslashes == 0 && self.peek_at(1).is_none() {
            return Err(self.error("a template cannot end with '#'"));
        }
        if backslashes == 0 && self.peek_at(1) == Some('#') {
            return Ok(self.parse_line_comment(builder));
        }
        if backslashes == 0 && self.peek_at(1) == Some('*') {
            self.skip_block_comment();
            builder.mark_token();
            return Ok(None);
        }
        if backslashes == 0 && self.starts_with("#[[") {
            self.pos = self.pos.saturating_add(3);
            self.copy_unparsed(builder)?;
            return Ok(None);
        }
        let token = self.directive_at(backslashes.is_multiple_of(2));
        if token
            .as_ref()
            .is_none_or(|token| token.directive != Directive::Set)
            && self.lex.in_reference()
        {
            self.lex.pop();
        }
        let Some(token) = token else {
            if backslashes == 0 {
                self.parse_unknown_directive(builder)?;
            }
            return Ok(None);
        };
        let executes = backslashes.is_multiple_of(2);
        if !executes {
            let kept = "\\".repeat(backslashes.div_euclid(2));
            builder.add_text(&kept);
            builder.add_text(&token.text);
            self.pos = token.end;
            return Ok(None);
        }
        let kept = if token.directive == Directive::Set {
            backslashes
        } else {
            backslashes.div_euclid(2)
        };
        builder.add_text(&"\\".repeat(kept));
        self.pos = token.end;
        self.run_directive(builder, &token)
    }

    /// `##`: a comment to the end of the line, except where the lexer is still in a reference
    /// that ended in a property, which reads it as text.
    fn parse_line_comment(&mut self, builder: &mut BlockBuilder) -> Option<BlockEnd> {
        match self.lex.mode {
            Mode::RefModifier | Mode::RefMod2 => {
                if self.lex.mode == Mode::RefModifier {
                    self.lex.pop();
                }
                builder.add_text("##");
                self.pos = self.pos.saturating_add(2);
            }
            Mode::Default | Mode::Reference => {
                if self.lex.mode == Mode::Reference {
                    self.lex.pop();
                }
                self.skip_line_comment();
                builder.mark_token();
            }
        }
        None
    }

    /// A `#` that starts no directive: `#name` is a macro call, which API Gateway renders as
    /// written, `#@name(...)...#end` a block macro call that renders as written with its
    /// body, and anything else is text.
    fn parse_unknown_directive(&mut self, builder: &mut BlockBuilder) -> Result<(), ParseError> {
        let start = self.pos;
        self.advance();
        if self.peek() == Some('@') && self.peek_at(1).is_some_and(is_ident_start) {
            return self.parse_block_macro_call(builder, start);
        }
        let mut token = String::from("#");
        while let Some(c) = self
            .peek()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        {
            token.push(c);
            self.advance();
        }
        if token.len() > 1 {
            builder.flush();
            builder.add_text(&token);
            if token
                .chars()
                .nth(1)
                .is_some_and(|c| c.is_ascii_alphabetic())
            {
                self.parse_macro_call_text(builder)?;
            }
            builder.mark_token();
        } else {
            builder.add_char('#');
        }
        Ok(())
    }

    fn parse_block_macro_call(
        &mut self,
        builder: &mut BlockBuilder,
        start: usize,
    ) -> Result<(), ParseError> {
        self.advance();
        while self.peek().is_some_and(is_word_char) {
            self.advance();
        }
        let name_end = self.pos;
        self.skip_whitespace();
        if self.peek() != Some('(') {
            self.pos = name_end;
            builder.add_text(&self.source(start));
            builder.mark_token();
            return Ok(());
        }
        self.parse_directive_args()?;
        self.eat_line_end();
        let (_, end) = self.parse_block(true)?;
        if !matches!(end, BlockEnd::End) {
            return Err(self.error("missing #end for a block macro call"));
        }
        builder.flush();
        builder.add_text(&self.source(start));
        builder.mark_token();
        Ok(())
    }

    /// `#name(args)` for a name that is not a directive is a call of a macro, which renders as
    /// written; arguments that do not parse are an error.
    fn parse_macro_call_text(&mut self, builder: &mut BlockBuilder) -> Result<(), ParseError> {
        let start = self.pos;
        self.skip_whitespace();
        if self.peek() != Some('(') {
            self.pos = start;
            return Ok(());
        }
        self.parse_directive_args()?;
        builder.add_text(&self.source(start));
        Ok(())
    }

    /// The parenthesized arguments of a directive: words and values separated by whitespace
    /// or commas.
    fn parse_directive_args(&mut self) -> Result<Vec<DirectiveArg>, ParseError> {
        self.enter()?;
        let result = self.parse_directive_args_inner();
        self.leave();
        result
    }

    fn parse_directive_args_inner(&mut self) -> Result<Vec<DirectiveArg>, ParseError> {
        self.expect('(')?;
        let mut args = Vec::new();
        loop {
            self.skip_whitespace();
            if self.eat(')') {
                return Ok(args);
            }
            if self.eat(',') {
                self.skip_whitespace();
            }
            if self
                .peek()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '@')
                && !self.word_ahead("true")
                && !self.word_ahead("false")
            {
                while self.peek().is_some_and(is_word_char) {
                    self.advance();
                }
                args.push(DirectiveArg::Word);
            } else {
                args.push(DirectiveArg::Value(self.parse_parameter()?));
            }
        }
    }

    fn skip_line_comment(&mut self) {
        while let Some(c) = self.peek() {
            if c == '\n' || c == '\r' {
                break;
            }
            self.advance();
        }
        match self.peek() {
            Some('\r') => {
                self.advance();
                self.eat('\n');
            }
            Some('\n') => self.advance(),
            _ => {}
        }
    }

    fn skip_block_comment(&mut self) {
        self.pos = self.pos.saturating_add(2);
        while self.peek().is_some() {
            if self.eat_str("*#") {
                return;
            }
            self.advance();
        }
    }

    fn copy_unparsed(&mut self, builder: &mut BlockBuilder) -> Result<(), ParseError> {
        while self.peek().is_some() {
            if self.eat_str("]]#") {
                return Ok(());
            }
            if let Some(c) = self.peek() {
                builder.add_char(c);
            }
            self.advance();
        }
        Err(self.error("unterminated #[[ literal"))
    }

    /// Recognizes a directive at the `#` under the cursor without consuming anything.
    fn directive_at(&self, set_needs_paren: bool) -> Option<DirectiveToken> {
        let (name, name_end) = if self.peek_at(1) == Some('{') {
            let mut offset = 2;
            let mut name = String::new();
            while let Some(c) = self.peek_at(offset).filter(char::is_ascii_alphabetic) {
                name.push(c);
                offset = offset.saturating_add(1);
            }
            if self.peek_at(offset) != Some('}') {
                return None;
            }
            (name, self.pos.saturating_add(offset).saturating_add(1))
        } else {
            let mut offset = 1;
            let mut name = String::new();
            while let Some(c) = self.peek_at(offset).filter(char::is_ascii_alphabetic) {
                name.push(c);
                offset = offset.saturating_add(1);
            }
            if self
                .peek_at(offset)
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return None;
            }
            (name, self.pos.saturating_add(offset))
        };
        let directive = match name.as_str() {
            "set" => Directive::Set,
            "if" => Directive::If,
            "elseif" => Directive::ElseIf,
            "else" => Directive::Else,
            "end" => Directive::End,
            "foreach" => Directive::Foreach,
            "break" => Directive::Break,
            "stop" => Directive::Stop,
            "define" => Directive::Define,
            "macro" => Directive::Macro,
            "parse" | "include" => Directive::Unsupported,
            _ => return None,
        };
        if directive == Directive::Set && set_needs_paren {
            let mut next = name_end;
            while matches!(self.chars.get(next), Some(' ' | '\t')) {
                next = next.saturating_add(1);
            }
            if self.chars.get(next) != Some(&'(') {
                return None;
            }
        }
        let text: String = self
            .chars
            .get(self.pos..name_end)
            .map_or_default(|slice| slice.iter().collect());
        Some(DirectiveToken {
            directive,
            text,
            end: name_end,
        })
    }

    /// Runs a directive whose name has been consumed.
    fn run_directive(
        &mut self,
        builder: &mut BlockBuilder,
        token: &DirectiveToken,
    ) -> Result<Option<BlockEnd>, ParseError> {
        match token.directive {
            Directive::Unsupported => Err(ParseError::UnsupportedDirective {
                name: token
                    .text
                    .trim_start_matches('#')
                    .trim_matches(['{', '}'])
                    .to_owned(),
                line: self.line(),
            }),
            Directive::Set => {
                builder.drop_leading_space_for_set();
                let set = self.parse_set()?;
                builder.push_node(Node::Set(set));
                self.eat_line_end();
                Ok(None)
            }
            Directive::If => {
                let node = self.parse_if()?;
                builder.push_node(Node::If(node));
                Ok(None)
            }
            Directive::Foreach => {
                let node = self.parse_foreach()?;
                builder.push_node(Node::Foreach(node));
                Ok(None)
            }
            Directive::Define => {
                let node = self.parse_define()?;
                builder.push_node(Node::Define(node));
                Ok(None)
            }
            Directive::Macro => {
                self.parse_macro()?;
                builder.mark_token();
                Ok(None)
            }
            Directive::Break | Directive::Stop if self.peek() == Some('(') => {
                Err(self.error("unexpected '(' after a directive without arguments"))
            }
            Directive::Break | Directive::Stop => {
                builder.push_node(if token.directive == Directive::Break {
                    Node::Break
                } else {
                    Node::Stop
                });
                if self.lex.mode != Mode::RefMod2 {
                    self.eat_line_end();
                }
                Ok(None)
            }
            Directive::End => {
                builder.flush();
                self.eat_line_end();
                Ok(Some(BlockEnd::End))
            }
            Directive::Else => {
                builder.flush();
                self.eat_line_end();
                Ok(Some(BlockEnd::Else))
            }
            Directive::ElseIf => {
                builder.flush();
                let condition = self.parse_parenthesized()?;
                self.eat_line_end();
                Ok(Some(BlockEnd::ElseIf(condition)))
            }
        }
    }

    fn parse_parenthesized(&mut self) -> Result<Expr, ParseError> {
        self.skip_spaces_and_tabs();
        self.expect('(')?;
        self.skip_whitespace();
        let expression = self.parse_expression()?;
        self.skip_whitespace();
        self.expect(')')?;
        Ok(expression)
    }

    fn skip_spaces_and_tabs(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.advance();
        }
    }

    fn parse_set(&mut self) -> Result<Set, ParseError> {
        self.skip_spaces_and_tabs();
        self.expect('(')?;
        self.skip_whitespace();
        if self.peek() != Some('$') {
            return Err(self.error("expected a reference on the left of #set"));
        }
        let Dollar::Reference(target) = self.parse_dollar(0)? else {
            return Err(self.error("expected a reference on the left of #set"));
        };
        if matches!(target.steps.last(), Some(Step::Method(..))) {
            return Err(self.error("a method call cannot be assigned to"));
        }
        self.skip_whitespace();
        self.expect('=')?;
        self.skip_whitespace();
        let value = self.parse_expression()?;
        self.skip_whitespace();
        self.expect(')')?;
        Ok(Set {
            head: target.head,
            steps: target.steps,
            value,
        })
    }

    fn parse_if(&mut self) -> Result<If, ParseError> {
        let mut branches = Vec::new();
        let mut otherwise = None;
        let mut condition = self.parse_parenthesized()?;
        self.eat_line_end();
        loop {
            let (body, end) = self.parse_block(true)?;
            branches.push((condition, body));
            match end {
                BlockEnd::End => break,
                BlockEnd::ElseIf(next) => condition = next,
                BlockEnd::Else => {
                    let (body, end) = self.parse_block(true)?;
                    match end {
                        BlockEnd::End => {
                            otherwise = Some(body);
                            break;
                        }
                        BlockEnd::Eof => return Err(self.error("missing #end for #if")),
                        BlockEnd::Else | BlockEnd::ElseIf(_) => {
                            return Err(self.error("unexpected directive after #else"));
                        }
                    }
                }
                BlockEnd::Eof => return Err(self.error("missing #end for #if")),
            }
        }
        Ok(If {
            branches,
            otherwise,
        })
    }

    fn parse_foreach(&mut self) -> Result<Foreach, ParseError> {
        self.skip_spaces_and_tabs();
        self.expect('(')?;
        self.skip_whitespace();
        if self.peek() != Some('$') {
            return Err(self.error("expected a loop variable"));
        }
        self.advance();
        let var = self
            .parse_identifier()
            .ok_or_else(|| self.error("expected a loop variable"))?;
        self.skip_whitespace();
        if !self.eat_word_ignoring_case("in") {
            return Err(self.error("expected 'in'"));
        }
        self.skip_whitespace();
        let source = self.parse_parameter()?;
        self.skip_whitespace();
        self.expect(')')?;
        self.eat_line_end();
        let body = self.parse_block_to_end("#foreach")?;
        Ok(Foreach {
            var: var.into(),
            source,
            body,
        })
    }

    /// The body of a block directive, which must end with `#end`.
    fn parse_block_to_end(&mut self, directive: &str) -> Result<Block, ParseError> {
        let (body, end) = self.parse_block(true)?;
        match end {
            BlockEnd::End => Ok(body),
            BlockEnd::Eof => Err(self.error(&format!("missing #end for {directive}"))),
            BlockEnd::Else | BlockEnd::ElseIf(_) => {
                Err(self.error(&format!("#else is not allowed in {directive}")))
            }
        }
    }

    /// `#define($name)...#end`. The block's variable is the reference's name; Velocity takes it
    /// from the reference's first token, so `$a.b` defines `$a`, and a quiet, formal, or
    /// non-reference argument names no variable a template can reach.
    fn parse_define(&mut self) -> Result<Define, ParseError> {
        self.skip_whitespace();
        if self.peek() != Some('(') {
            return Err(self.error("#define needs a reference"));
        }
        let args = self.parse_directive_args()?;
        let name = match args.as_slice() {
            [DirectiveArg::Value(Expr::Reference(reference))] => {
                let plain = !reference.quiet && !reference.source.starts_with("${");
                plain.then(|| Arc::clone(&reference.head))
            }
            [DirectiveArg::Value(_)] => None,
            [DirectiveArg::Word] => return Err(self.error("invalid argument to #define")),
            _ => return Err(self.error("#define takes exactly one reference")),
        };
        self.eat_line_end();
        let body = self.parse_block_to_end("#define")?;
        Ok(Define {
            name,
            body: Arc::new(body),
        })
    }

    /// `#macro(name $arg ...)...#end`. API Gateway does not define inline macros: the
    /// definition is parsed, checked as Velocity checks it, and ignored.
    fn parse_macro(&mut self) -> Result<(), ParseError> {
        self.skip_whitespace();
        if self.peek() != Some('(') {
            return Err(self.error("a macro declaration requires at least a name argument"));
        }
        let args = self.parse_directive_args()?;
        let mut args = args.iter();
        if !matches!(args.next(), Some(DirectiveArg::Word)) {
            return Err(self.error("the first argument to #macro must be the macro name"));
        }
        if args.any(|arg| matches!(arg, DirectiveArg::Word)) {
            return Err(self.error("macro arguments must be references"));
        }
        self.eat_line_end();
        self.parse_block_to_end("#macro")?;
        Ok(())
    }

    // ----- expressions -----

    fn parse_expression(&mut self) -> Result<Expr, ParseError> {
        self.enter()?;
        let result = self.parse_or();
        self.leave();
        result
    }

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and()?;
        loop {
            self.skip_whitespace();
            if self.eat_str("||") || self.eat_word("or") {
                self.skip_whitespace();
                let right = self.parse_and()?;
                left = Expr::Binary(BinaryOp::Or, Box::new(left), Box::new(right));
            } else {
                return Ok(left);
            }
        }
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_equality()?;
        loop {
            self.skip_whitespace();
            if self.eat_str("&&") || self.eat_word("and") {
                self.skip_whitespace();
                let right = self.parse_equality()?;
                left = Expr::Binary(BinaryOp::And, Box::new(left), Box::new(right));
            } else {
                return Ok(left);
            }
        }
    }

    fn parse_equality(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_relational()?;
        loop {
            self.skip_whitespace();
            let op = if self.eat_str("==") || self.eat_word("eq") {
                BinaryOp::Eq
            } else if self.eat_str("!=") || self.eat_word("ne") {
                BinaryOp::Ne
            } else {
                return Ok(left);
            };
            self.skip_whitespace();
            let right = self.parse_relational()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
    }

    fn parse_relational(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_additive()?;
        loop {
            self.skip_whitespace();
            let op = if self.eat_str("<=") || self.eat_word("le") {
                BinaryOp::Le
            } else if self.eat_str(">=") || self.eat_word("ge") {
                BinaryOp::Ge
            } else if self.eat('<') || self.eat_word("lt") {
                BinaryOp::Lt
            } else if self.eat('>') || self.eat_word("gt") {
                BinaryOp::Gt
            } else {
                return Ok(left);
            };
            self.skip_whitespace();
            let right = self.parse_additive()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
    }

    fn parse_additive(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_multiplicative()?;
        loop {
            self.skip_whitespace();
            let op = match self.peek() {
                Some('+') => BinaryOp::Add,
                Some('-') if !self.number_starts_here() => BinaryOp::Sub,
                _ => return Ok(left),
            };
            self.advance();
            let right_start = self.pos;
            self.skip_whitespace();
            let right = self.parse_multiplicative()?;
            left = self.sourced_math(op, left, right, right_start);
        }
    }

    /// An arithmetic node, with the text Velocity prints for it when it is null: its right
    /// operand and the whitespace around it.
    fn sourced_math(&mut self, op: BinaryOp, left: Expr, right: Expr, right_start: usize) -> Expr {
        let operand_end = self.pos;
        self.skip_whitespace();
        let text = self.source(right_start);
        self.pos = operand_end;
        Expr::Sourced(
            Box::new(Expr::Binary(op, Box::new(left), Box::new(right))),
            text.into(),
        )
    }

    fn parse_multiplicative(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_unary()?;
        loop {
            self.skip_whitespace();
            let op = match self.peek() {
                Some('*') => BinaryOp::Mul,
                Some('/') => BinaryOp::Div,
                Some('%') => BinaryOp::Rem,
                _ => return Ok(left),
            };
            self.advance();
            let right_start = self.pos;
            self.skip_whitespace();
            let right = self.parse_unary()?;
            left = self.sourced_math(op, left, right, right_start);
        }
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if (self.peek() == Some('!') && self.peek_at(1) != Some('=')) || self.eat_word("not") {
            if self.peek() == Some('!') {
                self.advance();
            }
            self.skip_whitespace();
            self.enter()?;
            let operand = self.parse_unary();
            self.leave();
            return Ok(Expr::Not(Box::new(operand?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        if self.peek() == Some('(') {
            self.advance();
            let start = self.pos;
            self.skip_whitespace();
            let inner = self.parse_expression()?;
            self.skip_whitespace();
            let text = self.source(start);
            self.expect(')')?;
            return Ok(Expr::Sourced(Box::new(inner), text.into()));
        }
        self.parse_parameter()
    }

    /// Parses the operands Velocity allows in method arguments, list and map literals, and
    /// indexes: literals, references, lists, ranges, and maps.
    fn parse_parameter(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Some('\'') => self.parse_single_quoted(),
            Some('"') => self.parse_double_quoted(),
            Some('$') => match self.parse_dollar(0)? {
                Dollar::Reference(reference) => Ok(Expr::Reference(reference)),
                Dollar::Text => Err(self.error("expected a reference")),
            },
            Some('[') => {
                self.enter()?;
                let result = self.parse_bracket();
                self.leave();
                result
            }
            Some('{') => {
                self.enter()?;
                let result = self.parse_map();
                self.leave();
                result
            }
            Some(c) if c == '-' || c == '.' || c.is_ascii_digit() => self.parse_number(),
            Some(c) if c.is_ascii_alphabetic() => {
                if self.eat_word("true") {
                    Ok(Expr::Literal(Value::Bool(true)))
                } else if self.eat_word("false") {
                    Ok(Expr::Literal(Value::Bool(false)))
                } else {
                    Err(self.error("unexpected word"))
                }
            }
            _ => Err(self.error("expected a value")),
        }
    }

    fn number_starts_here(&self) -> bool {
        let digit_at = |offset: usize| self.peek_at(offset).is_some_and(|c| c.is_ascii_digit());
        match self.peek() {
            Some('-') => digit_at(1) || (self.peek_at(1) == Some('.') && digit_at(2)),
            Some('.') => digit_at(1),
            Some(c) => c.is_ascii_digit(),
            None => false,
        }
    }

    fn parse_number(&mut self) -> Result<Expr, ParseError> {
        if !self.number_starts_here() {
            return Err(self.error("expected a number"));
        }
        let start = self.pos;
        self.eat('-');
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.advance();
        }
        let mut is_float = false;
        let fraction_follows = self.peek() == Some('.')
            && self
                .peek_at(1)
                .is_none_or(|c| c.is_ascii_digit() || !(c == '.' || is_ident_start(c)));
        if fraction_follows {
            is_float = true;
            self.advance();
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.advance();
            }
        }
        if self.peek().is_some_and(|c| c == 'e' || c == 'E') {
            let digit_after =
                |offset: usize| self.peek_at(offset).is_some_and(|c| c.is_ascii_digit());
            let signed = matches!(self.peek_at(1), Some('+' | '-'));
            if digit_after(1) || (signed && digit_after(2)) {
                is_float = true;
                self.advance();
                if signed {
                    self.advance();
                }
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.advance();
                }
            }
        }
        let text = self.source(start);
        if is_float {
            let value: f64 = text
                .parse()
                .map_err(|_| self.error("invalid floating point literal"))?;
            return Ok(Expr::Literal(Value::Double(value)));
        }
        // Velocity reads an integer literal as an Integer, else a Long, else a BigInteger.
        match BigInt::parse(&text) {
            Ok(Some(value)) => Ok(Expr::Literal(Value::big_integer(value))),
            Ok(None) => Err(self.error("invalid integer literal")),
            Err(_) => Err(ParseError::IntegerLiteralTooLarge {
                literal: text,
                line: self.line(),
            }),
        }
    }

    fn parse_single_quoted(&mut self) -> Result<Expr, ParseError> {
        self.advance();
        let mut text = String::new();
        loop {
            match self.peek() {
                Some('\'') => {
                    self.advance();
                    if self.eat('\'') {
                        text.push('\'');
                    } else {
                        return Ok(Expr::Literal(Value::string(text)));
                    }
                }
                Some(c) => {
                    text.push(c);
                    self.advance();
                }
                None => return Err(self.error("unterminated string")),
            }
        }
    }

    /// A double-quoted string is a template: references and directives inside are evaluated.
    fn parse_double_quoted(&mut self) -> Result<Expr, ParseError> {
        let line = self.line();
        self.advance();
        let mut raw = String::new();
        loop {
            match self.peek() {
                Some('"') => {
                    self.advance();
                    if self.eat('"') {
                        raw.push('"');
                    } else {
                        break;
                    }
                }
                Some(c) => {
                    raw.push(c);
                    self.advance();
                }
                None => return Err(self.error("unterminated string")),
            }
        }
        if !raw.contains(['$', '#']) {
            return Ok(Expr::Literal(Value::string(raw)));
        }
        let block = Self::parse_at(&raw, self.depth, line)?;
        Ok(Expr::Interpolated(block))
    }

    fn parse_bracket(&mut self) -> Result<Expr, ParseError> {
        self.expect('[')?;
        self.skip_whitespace();
        if self.eat(']') {
            return Ok(Expr::List(Vec::new()));
        }
        let first = self.parse_parameter()?;
        self.skip_whitespace();
        if self.eat_str("..") {
            self.skip_whitespace();
            let last = self.parse_parameter()?;
            self.skip_whitespace();
            self.expect(']')?;
            let valid = |expr: &Expr| {
                matches!(
                    expr,
                    Expr::Literal(Value::Int(_) | Value::Long(_) | Value::BigInt(_))
                        | Expr::Reference(_)
                )
            };
            if !valid(&first) || !valid(&last) {
                return Err(self.error("a range needs integer or reference endpoints"));
            }
            return Ok(Expr::Range(Box::new(first), Box::new(last)));
        }
        let mut items = vec![first];
        loop {
            self.skip_whitespace();
            if self.eat(',') {
                self.skip_whitespace();
                items.push(self.parse_parameter()?);
            } else {
                self.expect(']')?;
                return Ok(Expr::List(items));
            }
        }
    }

    fn parse_map(&mut self) -> Result<Expr, ParseError> {
        self.expect('{')?;
        self.skip_whitespace();
        let mut entries = Vec::new();
        if self.eat('}') {
            return Ok(Expr::Map(entries));
        }
        loop {
            let key = self.parse_parameter()?;
            self.skip_whitespace();
            self.expect(':')?;
            self.skip_whitespace();
            let value = self.parse_parameter()?;
            entries.push((key, value));
            self.skip_whitespace();
            if self.eat(',') {
                self.skip_whitespace();
            } else {
                self.expect('}')?;
                return Ok(Expr::Map(entries));
            }
        }
    }
}
