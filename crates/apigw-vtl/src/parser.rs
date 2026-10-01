//! A parser for Velocity 1.7 templates.
//!
//! The grammar and its lexical quirks follow Velocity 1.7 as observed against the real engine:
//! which characters continue an identifier, that `-1` is a single number token, that method
//! arguments are not full expressions, how backslashes escape references and directives, and
//! which whitespace around directives is swallowed.

use crate::ast::{BinaryOp, Block, Expr, Foreach, If, Node, Reference, Set, Step};
use crate::error::ParseError;
use crate::value::Value;

/// Deepest nesting of directives, expressions, collections, and interpolated strings.
pub(crate) const MAX_PARSE_DEPTH: usize = 64;

const fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

const fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
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
    /// `#macro`, `#parse`, `#include`, `#evaluate`, and `#define`.
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

/// Accumulates the nodes of one block.
struct BlockBuilder {
    nodes: Vec<Node>,
    text: String,
    /// Whether the current text run started right after a token that is not text: a reference,
    /// a directive, or a comment. Whitespace alone in such a run before `#set` is dropped.
    after_token: bool,
    /// Whether the last text or reference was a reference, so that a `[` would start an index:
    /// Velocity's lexer stays in that state across directives and comments.
    reference_pending: PendingReference,
    /// The value of `reference_pending` before the current text run began.
    pending_before_text: PendingReference,
}

/// A reference that the lexer is still "inside" until text follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingReference {
    None,
    /// The reference ended in a property: `##` is then text, not a comment.
    Property,
    /// Any other reference; only `[` is affected.
    Other,
}

impl BlockBuilder {
    const fn new(after_token: bool) -> Self {
        Self {
            nodes: Vec::new(),
            text: String::new(),
            after_token,
            reference_pending: PendingReference::None,
            pending_before_text: PendingReference::None,
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
            self.reference_pending = self.pending_before_text;
        }
    }

    fn add_text(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        if self.text.is_empty() {
            self.pending_before_text = self.reference_pending;
        }
        self.reference_pending = PendingReference::None;
        self.text.push_str(text);
    }

    fn add_char(&mut self, c: char) {
        let mut buffer = [0_u8; 4];
        self.add_text(c.encode_utf8(&mut buffer));
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

pub(crate) struct Parser {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
    first_line: usize,
}

impl Parser {
    /// Parses a template.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] for anything Velocity 1.7 rejects, for directives that are not
    /// supported, and for templates nested beyond [`MAX_PARSE_DEPTH`].
    pub(crate) fn parse(source: &str) -> Result<Block, ParseError> {
        Self::parse_at(source, 0, 1)
    }

    fn parse_at(source: &str, depth: usize, first_line: usize) -> Result<Block, ParseError> {
        let mut parser = Self {
            chars: source.chars().collect(),
            pos: 0,
            depth,
            first_line,
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
            if c == '[' && builder.reference_pending != PendingReference::None {
                return Err(self.error("unexpected '[' after a reference"));
            }
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
                other => {
                    builder.add_char(other);
                    self.advance();
                }
            }
        }
        Ok((builder.finish(), BlockEnd::Eof))
    }

    fn parse_dollar_in_text(
        &mut self,
        builder: &mut BlockBuilder,
        backslashes: usize,
    ) -> Result<(), ParseError> {
        match self.parse_dollar(backslashes)? {
            Dollar::Reference(reference) => {
                let formal =
                    reference.source.starts_with("${") || reference.source.starts_with("$!{");
                let pending = if formal {
                    PendingReference::None
                } else if matches!(reference.steps.last(), Some(Step::Property(_))) {
                    PendingReference::Property
                } else {
                    PendingReference::Other
                };
                builder.push_node(Node::Reference(reference));
                builder.reference_pending = pending;
            }
            Dollar::Text => builder.add_char('$'),
        }
        Ok(())
    }

    /// Handles a run of backslashes, which escape a following reference or directive.
    fn parse_backslashes(
        &mut self,
        builder: &mut BlockBuilder,
    ) -> Result<Option<BlockEnd>, ParseError> {
        let mut count = 0_usize;
        while self.peek() == Some('\\') {
            count = count.saturating_add(1);
            self.advance();
        }
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
        let source: String = self
            .chars
            .get(start..self.pos)
            .map(|slice| slice.iter().collect())
            .unwrap_or_default();
        Ok(Dollar::Reference(Reference {
            head: head.into(),
            steps,
            quiet,
            source,
            backslashes,
        }))
    }

    /// Whether the `(` under the cursor is followed by a directive without arguments and then by
    /// something other than a space, `.`, or `:`. Velocity looks three tokens ahead to tell a
    /// method call from a property, and a directive cannot start an argument, so the `(` is then
    /// plain text; the text after the directive decides whether the rest still lexes.
    fn directive_after_paren(&mut self) -> bool {
        if self.peek_at(1) != Some('#') {
            return false;
        }
        let saved = self.pos;
        self.advance();
        let token = self.directive_at(false);
        self.pos = saved;
        token.is_some_and(|token| {
            matches!(
                token.directive,
                Directive::End | Directive::Else | Directive::Break | Directive::Stop
            ) && !matches!(self.chars.get(token.end), Some(' ' | '\t' | '.' | ':'))
        })
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
                    if self.peek() == Some('(') && self.directive_after_paren() {
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
        if backslashes == 0
            && self.peek_at(1) == Some('#')
            && builder.reference_pending == PendingReference::Property
        {
            builder.add_text("##");
            self.pos = self.pos.saturating_add(2);
            return Ok(None);
        }
        if backslashes == 0 && self.peek_at(1) == Some('#') {
            self.skip_line_comment();
            builder.mark_token();
            return Ok(None);
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
        let Some(token) = self.directive_at(backslashes.is_multiple_of(2)) else {
            if backslashes == 0 {
                self.advance();
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

    /// `#name(args)` for a name that is not a directive is a call of a macro that is not defined,
    /// which renders as written; arguments that do not parse are an error.
    fn parse_macro_call_text(&mut self, builder: &mut BlockBuilder) -> Result<(), ParseError> {
        if self.peek() != Some('(') {
            return Ok(());
        }
        let start = self.pos;
        self.advance();
        loop {
            self.skip_whitespace();
            if self.eat(')') {
                break;
            }
            self.eat(',');
            self.skip_whitespace();
            self.parse_parameter()?;
        }
        let call: String = self
            .chars
            .get(start..self.pos)
            .map(|s| s.iter().collect())
            .unwrap_or_default();
        builder.add_text(&call);
        Ok(())
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
            "macro" | "parse" | "include" | "evaluate" | "define" => Directive::Unsupported,
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
            .map(|slice| slice.iter().collect())
            .unwrap_or_default();
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
                builder.reference_pending = PendingReference::None;
                Ok(None)
            }
            Directive::Foreach => {
                let node = self.parse_foreach()?;
                builder.push_node(Node::Foreach(node));
                builder.reference_pending = PendingReference::None;
                Ok(None)
            }
            Directive::Break | Directive::Stop if self.peek() == Some('(') => {
                Err(self.error("unexpected '(' after a directive without arguments"))
            }
            Directive::Break => {
                builder.push_node(Node::Break);
                self.eat_line_end();
                Ok(None)
            }
            Directive::Stop => {
                builder.push_node(Node::Stop);
                self.eat_line_end();
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
        let (body, end) = self.parse_block(true)?;
        match end {
            BlockEnd::End => Ok(Foreach {
                var: var.into(),
                source,
                body,
            }),
            BlockEnd::Eof => Err(self.error("missing #end for #foreach")),
            BlockEnd::Else | BlockEnd::ElseIf(_) => {
                Err(self.error("#else is not allowed in #foreach"))
            }
        }
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
            self.skip_whitespace();
            let right = self.parse_multiplicative()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
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
            self.skip_whitespace();
            let right = self.parse_unary()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
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
            self.skip_whitespace();
            let inner = self.parse_expression()?;
            self.skip_whitespace();
            self.expect(')')?;
            return Ok(inner);
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
        let text: String = self
            .chars
            .get(start..self.pos)
            .map(|slice| slice.iter().collect())
            .unwrap_or_default();
        if is_float {
            let value: f64 = text
                .parse()
                .map_err(|_| self.error("invalid floating point literal"))?;
            Ok(Expr::Literal(Value::Double(value)))
        } else {
            let value: i64 = text
                .parse()
                .map_err(|_| ParseError::IntegerLiteralTooLarge {
                    literal: text.clone(),
                    line: self.line(),
                })?;
            Ok(Expr::Literal(Value::Int(value)))
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
            let valid =
                |expr: &Expr| matches!(expr, Expr::Literal(Value::Int(_)) | Expr::Reference(_));
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
