//! Parser for Java regex syntax.
//!
//! Follows `java.util.regex.Pattern`'s own grammar closely, including its error cases, so
//! that a pattern Java rejects is rejected here and a pattern Java accepts is either
//! translated faithfully or refused with an explicit [`Unsupported`] error.

use crate::ast::{
    Anchor, BackReference, CaseMode, ClassItem, ClassSet, Flag, Flags, Greed, GroupKind, LineMode,
    Node,
};
use crate::classes::{Predefined, Property};
use crate::error::{RegexError, Unsupported};

/// Deepest group or class nesting accepted; Java itself overflows its stack far later, but a
/// bound keeps the recursive descent safe for untrusted patterns.
const MAX_DEPTH: usize = 100;

/// The result of parsing: the tree plus the group table.
#[derive(Debug)]
pub(crate) struct Parsed {
    pub(crate) root: Node,
    pub(crate) group_count: usize,
    pub(crate) group_names: Vec<(String, usize)>,
}

/// What `\x` style escapes resolve to inside and outside classes.
enum Escape {
    Char(char),
    Class(ClassItem),
}

pub(crate) struct Parser {
    chars: Vec<char>,
    pos: usize,
    flags: Flags,
    group_count: usize,
    names: Vec<(String, usize)>,
    depth: usize,
}

const fn is_ascii_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{B}' | '\u{C}' | '\r')
}

const fn is_line_end(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

impl Parser {
    /// Parses a Java pattern into a tree with all inline flags resolved.
    ///
    /// # Errors
    ///
    /// Returns [`RegexError::Syntax`] when Java would reject the pattern,
    /// [`RegexError::Unsupported`] when Java accepts it but it cannot be translated, and
    /// [`RegexError::TooDeep`] for pathological nesting.
    pub(crate) fn parse(pattern: &str) -> Result<Parsed, RegexError> {
        let mut parser = Self {
            chars: pattern.chars().collect(),
            pos: 0,
            flags: Flags::default(),
            group_count: 0,
            names: Vec::new(),
            depth: 0,
        };
        let root = parser.parse_alternation()?;
        if parser.peek().is_some() {
            return Err(RegexError::syntax("Unmatched closing ')'", parser.pos));
        }
        Ok(Parsed {
            root,
            group_count: parser.group_count,
            group_names: parser.names,
        })
    }

    fn error(&self, message: &str) -> RegexError {
        RegexError::syntax(message, self.pos)
    }

    fn raw(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos.saturating_add(offset)).copied()
    }

    fn advance(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn next_raw(&mut self) -> Option<char> {
        let c = self.raw(0)?;
        self.advance();
        Some(c)
    }

    fn eat_raw(&mut self, expected: char) -> bool {
        if self.raw(0) == Some(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    /// Skips whitespace and comments under `COMMENTS`, plus empty `\Q\E` pairs.
    fn skip_trivia(&mut self) {
        let comments = self.flags.has(Flag::Comments);
        loop {
            match self.raw(0) {
                Some(c) if comments && is_ascii_space(c) => self.advance(),
                Some('#') if comments => {
                    while self.raw(0).is_some_and(|c| !is_line_end(c)) {
                        self.advance();
                    }
                }
                Some('\\')
                    if self.raw(1) == Some('Q')
                        && self.raw(2) == Some('\\')
                        && self.raw(3) == Some('E') =>
                {
                    self.pos = self.pos.saturating_add(4);
                }
                _ => return,
            }
        }
    }

    fn peek(&mut self) -> Option<char> {
        self.skip_trivia();
        self.raw(0)
    }

    fn next(&mut self) -> Option<char> {
        self.skip_trivia();
        self.next_raw()
    }

    fn enter(&mut self) -> Result<(), RegexError> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_DEPTH {
            return Err(RegexError::TooDeep { limit: MAX_DEPTH });
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn line_mode(&self) -> LineMode {
        if self.flags.has(Flag::UnixLines) {
            LineMode::UnixOnly
        } else {
            LineMode::Any
        }
    }

    fn unicode_classes(&self) -> bool {
        self.flags.has(Flag::UnicodeCharacterClass)
    }

    fn parse_alternation(&mut self) -> Result<Node, RegexError> {
        let mut alternatives = vec![self.parse_sequence()?];
        while self.peek() == Some('|') {
            self.advance();
            alternatives.push(self.parse_sequence()?);
        }
        if alternatives.len() == 1 {
            Ok(alternatives.pop().unwrap_or(Node::Empty))
        } else {
            Ok(Node::Alternate(alternatives))
        }
    }

    fn parse_sequence(&mut self) -> Result<Node, RegexError> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            match c {
                '|' | ')' => break,
                '*' | '+' | '?' => {
                    return Err(RegexError::syntax(
                        format!("Dangling meta character '{c}'"),
                        self.pos,
                    ));
                }
                '{' => {
                    items.push(self.parse_quantifier(Node::Empty)?);
                    continue;
                }
                _ => {}
            }
            let mut atoms = self.parse_atom()?;
            let Some(last) = atoms.pop() else { continue };
            items.extend(atoms);
            items.push(self.parse_quantifier(last)?);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap_or(Node::Empty),
            _ => Node::Concat(items),
        })
    }

    fn parse_quantifier(&mut self, node: Node) -> Result<Node, RegexError> {
        let Some(symbol) = self.peek() else {
            return Ok(node);
        };
        let (min, max) = match symbol {
            '*' => (0, None),
            '+' => (1, None),
            '?' => (0, Some(1)),
            '{' => {
                self.advance();
                self.parse_braces()?
            }
            _ => return Ok(node),
        };
        if symbol != '{' {
            self.advance();
        }
        let greed = match self.peek() {
            Some('?') => {
                self.advance();
                Greed::Lazy
            }
            Some('+') => {
                self.advance();
                Greed::Possessive
            }
            _ => Greed::Greedy,
        };
        if let Some(c @ ('*' | '+' | '?')) = self.peek() {
            return Err(RegexError::syntax(
                format!("Dangling meta character '{c}'"),
                self.pos,
            ));
        }
        Ok(Node::Repeat {
            node: Box::new(node),
            min,
            max,
            greed,
        })
    }

    /// Parses the inside of `{n}`, `{n,}`, or `{n,m}` after the opening brace.
    fn parse_braces(&mut self) -> Result<(u32, Option<u32>), RegexError> {
        let min = self
            .parse_count()?
            .ok_or_else(|| self.error("Illegal repetition"))?;
        let max = if self.eat_raw(',') {
            self.parse_count()?
        } else {
            Some(min)
        };
        if !self.eat_raw('}') {
            return Err(self.error("Unclosed counted closure"));
        }
        if max.is_some_and(|max| max < min) {
            return Err(self.error("Illegal repetition range"));
        }
        Ok((min, max))
    }

    fn parse_count(&mut self) -> Result<Option<u32>, RegexError> {
        let mut value: Option<u32> = None;
        while let Some(digit) = self.raw(0).and_then(|c| c.to_digit(10)) {
            let next = value
                .unwrap_or(0)
                .checked_mul(10)
                .and_then(|v| v.checked_add(digit))
                .filter(|v| i32::try_from(*v).is_ok())
                .ok_or_else(|| self.error("Illegal repetition range"))?;
            value = Some(next);
            self.advance();
        }
        Ok(value)
    }

    /// Parses one atom; a `\Q...\E` quote yields one node per character.
    fn parse_atom(&mut self) -> Result<Vec<Node>, RegexError> {
        let start = self.pos;
        let Some(c) = self.next() else {
            return Ok(Vec::new());
        };
        let mode = self.flags.case_mode();
        let node = match c {
            '(' => self.parse_group()?,
            '[' => {
                let set = self.parse_class()?;
                Node::Class(set, mode)
            }
            '.' => Node::Dot {
                dot_all: self.flags.has(Flag::DotAll),
                lines: self.line_mode(),
            },
            '^' => {
                if self.flags.has(Flag::Multiline) {
                    Node::Anchor(Anchor::LineStart(self.line_mode()))
                } else {
                    Node::Anchor(Anchor::InputStart)
                }
            }
            '$' => {
                if self.flags.has(Flag::Multiline) {
                    Node::Anchor(Anchor::LineEnd(self.line_mode()))
                } else {
                    Node::Anchor(Anchor::InputEndBeforeTerminator(self.line_mode()))
                }
            }
            '\\' => return self.parse_escape(start),
            other => Node::Literal(other, mode),
        };
        Ok(vec![node])
    }

    fn parse_escape(&mut self, start: usize) -> Result<Vec<Node>, RegexError> {
        let mode = self.flags.case_mode();
        let Some(e) = self.next_raw() else {
            return Err(RegexError::syntax(
                "Unexpected internal error: pattern ends with a backslash",
                start,
            ));
        };
        let node = match e {
            'Q' => return Ok(self.parse_quote(mode)),
            'A' => Node::Anchor(Anchor::InputStart),
            'z' => Node::Anchor(Anchor::InputEnd),
            'Z' => Node::Anchor(Anchor::InputEndBeforeTerminator(self.line_mode())),
            'b' | 'B' => self.parse_boundary(e == 'B', start)?,
            'G' => {
                return Err(RegexError::unsupported(
                    Unsupported::EndOfPreviousMatch,
                    start,
                ));
            }
            'X' => return Err(RegexError::unsupported(Unsupported::GraphemeCluster, start)),
            'R' => Node::LineBreak,
            'N' => return Err(self.parse_named_character(start)),
            'k' => self.parse_named_back_reference(start)?,
            '1'..='9' => self.parse_numeric_back_reference(e, start)?,
            _ => match self.parse_class_escape(e, start)? {
                Escape::Char(c) => Node::Literal(c, mode),
                Escape::Class(item) => Node::Class(ClassSet::union(false, vec![item]), mode),
            },
        };
        Ok(vec![node])
    }

    fn parse_named_character(&mut self, start: usize) -> RegexError {
        if self.raw(0) == Some('{') {
            RegexError::unsupported(Unsupported::NamedCharacter, start)
        } else {
            RegexError::syntax("Illegal/unsupported escape sequence", start)
        }
    }

    fn parse_boundary(&mut self, negated: bool, start: usize) -> Result<Node, RegexError> {
        if self.raw(0) == Some('{') {
            return Err(RegexError::unsupported(Unsupported::GraphemeCluster, start));
        }
        let unicode = self.unicode_classes();
        Ok(Node::Anchor(if negated {
            Anchor::NotWordBoundary { unicode }
        } else {
            Anchor::WordBoundary { unicode }
        }))
    }

    /// Reads the text of a `\Q...\E` quote, whose characters are all literal.
    fn parse_quote(&mut self, mode: CaseMode) -> Vec<Node> {
        let mut nodes = Vec::new();
        while let Some(c) = self.next_raw() {
            if c == '\\' && self.raw(0) == Some('E') {
                self.advance();
                break;
            }
            nodes.push(Node::Literal(c, mode));
        }
        nodes
    }

    fn parse_named_back_reference(&mut self, start: usize) -> Result<Node, RegexError> {
        if !self.eat_raw('<') {
            return Err(self.error("\\k is not followed by '<' for named capturing group"));
        }
        let name = self.parse_group_name()?;
        if !self.names.iter().any(|(known, _)| *known == name) {
            return Err(RegexError::syntax(
                format!("named capturing group <{name}> does not exist"),
                self.pos,
            ));
        }
        self.reject_case_insensitive_back_reference(start)?;
        Ok(Node::BackReference(BackReference::Named(name)))
    }

    /// Reads Java's greedy back reference number: more digits are taken only while the
    /// resulting group number already exists.
    fn parse_numeric_back_reference(
        &mut self,
        first: char,
        start: usize,
    ) -> Result<Node, RegexError> {
        let mut number = first.to_digit(10).map_or(0, |d| d as usize);
        while let Some(digit) = self.raw(0).and_then(|c| c.to_digit(10)) {
            let candidate = number.saturating_mul(10).saturating_add(digit as usize);
            if self.group_count < candidate {
                break;
            }
            number = candidate;
            self.advance();
        }
        self.reject_case_insensitive_back_reference(start)?;
        Ok(Node::BackReference(BackReference::Number(number)))
    }

    fn reject_case_insensitive_back_reference(&self, start: usize) -> Result<(), RegexError> {
        if self.flags.has(Flag::CaseInsensitive) {
            Err(RegexError::unsupported(
                Unsupported::CaseInsensitiveBackReference,
                start,
            ))
        } else {
            Ok(())
        }
    }

    fn parse_group_name(&mut self) -> Result<String, RegexError> {
        let mut name = String::new();
        match self.next_raw() {
            Some(c) if c.is_ascii_alphabetic() => name.push(c),
            _ => {
                return Err(self.error("capturing group name does not start with a Latin letter"));
            }
        }
        while let Some(c) = self.raw(0).filter(char::is_ascii_alphanumeric) {
            name.push(c);
            self.advance();
        }
        if !self.eat_raw('>') {
            return Err(self.error("named capturing group is missing trailing '>'"));
        }
        Ok(name)
    }

    fn parse_group(&mut self) -> Result<Node, RegexError> {
        self.enter()?;
        let saved = self.flags;
        let result = self.parse_group_body(saved);
        self.leave();
        result
    }

    fn parse_group_body(&mut self, saved: Flags) -> Result<Node, RegexError> {
        let open = self.pos;
        let kind = if self.eat_raw('?') {
            match self.parse_group_prefix()? {
                GroupPrefix::Kind(kind) => kind,
                GroupPrefix::FlagsOnly => return Ok(Node::Empty),
            }
        } else {
            self.group_count = self.group_count.saturating_add(1);
            GroupKind::Capture(None)
        };
        let kind = self.register_group_name(kind)?;
        let inner = self.parse_alternation()?;
        if !self.eat_raw(')') {
            return Err(RegexError::syntax("Unclosed group", self.pos));
        }
        self.flags = saved;
        if matches!(kind, GroupKind::LookBehind | GroupKind::NegLookBehind)
            && inner.contains_back_reference()
        {
            return Err(RegexError::syntax(
                "Look-behind group does not have an obvious maximum length",
                open,
            ));
        }
        Ok(Node::Group(kind, Box::new(inner)))
    }

    /// Records a named group's number now that it has been counted.
    fn register_group_name(&mut self, kind: GroupKind) -> Result<GroupKind, RegexError> {
        if let GroupKind::Capture(Some(name)) = &kind {
            if self.names.iter().any(|(known, _)| known == name) {
                return Err(RegexError::syntax(
                    format!("Named capturing group <{name}> is already defined"),
                    self.pos,
                ));
            }
            self.names.push((name.clone(), self.group_count));
        }
        Ok(kind)
    }

    /// Parses what follows `(?`.
    fn parse_group_prefix(&mut self) -> Result<GroupPrefix, RegexError> {
        let Some(c) = self.next_raw() else {
            return Err(self.error("Unknown group type"));
        };
        let kind = match c {
            ':' => GroupKind::NonCapture,
            '=' => GroupKind::LookAhead,
            '!' => GroupKind::NegLookAhead,
            '>' => GroupKind::Atomic,
            '<' => match self.raw(0) {
                Some('=') => {
                    self.advance();
                    GroupKind::LookBehind
                }
                Some('!') => {
                    self.advance();
                    GroupKind::NegLookBehind
                }
                _ => {
                    let name = self.parse_group_name()?;
                    self.group_count = self.group_count.saturating_add(1);
                    GroupKind::Capture(Some(name))
                }
            },
            _ => {
                self.pos = self.pos.saturating_sub(1);
                return self.parse_inline_flags();
            }
        };
        Ok(GroupPrefix::Kind(kind))
    }

    /// Parses `idmsuxU-idmsuxU` followed by `)` or `:`.
    fn parse_inline_flags(&mut self) -> Result<GroupPrefix, RegexError> {
        let mut on = true;
        loop {
            let Some(c) = self.next_raw() else {
                return Err(self.error("Unknown inline modifier"));
            };
            match c {
                '-' => on = false,
                ')' => return Ok(GroupPrefix::FlagsOnly),
                ':' => return Ok(GroupPrefix::Kind(GroupKind::NonCapture)),
                _ => {
                    let flag = Flag::from_letter(c)
                        .ok_or_else(|| self.error("Unknown inline modifier"))?;
                    self.flags.set(flag, on);
                }
            }
        }
    }

    /// Parses a bracketed class after its opening `[`.
    fn parse_class(&mut self) -> Result<ClassSet, RegexError> {
        self.enter()?;
        let result = self.parse_class_body();
        self.leave();
        result
    }

    fn parse_class_body(&mut self) -> Result<ClassSet, RegexError> {
        let negated = self.peek() == Some('^') && {
            self.advance();
            true
        };
        let mut operands: Vec<Vec<ClassItem>> = vec![Vec::new()];
        loop {
            let Some(c) = self.peek() else {
                return Err(self.error("Unclosed character class"));
            };
            let at_start = operands.len() == 1 && operands.first().is_some_and(Vec::is_empty);
            if c == ']' && !at_start {
                self.advance();
                break;
            }
            if c == '[' {
                self.advance();
                let nested = self.parse_class()?;
                Self::push_item(&mut operands, ClassItem::Nested(nested));
            } else if c == '&' && self.raw(1) == Some('&') {
                self.pos = self.pos.saturating_add(2);
                operands.push(Vec::new());
            } else {
                for item in self.parse_class_atom()? {
                    Self::push_item(&mut operands, item);
                }
            }
        }
        operands.retain(|operand| !operand.is_empty());
        if operands.is_empty() {
            return Err(self.error("Bad class syntax"));
        }
        Ok(ClassSet { negated, operands })
    }

    fn push_item(operands: &mut [Vec<ClassItem>], item: ClassItem) {
        if let Some(current) = operands.last_mut() {
            current.push(item);
        }
    }

    /// Parses a single class member: a character, a range, or a class escape.
    fn parse_class_atom(&mut self) -> Result<Vec<ClassItem>, RegexError> {
        let start = self.pos;
        let Some(c) = self.next() else {
            return Err(self.error("Unclosed character class"));
        };
        let low = if c == '\\' {
            let Some(e) = self.next_raw() else {
                return Err(self.error("Unclosed character class"));
            };
            if e == 'Q' {
                return Ok(self
                    .parse_quote(CaseMode::Sensitive)
                    .into_iter()
                    .filter_map(|node| match node {
                        Node::Literal(ch, _) => Some(ClassItem::Range(ch, ch)),
                        _ => None,
                    })
                    .collect());
            }
            match self.parse_class_escape(e, start)? {
                Escape::Char(ch) => ch,
                Escape::Class(item) => return Ok(vec![item]),
            }
        } else {
            c
        };
        if self.peek() == Some('-') && !matches!(self.raw(1), Some('[' | ']') | None) {
            self.advance();
            let high = self.parse_range_end()?;
            if high < low {
                return Err(RegexError::syntax("Illegal character range", start));
            }
            return Ok(vec![ClassItem::Range(low, high)]);
        }
        Ok(vec![ClassItem::Range(low, low)])
    }

    fn parse_range_end(&mut self) -> Result<char, RegexError> {
        let start = self.pos;
        let Some(c) = self.next() else {
            return Err(self.error("Unclosed character class"));
        };
        if c != '\\' {
            return Ok(c);
        }
        let Some(e) = self.next_raw() else {
            return Err(self.error("Unclosed character class"));
        };
        match self.parse_class_escape(e, start)? {
            Escape::Char(ch) => Ok(ch),
            Escape::Class(_) => Err(RegexError::syntax("Illegal character range", start)),
        }
    }

    /// Resolves the character after a backslash that is valid both inside and outside a class.
    ///
    /// `start` is the index of the backslash, for error reporting.
    fn parse_class_escape(&mut self, e: char, start: usize) -> Result<Escape, RegexError> {
        let unicode = self.unicode_classes();
        let item = match e {
            't' => return Ok(Escape::Char('\t')),
            'n' => return Ok(Escape::Char('\n')),
            'r' => return Ok(Escape::Char('\r')),
            'f' => return Ok(Escape::Char('\u{C}')),
            'a' => return Ok(Escape::Char('\u{7}')),
            'e' => return Ok(Escape::Char('\u{1B}')),
            '0' => return self.parse_octal(start).map(Escape::Char),
            'x' => return self.parse_hex(start).map(Escape::Char),
            'u' => return self.parse_unicode(start).map(Escape::Char),
            'c' => {
                let control = self
                    .next_raw()
                    .ok_or_else(|| RegexError::syntax("Illegal control escape sequence", start))?;
                return Ok(Escape::Char(
                    char::from_u32(u32::from(control) ^ 64).unwrap_or(control),
                ));
            }
            'd' | 'D' | 's' | 'S' | 'w' | 'W' | 'h' | 'H' | 'v' | 'V' => {
                Predefined::item(e, unicode)
            }
            'p' | 'P' => self.parse_property(e == 'P', start)?,
            e if e.is_ascii_alphabetic() || e.is_ascii_digit() => {
                return Err(RegexError::syntax(
                    "Illegal/unsupported escape sequence",
                    start,
                ));
            }
            e => return Ok(Escape::Char(e)),
        };
        Ok(Escape::Class(item))
    }

    fn parse_octal(&mut self, start: usize) -> Result<char, RegexError> {
        let octal = |c: Option<char>| c.and_then(|c| c.to_digit(8));
        let Some(n) = octal(self.raw(0)) else {
            return Err(RegexError::syntax("Illegal octal escape sequence", start));
        };
        self.advance();
        let mut value = n;
        if let Some(m) = octal(self.raw(0)) {
            self.advance();
            value = Self::shift_in(value, 8, m);
            if n <= 3
                && let Some(o) = octal(self.raw(0))
            {
                self.advance();
                value = Self::shift_in(value, 8, o);
            }
        }
        char::from_u32(value)
            .ok_or_else(|| RegexError::syntax("Illegal octal escape sequence", start))
    }

    fn parse_hex(&mut self, start: usize) -> Result<char, RegexError> {
        let hex = |c: Option<char>| c.and_then(|c| c.to_digit(16));
        if self.raw(0) == Some('{') && hex(self.raw(1)).is_some() {
            self.advance();
            let mut value: u32 = 0;
            while let Some(d) = hex(self.raw(0)) {
                self.advance();
                value = value.saturating_mul(16).saturating_add(d);
                if value > 0x0010_FFFF {
                    return Err(RegexError::syntax(
                        "Hexadecimal codepoint is too big",
                        start,
                    ));
                }
            }
            if !self.eat_raw('}') {
                return Err(RegexError::syntax(
                    "Unclosed hexadecimal escape sequence",
                    start,
                ));
            }
            return Self::scalar(value, start);
        }
        match (hex(self.raw(0)), hex(self.raw(1))) {
            (Some(a), Some(b)) => {
                self.pos = self.pos.saturating_add(2);
                Self::scalar(Self::shift_in(a, 16, b), start)
            }
            _ => Err(RegexError::syntax(
                "Illegal hexadecimal escape sequence",
                start,
            )),
        }
    }

    /// Reads `\uXXXX`, joining a high surrogate with a following `\uXXXX` low surrogate.
    fn parse_unicode(&mut self, start: usize) -> Result<char, RegexError> {
        let high = self.parse_four_hex(start)?;
        if (0xD800..0xDC00).contains(&high) && self.raw(0) == Some('\\') && self.raw(1) == Some('u')
        {
            let saved = self.pos;
            self.pos = self.pos.saturating_add(2);
            if let Ok(low) = self.parse_four_hex(start)
                && let (Ok(high_unit), Ok(low_unit)) = (u16::try_from(high), u16::try_from(low))
                && let Some(Ok(pair)) = char::decode_utf16([high_unit, low_unit]).next()
            {
                return Ok(pair);
            }
            self.pos = saved;
        }
        Self::scalar(high, start)
    }

    fn parse_four_hex(&mut self, start: usize) -> Result<u32, RegexError> {
        let mut value = 0_u32;
        for _ in 0..4 {
            let digit = self
                .raw(0)
                .and_then(|c| c.to_digit(16))
                .ok_or_else(|| RegexError::syntax("Illegal Unicode escape sequence", start))?;
            self.advance();
            value = Self::shift_in(value, 16, digit);
        }
        Ok(value)
    }

    fn shift_in(value: u32, radix: u32, digit: u32) -> u32 {
        value.saturating_mul(radix).saturating_add(digit)
    }

    fn scalar(value: u32, start: usize) -> Result<char, RegexError> {
        char::from_u32(value)
            .ok_or_else(|| RegexError::unsupported(Unsupported::LoneSurrogate, start))
    }

    /// Parses `\p{Name}` or `\pL` after the `p` or `P`.
    fn parse_property(&mut self, negated: bool, start: usize) -> Result<ClassItem, RegexError> {
        let name = match self.next_raw() {
            Some('{') => {
                let mut name = String::new();
                loop {
                    match self.next_raw() {
                        Some('}') => break,
                        Some(c) => name.push(c),
                        None => return Err(RegexError::syntax("Unclosed character family", start)),
                    }
                }
                if name.is_empty() {
                    return Err(RegexError::syntax("Empty character family", start));
                }
                name
            }
            Some(c) => c.to_string(),
            None => return Err(RegexError::syntax("Illegal character family", start)),
        };
        let property = Property::resolve(&name, self.unicode_classes())
            .map_err(|construct| RegexError::unsupported(construct, start))?
            .ok_or_else(|| {
                RegexError::syntax(format!("Unknown character property name {{{name}}}"), start)
            })?;
        Ok(property.into_item(negated))
    }
}

/// What follows `(?`.
enum GroupPrefix {
    /// A group with a body.
    Kind(GroupKind),
    /// `(?i)`: flags that apply to the rest of the enclosing group.
    FlagsOnly,
}
