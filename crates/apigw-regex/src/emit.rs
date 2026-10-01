//! Renders the parsed tree as `fancy-regex` syntax.
//!
//! Every Java flag is resolved by the parser, so the output spells out each construct
//! explicitly: literals and ranges are `\x{..}` escapes, case folding is expanded for ASCII
//! and delegated to `(?i:..)` for Unicode, and anchors are built from look-around.

use std::fmt;

use crate::ast::{
    Anchor, BackReference, CaseMode, ClassItem, ClassSet, Greed, GroupKind, LineMode, Node,
};

/// Positions where `$` and `\Z` match without `MULTILINE`: the very end, or just before one
/// final line terminator (never between the `\r` and `\n` of a CRLF pair).
const END_BEFORE_TERMINATOR: &str =
    r"(?:\z|(?=\r\n\z)|(?=[\r\x{85}\x{2028}\x{2029}]\z)|(?<!\r)(?=\n\z))";
const END_BEFORE_TERMINATOR_UNIX: &str = r"(?:\z|(?=\n\z))";
const LINE_START: &str = r"(?!\z)(?:\A|(?<=[\n\x{85}\x{2028}\x{2029}])|(?<=\r)(?!\n))";
const LINE_START_UNIX: &str = r"(?!\z)(?:\A|(?<=\n))";
const LINE_END: &str = r"(?:\z|(?=[\r\x{85}\x{2028}\x{2029}])|(?<!\r)(?=\n))";
const LINE_END_UNIX: &str = r"(?:\z|(?=\n))";
const LINE_BREAK: &str = r"(?:\r\n|[\n\x{B}\x{C}\r\x{85}\x{2028}\x{2029}])";
const ASCII_WORD_BOUNDARY: &str =
    r"(?:(?<=[a-zA-Z0-9_])(?![a-zA-Z0-9_])|(?<![a-zA-Z0-9_])(?=[a-zA-Z0-9_]))";
const ASCII_NOT_WORD_BOUNDARY: &str =
    r"(?:(?<=[a-zA-Z0-9_])(?=[a-zA-Z0-9_])|(?<![a-zA-Z0-9_])(?![a-zA-Z0-9_]))";
const NEVER_MATCHES: &str = "(?!)";

/// Writes the translation of a parsed pattern.
#[derive(Debug)]
pub(crate) struct Emitter {
    out: String,
    group_count: usize,
}

impl Emitter {
    /// Renders `root`, a pattern with `group_count` capture groups, as `fancy-regex` syntax.
    pub(crate) fn render(root: &Node, group_count: usize) -> String {
        let mut emitter = Self {
            out: String::new(),
            group_count,
        };
        emitter.node(root);
        emitter.out
    }

    fn push_fmt(&mut self, args: fmt::Arguments<'_>) {
        self.out.push_str(&fmt::format(args));
    }

    fn push(&mut self, text: &str) {
        self.out.push_str(text);
    }

    fn literal(&mut self, c: char) {
        if c.is_ascii_alphanumeric() {
            self.out.push(c);
        } else {
            self.escaped(c);
        }
    }

    fn escaped(&mut self, c: char) {
        self.push_fmt(format_args!(r"\x{{{:X}}}", u32::from(c)));
    }

    fn node(&mut self, node: &Node) {
        match node {
            Node::Empty => {}
            Node::Literal(c, mode) => self.case_literal(*c, *mode),
            Node::Dot { dot_all, lines } => self.dot(*dot_all, *lines),
            Node::Class(set, mode) => self.class(set, *mode),
            Node::Anchor(anchor) => self.anchor(*anchor),
            Node::LineBreak => self.push(LINE_BREAK),
            Node::BackReference(target) => self.back_reference(target),
            Node::Concat(nodes) => {
                for child in nodes {
                    self.concat_member(child);
                }
            }
            Node::Alternate(nodes) => {
                for (index, child) in nodes.iter().enumerate() {
                    if index > 0 {
                        self.push("|");
                    }
                    self.node(child);
                }
            }
            Node::Group(kind, inner) => self.group(kind, inner),
            Node::Repeat {
                node,
                min,
                max,
                greed,
            } => self.repeat(node, *min, *max, *greed),
        }
    }

    fn concat_member(&mut self, node: &Node) {
        if matches!(node, Node::Alternate(_)) {
            self.push("(?:");
            self.node(node);
            self.push(")");
        } else {
            self.node(node);
        }
    }

    fn case_literal(&mut self, c: char, mode: CaseMode) {
        match mode {
            CaseMode::Ascii if c.is_ascii_alphabetic() => {
                self.push("[");
                self.out.push(c.to_ascii_lowercase());
                self.out.push(c.to_ascii_uppercase());
                self.push("]");
            }
            CaseMode::Unicode if c.is_alphabetic() => {
                self.push("(?i:");
                self.literal(c);
                self.push(")");
            }
            CaseMode::Sensitive | CaseMode::Ascii | CaseMode::Unicode => self.literal(c),
        }
    }

    fn dot(&mut self, dot_all: bool, lines: LineMode) {
        if dot_all {
            self.push("(?s:.)");
        } else {
            match lines {
                LineMode::Any => self.push(r"[^\n\r\x{85}\x{2028}\x{2029}]"),
                LineMode::UnixOnly => self.push(r"[^\n]"),
            }
        }
    }

    fn anchor(&mut self, anchor: Anchor) {
        let text = match anchor {
            Anchor::InputStart => r"\A",
            Anchor::InputEnd => r"\z",
            Anchor::InputEndBeforeTerminator(LineMode::Any) => END_BEFORE_TERMINATOR,
            Anchor::InputEndBeforeTerminator(LineMode::UnixOnly) => END_BEFORE_TERMINATOR_UNIX,
            Anchor::LineStart(LineMode::Any) => LINE_START,
            Anchor::LineStart(LineMode::UnixOnly) => LINE_START_UNIX,
            Anchor::LineEnd(LineMode::Any) => LINE_END,
            Anchor::LineEnd(LineMode::UnixOnly) => LINE_END_UNIX,
            Anchor::WordBoundary { unicode: true } => r"\b",
            Anchor::WordBoundary { unicode: false } => ASCII_WORD_BOUNDARY,
            Anchor::NotWordBoundary { unicode: true } => r"\B",
            Anchor::NotWordBoundary { unicode: false } => ASCII_NOT_WORD_BOUNDARY,
        };
        self.push(text);
    }

    fn back_reference(&mut self, target: &BackReference) {
        match target {
            BackReference::Number(n) if *n <= self.group_count => {
                self.push_fmt(format_args!(r"(?:\{n})"));
            }
            BackReference::Number(_) => self.push(NEVER_MATCHES),
            BackReference::Named(name) => {
                self.push_fmt(format_args!(r"(?:\k<{name}>)"));
            }
        }
    }

    fn group(&mut self, kind: &GroupKind, inner: &Node) {
        match kind {
            GroupKind::Capture(None) => self.push("("),
            GroupKind::Capture(Some(name)) => {
                self.push_fmt(format_args!("(?<{name}>"));
            }
            GroupKind::NonCapture => self.push("(?:"),
            GroupKind::LookAhead => self.push("(?="),
            GroupKind::NegLookAhead => self.push("(?!"),
            GroupKind::LookBehind => self.push("(?<="),
            GroupKind::NegLookBehind => self.push("(?<!"),
            GroupKind::Atomic => self.push("(?>"),
        }
        self.node(inner);
        self.push(")");
    }

    fn repeat(&mut self, operand: &Node, min: u32, max: Option<u32>, greed: Greed) {
        if operand.is_zero_width() {
            self.repeat_zero_width(operand, min, greed);
            return;
        }
        if greed == Greed::Possessive {
            self.push("(?>");
        }
        if operand.is_single_unit() {
            self.node(operand);
        } else {
            self.push("(?:");
            self.node(operand);
            self.push(")");
        }
        match (min, max) {
            (0, None) => self.push("*"),
            (1, None) => self.push("+"),
            (0, Some(1)) => self.push("?"),
            (min, None) => {
                self.push_fmt(format_args!("{{{min},}}"));
            }
            (min, Some(max)) if min == max => {
                self.push_fmt(format_args!("{{{min}}}"));
            }
            (min, Some(max)) => {
                self.push_fmt(format_args!("{{{min},{max}}}"));
            }
        }
        match greed {
            Greed::Greedy => {}
            Greed::Lazy => self.push("?"),
            Greed::Possessive => self.push(")"),
        }
    }

    /// Repeating a zero-width assertion is the assertion itself, or an alternative with the
    /// empty match when it may be skipped; the engine rejects quantifiers on assertions.
    fn repeat_zero_width(&mut self, operand: &Node, min: u32, greed: Greed) {
        if min == 0 {
            self.push("(?:");
            if greed == Greed::Lazy {
                self.push("|");
                self.node(operand);
            } else {
                self.node(operand);
                self.push("|");
            }
            self.push(")");
        } else {
            self.concat_member(operand);
        }
    }

    fn class(&mut self, set: &ClassSet, mode: CaseMode) {
        if mode == CaseMode::Unicode {
            self.push("(?i:");
            self.class_set(set, false);
            self.push(")");
        } else {
            self.class_set(set, mode == CaseMode::Ascii);
        }
    }

    fn class_set(&mut self, set: &ClassSet, fold_ascii: bool) {
        self.push("[");
        if set.negated {
            self.push("^");
        }
        if let [only] = set.operands.as_slice() {
            self.class_items(only, fold_ascii);
        } else {
            for (index, operand) in set.operands.iter().enumerate() {
                if index > 0 {
                    self.push("&&");
                }
                self.push("[");
                self.class_items(operand, fold_ascii);
                self.push("]");
            }
        }
        self.push("]");
    }

    fn class_items(&mut self, items: &[ClassItem], fold_ascii: bool) {
        for item in items {
            match item {
                ClassItem::Range(low, high) => {
                    self.class_range(*low, *high);
                    if fold_ascii {
                        self.folded_ranges(*low, *high);
                    }
                }
                ClassItem::Engine(text) => self.push(text),
                ClassItem::Nested(nested) => self.class_set(nested, fold_ascii),
            }
        }
    }

    fn class_range(&mut self, low: char, high: char) {
        self.escaped(low);
        if low != high {
            self.push("-");
            self.escaped(high);
        }
    }

    /// Adds the other-case counterparts of the ASCII letters inside `low..=high`.
    fn folded_ranges(&mut self, low: char, high: char) {
        let lower_start = low.max('a');
        let lower_end = high.min('z');
        if lower_start <= lower_end {
            self.class_range(
                lower_start.to_ascii_uppercase(),
                lower_end.to_ascii_uppercase(),
            );
        }
        let upper_start = low.max('A');
        let upper_end = high.min('Z');
        if upper_start <= upper_end {
            self.class_range(
                upper_start.to_ascii_lowercase(),
                upper_end.to_ascii_lowercase(),
            );
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;
    use crate::parser::Parser;

    fn translate(pattern: &str) -> String {
        let parsed = Parser::parse(pattern).unwrap();
        Emitter::render(&parsed.root, parsed.group_count)
    }

    #[test]
    fn digits_are_ascii_ranges() {
        assert_eq!(translate(r"\d+"), r"[\x{30}-\x{39}]+");
    }

    #[test]
    fn ascii_case_folding_expands_literals_and_ranges() {
        assert_eq!(translate("(?i)a"), "[aA]");
        assert_eq!(translate("(?i)[a-c]"), r"[\x{61}-\x{63}\x{41}-\x{43}]");
    }

    #[test]
    fn unicode_case_folding_defers_to_the_engine() {
        assert_eq!(translate("(?iu)é"), r"(?i:\x{E9})");
    }

    #[test]
    fn possessive_quantifiers_become_atomic_groups() {
        assert_eq!(translate("a*+"), "(?>a*)");
    }

    #[test]
    fn quantified_assertions_are_simplified() {
        assert_eq!(translate("(?=a){2}"), "(?=a)");
        assert_eq!(translate("(?=a)*"), "(?:(?=a)|)");
        assert_eq!(translate("(?=a)*?"), "(?:|(?=a))");
    }

    #[test]
    fn back_references_are_isolated_from_following_digits() {
        assert_eq!(translate(r"(a)\10"), r"(a)(?:\1)0");
    }

    #[test]
    fn back_reference_to_missing_group_never_matches() {
        assert_eq!(translate(r"\1"), NEVER_MATCHES);
    }

    #[test]
    fn alternation_inside_concatenation_is_grouped() {
        assert_eq!(translate("a(?:b|c)d"), "a(?:b|c)d");
        assert_eq!(translate("a|b"), "a|b");
    }
}
