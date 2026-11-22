//! Renders the parsed tree as `fancy-regex` syntax.
//!
//! Every Java flag is resolved by the parser, so the output spells out each construct
//! explicitly: literals and ranges are `\x{..}` escapes, case-insensitive matching is expanded
//! into the exact characters Java compares equal, and anchors are built from look-around.

use std::fmt;

use crate::ast::{Anchor, CaseMode, ClassItem, ClassSet, Greed, GroupKind, LineMode, Node};
use crate::case::JavaCase;

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
const NEVER_MATCHES: &str = "(?!)";
/// `\G`. fancy-regex stops the whole search when a `\G` it considers to be at the start of
/// the pattern fails, which it also does for a `\G` at the start of a look-behind such as
/// `(?<=\G..)`. Inside an alternation the `\G` is never considered at the start.
const PREVIOUS_MATCH_END: &str = r"(?:\G|(?!))";

/// Java's ASCII `\b` and `\B` (`Pattern.Bound`). A character counts as a word character when
/// it is an ASCII word character, or a non-spacing mark that follows a chain of BMP
/// non-spacing marks back to a letter or digit. Java walks back over UTF-16 code units, so a
/// supplementary base or mark in that chain ends it.
#[derive(Debug)]
struct AsciiBound;

impl AsciiBound {
    /// The character before the position is a word character (inside a look-behind).
    const LEFT: &'static str =
        r"[a-zA-Z0-9_]|[[\p{L}\p{Nd}]&&[\x{0}-\x{FFFF}]][\p{Mn}&&[\x{0}-\x{FFFF}]]+";
    /// The character after the position is a word character.
    const RIGHT: &'static str = r"(?:(?=[a-zA-Z0-9_])|(?=\p{Mn})(?<=[[\p{L}\p{Nd}]&&[\x{0}-\x{FFFF}]][\p{Mn}&&[\x{0}-\x{FFFF}]]*))";

    fn render(negated: bool) -> String {
        let (left, right) = (Self::LEFT, Self::RIGHT);
        if negated {
            format!("(?:(?<={left}){right}|(?<!{left})(?!{right}))")
        } else {
            format!("(?:(?<={left})(?!{right})|(?<!{left}){right})")
        }
    }
}

/// Character classes of Java's grapheme cluster types (`jdk.internal.util.regex.Grapheme`).
#[derive(Debug)]
struct Grapheme;

impl Grapheme {
    const EXTENDED_PICTOGRAPHIC: &'static str = r"\p{Extended_Pictographic}";
    const PREPEND: &'static str = r"[\x{600}-\x{605}\x{6DD}\x{70F}\x{890}\x{891}\x{8E2}\x{110BD}\x{110CD}\x{D4E}\x{111C2}\x{111C3}\x{1193F}\x{11941}\x{11A3A}\x{11A84}-\x{11A89}\x{11D46}\x{11F02}]";
    const CONTROL: &'static str = r"[\x{0}-\x{9}\x{B}\x{C}\x{E}-\x{1F}[[\p{Cc}\p{Zl}\p{Zp}\p{Cs}\p{Cn}\p{Cf}]&&[^\x{0}-\x{7E}\p{Extended_Pictographic}\x{378}\x{200C}\x{200D}\x{E0020}-\x{E007F}\x{600}-\x{605}\x{6DD}\x{70F}\x{890}\x{891}\x{8E2}\x{110BD}\x{110CD}]]]";
    const EXTEND: &'static str = r"[[\p{Mn}\p{Me}\x{200C}\x{E0020}-\x{E007F}\x{FF9E}\x{FF9F}\x{1F3FB}-\x{1F3FF}]&&[^\p{Extended_Pictographic}]]";
    const SPACING_MARK: &'static str = r"[[\p{Mc}\x{E33}\x{EB3}]&&[^\x{102B}\x{102C}\x{1038}\x{1062}-\x{1064}\x{1067}-\x{106D}\x{1083}\x{1087}-\x{108C}\x{108F}\x{109A}-\x{109C}\x{1A61}\x{1A63}\x{1A64}\x{AA7B}\x{AA7D}\p{Extended_Pictographic}]]";
    const ZWJ: &'static str = r"\x{200D}";
    const REGIONAL_INDICATOR: &'static str = r"[\x{1F1E6}-\x{1F1FF}]";
    const L: &'static str = r"[\x{1100}-\x{115F}\x{A960}-\x{A97C}]";
    const V: &'static str = r"[\x{1160}-\x{11A7}\x{D7B0}-\x{D7C6}]";
    const T: &'static str = r"[\x{11A8}-\x{11FF}\x{D7CB}-\x{D7FB}]";

    /// Hangul syllables without a final consonant: every 28th from U+AC00.
    fn lv() -> String {
        let mut class = String::from("[");
        for index in 0..399_u32 {
            let code = 0xAC00_u32.saturating_add(index.saturating_mul(28));
            class.push_str(&fmt::format(format_args!(r"\x{{{code:X}}}")));
        }
        class.push(']');
        class
    }

    /// `\X`: Java's `Grapheme.nextBoundary` as an atomic pattern.
    fn cluster() -> String {
        format!("(?>{})", Self::partial_cluster())
    }

    /// Every run of characters that `Grapheme.nextBoundary` reads without a break, which is a
    /// whole cluster or the start of one. Java applies the pair rules of UAX #29 from the first
    /// character, continues emoji ZWJ sequences only when the cluster starts with an extended
    /// pictographic, and pairs regional indicators.
    fn partial_cluster() -> String {
        let lv = Self::lv();
        let lvt = format!(
            r"[[\x{{AC00}}-\x{{D7A3}}]&&[^{}]]",
            lv.get(1..lv.len().saturating_sub(1)).unwrap_or("")
        );
        let (l, v, t) = (Self::L, Self::V, Self::T);
        let hangul =
            format!("{l}+(?:(?:{lv}|{v}){v}*{t}*|{lvt}{t}*)?|(?:{lv}|{v}){v}*{t}*|{lvt}{t}*|{t}+");
        let marks = format!("[{}{}{}]", Self::EXTEND, Self::ZWJ, Self::SPACING_MARK);
        let ri = Self::REGIONAL_INDICATOR;
        let control = Self::CONTROL;
        let core = format!(r"{ri}{ri}?|{hangul}|[^\r\n{control}]");
        let pictographic = Self::EXTENDED_PICTOGRAPHIC;
        format!(
            r"\r\n|[\r\n{control}]|{pictographic}(?:[{extend}{spacing}]|{zwj}{pictographic}?)*|{prepend}+(?:(?:{core}){marks}*)?|(?:{core}){marks}*",
            extend = Self::EXTEND,
            spacing = Self::SPACING_MARK,
            zwj = Self::ZWJ,
            prepend = Self::PREPEND,
        )
    }
}

/// A translated pattern with the engine group number of each Java group.
#[derive(Debug)]
pub(crate) struct Translation {
    pub(crate) pattern: String,
    /// Index `n` holds the engine group of Java group `n`, or `None` when the translation drops
    /// a group that Java can never set; index 0 is the whole match.
    pub(crate) groups: Vec<Option<usize>>,
}

/// Writes the translation of a parsed pattern.
#[derive(Debug)]
pub(crate) struct Emitter {
    out: String,
    groups: Vec<Option<usize>>,
}

impl Emitter {
    /// Renders `root`, a pattern with `group_count` capture groups, as `fancy-regex` syntax.
    pub(crate) fn render(root: &Node, group_count: usize) -> Translation {
        let mut groups = Vec::with_capacity(group_count.saturating_add(1));
        groups.push(Some(0));
        let mut engine = 0;
        Self::number_groups(root, &mut groups, &mut engine, false);
        let mut emitter = Self {
            out: String::new(),
            groups,
        };
        emitter.node(root);
        Translation {
            pattern: emitter.out,
            groups: emitter.groups,
        }
    }

    /// Assigns engine group numbers in pattern order, the order the emitter writes them.
    fn number_groups(
        node: &Node,
        groups: &mut Vec<Option<usize>>,
        engine: &mut usize,
        dropped: bool,
    ) {
        match node {
            Node::Group(kind, inner) => {
                if *kind == GroupKind::Capture {
                    if dropped {
                        groups.push(None);
                    } else {
                        *engine = engine.saturating_add(1);
                        groups.push(Some(*engine));
                    }
                }
                Self::number_groups(inner, groups, engine, false);
            }
            Node::Repeat {
                node: operand,
                min,
                max,
                greed,
            } => {
                let drops = Self::dropped_capture(operand, *min, *max, *greed).is_some();
                Self::number_groups(operand, groups, engine, drops);
            }
            Node::Concat(nodes) | Node::Alternate(nodes) => {
                for child in nodes {
                    Self::number_groups(child, groups, engine, false);
                }
            }
            Node::Empty
            | Node::Literal { .. }
            | Node::Dot { .. }
            | Node::Class(..)
            | Node::Anchor(_)
            | Node::LineBreak
            | Node::Grapheme
            | Node::BackReference { .. } => {}
        }
    }

    /// The body of a capturing group that Java repeats with `GroupCurly` and never records:
    /// a greedy `(X)*` or `(X){0,n}` around a zero-width `X` with a single way to match.
    /// Java evaluates `X` once, keeps the groups inside it, and restores the outer group.
    fn dropped_capture(operand: &Node, min: u32, max: Option<u32>, greed: Greed) -> Option<&Node> {
        match operand {
            Node::Group(GroupKind::Capture, inner)
                if min == 0
                    && greed == Greed::Greedy
                    && max.is_none_or(|max| max > 1)
                    && inner.is_deterministic_zero_width() =>
            {
                Some(inner)
            }
            _ => None,
        }
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
            Node::Literal { ch, mode, slice } => self.case_literal(*ch, *mode, *slice),
            Node::Dot { dot_all, lines } => self.dot(*dot_all, *lines),
            Node::Class(set, mode) => self.class_set(set, *mode),
            Node::Anchor(anchor) => self.anchor(*anchor),
            Node::LineBreak => self.push(LINE_BREAK),
            Node::Grapheme => self.push(&Grapheme::cluster()),
            Node::BackReference { group, mode } => self.back_reference(*group, *mode),
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

    fn case_literal(&mut self, c: char, mode: CaseMode, slice: bool) {
        match mode {
            CaseMode::Ascii if c.is_ascii_alphabetic() => {
                self.push("[");
                self.out.push(c.to_ascii_lowercase());
                self.out.push(c.to_ascii_uppercase());
                self.push("]");
            }
            CaseMode::Unicode => {
                let chars = if slice {
                    JavaCase::in_slice(c)
                } else {
                    JavaCase::single(c)
                };
                self.char_set(&chars);
            }
            CaseMode::Sensitive | CaseMode::Ascii => self.literal(c),
        }
    }

    /// A literal standing for any of `chars`.
    fn char_set(&mut self, chars: &[char]) {
        if let [only] = chars {
            self.literal(*only);
            return;
        }
        self.push("[");
        for c in chars {
            self.escaped(*c);
        }
        self.push("]");
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
            Anchor::NotWordBoundary { unicode: true } => r"\B",
            Anchor::WordBoundary { unicode: false } => {
                return self.push(&AsciiBound::render(false));
            }
            Anchor::NotWordBoundary { unicode: false } => {
                return self.push(&AsciiBound::render(true));
            }
            Anchor::PreviousMatchEnd => PREVIOUS_MATCH_END,
            Anchor::GraphemeBoundary => {
                // `Pattern.GraphemeBound`: the start and end of input, and every position at
                // or after the end of the first grapheme cluster that starts where the previous
                // match ended. A position is before that end when the text from the previous
                // match end through the next character is still a partial cluster; checking it
                // that way keeps the look-behind as short as one cluster.
                let partial = Grapheme::partial_cluster();
                return self.push_fmt(format_args!(
                    r"(?:\A|\z|(?!(?s:.)(?<={PREVIOUS_MATCH_END}(?:{partial}))))"
                ));
            }
        };
        self.push(text);
    }

    fn back_reference(&mut self, group: usize, mode: CaseMode) {
        let Some(Some(engine)) = self.groups.get(group).copied() else {
            self.push(NEVER_MATCHES);
            return;
        };
        if group == 0 {
            self.push(NEVER_MATCHES);
            return;
        }
        match mode {
            CaseMode::Sensitive => self.push_fmt(format_args!(r"(?:\{engine})")),
            CaseMode::Ascii | CaseMode::Unicode => {
                self.push_fmt(format_args!(r"(?i:\{engine})"));
            }
        }
    }

    fn group(&mut self, kind: &GroupKind, inner: &Node) {
        self.push(match kind {
            GroupKind::Capture => "(",
            GroupKind::NonCapture => "(?:",
            GroupKind::LookAhead => "(?=",
            GroupKind::NegLookAhead => "(?!",
            GroupKind::LookBehind => "(?<=",
            GroupKind::NegLookBehind => "(?<!",
            GroupKind::Atomic => "(?>",
        });
        self.node(inner);
        self.push(")");
    }

    fn repeat(&mut self, operand: &Node, min: u32, max: Option<u32>, greed: Greed) {
        if max == Some(0) {
            // Never evaluated: the groups inside exist but stay unset.
            self.push("(?:(?!)");
            self.node(operand);
            self.push(")?");
            return;
        }
        if operand.is_zero_width() {
            if let Some(inner) = Self::dropped_capture(operand, min, max, greed) {
                self.repeat_zero_width(inner, min, greed);
            } else {
                self.repeat_zero_width(operand, min, greed);
            }
            return;
        }
        if greed == Greed::Possessive {
            self.push("(?>");
        }
        if operand.can_match_empty() && max.is_none_or(|max| max > 1) {
            // Java stops a loop at an iteration that matches the empty string and keeps that
            // iteration's groups. The engine's backtracking VM does the same, but its default
            // delegated matcher does not, so the empty look-ahead keeps the loop on the VM.
            self.push("(?:(?=)");
            self.node(operand);
            self.push(")");
        } else if operand.is_single_unit() {
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

    fn class_set(&mut self, set: &ClassSet, mode: CaseMode) {
        self.push("[");
        if set.negated {
            self.push("^");
        }
        if let [only] = set.operands.as_slice() {
            self.class_items(only, mode);
        } else {
            for (index, operand) in set.operands.iter().enumerate() {
                if index > 0 {
                    self.push("&&");
                }
                self.push("[");
                self.class_items(operand, mode);
                self.push("]");
            }
        }
        self.push("]");
    }

    fn class_items(&mut self, items: &[ClassItem], mode: CaseMode) {
        for item in items {
            match item {
                ClassItem::Single(c) => self.class_single(*c, mode),
                ClassItem::Range(low, high) => self.class_range_folded(*low, *high, mode),
                ClassItem::Engine(text) => self.push(text),
                ClassItem::Nested(nested) => self.nested_set(nested, mode),
                ClassItem::Predicate(nested) => self.nested_set(nested, CaseMode::Sensitive),
            }
        }
    }

    /// A class inside a class; a plain union is written inline.
    fn nested_set(&mut self, set: &ClassSet, mode: CaseMode) {
        match set.operands.as_slice() {
            [only] if !set.negated => self.class_items(only, mode),
            _ => self.class_set(set, mode),
        }
    }

    fn class_single(&mut self, c: char, mode: CaseMode) {
        match mode {
            CaseMode::Sensitive => self.escaped(c),
            CaseMode::Ascii => {
                self.escaped(c);
                if c.is_ascii_alphabetic() {
                    self.escaped(if c.is_ascii_lowercase() {
                        c.to_ascii_uppercase()
                    } else {
                        c.to_ascii_lowercase()
                    });
                }
            }
            CaseMode::Unicode => {
                for folded in JavaCase::in_class(c) {
                    self.escaped(folded);
                }
            }
        }
    }

    fn class_range_folded(&mut self, low: char, high: char, mode: CaseMode) {
        self.class_range(low, high);
        match mode {
            CaseMode::Sensitive => {}
            CaseMode::Ascii => self.folded_ranges(low, high),
            CaseMode::Unicode => {
                for extra in JavaCase::range_extras(low, high) {
                    self.escaped(extra);
                }
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
        Emitter::render(&parsed.root, parsed.group_count).pattern
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
    fn unicode_case_folding_lists_the_characters_java_compares_equal() {
        assert_eq!(translate("(?iu)é"), r"[\x{E9}\x{C9}]");
        assert_eq!(translate("(?iu)ß"), r"\x{DF}");
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
    fn loops_whose_body_can_be_empty_stay_on_the_backtracking_engine() {
        assert_eq!(translate("(a*)*"), "(?:(?=)(a*))*");
        assert_eq!(translate("(a*)?"), "(a*)?");
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
    fn a_group_java_never_records_is_dropped_and_later_groups_renumbered() {
        let parsed = Parser::parse(r"(^)*(a)\2").unwrap();
        let translation = Emitter::render(&parsed.root, parsed.group_count);
        assert_eq!(translation.groups, [Some(0), None, Some(1)]);
        assert_eq!(translation.pattern, r"(?:\A|)(a)(?:\1)");
    }

    #[test]
    fn alternation_inside_concatenation_is_grouped() {
        assert_eq!(translate("a(?:b|c)d"), "a(?:b|c)d");
        assert_eq!(translate("a|b"), "a|b");
    }
}
