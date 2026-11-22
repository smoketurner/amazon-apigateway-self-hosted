//! Intermediate representation of a Java pattern with every inline flag already resolved.

/// How a literal or class compares characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaseMode {
    /// Exact comparison.
    Sensitive,
    /// `CASE_INSENSITIVE` alone: only `A-Z` and `a-z` fold.
    Ascii,
    /// `CASE_INSENSITIVE | UNICODE_CASE`: Java's `toUpperCase`/`toLowerCase` comparison.
    Unicode,
}

/// A single inline flag letter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flag {
    /// `i`
    CaseInsensitive,
    /// `d`
    UnixLines,
    /// `m`
    Multiline,
    /// `s`
    DotAll,
    /// `u`
    UnicodeCase,
    /// `x`
    Comments,
    /// `U`
    UnicodeCharacterClass,
}

impl Flag {
    /// Maps a flag letter to the flag it toggles.
    pub(crate) fn from_letter(letter: char) -> Option<Self> {
        Some(match letter {
            'i' => Self::CaseInsensitive,
            'd' => Self::UnixLines,
            'm' => Self::Multiline,
            's' => Self::DotAll,
            'u' => Self::UnicodeCase,
            'x' => Self::Comments,
            'U' => Self::UnicodeCharacterClass,
            _ => return None,
        })
    }

    const fn bit(self) -> u8 {
        match self {
            Self::CaseInsensitive => 1,
            Self::UnixLines => 1 << 1,
            Self::Multiline => 1 << 2,
            Self::DotAll => 1 << 3,
            Self::UnicodeCase => 1 << 4,
            Self::Comments => 1 << 5,
            Self::UnicodeCharacterClass => 1 << 6,
        }
    }
}

/// The set of inline flags in effect at a point in the pattern.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Flags(u8);

impl Flags {
    /// Returns whether `flag` is set.
    pub(crate) const fn has(self, flag: Flag) -> bool {
        self.0 & flag.bit() != 0
    }

    /// Sets or clears `flag`. Java's `U` flag also turns on `u`.
    pub(crate) fn set(&mut self, flag: Flag, on: bool) {
        let mut bits = flag.bit();
        if flag == Flag::UnicodeCharacterClass {
            bits |= Flag::UnicodeCase.bit();
        }
        if on {
            self.0 |= bits;
        } else {
            self.0 &= !bits;
        }
    }

    /// How literals and classes compare characters under these flags.
    pub(crate) const fn case_mode(self) -> CaseMode {
        if !self.has(Flag::CaseInsensitive) {
            CaseMode::Sensitive
        } else if self.has(Flag::UnicodeCase) {
            CaseMode::Unicode
        } else {
            CaseMode::Ascii
        }
    }
}

/// Which characters terminate a line for `.`, `^`, and `$`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineMode {
    /// Java's default: the line feed, carriage return, CR LF pair, NEL, LINE SEPARATOR, and PARAGRAPH SEPARATOR.
    Any,
    /// `UNIX_LINES`: only `\n`.
    UnixOnly,
}

/// A zero-width position assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Anchor {
    /// `\A`
    InputStart,
    /// `\z`
    InputEnd,
    /// `$` and `\Z` without `MULTILINE`: the end, or before a final line terminator.
    InputEndBeforeTerminator(LineMode),
    /// `^` with `MULTILINE`.
    LineStart(LineMode),
    /// `$` with `MULTILINE`.
    LineEnd(LineMode),
    /// `\b`; the flag says whether word characters are Unicode.
    WordBoundary { unicode: bool },
    /// `\B`
    NotWordBoundary { unicode: bool },
    /// `\G`: where the previous match ended, or where the search started.
    PreviousMatchEnd,
    /// `\b{g}`: a grapheme cluster boundary.
    GraphemeBoundary,
}

impl Anchor {
    /// Whether the assertion depends on where the previous match ended.
    pub(crate) const fn reads_previous_match_end(self) -> bool {
        matches!(self, Self::PreviousMatchEnd | Self::GraphemeBoundary)
    }
}

/// Quantifier greediness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Greed {
    /// `X*`
    Greedy,
    /// `X*?`
    Lazy,
    /// `X*+`
    Possessive,
}

/// The kind of group around a sub-pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GroupKind {
    /// `(...)` or `(?<name>...)`; the parser resolves names to group numbers.
    Capture,
    /// `(?:...)`
    NonCapture,
    /// `(?=...)`
    LookAhead,
    /// `(?!...)`
    NegLookAhead,
    /// `(?<=...)`
    LookBehind,
    /// `(?<!...)`
    NegLookBehind,
    /// `(?>...)`
    Atomic,
}

impl GroupKind {
    /// Whether the group asserts without consuming input.
    pub(crate) const fn is_look_around(&self) -> bool {
        matches!(
            self,
            Self::LookAhead | Self::NegLookAhead | Self::LookBehind | Self::NegLookBehind
        )
    }
}

/// An element of a bracketed character class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClassItem {
    /// A single character written in the class.
    Single(char),
    /// An inclusive range of characters written in the class.
    Range(char, char),
    /// A Unicode class written in the matching engine's own syntax, such as `\p{L}`.
    Engine(String),
    /// A nested class.
    Nested(ClassSet),
    /// A predefined class or property, such as `\w` or `\p{Lower}`. Case-insensitive matching
    /// never folds it: Java resolves case insensitivity when it looks the property up.
    Predicate(ClassSet),
}

impl ClassItem {
    /// An item that matches no character.
    pub(crate) fn nothing() -> Self {
        Self::Predicate(ClassSet::union(true, vec![Self::Range('\0', char::MAX)]))
    }

    /// The characters from `low` to `high`, code points that may include UTF-16 surrogates.
    ///
    /// A Rust string cannot contain a lone surrogate, and Java never matches half of a
    /// surrogate pair against a class, so the surrogates in the range match nothing.
    pub(crate) fn code_range(low: u32, high: u32) -> Self {
        const FIRST_SURROGATE: u32 = 0xD800;
        const LAST_SURROGATE: u32 = 0xDFFF;
        let mut items = Vec::new();
        let below = high.min(FIRST_SURROGATE.saturating_sub(1));
        if low <= below
            && let (Some(start), Some(end)) = (char::from_u32(low), char::from_u32(below))
        {
            items.push(Self::Range(start, end));
        }
        let above = low.max(LAST_SURROGATE.saturating_add(1));
        if above <= high
            && let (Some(start), Some(end)) = (char::from_u32(above), char::from_u32(high))
        {
            items.push(Self::Range(start, end));
        }
        match items.len() {
            0 => Self::nothing(),
            1 => items.pop().unwrap_or_else(Self::nothing),
            _ => Self::Predicate(ClassSet::union(false, items)),
        }
    }
}

/// A bracketed class: the intersection of one or more unions, optionally negated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClassSet {
    pub(crate) negated: bool,
    /// Operands of `&&`; a class without `&&` has exactly one.
    pub(crate) operands: Vec<Vec<ClassItem>>,
}

impl ClassSet {
    /// A class made of a single union of `items`.
    pub(crate) fn union(negated: bool, items: Vec<ClassItem>) -> Self {
        Self {
            negated,
            operands: vec![items],
        }
    }
}

/// A node of the parsed pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Node {
    /// Matches the empty string.
    Empty,
    /// A literal character. `slice` is set when Java reads it as part of a run of literal
    /// characters, which compares case-insensitively slightly differently from a lone one.
    Literal {
        ch: char,
        mode: CaseMode,
        slice: bool,
    },
    /// `.`
    Dot { dot_all: bool, lines: LineMode },
    /// A bracketed class.
    Class(ClassSet, CaseMode),
    /// A zero-width assertion.
    Anchor(Anchor),
    /// `\R`: `\r\n` or any single vertical whitespace character.
    LineBreak,
    /// `\X`: one extended grapheme cluster.
    Grapheme,
    /// A back reference to group `group`, which may not exist (and then never matches).
    BackReference { group: usize, mode: CaseMode },
    /// A sequence of nodes.
    Concat(Vec<Self>),
    /// Alternatives separated by `|`.
    Alternate(Vec<Self>),
    /// A group around a node.
    Group(GroupKind, Box<Self>),
    /// A quantified node.
    Repeat {
        node: Box<Self>,
        min: u32,
        max: Option<u32>,
        greed: Greed,
    },
}

impl Node {
    /// A node that matches no character, for a lone surrogate.
    pub(crate) fn nothing() -> Self {
        Self::Class(
            ClassSet::union(false, vec![ClassItem::nothing()]),
            CaseMode::Sensitive,
        )
    }

    /// Whether the node can be the operand of a quantifier without extra grouping.
    pub(crate) const fn is_single_unit(&self) -> bool {
        match self {
            Self::Literal { .. }
            | Self::Dot { .. }
            | Self::Class(..)
            | Self::LineBreak
            | Self::Grapheme
            | Self::BackReference { .. }
            | Self::Group(..) => true,
            Self::Empty
            | Self::Anchor(_)
            | Self::Concat(_)
            | Self::Alternate(_)
            | Self::Repeat { .. } => false,
        }
    }

    /// Whether the node can only ever match the empty string.
    pub(crate) fn is_zero_width(&self) -> bool {
        match self {
            Self::Empty | Self::Anchor(_) => true,
            Self::Group(kind, inner) => kind.is_look_around() || inner.is_zero_width(),
            Self::Concat(nodes) | Self::Alternate(nodes) => nodes.iter().all(Self::is_zero_width),
            Self::Repeat { node, .. } => node.is_zero_width(),
            Self::Literal { .. }
            | Self::Dot { .. }
            | Self::Class(..)
            | Self::LineBreak
            | Self::Grapheme
            | Self::BackReference { .. } => false,
        }
    }

    /// Whether the node is zero-width with a single way to match. Java repeats a capturing
    /// group around such a node with `GroupCurly`, which keeps no capture for an empty
    /// iteration, instead of with its general loop.
    pub(crate) fn is_deterministic_zero_width(&self) -> bool {
        match self {
            Self::Empty | Self::Anchor(_) => true,
            Self::Group(kind, inner) => {
                kind.is_look_around() || inner.is_deterministic_zero_width()
            }
            Self::Concat(nodes) => nodes.iter().all(Self::is_deterministic_zero_width),
            Self::Repeat { node, min, max, .. } => {
                *max == Some(*min) && node.is_deterministic_zero_width()
            }
            Self::Alternate(_)
            | Self::Literal { .. }
            | Self::Dot { .. }
            | Self::Class(..)
            | Self::LineBreak
            | Self::Grapheme
            | Self::BackReference { .. } => false,
        }
    }

    /// Whether the node can match the empty string.
    pub(crate) fn can_match_empty(&self) -> bool {
        match self {
            Self::Empty | Self::Anchor(_) | Self::BackReference { .. } => true,
            Self::Group(kind, inner) => kind.is_look_around() || inner.can_match_empty(),
            Self::Concat(nodes) => nodes.iter().all(Self::can_match_empty),
            Self::Alternate(nodes) => nodes.iter().any(Self::can_match_empty),
            Self::Repeat { node, min, max, .. } => {
                *min == 0 || *max == Some(0) || node.can_match_empty()
            }
            Self::Literal { .. }
            | Self::Dot { .. }
            | Self::Class(..)
            | Self::LineBreak
            | Self::Grapheme => false,
        }
    }

    /// Whether a back reference occurs anywhere inside the node.
    ///
    /// Java refuses look-behinds that contain one because their width cannot be bounded.
    pub(crate) fn contains_back_reference(&self) -> bool {
        self.any(&|node| matches!(node, Self::BackReference { .. }))
    }

    /// Whether an assertion that depends on the previous match end occurs inside the node.
    pub(crate) fn reads_previous_match_end(&self) -> bool {
        self.any(&|node| matches!(node, Self::Anchor(anchor) if anchor.reads_previous_match_end()))
    }

    fn any(&self, predicate: &impl Fn(&Self) -> bool) -> bool {
        if predicate(self) {
            return true;
        }
        match self {
            Self::Concat(nodes) | Self::Alternate(nodes) => {
                nodes.iter().any(|node| node.any(predicate))
            }
            Self::Group(_, inner) | Self::Repeat { node: inner, .. } => inner.any(predicate),
            Self::Empty
            | Self::Literal { .. }
            | Self::Dot { .. }
            | Self::Class(..)
            | Self::Anchor(_)
            | Self::LineBreak
            | Self::Grapheme
            | Self::BackReference { .. } => false,
        }
    }
}
