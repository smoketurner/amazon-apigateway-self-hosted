//! Intermediate representation of a Java pattern with every inline flag already resolved.

/// How a literal or class compares characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaseMode {
    /// Exact comparison.
    Sensitive,
    /// `CASE_INSENSITIVE` alone: only `A-Z` and `a-z` fold.
    Ascii,
    /// `CASE_INSENSITIVE | UNICODE_CASE`: Unicode simple case folding.
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
    /// `(...)`, with the name for `(?<name>...)`.
    Capture(Option<String>),
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
    /// An inclusive range of characters; a single character has equal ends.
    Range(char, char),
    /// A Unicode class written in the matching engine's own syntax, such as `\w` or `\p{L}`.
    Engine(String),
    /// A nested class.
    Nested(ClassSet),
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
    /// A literal character.
    Literal(char, CaseMode),
    /// `.`
    Dot { dot_all: bool, lines: LineMode },
    /// A bracketed class.
    Class(ClassSet, CaseMode),
    /// A zero-width assertion.
    Anchor(Anchor),
    /// `\R`: `\r\n` or any single vertical whitespace character.
    LineBreak,
    /// A back reference to group `n`, or to a group that does not exist (which never matches).
    BackReference(BackReference),
    /// A sequence of nodes.
    Concat(Vec<Node>),
    /// Alternatives separated by `|`.
    Alternate(Vec<Node>),
    /// A group around a node.
    Group(GroupKind, Box<Node>),
    /// A quantified node.
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
        greed: Greed,
    },
}

/// The target of a back reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BackReference {
    /// `\n`
    Number(usize),
    /// `\k<name>`
    Named(String),
}

impl Node {
    /// Whether the node can be the operand of a quantifier without extra grouping.
    pub(crate) const fn is_single_unit(&self) -> bool {
        match self {
            Self::Literal(..)
            | Self::Dot { .. }
            | Self::Class(..)
            | Self::LineBreak
            | Self::BackReference(_)
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
            Self::Literal(..)
            | Self::Dot { .. }
            | Self::Class(..)
            | Self::LineBreak
            | Self::BackReference(_) => false,
        }
    }

    /// Whether a back reference occurs anywhere inside the node.
    ///
    /// Java refuses look-behinds that contain one because their width cannot be bounded.
    pub(crate) fn contains_back_reference(&self) -> bool {
        match self {
            Self::BackReference(_) => true,
            Self::Concat(nodes) | Self::Alternate(nodes) => {
                nodes.iter().any(Self::contains_back_reference)
            }
            Self::Group(_, inner) | Self::Repeat { node: inner, .. } => {
                inner.contains_back_reference()
            }
            Self::Empty
            | Self::Literal(..)
            | Self::Dot { .. }
            | Self::Class(..)
            | Self::Anchor(_)
            | Self::LineBreak => false,
        }
    }
}
