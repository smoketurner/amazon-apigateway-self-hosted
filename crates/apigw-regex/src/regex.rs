//! The compiled pattern and Java's matching, replacing, and splitting operations.

use fancy_regex::{Regex, RegexBuilder};

use crate::emit::Emitter;
use crate::error::RegexError;
use crate::parser::Parser;
use crate::replacement::Replacement;

/// Default number of backtracking steps before matching fails with
/// [`RegexError::BacktrackLimitExceeded`].
pub const DEFAULT_BACKTRACK_LIMIT: usize = 1_000_000;

/// Default size limit, in bytes, of each compiled program.
pub const DEFAULT_SIZE_LIMIT: usize = 1 << 20;

/// Limits applied when compiling and running a pattern.
///
/// # Examples
///
/// ```
/// use apigw_regex::{JavaRegex, RegexError, RegexOptions};
///
/// # fn main() -> Result<(), apigw_regex::RegexError> {
/// let options = RegexOptions::default().with_backtrack_limit(5_000);
/// let regex = JavaRegex::with_options(r"(a|aa)+\1c", &options)?;
/// let input = format!("{}b", "a".repeat(40));
/// assert_eq!(regex.matches(&input), Err(RegexError::BacktrackLimitExceeded));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RegexOptions {
    backtrack_limit: usize,
    size_limit: usize,
}

impl Default for RegexOptions {
    fn default() -> Self {
        Self {
            backtrack_limit: DEFAULT_BACKTRACK_LIMIT,
            size_limit: DEFAULT_SIZE_LIMIT,
        }
    }
}

impl RegexOptions {
    /// Sets how many backtracking steps a match may take.
    ///
    /// Exceeding it fails the operation with [`RegexError::BacktrackLimitExceeded`]. Only
    /// patterns that need backtracking (back references, look-around, atomic groups) are
    /// subject to the limit; the rest run in linear time.
    #[must_use]
    pub const fn with_backtrack_limit(mut self, limit: usize) -> Self {
        self.backtrack_limit = limit;
        self
    }

    /// Sets the approximate size limit, in bytes, of each compiled program.
    ///
    /// Patterns such as `(a{1000}){1000}` are rejected at compile time when they exceed it.
    #[must_use]
    pub const fn with_size_limit(mut self, limit: usize) -> Self {
        self.size_limit = limit;
        self
    }

    fn build(&self, pattern: &str) -> Result<Regex, RegexError> {
        Ok(RegexBuilder::new(pattern)
            .backtrack_limit(self.backtrack_limit)
            .delegate_size_limit(self.size_limit)
            .delegate_dfa_size_limit(self.size_limit)
            .build()?)
    }
}

/// A matched region of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match<'t> {
    input: &'t str,
    start: usize,
    end: usize,
}

impl<'t> Match<'t> {
    /// Byte offset where the match starts.
    #[must_use]
    pub const fn start(&self) -> usize {
        self.start
    }

    /// Byte offset just past the end of the match.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.end
    }

    /// The matched text.
    #[must_use]
    pub fn as_str(&self) -> &'t str {
        self.input.get(self.start..self.end).unwrap_or_default()
    }
}

/// The groups of one match: group 0 is the whole match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captures<'t> {
    groups: Vec<Option<Match<'t>>>,
}

impl<'t> Captures<'t> {
    fn new(input: &'t str, captures: &fancy_regex::Captures<'t, str>) -> Self {
        let groups = captures
            .iter()
            .map(|group| {
                group.map(|m| Match {
                    input,
                    start: m.start(),
                    end: m.end(),
                })
            })
            .collect();
        Self { groups }
    }

    /// The text of group `index`, or `None` when the group did not take part in the match.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<Match<'t>> {
        self.groups.get(index).copied().flatten()
    }

    /// The whole match.
    #[must_use]
    pub fn whole(&self) -> Option<Match<'t>> {
        self.get(0)
    }

    /// Number of groups including group 0.
    #[must_use]
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Whether there are no groups; a successful match always has group 0.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Iterates over group 0 and every numbered group in order.
    pub fn iter(&self) -> impl Iterator<Item = Option<Match<'t>>> + '_ {
        self.groups.iter().copied()
    }
}

/// A `java.util.regex` pattern.
///
/// The pattern is parsed with Java's grammar and translated to `fancy-regex` once, at
/// construction. The operations then follow `Matcher` and `String`: [`matches`] must cover the
/// whole input, [`find`] and [`find_iter`] search, [`replace_all`] and [`replace_first`] take
/// Java replacement strings, and [`split`] follows `Pattern.split`.
///
/// # Examples
///
/// ```
/// use apigw_regex::{JavaRegex, Replacement};
///
/// # fn main() -> Result<(), apigw_regex::RegexError> {
/// let regex = JavaRegex::new(r"\d+")?;
/// assert!(regex.matches("2024")?);
/// assert!(!regex.matches("2024-01")?);
/// assert_eq!(regex.find("ab12cd")?.map(|m| m.as_str()), Some("12"));
/// assert_eq!(regex.replace_all("a1b22", &Replacement::from("#"))?, "a#b#");
/// assert_eq!(JavaRegex::new(",")?.split("a,b,,", 0)?, ["a", "b"]);
/// # Ok(())
/// # }
/// ```
///
/// [`matches`]: JavaRegex::matches
/// [`find`]: JavaRegex::find
/// [`find_iter`]: JavaRegex::find_iter
/// [`replace_all`]: JavaRegex::replace_all
/// [`replace_first`]: JavaRegex::replace_first
/// [`split`]: JavaRegex::split
#[derive(Debug, Clone)]
pub struct JavaRegex {
    source: String,
    search: Regex,
    whole: Regex,
    group_count: usize,
    group_names: Vec<(String, usize)>,
}

impl JavaRegex {
    /// Compiles `pattern` with the default [`RegexOptions`].
    ///
    /// # Errors
    ///
    /// See [`JavaRegex::with_options`].
    pub fn new(pattern: &str) -> Result<Self, RegexError> {
        Self::with_options(pattern, &RegexOptions::default())
    }

    /// Compiles `pattern` with explicit limits.
    ///
    /// # Errors
    ///
    /// Returns [`RegexError::Syntax`] for patterns Java rejects, the typed
    /// [`RegexError::Unsupported`] for constructs that cannot be translated, and
    /// [`RegexError::Engine`] when the translated pattern exceeds the engine's limits.
    pub fn with_options(pattern: &str, options: &RegexOptions) -> Result<Self, RegexError> {
        let parsed = Parser::parse(pattern)?;
        let translated = Emitter::render(&parsed.root, parsed.group_count);
        let search = options.build(&translated)?;
        let whole = options.build(&format!(r"\A(?:{translated})\z"))?;
        Ok(Self {
            source: pattern.to_owned(),
            search,
            whole,
            group_count: parsed.group_count,
            group_names: parsed.group_names,
        })
    }

    /// Escapes `text` so it matches literally, like `Pattern.quote`.
    #[must_use]
    pub fn quote(text: &str) -> String {
        format!(r"\Q{}\E", text.replace(r"\E", r"\E\\E\Q"))
    }

    /// The pattern as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Number of capturing groups, not counting group 0.
    #[must_use]
    pub const fn group_count(&self) -> usize {
        self.group_count
    }

    /// The number of the group named `name`, if the pattern defines one.
    #[must_use]
    pub fn group_index(&self, name: &str) -> Option<usize> {
        self.group_names
            .iter()
            .find_map(|(known, index)| (known == name).then_some(*index))
    }

    /// Whether the whole of `input` matches, like `Matcher.matches`.
    ///
    /// # Errors
    ///
    /// Returns [`RegexError::BacktrackLimitExceeded`] when matching takes too many steps.
    pub fn matches(&self, input: &str) -> Result<bool, RegexError> {
        Ok(self.whole.is_match(input)?)
    }

    /// Finds the first match, like `Matcher.find`.
    ///
    /// # Errors
    ///
    /// Returns [`RegexError::BacktrackLimitExceeded`] when matching takes too many steps.
    pub fn find<'t>(&self, input: &'t str) -> Result<Option<Match<'t>>, RegexError> {
        Ok(self.captures(input)?.and_then(|captures| captures.whole()))
    }

    /// Finds the first match with its groups.
    ///
    /// # Errors
    ///
    /// Returns [`RegexError::BacktrackLimitExceeded`] when matching takes too many steps.
    pub fn captures<'t>(&self, input: &'t str) -> Result<Option<Captures<'t>>, RegexError> {
        self.captures_from(input, 0)
    }

    fn captures_from<'t>(
        &self,
        input: &'t str,
        from: usize,
    ) -> Result<Option<Captures<'t>>, RegexError> {
        Ok(self
            .search
            .captures_from_pos(input, from)?
            .map(|captures| Captures::new(input, &captures)))
    }

    /// Iterates over successive matches the way repeated `Matcher.find` calls do, including
    /// the empty matches Java reports between and after non-empty ones.
    ///
    /// Each item is a `Result` because matching can exceed the backtrack limit; after an error
    /// the iterator ends.
    #[must_use]
    pub fn find_iter<'r, 't>(&'r self, input: &'t str) -> Matches<'r, 't> {
        Matches {
            regex: self,
            input,
            next_from: Some(0),
        }
    }

    /// Replaces every match, like `String.replaceAll`.
    ///
    /// # Errors
    ///
    /// Returns [`RegexError::Replacement`] when a match is expanded with a malformed
    /// replacement, and [`RegexError::BacktrackLimitExceeded`] when matching takes too many
    /// steps.
    pub fn replace_all(
        &self,
        input: &str,
        replacement: &Replacement,
    ) -> Result<String, RegexError> {
        self.replace_limited(input, replacement, usize::MAX)
    }

    /// Replaces the first match, like `String.replaceFirst`.
    ///
    /// # Errors
    ///
    /// As for [`JavaRegex::replace_all`].
    pub fn replace_first(
        &self,
        input: &str,
        replacement: &Replacement,
    ) -> Result<String, RegexError> {
        self.replace_limited(input, replacement, 1)
    }

    fn replace_limited(
        &self,
        input: &str,
        replacement: &Replacement,
        limit: usize,
    ) -> Result<String, RegexError> {
        let mut out = String::with_capacity(input.len());
        let mut copied = 0;
        for captures in self.captures_iter(input).take(limit) {
            let captures = captures?;
            let Some(whole) = captures.whole() else {
                continue;
            };
            out.push_str(input.get(copied..whole.start()).unwrap_or_default());
            replacement.expand_into(self, &captures, &mut out)?;
            copied = whole.end();
        }
        out.push_str(input.get(copied..).unwrap_or_default());
        Ok(out)
    }

    /// Splits `input` around matches, like `Pattern.split(input, limit)`.
    ///
    /// A positive `limit` caps the number of pieces; the last piece keeps the remaining
    /// text. A zero `limit` drops trailing empty pieces, and a negative one keeps them. A
    /// zero-width match at the start never produces a leading empty piece.
    ///
    /// # Errors
    ///
    /// Returns [`RegexError::BacktrackLimitExceeded`] when matching takes too many steps.
    pub fn split<'t>(&self, input: &'t str, limit: i32) -> Result<Vec<&'t str>, RegexError> {
        let max_pieces = usize::try_from(limit).ok().filter(|limit| *limit > 0);
        let mut pieces: Vec<&'t str> = Vec::new();
        let mut index = 0;
        for found in self.find_iter(input) {
            let found = found?;
            if max_pieces.is_some_and(|max| pieces.len() >= max.saturating_sub(1)) {
                break;
            }
            if index == 0 && found.start() == 0 && found.end() == 0 {
                continue;
            }
            pieces.push(input.get(index..found.start()).unwrap_or_default());
            index = found.end();
        }
        if index == 0 {
            return Ok(vec![input]);
        }
        pieces.push(input.get(index..).unwrap_or_default());
        if limit == 0 {
            while pieces.last().is_some_and(|piece| piece.is_empty()) {
                pieces.pop();
            }
        }
        Ok(pieces)
    }

    fn captures_iter<'r, 't>(&'r self, input: &'t str) -> CapturesIter<'r, 't> {
        CapturesIter {
            regex: self,
            input,
            next_from: Some(0),
        }
    }

    /// Where the next search starts after `captures`: Java skips one character after an
    /// empty match so the scan always advances.
    fn resume_after(input: &str, whole: Match<'_>) -> Option<usize> {
        if whole.start() != whole.end() {
            return Some(whole.end());
        }
        let width = input.get(whole.end()..)?.chars().next()?.len_utf8();
        Some(whole.end().saturating_add(width))
    }
}

struct CapturesIter<'r, 't> {
    regex: &'r JavaRegex,
    input: &'t str,
    next_from: Option<usize>,
}

impl<'t> Iterator for CapturesIter<'_, 't> {
    type Item = Result<Captures<'t>, RegexError>;

    fn next(&mut self) -> Option<Self::Item> {
        let from = self.next_from.take()?;
        match self.regex.captures_from(self.input, from) {
            Ok(Some(captures)) => {
                self.next_from = captures
                    .whole()
                    .and_then(|whole| JavaRegex::resume_after(self.input, whole));
                Some(Ok(captures))
            }
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        }
    }
}

/// Iterator over the matches of a pattern; see [`JavaRegex::find_iter`].
#[derive(Debug)]
pub struct Matches<'r, 't> {
    regex: &'r JavaRegex,
    input: &'t str,
    next_from: Option<usize>,
}

impl<'t> Iterator for Matches<'_, 't> {
    type Item = Result<Match<'t>, RegexError>;

    fn next(&mut self) -> Option<Self::Item> {
        let from = self.next_from.take()?;
        match self.regex.captures_from(self.input, from) {
            Ok(Some(captures)) => {
                let whole = captures.whole()?;
                self.next_from = JavaRegex::resume_after(self.input, whole);
                Some(Ok(whole))
            }
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        }
    }
}
