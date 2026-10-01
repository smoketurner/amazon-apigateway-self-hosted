//! Predefined classes (`\d`, `\w`, ...), POSIX classes, and Unicode properties.

use crate::ast::{ClassItem, ClassSet};
use crate::error::Unsupported;

const fn range(low: char, high: char) -> ClassItem {
    ClassItem::Range(low, high)
}

fn engine(text: &str) -> ClassItem {
    ClassItem::Engine(text.to_owned())
}

const GENERAL_CATEGORIES: &[&str] = &[
    "L", "LC", "Lu", "Ll", "Lt", "Lm", "Lo", "M", "Mn", "Mc", "Me", "N", "Nd", "Nl", "No", "P",
    "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "S", "Sm", "Sc", "Sk", "So", "Z", "Zs", "Zl", "Zp",
    "C", "Cc", "Cf", "Cs", "Co", "Cn",
];

/// The escapes `\d \D \s \S \w \W \h \H \v \V`.
#[derive(Debug)]
pub(crate) struct Predefined;

impl Predefined {
    /// The class for an escape letter. Without `UNICODE_CHARACTER_CLASS` the digit, word and
    /// space classes are ASCII only, as in Java.
    pub(crate) fn item(letter: char, unicode: bool) -> ClassItem {
        let negated = letter.is_ascii_uppercase();
        let base = match letter.to_ascii_lowercase() {
            'd' => Self::digit(unicode),
            'w' => Self::word(unicode),
            's' => Self::space(unicode),
            'h' => Self::horizontal_space(),
            _ => Self::vertical_space(),
        };
        if negated {
            ClassItem::Nested(ClassSet::union(true, base))
        } else if let [single] = base.as_slice() {
            single.clone()
        } else {
            ClassItem::Nested(ClassSet::union(false, base))
        }
    }

    fn digit(unicode: bool) -> Vec<ClassItem> {
        if unicode {
            vec![engine(r"\d")]
        } else {
            vec![range('0', '9')]
        }
    }

    fn word(unicode: bool) -> Vec<ClassItem> {
        if unicode {
            vec![engine(r"\w")]
        } else {
            vec![
                range('a', 'z'),
                range('A', 'Z'),
                range('0', '9'),
                range('_', '_'),
            ]
        }
    }

    fn space(unicode: bool) -> Vec<ClassItem> {
        if unicode {
            vec![engine(r"\s")]
        } else {
            vec![range(' ', ' '), range('\t', '\r')]
        }
    }

    fn horizontal_space() -> Vec<ClassItem> {
        vec![
            range(' ', ' '),
            range('\t', '\t'),
            range('\u{A0}', '\u{A0}'),
            range('\u{1680}', '\u{1680}'),
            range('\u{180E}', '\u{180E}'),
            range('\u{2000}', '\u{200A}'),
            range('\u{202F}', '\u{202F}'),
            range('\u{205F}', '\u{205F}'),
            range('\u{3000}', '\u{3000}'),
        ]
    }

    fn vertical_space() -> Vec<ClassItem> {
        vec![
            range('\n', '\r'),
            range('\u{85}', '\u{85}'),
            range('\u{2028}', '\u{2029}'),
        ]
    }
}

/// A resolved `\p{...}` property, before negation is applied.
#[derive(Debug)]
pub(crate) struct Property {
    items: Vec<ClassItem>,
}

impl Property {
    /// Resolves a Java property name.
    ///
    /// Returns `Ok(None)` when Java would reject the name as unknown, and an
    /// [`Unsupported`] when Java accepts it but there is no equivalent here. Names that look
    /// like Unicode properties or scripts are passed to the engine, which rejects any it does
    /// not know when the pattern is compiled.
    pub(crate) fn resolve(name: &str, unicode: bool) -> Result<Option<Self>, Unsupported> {
        if unicode && matches!(name, "Graph" | "Print") {
            return Err(Unsupported::UnicodePosixClass(name.to_owned()));
        }
        if let Some(items) = Self::posix(name, unicode) {
            return Ok(Some(Self { items }));
        }
        if name.starts_with("java") {
            return Err(Unsupported::JavaCharacterPredicate(name.to_owned()));
        }
        if let Some((key, value)) = name.split_once('=') {
            return Self::resolve_key_value(name, key, value);
        }
        if name.starts_with("In") {
            return Err(Unsupported::UnicodeBlock(name.to_owned()));
        }
        if let Some(bare) = name.strip_prefix("Is") {
            return Ok((!bare.is_empty()).then(|| Self::unicode_property(bare)));
        }
        Ok(GENERAL_CATEGORIES
            .contains(&name)
            .then(|| Self::unicode_property(name)))
    }

    fn resolve_key_value(name: &str, key: &str, value: &str) -> Result<Option<Self>, Unsupported> {
        match key.to_ascii_lowercase().as_str() {
            "script" | "sc" => Ok(Some(Self::unicode_property(&format!("Script={value}")))),
            "general_category" | "gc" => Ok(Some(Self::unicode_property(value))),
            "block" | "blk" => Err(Unsupported::UnicodeBlock(name.to_owned())),
            _ => Ok(None),
        }
    }

    fn unicode_property(name: &str) -> Self {
        let mapped = match name {
            "Titlecase" => "Lt",
            "Punctuation" => "P",
            "Control" => "Cc",
            "Digit" => "Nd",
            "Letter" => "L",
            other => other,
        };
        Self {
            items: vec![ClassItem::Engine(format!(r"\p{{{mapped}}}"))],
        }
    }

    /// The POSIX classes, ASCII-only unless `UNICODE_CHARACTER_CLASS` is on.
    fn posix(name: &str, unicode: bool) -> Option<Vec<ClassItem>> {
        if name == "ASCII" {
            return Some(vec![range('\0', '\u{7F}')]);
        }
        match (name, unicode) {
            ("Lower", false) => Some(vec![range('a', 'z')]),
            ("Upper", false) => Some(vec![range('A', 'Z')]),
            ("Alpha", false) => Some(vec![range('a', 'z'), range('A', 'Z')]),
            ("Digit", false) => Some(vec![range('0', '9')]),
            ("Alnum", false) => Some(vec![range('a', 'z'), range('A', 'Z'), range('0', '9')]),
            ("Punct", false) => Some(vec![
                range('!', '/'),
                range(':', '@'),
                range('[', '`'),
                range('{', '~'),
            ]),
            ("Graph", false) => Some(vec![range('!', '~')]),
            ("Print", false) => Some(vec![range(' ', '~')]),
            ("Blank", false) => Some(vec![range(' ', ' '), range('\t', '\t')]),
            ("Cntrl", false) => Some(vec![range('\0', '\u{1F}'), range('\u{7F}', '\u{7F}')]),
            ("XDigit", false) => Some(vec![range('0', '9'), range('a', 'f'), range('A', 'F')]),
            ("Space", false) => Some(vec![range(' ', ' '), range('\t', '\r')]),
            ("Lower", true) => Some(vec![engine(r"\p{Lowercase}")]),
            ("Upper", true) => Some(vec![engine(r"\p{Uppercase}")]),
            ("Alpha", true) => Some(vec![engine(r"\p{Alphabetic}")]),
            ("Digit", true) => Some(vec![engine(r"\p{Nd}")]),
            ("Alnum", true) => Some(vec![engine(r"\p{Alphabetic}"), engine(r"\p{Nd}")]),
            ("Punct", true) => Some(vec![engine(r"\p{P}")]),
            ("Blank", true) => Some(vec![engine(r"\p{Zs}"), range('\t', '\t')]),
            ("Cntrl", true) => Some(vec![engine(r"\p{Cc}")]),
            ("XDigit", true) => Some(vec![engine(r"\p{Hex_Digit}")]),
            ("Space", true) => Some(vec![engine(r"\s")]),
            _ => None,
        }
    }

    /// Applies `\P` negation, returning an item usable in a class.
    pub(crate) fn into_item(self, negated: bool) -> ClassItem {
        let mut items = self.items;
        if !negated
            && items.len() == 1
            && let Some(single) = items.pop()
        {
            return single;
        }
        ClassItem::Nested(ClassSet::union(negated, items))
    }
}
