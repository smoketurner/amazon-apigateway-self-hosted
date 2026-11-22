//! Predefined classes (`\d`, `\w`, ...), POSIX classes, and Unicode properties, resolved the way
//! `java.util.regex.Pattern` and `CharPredicates` resolve them.

use crate::ast::{ClassItem, ClassSet};
use crate::tables::{BLOCKS, SCRIPTS};

const fn range(low: char, high: char) -> ClassItem {
    ClassItem::Range(low, high)
}

const fn single(c: char) -> ClassItem {
    ClassItem::Range(c, c)
}

fn engine(text: &str) -> ClassItem {
    ClassItem::Engine(text.to_owned())
}

fn union(items: Vec<ClassItem>) -> ClassItem {
    ClassItem::Predicate(ClassSet::union(false, items))
}

fn complement(items: Vec<ClassItem>) -> ClassItem {
    ClassItem::Predicate(ClassSet::union(true, items))
}

/// The escapes `\d \D \s \S \w \W \h \H \v \V`.
#[derive(Debug)]
pub(crate) struct Predefined;

impl Predefined {
    /// The class for an escape letter. Without `UNICODE_CHARACTER_CLASS` the digit, word and
    /// space classes are ASCII only, as in Java.
    pub(crate) fn item(letter: char, unicode: bool) -> ClassItem {
        let base = match letter.to_ascii_lowercase() {
            'd' => Self::digit(unicode),
            'w' => Self::word(unicode),
            's' => Self::space(unicode),
            'h' => Self::horizontal_space(),
            _ => Self::vertical_space(),
        };
        ClassItem::Predicate(ClassSet::union(letter.is_ascii_uppercase(), base))
    }

    fn digit(unicode: bool) -> Vec<ClassItem> {
        if unicode {
            vec![engine(r"\p{Nd}")]
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
                single('_'),
            ]
        }
    }

    fn space(unicode: bool) -> Vec<ClassItem> {
        if unicode {
            vec![engine(r"\p{White_Space}")]
        } else {
            vec![single(' '), range('\t', '\r')]
        }
    }

    fn horizontal_space() -> Vec<ClassItem> {
        vec![
            single(' '),
            single('\t'),
            single('\u{A0}'),
            single('\u{1680}'),
            single('\u{180E}'),
            range('\u{2000}', '\u{200A}'),
            single('\u{202F}'),
            single('\u{205F}'),
            single('\u{3000}'),
        ]
    }

    fn vertical_space() -> Vec<ClassItem> {
        vec![
            range('\n', '\r'),
            single('\u{85}'),
            range('\u{2028}', '\u{2029}'),
        ]
    }
}

/// A resolved `\p{...}` property, before negation is applied.
#[derive(Debug)]
pub(crate) struct Property {
    item: ClassItem,
}

impl Property {
    /// Resolves a Java property name as `Pattern.family` does, or `None` when Java rejects it.
    ///
    /// `unicode` is `UNICODE_CHARACTER_CLASS` and `case_insensitive` is `CASE_INSENSITIVE`,
    /// which selects Java's case-insensitive variants of the case properties.
    pub(crate) fn resolve(name: &str, unicode: bool, case_insensitive: bool) -> Option<Self> {
        let item = if let Some((key, value)) = name.split_once('=') {
            match key.to_ascii_lowercase().as_str() {
                "sc" | "script" => Self::script(value),
                "blk" | "block" => Self::block(value),
                "gc" | "general_category" => Self::property(value, case_insensitive),
                _ => None,
            }
        } else if let Some(block) = name.strip_prefix("In") {
            Self::block(block)
        } else if let Some(short) = name.strip_prefix("Is") {
            Self::unicode_property(&short.to_uppercase(), case_insensitive)
                .or_else(|| Self::property(short, case_insensitive))
                .or_else(|| Self::script(short))
        } else {
            unicode
                .then(|| Self::posix(&name.to_uppercase(), case_insensitive))
                .flatten()
                .or_else(|| Self::property(name, case_insensitive))
        }?;
        Some(Self { item })
    }

    /// Applies `\P` negation, returning an item usable in a class.
    pub(crate) fn into_item(self, negated: bool) -> ClassItem {
        if negated {
            complement(vec![self.item])
        } else {
            self.item
        }
    }

    /// `Character.UnicodeBlock.forName`.
    fn block(name: &str) -> Option<ClassItem> {
        let key = name.to_uppercase();
        let index = BLOCKS
            .binary_search_by(|(known, _, _)| (*known).cmp(key.as_str()))
            .ok()?;
        let &(_, first, last) = BLOCKS.get(index)?;
        Some(if first > last {
            ClassItem::nothing()
        } else {
            ClassItem::code_range(first, last)
        })
    }

    /// `Character.UnicodeScript.forName`: a constant name or a four-letter alias.
    fn script(name: &str) -> Option<ClassItem> {
        let key = name.to_uppercase();
        let index = SCRIPTS
            .binary_search_by(|(known, _)| (*known).cmp(key.as_str()))
            .ok()?;
        let &(_, script) = SCRIPTS.get(index)?;
        Some(if script == "UNKNOWN" {
            // The engine has no Unknown script: it is every code point that `Scripts.txt`
            // leaves out, the unassigned, private use, and surrogate ones.
            union(vec![
                engine(r"\p{Cn}"),
                engine(r"\p{Co}"),
                engine(r"\p{Cs}"),
            ])
        } else {
            engine(&format!(r"\p{{Script={script}}}"))
        })
    }

    /// Lower, upper, and title case together, Java's case-insensitive form of each of them.
    fn any_case() -> ClassItem {
        union(vec![
            engine(r"\p{Lowercase}"),
            engine(r"\p{Uppercase}"),
            engine(r"\p{Lt}"),
        ])
    }

    fn cased(case_insensitive: bool, exact: &str) -> ClassItem {
        if case_insensitive {
            Self::any_case()
        } else {
            engine(exact)
        }
    }

    /// `CharPredicates.WHITE_SPACE`.
    fn white_space() -> ClassItem {
        union(vec![engine(r"\p{Z}"), range('\t', '\r'), single('\u{85}')])
    }

    /// `CharPredicates.HEX_DIGIT`: every decimal digit plus the ASCII and full-width letters.
    fn hex_digit() -> ClassItem {
        union(vec![
            engine(r"\p{Nd}"),
            range('A', 'F'),
            range('a', 'f'),
            range('\u{FF21}', '\u{FF26}'),
            range('\u{FF41}', '\u{FF46}'),
        ])
    }

    /// `CharPredicates.GRAPH`: not a separator, control, surrogate, or unassigned.
    fn graph() -> ClassItem {
        complement(vec![
            engine(r"\p{Z}"),
            engine(r"\p{Cc}"),
            engine(r"\p{Cs}"),
            engine(r"\p{Cn}"),
        ])
    }

    /// `Character.isIdentifierIgnorable`.
    fn identifier_ignorable() -> ClassItem {
        union(vec![
            range('\0', '\u{8}'),
            range('\u{E}', '\u{1B}'),
            range('\u{7F}', '\u{9F}'),
            engine(r"\p{Cf}"),
        ])
    }

    /// `CharPredicates.forPOSIXName`, used under `UNICODE_CHARACTER_CLASS`.
    fn posix(name: &str, case_insensitive: bool) -> Option<ClassItem> {
        Some(match name {
            "ALPHA" => engine(r"\p{Alphabetic}"),
            "LOWER" => Self::cased(case_insensitive, r"\p{Lowercase}"),
            "UPPER" => Self::cased(case_insensitive, r"\p{Uppercase}"),
            "SPACE" => Self::white_space(),
            "PUNCT" => engine(r"\p{P}"),
            "XDIGIT" => Self::hex_digit(),
            "ALNUM" => union(vec![engine(r"\p{Alphabetic}"), engine(r"\p{Nd}")]),
            "CNTRL" => engine(r"\p{Cc}"),
            "DIGIT" => engine(r"\p{Nd}"),
            "BLANK" => union(vec![engine(r"\p{Zs}"), single('\t')]),
            "GRAPH" => Self::graph(),
            "PRINT" => complement(vec![
                engine(r"\p{Zl}"),
                engine(r"\p{Zp}"),
                engine(r"\p{Cc}"),
                engine(r"\p{Cs}"),
                engine(r"\p{Cn}"),
            ]),
            _ => return None,
        })
    }

    /// `CharPredicates.forUnicodeProperty`, for `\p{IsName}`; `name` is upper case.
    fn unicode_property(name: &str, case_insensitive: bool) -> Option<ClassItem> {
        let item = match name {
            "ALPHABETIC" => engine(r"\p{Alphabetic}"),
            "ASSIGNED" => complement(vec![engine(r"\p{Cn}")]),
            "CONTROL" => engine(r"\p{Cc}"),
            "EMOJI" => engine(r"\p{Emoji}"),
            "EMOJI_PRESENTATION" => engine(r"\p{Emoji_Presentation}"),
            "EMOJI_MODIFIER" => engine(r"\p{Emoji_Modifier}"),
            "EMOJI_MODIFIER_BASE" => engine(r"\p{Emoji_Modifier_Base}"),
            "EMOJI_COMPONENT" => engine(r"\p{Emoji_Component}"),
            "EXTENDED_PICTOGRAPHIC" => engine(r"\p{Extended_Pictographic}"),
            "HEXDIGIT" | "HEX_DIGIT" => Self::hex_digit(),
            "IDEOGRAPHIC" => engine(r"\p{Ideographic}"),
            "JOINCONTROL" | "JOIN_CONTROL" => range('\u{200C}', '\u{200D}'),
            "LETTER" => engine(r"\p{L}"),
            "LOWERCASE" => Self::cased(case_insensitive, r"\p{Lowercase}"),
            "NONCHARACTERCODEPOINT" | "NONCHARACTER_CODE_POINT" => {
                engine(r"\p{Noncharacter_Code_Point}")
            }
            "TITLECASE" => Self::cased(case_insensitive, r"\p{Lt}"),
            "PUNCTUATION" => engine(r"\p{P}"),
            "UPPERCASE" => Self::cased(case_insensitive, r"\p{Uppercase}"),
            "WHITESPACE" | "WHITE_SPACE" => Self::white_space(),
            "WORD" => engine(r"\w"),
            _ => return Self::posix(name, case_insensitive),
        };
        Some(item)
    }

    /// `CharPredicates.forProperty`: general categories, ASCII POSIX classes, and the
    /// `java.lang.Character` predicates. Names are case-sensitive.
    fn property(name: &str, case_insensitive: bool) -> Option<ClassItem> {
        if let Some(item) = Self::category(name, case_insensitive) {
            return Some(item);
        }
        if let Some(items) = Self::ascii_posix(name, case_insensitive) {
            return Some(union(items));
        }
        Self::java_predicate(name, case_insensitive)
    }

    fn category(name: &str, case_insensitive: bool) -> Option<ClassItem> {
        const CATEGORIES: &[&str] = &[
            "Cn", "Lm", "Lo", "Mn", "Me", "Mc", "Nd", "Nl", "No", "Zs", "Zl", "Zp", "Cc", "Cf",
            "Co", "Cs", "Pd", "Ps", "Pe", "Pc", "Po", "Sm", "Sc", "Sk", "So", "Pi", "Pf", "L", "M",
            "N", "Z", "C", "P", "S", "LC",
        ];
        Some(match name {
            "Lu" | "Ll" | "Lt" if case_insensitive => engine(r"\p{LC}"),
            "Lu" | "Ll" | "Lt" => engine(&format!(r"\p{{{name}}}")),
            "LD" => union(vec![engine(r"\p{L}"), engine(r"\p{Nd}")]),
            "L1" => range('\0', '\u{FF}'),
            "all" => range('\0', char::MAX),
            _ if CATEGORIES.contains(&name) => engine(&format!(r"\p{{{name}}}")),
            _ => return None,
        })
    }

    /// The ASCII POSIX classes of `CharPredicates.forProperty`.
    fn ascii_posix(name: &str, case_insensitive: bool) -> Option<Vec<ClassItem>> {
        let alpha = || vec![range('a', 'z'), range('A', 'Z')];
        Some(match name {
            "ASCII" => vec![range('\0', '\u{7F}')],
            "Alnum" => vec![range('a', 'z'), range('A', 'Z'), range('0', '9')],
            "Alpha" => alpha(),
            "Blank" => vec![single(' '), single('\t')],
            "Cntrl" => vec![range('\0', '\u{1F}'), single('\u{7F}')],
            "Digit" => vec![range('0', '9')],
            "Graph" => vec![range('!', '~')],
            "Lower" | "Upper" if case_insensitive => alpha(),
            "Lower" => vec![range('a', 'z')],
            "Print" => vec![range(' ', '~')],
            "Punct" => vec![
                range('!', '/'),
                range(':', '@'),
                range('[', '`'),
                range('{', '~'),
            ],
            "Space" => vec![single(' '), range('\t', '\r')],
            "Upper" => vec![range('A', 'Z')],
            "XDigit" => vec![range('0', '9'), range('a', 'f'), range('A', 'F')],
            _ => return None,
        })
    }

    /// `\p{javaXxx}`: the `java.lang.Character` predicates of the same name.
    fn java_predicate(name: &str, case_insensitive: bool) -> Option<ClassItem> {
        Some(match name {
            "javaLowerCase" => Self::cased(case_insensitive, r"\p{Lowercase}"),
            "javaUpperCase" => Self::cased(case_insensitive, r"\p{Uppercase}"),
            "javaTitleCase" => Self::cased(case_insensitive, r"\p{Lt}"),
            "javaAlphabetic" => engine(r"\p{Alphabetic}"),
            "javaIdeographic" => engine(r"\p{Ideographic}"),
            "javaDigit" => engine(r"\p{Nd}"),
            "javaDefined" => complement(vec![engine(r"\p{Cn}")]),
            "javaLetter" => engine(r"\p{L}"),
            "javaLetterOrDigit" => union(vec![engine(r"\p{L}"), engine(r"\p{Nd}")]),
            "javaJavaIdentifierStart" => union(vec![
                engine(r"\p{L}"),
                engine(r"\p{Nl}"),
                engine(r"\p{Sc}"),
                engine(r"\p{Pc}"),
            ]),
            "javaJavaIdentifierPart" => union(vec![
                engine(r"\p{L}"),
                engine(r"\p{Nl}"),
                engine(r"\p{Sc}"),
                engine(r"\p{Pc}"),
                engine(r"\p{Nd}"),
                engine(r"\p{Mc}"),
                engine(r"\p{Mn}"),
                Self::identifier_ignorable(),
            ]),
            "javaUnicodeIdentifierStart" => {
                union(vec![engine(r"\p{ID_Start}"), single('\u{2E2F}')])
            }
            "javaUnicodeIdentifierPart" => union(vec![
                engine(r"\p{ID_Continue}"),
                single('\u{2E2F}'),
                Self::identifier_ignorable(),
            ]),
            "javaIdentifierIgnorable" => Self::identifier_ignorable(),
            "javaSpaceChar" => engine(r"\p{Z}"),
            "javaWhitespace" => union(vec![
                ClassItem::Predicate(ClassSet {
                    negated: false,
                    operands: vec![
                        vec![engine(r"\p{Z}")],
                        vec![complement(vec![
                            single('\u{A0}'),
                            single('\u{2007}'),
                            single('\u{202F}'),
                        ])],
                    ],
                }),
                range('\t', '\r'),
                range('\u{1C}', '\u{1F}'),
            ]),
            "javaISOControl" => union(vec![range('\0', '\u{1F}'), range('\u{7F}', '\u{9F}')]),
            "javaMirrored" => engine(r"\p{Bidi_Mirrored}"),
            _ => return None,
        })
    }
}
