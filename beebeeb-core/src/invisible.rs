//! The one table of characters that render as nothing (or blank space).
//!
//! Two rules judge what a name LOOKS like rather than what its bytes are, and
//! they must agree:
//!
//! - [`crate::kdf::sanitize_actor_name`] strips display controls and refuses a
//!   visibly blank guest name;
//! - [`crate::path_safety::check_component_for`] refuses an empty name and the
//!   dot names after removing everything that shows nothing (`.\u{00AD}.`
//!   displays as `..`).
//!
//! Both read this module, so the table exists once. Adding or dropping a
//! character is a visible edit here.

/// L16b: the display-control characters [`crate::kdf::sanitize_actor_name`]
/// removes, in addition to every `char::is_control` (Cc) character. The table
/// is the whole rule, so adding or dropping a character is a visible edit here:
///
/// - U+00AD soft hyphen, U+061C Arabic letter mark, U+180E Mongolian vowel
///   separator;
/// - U+200B zero-width space, U+200E/U+200F the LRM/RLM marks;
/// - U+2028-U+202E the line and paragraph separators and the bidi embeddings
///   and overrides;
/// - U+2060-U+2064 the word joiner and the invisible operators;
/// - U+2066-U+206F the bidi isolates and the deprecated format characters;
/// - U+FEFF the zero-width no-break space (BOM), U+FFF9-U+FFFB the interlinear
///   annotations.
///
/// **Kept**, because legitimate scripts and emoji need them: U+200C ZWNJ,
/// U+200D ZWJ, the variation selectors and the tag characters U+E0020-U+E007F.
/// A name made only of such characters is refused by the blank rule instead
/// ([`ACTOR_NAME_INVISIBLE_FILLERS`]).
pub(crate) const ACTOR_NAME_STRIPPED: [(u32, u32); 10] = [
    (0x00AD, 0x00AD), // soft hyphen
    (0x061C, 0x061C), // Arabic letter mark
    (0x180E, 0x180E), // Mongolian vowel separator
    (0x200B, 0x200B), // zero-width space
    (0x200E, 0x200F), // LRM, RLM
    (0x2028, 0x202E), // line/paragraph separators, bidi embeddings and overrides
    (0x2060, 0x2064), // word joiner, invisible operators
    (0x2066, 0x206F), // bidi isolates, deprecated format characters
    (0xFEFF, 0xFEFF), // zero-width no-break space (BOM)
    (0xFFF9, 0xFFFB), // interlinear annotations
];

/// L16b: characters that show nothing (or blank space) on their own. A name
/// must contain at least one character that is neither `char::is_whitespace`
/// nor in this table; inside a visible name they stay allowed. The entries
/// marked "default-ignorable" complete the table to every
/// Default_Ignorable_Code_Point that is not stripped (test
/// `every_default_ignorable_code_point_is_stripped_or_a_blank_filler`).
pub(crate) const ACTOR_NAME_INVISIBLE_FILLERS: [(u32, u32); 18] = [
    (0x034F, 0x034F),   // combining grapheme joiner
    (0x115F, 0x1160),   // Hangul choseong and jungseong fillers
    (0x17B4, 0x17B5),   // Khmer inherent vowels
    (0x180B, 0x180F),   // Mongolian free variation selectors (and U+180E)
    (0x200C, 0x200D),   // ZWNJ, ZWJ
    (0x2065, 0x2065),   // default-ignorable (unassigned)
    (0x2800, 0x2800),   // braille pattern blank
    (0x3164, 0x3164),   // Hangul filler
    (0xFE00, 0xFE0F),   // variation selectors
    (0xFFA0, 0xFFA0),   // halfwidth Hangul filler
    (0xFFF0, 0xFFF8),   // default-ignorable (unassigned)
    (0x1BCA0, 0x1BCA3), // default-ignorable: shorthand format controls
    (0x1D173, 0x1D17A), // musical symbol format characters
    (0xE0000, 0xE001F), // default-ignorable: language tag U+E0001, unassigned
    (0xE0020, 0xE007F), // tag characters
    (0xE0080, 0xE00FF), // default-ignorable (unassigned)
    (0xE0100, 0xE01EF), // variation selectors supplement
    (0xE01F0, 0xE0FFF), // default-ignorable (unassigned)
];

pub(crate) fn in_ranges(ranges: &[(u32, u32)], c: char) -> bool {
    let cp = c as u32;
    ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&cp))
}

pub(crate) fn is_stripped_display_control(c: char) -> bool {
    c.is_control() || in_ranges(&ACTOR_NAME_STRIPPED, c)
}

pub(crate) fn is_invisible_filler(c: char) -> bool {
    in_ranges(&ACTOR_NAME_INVISIBLE_FILLERS, c)
}

/// Every character in the two tables above: the complete set of characters a
/// renderer shows as nothing (or blank space). A name made only of these looks
/// empty, and dots plus these look like `.` or `..`. Both the actor-name rule
/// and the path rules judge those cases on the name with these removed.
pub(crate) fn is_display_invisible(c: char) -> bool {
    in_ranges(&ACTOR_NAME_STRIPPED, c) || in_ranges(&ACTOR_NAME_INVISIBLE_FILLERS, c)
}
