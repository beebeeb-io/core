//! Password-policy evaluator (task 1744, spec 2026-10-04 sections 2.5 and 5.12).
//!
//! OPAQUE means the server never sees the password, so it cannot enforce a
//! policy; the client must. Before this module the policy lived in web
//! TypeScript (`onboarding.tsx`) and every native client would have had to copy
//! it. Now there is one implementation, in core, driven by the numbers the
//! server declares (`policy.password.min_length`).
//!
//! This is advisory UX plus a client-side gate. It is **not** a security
//! boundary the server relies on, and it does not rate passwords the way a
//! guessing-cost estimator would: it ports the heuristic the web client already
//! shipped (length gate, then one point each for mixed case and for a digit or
//! symbol) so behaviour does not change while the logic moves.
//!
//! Known limit (review L6): a string of spaces or of one repeated character
//! that reaches the minimum length passes the gate and scores Fair or Good,
//! exactly as it did in the web heuristic. The breach check is the backstop for
//! the worst of them, and this evaluator makes no guessing-cost claim.
//!
//! Copy (labels, sentences, colours) stays in each client. The evaluator returns
//! facts and enums only.
//!
//! The password is borrowed for the duration of the call and never copied into
//! the result.

/// Absolute floor for `min_length`, in Unicode scalar values.
///
/// **A floor, not the policy.** The policy number comes from the server, and
/// the server may raise it. It may never lower it: the floor is the 12 the
/// product ships with (lead decision 2026-10-04, task 1744 review L5), so a
/// misconfigured or hostile onboarding document (`min_length: 0`, `8`) cannot
/// weaken what every client enforces. A server that raises the value to an
/// absurd number only denies service to itself.
pub const MIN_LENGTH_FLOOR: u32 = 12;

/// Password policy numbers as declared by the server.
///
/// Construct with [`PasswordPolicy::from_server`]; the floor is applied there so
/// no `PasswordPolicy` can exist below [`MIN_LENGTH_FLOOR`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordPolicy {
    min_length: u32,
}

impl PasswordPolicy {
    /// Build a policy from the server's `policy.password.min_length`, clamped
    /// up to [`MIN_LENGTH_FLOOR`].
    pub fn from_server(min_length: u32) -> Self {
        Self {
            min_length: min_length.max(MIN_LENGTH_FLOOR),
        }
    }

    /// The effective minimum length, in Unicode scalar values.
    pub fn min_length(&self) -> u32 {
        self.min_length
    }
}

/// Coarse strength level. Mirrors the four meter levels the web client
/// rendered (1 to 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordStrength {
    /// Below the policy minimum (including empty).
    TooShort,
    /// Meets the minimum, nothing else.
    Fair,
    /// Meets the minimum plus one of: mixed case, a number or symbol.
    Good,
    /// Meets the minimum plus both.
    Strong,
}

impl PasswordStrength {
    /// Stable lowercase token for clients that cannot share the enum (WASM).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooShort => "too_short",
            Self::Fair => "fair",
            Self::Good => "good",
            Self::Strong => "strong",
        }
    }

    /// Meter level, 1 (too short) to 4 (strong).
    pub fn level(self) -> u8 {
        match self {
            Self::TooShort => 1,
            Self::Fair => 2,
            Self::Good => 3,
            Self::Strong => 4,
        }
    }
}

/// What the client should suggest next. The client owns the sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordHint {
    /// Nothing to suggest (strong, or nothing typed yet).
    None,
    /// Below the minimum; see [`PasswordEvaluation::missing_characters`].
    NeedMoreCharacters,
    /// Neither mixed case nor a number or symbol.
    MixCaseAndAddNumberOrSymbol,
    /// Has a number or symbol, lacks mixed case.
    MixCase,
    /// Has mixed case, lacks a number or symbol.
    AddNumberOrSymbol,
}

impl PasswordHint {
    /// Stable lowercase token for clients that cannot share the enum (WASM).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::NeedMoreCharacters => "need_more_characters",
            Self::MixCaseAndAddNumberOrSymbol => "mix_case_and_add_number_or_symbol",
            Self::MixCase => "mix_case",
            Self::AddNumberOrSymbol => "add_number_or_symbol",
        }
    }
}

/// Result of [`evaluate_password`]. Contains no part of the password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordEvaluation {
    /// Length in Unicode scalar values (not UTF-16 units, not bytes, not
    /// grapheme clusters). Saturates at `u32::MAX`.
    pub length: u32,
    /// The effective minimum this evaluation used.
    pub min_length: u32,
    /// `min_length - length`, or 0 when the minimum is met.
    pub missing_characters: u32,
    /// `length >= min_length`.
    pub meets_minimum: bool,
    /// At least one lowercase and one uppercase letter (Unicode aware).
    pub has_mixed_case: bool,
    /// At least one character that is not a letter (digit, punctuation,
    /// symbol, space).
    pub has_number_or_symbol: bool,
    pub strength: PasswordStrength,
    pub hint: PasswordHint,
}

/// Evaluate `password` against `policy`.
///
/// Differences from the web heuristic this replaces, all deliberate:
/// - Length counts Unicode scalar values; JS counted UTF-16 code units, so an
///   emoji used to count as 2.
/// - Case and "symbol" detection is Unicode aware (`"É"` is an uppercase
///   letter, not a "symbol"); the web used ASCII ranges only.
pub fn evaluate_password(password: &str, policy: &PasswordPolicy) -> PasswordEvaluation {
    let length = u32::try_from(password.chars().count()).unwrap_or(u32::MAX);
    let min_length = policy.min_length();
    let meets_minimum = length >= min_length;
    let missing_characters = min_length.saturating_sub(length);

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_number_or_symbol = false;
    for c in password.chars() {
        if c.is_lowercase() {
            has_lower = true;
        } else if c.is_uppercase() {
            has_upper = true;
        } else if !c.is_alphabetic() {
            has_number_or_symbol = true;
        }
    }
    let has_mixed_case = has_lower && has_upper;

    let (strength, hint) = if length == 0 {
        (PasswordStrength::TooShort, PasswordHint::None)
    } else if !meets_minimum {
        (PasswordStrength::TooShort, PasswordHint::NeedMoreCharacters)
    } else {
        match (has_mixed_case, has_number_or_symbol) {
            (false, false) => (PasswordStrength::Fair, PasswordHint::MixCaseAndAddNumberOrSymbol),
            (false, true) => (PasswordStrength::Good, PasswordHint::MixCase),
            (true, false) => (PasswordStrength::Good, PasswordHint::AddNumberOrSymbol),
            (true, true) => (PasswordStrength::Strong, PasswordHint::None),
        }
    };

    PasswordEvaluation {
        length,
        min_length,
        missing_characters,
        meets_minimum,
        has_mixed_case,
        has_number_or_symbol,
        strength,
        hint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy12() -> PasswordPolicy {
        PasswordPolicy::from_server(12)
    }

    #[test]
    fn floor_clamps_a_hostile_server_value() {
        assert_eq!(PasswordPolicy::from_server(0).min_length(), MIN_LENGTH_FLOOR);
        assert_eq!(PasswordPolicy::from_server(1).min_length(), MIN_LENGTH_FLOOR);
        assert_eq!(
            PasswordPolicy::from_server(MIN_LENGTH_FLOOR).min_length(),
            MIN_LENGTH_FLOOR
        );
    }

    #[test]
    fn the_floor_is_the_shipped_policy_so_a_hostile_document_cannot_weaken_it() {
        // Lead decision 2026-10-04 (task 1744 review L5): the server may raise
        // the minimum, never lower it below the 12 the product ships with.
        assert_eq!(MIN_LENGTH_FLOOR, 12);
        for hostile in [0, 1, 8, 11] {
            assert_eq!(PasswordPolicy::from_server(hostile).min_length(), 12, "asked {hostile}");
        }
        let eleven = "a".repeat(11);
        assert!(!evaluate_password(&eleven, &PasswordPolicy::from_server(8)).meets_minimum);
    }

    #[test]
    fn server_value_above_the_floor_is_used_as_given() {
        assert_eq!(PasswordPolicy::from_server(12).min_length(), 12);
        assert_eq!(PasswordPolicy::from_server(16).min_length(), 16);
    }

    #[test]
    fn min_length_is_enforced_at_the_boundary() {
        let p = policy12();
        let eleven = "a".repeat(11);
        let twelve = "a".repeat(12);
        let e11 = evaluate_password(&eleven, &p);
        let e12 = evaluate_password(&twelve, &p);
        assert!(!e11.meets_minimum, "11 chars must fail a min of 12");
        assert_eq!(e11.missing_characters, 1);
        assert_eq!(e11.strength, PasswordStrength::TooShort);
        assert_eq!(e11.hint, PasswordHint::NeedMoreCharacters);
        assert!(e12.meets_minimum, "12 chars must pass a min of 12");
        assert_eq!(e12.missing_characters, 0);
    }

    #[test]
    fn the_numbers_come_from_the_policy_not_a_constant() {
        let pw = "a".repeat(14);
        assert!(evaluate_password(&pw, &PasswordPolicy::from_server(12)).meets_minimum);
        assert!(!evaluate_password(&pw, &PasswordPolicy::from_server(15)).meets_minimum);
        assert_eq!(
            evaluate_password(&pw, &PasswordPolicy::from_server(15)).missing_characters,
            1
        );
    }

    #[test]
    fn empty_password_is_too_short_with_no_hint() {
        let e = evaluate_password("", &policy12());
        assert_eq!(e.length, 0);
        assert!(!e.meets_minimum);
        assert_eq!(e.strength, PasswordStrength::TooShort);
        assert_eq!(e.hint, PasswordHint::None);
        assert_eq!(e.missing_characters, 12);
    }

    #[test]
    fn strength_ladder_matches_the_web_heuristic() {
        let p = policy12();
        let fair = evaluate_password("aaaaaaaaaaaa", &p);
        assert_eq!(fair.strength, PasswordStrength::Fair);
        assert_eq!(fair.hint, PasswordHint::MixCaseAndAddNumberOrSymbol);
        assert_eq!(fair.strength.level(), 2);

        let good_no_case = evaluate_password("aaaaaaaaaaa1", &p);
        assert_eq!(good_no_case.strength, PasswordStrength::Good);
        assert_eq!(good_no_case.hint, PasswordHint::MixCase);

        let good_no_symbol = evaluate_password("aaaaaaaaaaaA", &p);
        assert_eq!(good_no_symbol.strength, PasswordStrength::Good);
        assert_eq!(good_no_symbol.hint, PasswordHint::AddNumberOrSymbol);
        assert_eq!(good_no_symbol.strength.level(), 3);

        let strong = evaluate_password("aaaaaaaaaaA1", &p);
        assert_eq!(strong.strength, PasswordStrength::Strong);
        assert_eq!(strong.hint, PasswordHint::None);
        assert_eq!(strong.strength.level(), 4);
    }

    #[test]
    fn too_short_never_scores_above_level_one() {
        // Mixed case and a symbol do not rescue a short password.
        let e = evaluate_password("aA1!", &policy12());
        assert!(e.has_mixed_case && e.has_number_or_symbol);
        assert_eq!(e.strength, PasswordStrength::TooShort);
        assert_eq!(e.strength.level(), 1);
    }

    #[test]
    fn length_counts_scalar_values_not_utf16_units() {
        // 12 emoji = 12 scalar values (24 UTF-16 units, 48 bytes).
        let pw = "\u{1F36F}".repeat(12);
        let e = evaluate_password(&pw, &policy12());
        assert_eq!(e.length, 12);
        assert!(e.meets_minimum);
        // Combining sequence: 'e' + U+0301 is two scalar values.
        assert_eq!(evaluate_password("e\u{0301}", &policy12()).length, 2);
    }

    #[test]
    fn case_detection_is_unicode_aware() {
        let e = evaluate_password("\u{00E9}\u{00C9}", &PasswordPolicy::from_server(2));
        assert!(e.has_mixed_case, "e-acute and E-acute are a lower and an upper");
        assert!(!e.has_number_or_symbol, "accented letters are letters, not symbols");
    }

    #[test]
    fn a_space_counts_as_a_symbol() {
        let e = evaluate_password("correct horse battery staple", &policy12());
        assert!(e.has_number_or_symbol);
        assert!(e.meets_minimum);
    }

    #[test]
    fn evaluation_is_deterministic() {
        let p = policy12();
        assert_eq!(
            evaluate_password("Tr0ub4dor&3-horse", &p),
            evaluate_password("Tr0ub4dor&3-horse", &p)
        );
    }
}
