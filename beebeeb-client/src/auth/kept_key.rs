//! When a client may use the master key it kept on this device to sign someone in, and what the server's answer to
//! the proof means.
//!
//! A device keeps the master key of the last account that unlocked it. On a later sign-in the client may offer that
//! key only when it belongs to the signing-in account: either the key carries an owner tag naming the signing-in
//! user, or it carries no tag yet and the email stored with it is the signing-in email. Anything else (a foreign
//! tag, a tag that cannot be read, a different or missing email) means there is no usable key here. The key is then
//! proved against the server's recovery check before it unlocks anything; [`verdict`] turns that answer into what the
//! client does next.

use super::canonical_email;

/// What the client knows about the key it kept, and who is signing in.
#[derive(Debug, Clone, Copy)]
pub struct KeptKeyFacts<'a> {
    /// The owner tag stored with the kept key (the owning user id, as bytes), if any.
    pub owner_tag: Option<&'a [u8]>,
    /// The email stored with the kept key, if any.
    pub stored_email: Option<&'a str>,
    /// The user id of the account signing in.
    pub signing_user_id: &'a str,
    /// The email of the account signing in.
    pub signing_email: &'a str,
}

/// May the kept key be offered for this sign-in?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeptKeyUse {
    /// The key belongs to the signing-in account: prove it to the server before using it.
    ProveIt,
    /// There is no key here this account may use.
    NoneHere,
}

/// Decides whether the kept key may be offered for this sign-in, exactly as the desktop's `read_kept_key` did.
///
/// - A tag that is not UTF-8 cannot be read: [`KeptKeyUse::NoneHere`].
/// - A tag that is blank after trimming counts as no tag.
/// - A tag decides alone (the email is not consulted): [`KeptKeyUse::ProveIt`] only when the trimmed tag equals the
///   trimmed signing-in user id and that id is not blank.
/// - No tag, and the stored email equals the signing-in email under [`canonical_email`] (and is not empty):
///   [`KeptKeyUse::ProveIt`]. A different, empty or missing email: [`KeptKeyUse::NoneHere`].
pub fn may_use_kept_key(f: &KeptKeyFacts) -> KeptKeyUse {
    let tag = match f.owner_tag.map(std::str::from_utf8) {
        Some(Err(_)) => return KeptKeyUse::NoneHere,
        Some(Ok(tag)) => Some(tag.trim()).filter(|tag| !tag.is_empty()),
        None => None,
    };
    if let Some(tag) = tag {
        let signing = f.signing_user_id.trim();
        return if !signing.is_empty() && same_key(tag.as_bytes(), signing.as_bytes()) {
            KeptKeyUse::ProveIt
        } else {
            KeptKeyUse::NoneHere
        };
    }
    let Some(stored) = f.stored_email else {
        return KeptKeyUse::NoneHere;
    };
    let stored = canonical_email(stored);
    if !stored.is_empty() && stored == canonical_email(f.signing_email) {
        KeptKeyUse::ProveIt
    } else {
        KeptKeyUse::NoneHere
    }
}

/// The server's answer to proving the kept key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofAnswer {
    /// The key matches the account's recovery check.
    Matched,
    /// The server holds no recovery check for the account (`recovery_check_missing`).
    NoCheckOnFile,
    /// The server says the key is not the account's (`invalid_recovery_phrase`).
    WrongPhrase,
    /// Anything else: offline, a server error, an answer we do not know.
    Unavailable,
}

impl ProofAnswer {
    /// Reads a failed proof's HTTP status and exact server error code. Only a 400 with one of the two codes below
    /// has a meaning; every other status or code is [`ProofAnswer::Unavailable`].
    pub fn from_error_code(status: u16, code: &str) -> Self {
        if status != 400 {
            return Self::Unavailable;
        }
        match code {
            "recovery_check_missing" => Self::NoCheckOnFile,
            "invalid_recovery_phrase" => Self::WrongPhrase,
            _ => Self::Unavailable,
        }
    }
}

/// What the client does with the kept key after the proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeptKeyVerdict {
    /// Use the key. When `tag_it`, record the signing-in user as its owner tag.
    Proven { tag_it: bool },
    /// The server no longer accepts this key: do not use it, and sign in without it.
    Outdated,
    /// No decision could be made: keep the key as it is, and do not use it now.
    Unavailable,
}

/// Maps the server's answer to what the client does.
///
/// A key is only tagged after a real match; with no check on file the key is used but stays untagged, so a later
/// sign-in proves it again.
pub fn verdict(a: ProofAnswer) -> KeptKeyVerdict {
    match a {
        ProofAnswer::Matched => KeptKeyVerdict::Proven { tag_it: true },
        ProofAnswer::NoCheckOnFile => KeptKeyVerdict::Proven { tag_it: false },
        ProofAnswer::WrongPhrase => KeptKeyVerdict::Outdated,
        ProofAnswer::Unavailable => KeptKeyVerdict::Unavailable,
    }
}

/// Are `a` and `b` the same bytes? The time taken depends only on the lengths, never on where they differ. Lengths
/// are not secret (keys and ids have fixed public sizes), so different lengths return `false` at once.
pub fn same_key(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= std::hint::black_box(x ^ y);
    }
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const VECTORS: &str = include_str!("../../../test-vectors/kept_key.json");

    #[derive(Deserialize)]
    struct Vectors {
        may_use_kept_key: Vec<UseCase>,
        verdict: Vec<VerdictCase>,
        same_key: Vec<SameCase>,
    }

    #[derive(Deserialize)]
    struct UseCase {
        name: String,
        owner_tag_hex: Option<String>,
        stored_email: Option<String>,
        signing_user_id: String,
        signing_email: String,
        expect: String,
    }

    #[derive(Deserialize)]
    struct VerdictCase {
        answer: String,
        status: Option<u16>,
        error_code: Option<String>,
        expect: String,
        tag_it: Option<bool>,
    }

    #[derive(Deserialize)]
    struct SameCase {
        a_hex: String,
        b_hex: String,
        expect: bool,
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vectors() -> Vectors {
        serde_json::from_str(VECTORS).unwrap()
    }

    #[test]
    fn kept_key_use_vectors() {
        let v = vectors();
        assert!(!v.may_use_kept_key.is_empty());
        for c in v.may_use_kept_key {
            let tag = c.owner_tag_hex.as_deref().map(hex);
            let facts = KeptKeyFacts {
                owner_tag: tag.as_deref(),
                stored_email: c.stored_email.as_deref(),
                signing_user_id: &c.signing_user_id,
                signing_email: &c.signing_email,
            };
            let want = match c.expect.as_str() {
                "ProveIt" => KeptKeyUse::ProveIt,
                "NoneHere" => KeptKeyUse::NoneHere,
                other => panic!("unknown expect {other}"),
            };
            assert_eq!(may_use_kept_key(&facts), want, "{}", c.name);
        }
    }

    #[test]
    fn kept_key_verdict_vectors() {
        let v = vectors();
        assert!(!v.verdict.is_empty());
        for c in v.verdict {
            let answer = match c.answer.as_str() {
                "Matched" => ProofAnswer::Matched,
                "NoCheckOnFile" => ProofAnswer::NoCheckOnFile,
                "WrongPhrase" => ProofAnswer::WrongPhrase,
                "Unavailable" => ProofAnswer::Unavailable,
                other => panic!("unknown answer {other}"),
            };
            if let Some(status) = c.status {
                let code = c.error_code.as_deref().unwrap_or_default();
                assert_eq!(ProofAnswer::from_error_code(status, code), answer, "{status} {code}");
            }
            let want = match c.expect.as_str() {
                "Proven" => KeptKeyVerdict::Proven {
                    tag_it: c.tag_it.unwrap(),
                },
                "Outdated" => KeptKeyVerdict::Outdated,
                "Unavailable" => KeptKeyVerdict::Unavailable,
                other => panic!("unknown expect {other}"),
            };
            assert_eq!(verdict(answer), want, "{}", c.answer);
        }
    }

    #[test]
    fn kept_key_same_key_vectors() {
        let v = vectors();
        assert!(!v.same_key.is_empty());
        for c in v.same_key {
            assert_eq!(
                same_key(&hex(&c.a_hex), &hex(&c.b_hex)),
                c.expect,
                "{} vs {}",
                c.a_hex,
                c.b_hex
            );
        }
    }
}
