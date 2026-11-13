//! The screen-lock check record and the wrong-try rule (two-level lock, level 1).
//!
//! A check value that answers one question offline: "is this the account password that was
//! last proven on this device?". It unwraps nothing: the record never contains, derives from
//! or wraps the account key, a file key or a session token. Whoever can read the record can
//! test password guesses against it at the cost of one canonical Argon2id run per guess, so
//! it is stored only in the OS credential store, never in a plain file.
//!
//! ```text
//! stretch   = Argon2id v19 (password bytes, salt, 256 MiB, t = 4, p = 2, 32 bytes out,
//!                           associated data = "beebeeb/screen-lock/v1/stretch")
//! check_key = HKDF-SHA256 (ikm = stretch, no salt, info = "beebeeb/screen-lock/v1/key")
//! token     = 32 random bytes, used for nothing else, wiped after sealing
//! sealed    = AES-256-GCM (check_key, random 96-bit nonce, token,
//!                          aad = "beebeeb/screen-lock/v1" || u32 BE len || owner id || header)
//! header    = version (1) || pepper kind (0) || password counter (u64 BE) || salt (32)
//! record    = header (42) || nonce (12) || ciphertext (32) || tag (16)        = 102 bytes
//! ```
//!
//! The cost is not stored: version 1 means these numbers, and a reader accepts no others.
//! Verification is "the tag verifies"; the token's value is never compared, returned or used.
//! Pure functions: no I/O and no clock (the caller passes the time to the wrong-try rule).

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::CoreError;

/// Argon2id associated data of the stretch: its own domain, so the output is never the
/// master-key derivation's for the same password and salt.
pub(crate) const SCREEN_LOCK_STRETCH_LABEL: &[u8] = b"beebeeb/screen-lock/v1/stretch";
/// HKDF info that derives the check key from the stretch.
pub(crate) const SCREEN_LOCK_KEY_INFO: &[u8] = b"beebeeb/screen-lock/v1/key";
/// AES-GCM associated-data domain of the sealed token.
pub(crate) const SCREEN_LOCK_AAD_DOMAIN: &[u8] = b"beebeeb/screen-lock/v1";

const RECORD_VERSION: u8 = 1;
/// Reserved for a secret held by the device's hardware. Version 1 writes 0 and refuses
/// anything else.
const PEPPER_KIND_NONE: u8 = 0;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TOKEN_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 1 + 1 + 8 + SALT_LEN;
/// The exact size of a version-1 record.
pub const RECORD_LEN: usize = HEADER_LEN + NONCE_LEN + TOKEN_LEN + TAG_LEN;
const MAX_OWNER_LEN: usize = 4 * 1024;

const COUNTER_AT: usize = 2;
const SALT_AT: usize = 10;

/// The stored check record: opaque bytes. `Debug` prints the length only.
#[derive(Clone, PartialEq, Eq)]
pub struct ScreenCheckRecord {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for ScreenCheckRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScreenCheckRecord")
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

impl ScreenCheckRecord {
    /// The bytes to store.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Wraps stored bytes as they are. Nothing is checked here: [`verify`] answers
    /// [`CheckOutcome::Unusable`] for a record of another length, version or pepper kind.
    /// Bytes past one more than a record's length are not kept (they could not be a record).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes[..bytes.len().min(RECORD_LEN + 1)].to_vec(),
        }
    }

    /// Whether the length, version and pepper kind are the ones version 1 reads.
    pub fn is_readable(&self) -> bool {
        self.bytes.len() == RECORD_LEN && self.bytes[0] == RECORD_VERSION && self.bytes[1] == PEPPER_KIND_NONE
    }

    /// The server's password counter as of the enrolment, `None` for a record this version
    /// cannot read. Not authenticated without the password: use it only to decide that a
    /// record is stale and delete it, never to keep one.
    pub fn password_counter(&self) -> Option<u64> {
        if !self.is_readable() {
            return None;
        }
        let mut counter = [0u8; 8];
        counter.copy_from_slice(&self.bytes[COUNTER_AT..SALT_AT]);
        Some(u64::from_be_bytes(counter))
    }
}

/// The answer of [`verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The tag verified: this is the password the record was made with, for this owner.
    Match,
    /// The tag did not verify: another password, another owner, or an edited record. These
    /// cannot be told apart, and none of them opens anything.
    NoMatch,
    /// Not a version-1 record (length, version or pepper kind), or no owner to bind it to.
    /// The caller deletes it and treats it as absent.
    Unusable,
}

/// A stretched password waiting for the account it belongs to. Made while the password is in
/// hand ([`stretch`]) and sealed once the owner and the password counter are known
/// ([`Self::seal`]). Holds the check key, so it is wiped on drop, not `Clone`, and never printed.
pub struct PendingScreenCheck {
    salt: [u8; SALT_LEN],
    check_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for PendingScreenCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingScreenCheck([REDACTED])")
    }
}

impl PendingScreenCheck {
    /// Seals a fresh random token under the check key, bound to `owner` and to the header.
    pub fn seal(self, owner: &str, password_counter: u64) -> Result<ScreenCheckRecord, CoreError> {
        let mut nonce = [0u8; NONCE_LEN];
        let mut token = Zeroizing::new([0u8; TOKEN_LEN]);
        let mut rng = rand::rngs::OsRng;
        rng.try_fill_bytes(&mut nonce)
            .and_then(|()| rng.try_fill_bytes(&mut *token))
            .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
        self.seal_with(owner, password_counter, &nonce, &token)
    }

    fn seal_with(
        self,
        owner: &str,
        password_counter: u64,
        nonce: &[u8; NONCE_LEN],
        token: &Zeroizing<[u8; TOKEN_LEN]>,
    ) -> Result<ScreenCheckRecord, CoreError> {
        let mut bytes = Vec::with_capacity(RECORD_LEN);
        bytes.push(RECORD_VERSION);
        bytes.push(PEPPER_KIND_NONE);
        bytes.extend_from_slice(&password_counter.to_be_bytes());
        bytes.extend_from_slice(&self.salt);
        let aad = associated_data(owner, &bytes)?;
        let cipher = Aes256Gcm::new_from_slice(&*self.check_key)
            .map_err(|_| CoreError::Encryption("invalid screen-lock check key".into()))?;
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: token.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::Encryption("screen-lock sealing failed".into()))?;
        bytes.extend_from_slice(nonce);
        bytes.extend_from_slice(&sealed);
        if bytes.len() != RECORD_LEN {
            return Err(CoreError::Encryption("screen-lock record has the wrong size".into()));
        }
        Ok(ScreenCheckRecord { bytes })
    }
}

/// `domain || u32 BE len || owner id (UTF-8) || header`: the record cannot be moved to another
/// account or have a header field edited.
fn associated_data(owner: &str, header: &[u8]) -> Result<Vec<u8>, CoreError> {
    if owner.is_empty() || owner.len() > MAX_OWNER_LEN {
        return Err(CoreError::InvalidInput(format!(
            "the owner id must be 1 to {MAX_OWNER_LEN} bytes"
        )));
    }
    let owner_len =
        u32::try_from(owner.len()).map_err(|_| CoreError::InvalidInput("the owner id is too long".into()))?;
    let capacity = SCREEN_LOCK_AAD_DOMAIN
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_add(owner.len()))
        .and_then(|n| n.checked_add(header.len()))
        .ok_or_else(|| CoreError::InvalidInput("screen-lock context is too long".into()))?;
    let mut aad = Vec::with_capacity(capacity);
    aad.extend_from_slice(SCREEN_LOCK_AAD_DOMAIN);
    aad.extend_from_slice(&owner_len.to_be_bytes());
    aad.extend_from_slice(owner.as_bytes());
    aad.extend_from_slice(header);
    Ok(aad)
}

/// Argon2id v19 at core's canonical cost (256 MiB, 4 iterations, 2 lanes, 32 bytes out: the
/// master-key derivation's numbers, not a parameter here) with the stretch's own label as
/// associated data, so the output is never `derive_master_key`'s for the same password and salt.
fn stretch_bytes(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    use crate::kdf::{MK_ITERATIONS, MK_MEMORY_KIB, MK_PARALLELISM, allocate_argon_memory};
    let data = argon2::AssociatedData::new(SCREEN_LOCK_STRETCH_LABEL)
        .map_err(|e| CoreError::Kdf(format!("invalid argon2 associated data: {e}")))?;
    let params = argon2::ParamsBuilder::new()
        .m_cost(MK_MEMORY_KIB)
        .t_cost(MK_ITERATIONS)
        .p_cost(MK_PARALLELISM)
        .output_len(32)
        .data(data)
        .build()
        .map_err(|e| CoreError::Kdf(format!("invalid argon2 params: {e}")))?;
    let mut memory = allocate_argon_memory(params.block_count())?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into_with_memory(password, salt, &mut *output, memory.as_mut_slice())
        .map_err(|e| CoreError::Kdf(format!("argon2 hashing failed: {e}")))?;
    Ok(output)
}

fn check_key(password: &Zeroizing<String>, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    if password.is_empty() {
        return Err(CoreError::InvalidInput("the password must not be empty".into()));
    }
    // Exactly the bytes the sign-in hands to OPAQUE: no normalization, so the local check and
    // the server can never disagree about the same typed password.
    let stretched = stretch_bytes(password.as_bytes(), salt)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, &*stretched)
        .expand(SCREEN_LOCK_KEY_INFO, &mut *key)
        .map_err(|_| CoreError::Kdf("screen-lock check-key derivation failed".into()))?;
    Ok(key)
}

fn stretch_with_salt(password: &Zeroizing<String>, salt: [u8; SALT_LEN]) -> Result<PendingScreenCheck, CoreError> {
    Ok(PendingScreenCheck {
        check_key: check_key(password, &salt)?,
        salt,
    })
}

/// Stretches the password under a new random salt. An `Err` (Argon2id could not allocate its
/// memory) means "no record": never retry with lower parameters.
pub fn stretch(password: &Zeroizing<String>) -> Result<PendingScreenCheck, CoreError> {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
    stretch_with_salt(password, salt)
}

/// Makes a record for a password the server has just accepted. `password_counter` is the
/// server's count of password changes for the account at that moment (0 when it reports none).
pub fn enroll(
    password: &Zeroizing<String>,
    owner: &str,
    password_counter: u64,
) -> Result<ScreenCheckRecord, CoreError> {
    if owner.is_empty() || owner.len() > MAX_OWNER_LEN {
        return Err(CoreError::InvalidInput(format!(
            "the owner id must be 1 to {MAX_OWNER_LEN} bytes"
        )));
    }
    stretch(password)?.seal(owner, password_counter)
}

/// Checks a typed password against a record. An `Err` is "the local check is unavailable"
/// (Argon2id could not allocate): the caller falls back to another proof, never to a weaker
/// derivation.
pub fn verify(
    record: &ScreenCheckRecord,
    password: &Zeroizing<String>,
    owner: &str,
) -> Result<CheckOutcome, CoreError> {
    if !record.is_readable() || owner.is_empty() || owner.len() > MAX_OWNER_LEN {
        return Ok(CheckOutcome::Unusable);
    }
    let (header, rest) = record.bytes.split_at(HEADER_LEN);
    let (nonce, sealed) = rest.split_at(NONCE_LEN);
    let key = check_key(password, &header[SALT_AT..])?;
    let aad = associated_data(owner, header)?;
    let cipher =
        Aes256Gcm::new_from_slice(&*key).map_err(|_| CoreError::Encryption("invalid screen-lock check key".into()))?;
    match cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad: &aad }) {
        Ok(token) => {
            // Only the tag matters: the token is wiped unread.
            drop(Zeroizing::new(token));
            Ok(CheckOutcome::Match)
        }
        Err(_) => Ok(CheckOutcome::NoMatch),
    }
}

/// The failure count that turns the local check off.
pub const LOCAL_CHECK_OFF_AT: u32 = 10;
const ATTEMPT_STATE_VERSION: u8 = 1;
const ATTEMPT_STATE_LEN: usize = 1 + 4 + 8;

/// Consecutive wrong password tries from the screen lock, and when the last one was. Persisted
/// by the caller so that restarting the app does not reset it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AttemptState {
    failures: u32,
    last_failure_ms: u64,
}

impl AttemptState {
    /// No failures.
    pub const fn new() -> Self {
        Self {
            failures: 0,
            last_failure_ms: 0,
        }
    }

    /// The state to assume when the stored one cannot be parsed: the longest wait, from now,
    /// with the local check off. An edit can never buy tries.
    pub const fn unreadable(now_ms: u64) -> Self {
        Self {
            failures: LOCAL_CHECK_OFF_AT,
            last_failure_ms: now_ms,
        }
    }

    pub const fn failures(&self) -> u32 {
        self.failures
    }

    pub const fn last_failure_ms(&self) -> u64 {
        self.last_failure_ms
    }

    /// The state to store BEFORE a check runs: this try counted as a failure at `now_ms`. Only
    /// a success resets it, so ending the process mid-check does not buy a free try.
    pub const fn counting_try(&self, now_ms: u64) -> Self {
        Self {
            failures: self.failures.saturating_add(1),
            last_failure_ms: now_ms,
        }
    }

    /// A clock that reads earlier than the stored last failure restarts the full wait from
    /// now. The caller stores the result when it differs.
    pub const fn rebased(&self, now_ms: u64) -> Self {
        if self.failures > 0 && now_ms < self.last_failure_ms {
            Self {
                failures: self.failures,
                last_failure_ms: now_ms,
            }
        } else {
            *self
        }
    }

    pub fn to_bytes(&self) -> [u8; ATTEMPT_STATE_LEN] {
        let mut bytes = [0u8; ATTEMPT_STATE_LEN];
        bytes[0] = ATTEMPT_STATE_VERSION;
        bytes[1..5].copy_from_slice(&self.failures.to_be_bytes());
        bytes[5..].copy_from_slice(&self.last_failure_ms.to_be_bytes());
        bytes
    }

    /// `None` for anything that is not a stored state: the caller assumes [`Self::unreadable`].
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ATTEMPT_STATE_LEN || bytes[0] != ATTEMPT_STATE_VERSION {
            return None;
        }
        let mut failures = [0u8; 4];
        failures.copy_from_slice(&bytes[1..5]);
        let mut last = [0u8; 8];
        last.copy_from_slice(&bytes[5..]);
        Some(Self {
            failures: u32::from_be_bytes(failures),
            last_failure_ms: u64::from_be_bytes(last),
        })
    }
}

/// What the wrong-try rule says about the next password try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryDecision {
    /// A try may run now, through the online check or the local one.
    Allowed,
    /// No password try of any kind before this time (milliseconds, the caller's clock).
    WaitUntil(u64),
    /// The local check is off (the record is to be deleted): a try may run now, but only
    /// the online check can accept it.
    LocalCheckOff,
}

/// The wait after `failures` consecutive wrong tries, in milliseconds.
pub const fn wait_after_ms(failures: u32) -> u64 {
    const SECOND: u64 = 1_000;
    const MINUTE: u64 = 60 * SECOND;
    match failures {
        0..=4 => 0,
        5 => 30 * SECOND,
        6 => MINUTE,
        7 => 5 * MINUTE,
        8 => 15 * MINUTE,
        _ => 60 * MINUTE,
    }
}

/// The wrong-try rule. It gates every password try from the screen lock, the online check
/// included. Pass a state that went through [`AttemptState::rebased`] for the same `now_ms`.
pub fn next_try(state: &AttemptState, now_ms: u64) -> TryDecision {
    let wait = wait_after_ms(state.failures);
    if wait > 0 {
        // A clock set back is treated as "the failure was now": the full wait.
        let since = state.last_failure_ms.min(now_ms);
        let until = since.saturating_add(wait);
        if now_ms < until {
            return TryDecision::WaitUntil(until);
        }
    }
    if state.failures >= LOCAL_CHECK_OFF_AT {
        TryDecision::LocalCheckOff
    } else {
        TryDecision::Allowed
    }
}

#[cfg(test)]
#[path = "screen_lock_tests.rs"]
mod tests;
