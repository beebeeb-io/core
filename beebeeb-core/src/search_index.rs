//! Client-built, sharded, end-to-end-encrypted search index (task 0778, part B).
//!
//! The server is zero-knowledge: file names live there only as ciphertext, so a
//! search index cannot be built or queried server-side. This module is the
//! shared **core** primitive every client (web/WASM, mobile/UniFFI, CLI/desktop)
//! uses to build, incrementally maintain, encrypt, and query that index on-device.
//!
//! ## Shape
//!
//! **Tokenizer.** A decrypted file name is normalized (lowercase, Unicode NFKD +
//! combining-mark stripping for accent-folding) and split into tokens on separators
//! (space `_` `-` `.`) and camelCase boundaries. Each token maps to a posting list
//! of `file_id`s. The full normalized name is kept too, so a partial query that
//! spans token boundaries still matches ("nf" → `NF_song.mp3`).
//!
//! **Sharding.** Every token is assigned a deterministic bucket
//! (`blake3(token) % num_shards`); file records are bucketed the same way by
//! `file_id`. A shard (one bucket) serializes to one or more pages, each ≤ 128 KB
//! *after* encryption. A file add/rename/delete recomputes only the buckets it
//! touches — never the whole index (`upsert` / `remove` return the dirty bucket set).
//!
//! **Encryption.** Each shard page is serialized then sealed with AES-256-GCM under
//! a per-shard key derived from the user's master key
//! ([`crate::kdf::derive_search_index_key`]). The output blob
//! (`nonce || ciphertext || tag`) is opaque — the server never sees tokens or names.
//! Zero-knowledge is preserved.
//!
//! ## Storage layout (per shard page, the encrypted plaintext)
//!
//! Each page carries, for its bucket `b`, a `postings` section (every token `t`
//! with `bucket(t) == b` → its `file_id`s; a very hot token may be split across
//! pages and the loader unions them) and a `files` section (every `file_id` `f`
//! with `bucket(f) == b` → its normalized full name + token list). The names power
//! the substring fallback; the stored tokens let an incremental delete/rename find
//! the affected posting buckets without the caller re-supplying the old name.
//!
//! `num_shards` is fixed for an index instance; changing it requires a full
//! rebuild (the bucket function depends on it). Clients persist it in their index
//! manifest (server concern, separate task).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::CoreError;
use crate::encrypt::{decrypt_chunk_raw, encrypt_chunk_raw};
use crate::kdf::{MasterKey, derive_search_index_key};

/// Default shard count. A power-of-two-ish spread that keeps per-shard size small
/// for typical vaults while bounding the number of blobs to sync.
pub const DEFAULT_NUM_SHARDS: u32 = 64;

/// Hard upper bound on a single encrypted shard-page blob, in bytes.
pub const MAX_SHARD_BYTES: usize = 128 * 1024;

/// Plaintext budget per page. Leaves generous headroom under [`MAX_SHARD_BYTES`]
/// for JSON framing and the 28-byte AEAD overhead (12-byte nonce + 16-byte tag),
/// and absorbs the small over-count in the size estimator.
const PAGE_PLAINTEXT_BUDGET: usize = 100 * 1024;

/// On-disk shard-page format version.
const FORMAT_VERSION: u32 = 1;

// ── Tokenization ────────────────────────────────────────────────────────────

/// The result of normalizing a file name: the full normalized string (for the
/// substring fallback) plus the de-duplicated, order-preserving token list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tokenized {
    /// Lowercased, accent-folded full name (separators preserved).
    pub normalized: String,
    /// Lowercased, accent-folded tokens, de-duplicated, in first-seen order.
    pub tokens: Vec<String>,
}

/// True for Unicode combining marks (the five combining-mark blocks). After NFKD,
/// stripping these accent-folds precomposed Latin letters (é→e, ñ→n, ü→u, …).
fn is_combining_mark(c: char) -> bool {
    matches!(c as u32,
        0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F)
}

/// Token separators: whitespace plus `_`, `-`, `.`.
fn is_separator(c: char) -> bool {
    c.is_whitespace() || matches!(c, '_' | '-' | '.')
}

fn flush_token(cur: &mut String, out: &mut Vec<String>) {
    if !cur.is_empty() {
        out.push(std::mem::take(cur));
    }
}

/// Normalize and tokenize a (decrypted) file name.
///
/// Steps: NFKD + strip combining marks (accent-fold, case preserved for camelCase
/// detection) → split on separators and lower/digit→Upper boundaries → lowercase
/// each token → de-duplicate preserving first-seen order. The `normalized` field
/// is the accent-folded name lowercased as a whole (separators kept).
pub fn tokenize(name: &str) -> Tokenized {
    let folded: String = name.nfkd().filter(|c| !is_combining_mark(*c)).collect();
    let normalized = folded.to_lowercase();

    let mut raw: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut prev: Option<char> = None;
    for c in folded.chars() {
        if is_separator(c) {
            flush_token(&mut cur, &mut raw);
            prev = None;
            continue;
        }
        if let Some(p) = prev {
            // camelCase boundary: a lowercase letter or digit followed by an
            // uppercase letter starts a new token ("myPhoto" → my | Photo).
            if (p.is_lowercase() || p.is_numeric()) && c.is_uppercase() {
                flush_token(&mut cur, &mut raw);
            }
        }
        cur.push(c);
        prev = Some(c);
    }
    flush_token(&mut cur, &mut raw);

    let mut seen = BTreeSet::new();
    let tokens = raw
        .into_iter()
        .map(|t| t.to_lowercase())
        .filter(|t| !t.is_empty() && seen.insert(t.clone()))
        .collect();

    Tokenized { normalized, tokens }
}

/// Deterministic bucket for a key (token or file_id): the first 8 bytes of its
/// BLAKE3 hash, little-endian, modulo `num_shards`.
fn bucket_of(key: &str, num_shards: u32) -> u32 {
    debug_assert!(num_shards >= 1);
    let h = blake3::hash(key.as_bytes());
    let b = h.as_bytes();
    let v = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    (v % num_shards as u64) as u32
}

// ── In-memory index ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct FileRecord {
    normalized: String,
    tokens: Vec<String>,
}

/// A client-side search index over a vault's file names.
///
/// Holds the authoritative in-memory state (file records + inverted token index).
/// Build it from a file list, mutate it incrementally, and (de)serialize it to
/// encrypted shards for sync. Queries run entirely in memory.
#[derive(Debug, Clone)]
pub struct SearchIndex {
    num_shards: u32,
    files: BTreeMap<String, FileRecord>,
    postings: BTreeMap<String, BTreeSet<String>>,
}

impl SearchIndex {
    /// Create an empty index with the given shard count (clamped to ≥ 1).
    pub fn new(num_shards: u32) -> Self {
        Self {
            num_shards: num_shards.max(1),
            files: BTreeMap::new(),
            postings: BTreeMap::new(),
        }
    }

    /// Build an index from `(file_id, name)` pairs. A later pair with a
    /// duplicate `file_id` overwrites the earlier one (last-writer-wins).
    pub fn build(files: &[(String, String)], num_shards: u32) -> Self {
        let mut idx = Self::new(num_shards);
        for (file_id, name) in files {
            idx.upsert(file_id, name);
        }
        idx
    }

    /// Shard count this index uses.
    pub fn num_shards(&self) -> u32 {
        self.num_shards
    }

    /// Number of indexed files.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// True when no files are indexed.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Bucket a token would occupy in this index.
    pub fn shard_for_token(&self, token: &str) -> u32 {
        bucket_of(token, self.num_shards)
    }

    /// Bucket a file's record occupies in this index.
    pub fn shard_for_file(&self, file_id: &str) -> u32 {
        bucket_of(file_id, self.num_shards)
    }

    /// Insert or update a file (add or rename). Returns the set of buckets whose
    /// shards changed — re-encrypt only these for an incremental sync.
    pub fn upsert(&mut self, file_id: &str, name: &str) -> BTreeSet<u32> {
        let mut dirty = BTreeSet::new();
        dirty.insert(bucket_of(file_id, self.num_shards));

        let parsed = tokenize(name);
        let new_set: BTreeSet<String> = parsed.tokens.iter().cloned().collect();
        let old_set: BTreeSet<String> = self
            .files
            .get(file_id)
            .map(|r| r.tokens.iter().cloned().collect())
            .unwrap_or_default();

        for t in old_set.difference(&new_set) {
            if let Some(set) = self.postings.get_mut(t) {
                set.remove(file_id);
                if set.is_empty() {
                    self.postings.remove(t);
                }
            }
            dirty.insert(bucket_of(t, self.num_shards));
        }
        for t in new_set.difference(&old_set) {
            self.postings.entry(t.clone()).or_default().insert(file_id.to_string());
            dirty.insert(bucket_of(t, self.num_shards));
        }

        self.files.insert(
            file_id.to_string(),
            FileRecord {
                normalized: parsed.normalized,
                tokens: parsed.tokens,
            },
        );
        dirty
    }

    /// Remove a file. Returns the set of buckets whose shards changed (empty if
    /// the file was not indexed).
    pub fn remove(&mut self, file_id: &str) -> BTreeSet<u32> {
        let mut dirty = BTreeSet::new();
        if let Some(rec) = self.files.remove(file_id) {
            dirty.insert(bucket_of(file_id, self.num_shards));
            for t in &rec.tokens {
                if let Some(set) = self.postings.get_mut(t) {
                    set.remove(file_id);
                    if set.is_empty() {
                        self.postings.remove(t);
                    }
                }
                dirty.insert(bucket_of(t, self.num_shards));
            }
        }
        dirty
    }

    /// Search. Returns the matching `file_id`s. A file matches when any query
    /// token equals or is a prefix of an indexed token, OR the whole normalized
    /// query is a substring of the file's normalized name. The folder a file
    /// lives in is irrelevant — the index is flat over the whole vault, so a term
    /// that exists only in a deeply nested file is still found.
    pub fn query(&self, term: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let parsed = tokenize(term);

        for qt in &parsed.tokens {
            // Exact + prefix: BTreeMap range from `qt` while the key still starts with it.
            for (tok, set) in self.postings.range(qt.clone()..) {
                if !tok.starts_with(qt.as_str()) {
                    break;
                }
                out.extend(set.iter().cloned());
            }
        }

        let needle = parsed.normalized.trim();
        if !needle.is_empty() {
            for (fid, rec) in &self.files {
                if rec.normalized.contains(needle) {
                    out.insert(fid.clone());
                }
            }
        }
        out
    }

    // ── Encrypted-shard (de)serialization ───────────────────────────────────

    /// Group the current state into per-bucket `(postings, files)` payloads.
    fn collect_buckets(&self) -> BTreeMap<u32, BucketData> {
        let mut map: BTreeMap<u32, BucketData> = BTreeMap::new();
        for (tok, fids) in &self.postings {
            let b = bucket_of(tok, self.num_shards);
            map.entry(b)
                .or_default()
                .postings
                .push((tok.clone(), fids.iter().cloned().collect()));
        }
        for (fid, rec) in &self.files {
            let b = bucket_of(fid, self.num_shards);
            map.entry(b)
                .or_default()
                .files
                .push((fid.clone(), rec.normalized.clone(), rec.tokens.clone()));
        }
        map
    }

    /// Encrypt every non-empty shard page of the whole index.
    pub fn encrypt_shards(&self, master_key: &MasterKey) -> Result<Vec<EncryptedShard>, CoreError> {
        let buckets: Vec<u32> = self.collect_buckets().keys().copied().collect();
        self.encrypt_selected(master_key, &buckets)
    }

    /// Encrypt only the given buckets' shard pages (incremental sync). Buckets
    /// that are now empty (e.g. after a delete) yield no pages; the caller should
    /// delete their server-side shards. Pass the dirty set from [`upsert`]/[`remove`].
    pub fn encrypt_buckets(
        &self,
        master_key: &MasterKey,
        buckets: &BTreeSet<u32>,
    ) -> Result<Vec<EncryptedShard>, CoreError> {
        let buckets: Vec<u32> = buckets.iter().copied().collect();
        self.encrypt_selected(master_key, &buckets)
    }

    fn encrypt_selected(&self, master_key: &MasterKey, buckets: &[u32]) -> Result<Vec<EncryptedShard>, CoreError> {
        let mut data = self.collect_buckets();
        let mut out = Vec::new();
        for &b in buckets {
            let Some(bucket) = data.remove(&b) else {
                continue; // no data for this bucket (empty / not present)
            };
            let key = derive_search_index_key(master_key, b);
            for (page_idx, page) in paginate(b, bucket, PAGE_PLAINTEXT_BUDGET).into_iter().enumerate() {
                let plaintext = serde_json::to_vec(&page).map_err(|e| CoreError::Encryption(e.to_string()))?;
                let blob = encrypt_chunk_raw(&key, &plaintext)?;
                out.push(EncryptedShard {
                    bucket: b,
                    page: page_idx as u32,
                    blob,
                });
            }
        }
        Ok(out)
    }

    /// Reconstruct an index from its encrypted shards. Pages of the same bucket
    /// (a split hot token) are unioned. `num_shards` must match the value used to
    /// build the shards.
    pub fn from_encrypted_shards(
        master_key: &MasterKey,
        shards: &[EncryptedShard],
        num_shards: u32,
    ) -> Result<Self, CoreError> {
        let mut idx = Self::new(num_shards);
        for sh in shards {
            let key = derive_search_index_key(master_key, sh.bucket);
            let plaintext = decrypt_chunk_raw(&key, &sh.blob)?;
            let page: ShardPage = serde_json::from_slice(&plaintext).map_err(|_| CoreError::Decryption)?;
            if page.v != FORMAT_VERSION {
                return Err(CoreError::InvalidInput(format!(
                    "unsupported search index shard version {}",
                    page.v
                )));
            }
            for (tok, fids) in page.postings {
                let set = idx.postings.entry(tok).or_default();
                set.extend(fids);
            }
            for (fid, normalized, tokens) in page.files {
                idx.files.insert(fid, FileRecord { normalized, tokens });
            }
        }
        Ok(idx)
    }
}

/// One encrypted shard page: opaque blob plus the (non-secret) addressing the
/// server needs. `blob` is `nonce(12) || ciphertext || tag(16)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedShard {
    pub bucket: u32,
    pub page: u32,
    pub blob: Vec<u8>,
}

#[derive(Default)]
struct BucketData {
    postings: Vec<(String, Vec<String>)>,
    files: Vec<(String, String, Vec<String>)>,
}

/// Serializable plaintext of one shard page.
#[derive(Serialize, Deserialize)]
struct ShardPage {
    v: u32,
    bucket: u32,
    postings: Vec<(String, Vec<String>)>,
    files: Vec<(String, String, Vec<String>)>,
}

fn est_str(s: &str) -> usize {
    s.len() + 3 // quotes + comma
}
fn est_posting(tok: &str, fids: &[String]) -> usize {
    est_str(tok) + 4 + fids.iter().map(|f| est_str(f)).sum::<usize>()
}
fn est_file(fid: &str, normalized: &str, tokens: &[String]) -> usize {
    est_str(fid) + est_str(normalized) + 6 + tokens.iter().map(|t| est_str(t)).sum::<usize>()
}

/// Page-size base overhead for the JSON envelope (`{"v":1,"bucket":...,...}`).
const PAGE_BASE_OVERHEAD: usize = 60;

/// Split a bucket's data into pages, each estimated ≤ `budget` bytes. A token
/// whose posting list alone would exceed the per-unit budget is split across
/// pages (its key repeats; the loader unions them).
fn paginate(bucket: u32, data: BucketData, budget: usize) -> Vec<ShardPage> {
    let unit_cap = budget.saturating_sub(PAGE_BASE_OVERHEAD).max(1);

    // Pre-split hot posting lists so every posting unit fits an empty page.
    let mut posting_units: Vec<(String, Vec<String>)> = Vec::new();
    for (tok, fids) in data.postings {
        let mut chunk: Vec<String> = Vec::new();
        let mut sz = est_str(&tok) + 4;
        for f in fids {
            let add = est_str(&f);
            if !chunk.is_empty() && sz + add > unit_cap {
                posting_units.push((tok.clone(), std::mem::take(&mut chunk)));
                sz = est_str(&tok) + 4;
            }
            sz += add;
            chunk.push(f);
        }
        if !chunk.is_empty() {
            posting_units.push((tok, chunk));
        }
    }

    let mut pages: Vec<ShardPage> = Vec::new();
    let mut cur = ShardPage {
        v: FORMAT_VERSION,
        bucket,
        postings: Vec::new(),
        files: Vec::new(),
    };
    let mut size = PAGE_BASE_OVERHEAD;
    let has_content = |p: &ShardPage| !p.postings.is_empty() || !p.files.is_empty();

    for (tok, fids) in posting_units {
        let est = est_posting(&tok, &fids);
        if size + est > budget && has_content(&cur) {
            pages.push(std::mem::replace(
                &mut cur,
                ShardPage {
                    v: FORMAT_VERSION,
                    bucket,
                    postings: Vec::new(),
                    files: Vec::new(),
                },
            ));
            size = PAGE_BASE_OVERHEAD;
        }
        size += est;
        cur.postings.push((tok, fids));
    }
    for (fid, normalized, tokens) in data.files {
        let est = est_file(&fid, &normalized, &tokens);
        if size + est > budget && has_content(&cur) {
            pages.push(std::mem::replace(
                &mut cur,
                ShardPage {
                    v: FORMAT_VERSION,
                    bucket,
                    postings: Vec::new(),
                    files: Vec::new(),
                },
            ));
            size = PAGE_BASE_OVERHEAD;
        }
        size += est;
        cur.files.push((fid, normalized, tokens));
    }
    if has_content(&cur) {
        pages.push(cur);
    }
    pages
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::derive_master_key;

    fn mk() -> MasterKey {
        derive_master_key("test-password", b"test-salt-16bytes").unwrap()
    }

    // ── tokenizer ────────────────────────────────────────────────────────

    #[test]
    fn tokenize_separators() {
        let t = tokenize("IMG_2024-final.v2.png");
        assert_eq!(t.tokens, vec!["img", "2024", "final", "v2", "png"]);
        assert_eq!(t.normalized, "img_2024-final.v2.png");
    }

    #[test]
    fn tokenize_camelcase() {
        let t = tokenize("myVacationPhoto");
        assert_eq!(t.tokens, vec!["my", "vacation", "photo"]);
    }

    #[test]
    fn tokenize_accent_fold() {
        let t = tokenize("Café_Münchën.JPG");
        assert_eq!(t.normalized, "cafe_munchen.jpg");
        assert_eq!(t.tokens, vec!["cafe", "munchen", "jpg"]);
    }

    #[test]
    fn tokenize_dedup_preserves_order() {
        let t = tokenize("song song.SONG");
        assert_eq!(t.tokens, vec!["song"]);
    }

    #[test]
    fn tokenize_ligature_compatibility_decomposition() {
        // NFKD expands the ﬀ ligature (U+FB00) to "ff": "su\u{FB00}ix" → "suffix".
        let t = tokenize("su\u{FB00}ix");
        assert_eq!(t.normalized, "suffix");
        assert_eq!(t.tokens, vec!["suffix"]);
    }

    // ── bucketing determinism ────────────────────────────────────────────

    #[test]
    fn bucket_is_deterministic_and_bounded() {
        for n in [1u32, 7, 64, 1000] {
            for key in ["song", "report", "a-very-long-token-value", "2024"] {
                let b1 = bucket_of(key, n);
                let b2 = bucket_of(key, n);
                assert_eq!(b1, b2, "deterministic for {key}/{n}");
                assert!(b1 < n, "in range for {key}/{n}");
            }
        }
    }

    // ── search correctness ───────────────────────────────────────────────

    fn sample_index() -> SearchIndex {
        let files = vec![
            ("f1".to_string(), "NF_song.mp3".to_string()),
            ("f2".to_string(), "vacation_photo.jpg".to_string()),
            ("f3".to_string(), "Quarterly_Report_2024.pdf".to_string()),
            ("f4".to_string(), "myVacationPhoto.png".to_string()),
            ("f5".to_string(), "Café_notes.txt".to_string()),
        ];
        SearchIndex::build(&files, DEFAULT_NUM_SHARDS)
    }

    #[test]
    fn query_exact_token() {
        let idx = sample_index();
        assert_eq!(idx.query("nf"), BTreeSet::from(["f1".to_string()]));
        assert_eq!(idx.query("NF"), BTreeSet::from(["f1".to_string()])); // case-insensitive
    }

    #[test]
    fn query_prefix() {
        let idx = sample_index();
        // "vac" is a prefix of the token "vacation" in f2 and f4.
        assert_eq!(idx.query("vac"), BTreeSet::from(["f2".to_string(), "f4".to_string()]));
    }

    #[test]
    fn query_substring_fallback() {
        let idx = sample_index();
        // "ong" is neither a token nor a prefix, but is a substring of "song".
        assert_eq!(idx.query("ong"), BTreeSet::from(["f1".to_string()]));
    }

    #[test]
    fn query_accent_folded() {
        let idx = sample_index();
        // ASCII query finds an accented name.
        assert_eq!(idx.query("cafe"), BTreeSet::from(["f5".to_string()]));
    }

    #[test]
    fn query_nested_term_is_found_regardless_of_folder() {
        // The index is flat: a term unique to one file is found no matter how
        // deep that file's folder is (folders are not part of the index).
        let mut idx = SearchIndex::new(DEFAULT_NUM_SHARDS);
        idx.upsert("top", "readme.txt");
        idx.upsert("a", "a.txt");
        idx.upsert("deep", "buried_treasure_xyzzy.txt"); // conceptually 5 folders down
        assert_eq!(idx.query("xyzzy"), BTreeSet::from(["deep".to_string()]));
        assert_eq!(idx.query("treasure"), BTreeSet::from(["deep".to_string()]));
    }

    #[test]
    fn query_no_match_is_empty() {
        let idx = sample_index();
        assert!(idx.query("nonexistentterm").is_empty());
    }

    // ── incremental update touches only the right shards ─────────────────

    #[test]
    fn rename_touches_only_affected_shards() {
        let mut idx = SearchIndex::new(DEFAULT_NUM_SHARDS);
        idx.upsert("f", "report.pdf");
        let n = idx.num_shards();

        let dirty = idx.upsert("f", "report.txt"); // pdf → txt; "report" unchanged

        let expected: BTreeSet<u32> = [
            bucket_of("f", n),   // file record
            bucket_of("pdf", n), // token removed
            bucket_of("txt", n), // token added
        ]
        .into_iter()
        .collect();
        assert_eq!(dirty, expected, "only file + changed-token buckets are dirty");

        // "report" posting survived; pdf gone; txt present.
        assert_eq!(idx.query("report"), BTreeSet::from(["f".to_string()]));
        assert!(idx.query("pdf").is_empty());
        assert_eq!(idx.query("txt"), BTreeSet::from(["f".to_string()]));
    }

    #[test]
    fn delete_touches_only_affected_shards_and_removes() {
        let mut idx = SearchIndex::new(DEFAULT_NUM_SHARDS);
        idx.upsert("f", "report.pdf");
        idx.upsert("g", "report.txt"); // shares token "report"
        let n = idx.num_shards();

        let dirty = idx.remove("f");
        let expected: BTreeSet<u32> = [bucket_of("f", n), bucket_of("report", n), bucket_of("pdf", n)]
            .into_iter()
            .collect();
        assert_eq!(dirty, expected);

        assert!(idx.query("pdf").is_empty());
        // "report" still matches g (shared token correctly retained).
        assert_eq!(idx.query("report"), BTreeSet::from(["g".to_string()]));
        assert_eq!(idx.file_count(), 1);
    }

    #[test]
    fn remove_unknown_file_is_noop() {
        let mut idx = sample_index();
        let before = idx.file_count();
        assert!(idx.remove("does-not-exist").is_empty());
        assert_eq!(idx.file_count(), before);
    }

    // ── encryption round-trip + zero-knowledge ───────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip_preserves_queries() {
        let idx = sample_index();
        let key = mk();
        let shards = idx.encrypt_shards(&key).unwrap();
        assert!(!shards.is_empty());

        let restored = SearchIndex::from_encrypted_shards(&key, &shards, idx.num_shards()).unwrap();
        assert_eq!(restored.file_count(), idx.file_count());
        for term in ["nf", "vac", "ong", "cafe", "report", "png"] {
            assert_eq!(
                idx.query(term),
                restored.query(term),
                "query '{term}' must match after round-trip"
            );
        }
    }

    #[test]
    fn wrong_master_key_fails_to_decrypt() {
        let idx = sample_index();
        let shards = idx.encrypt_shards(&mk()).unwrap();
        let wrong = derive_master_key("different-password", b"different-salt-16").unwrap();
        assert!(SearchIndex::from_encrypted_shards(&wrong, &shards, idx.num_shards()).is_err());
    }

    #[test]
    fn shard_blob_leaks_no_plaintext() {
        // The opaque blob must not contain a recognizable token/name.
        let mut idx = SearchIndex::new(DEFAULT_NUM_SHARDS);
        idx.upsert("f1", "supersecretfilename.txt");
        let shards = idx.encrypt_shards(&mk()).unwrap();
        for s in &shards {
            assert!(
                !s.blob.windows(b"supersecret".len()).any(|w| w == b"supersecret"),
                "ciphertext must not contain plaintext token bytes"
            );
        }
    }

    // ── sharding: ≤128 KB bound + pagination ─────────────────────────────

    #[test]
    fn every_shard_blob_is_within_128kb_and_pagination_triggers() {
        // Build a large index: many files + a hot token shared by all of them
        // (forces a single bucket far past 128 KB → must paginate).
        let mut files = Vec::new();
        for i in 0..6000 {
            files.push((format!("file-id-{i:08}"), format!("shared_document_{i:06}.pdf")));
        }
        let idx = SearchIndex::build(&files, 8); // few shards → big buckets
        let shards = idx.encrypt_shards(&mk()).unwrap();

        for s in &shards {
            assert!(
                s.blob.len() <= MAX_SHARD_BYTES,
                "shard (bucket {}, page {}) is {} bytes, over the 128 KB bound",
                s.bucket,
                s.page,
                s.blob.len()
            );
        }
        // The hot token "shared" forces multiple pages in at least one bucket.
        let multipage = shards.iter().any(|s| s.page > 0);
        assert!(multipage, "expected at least one bucket to paginate past one page");

        // And it still round-trips with correct queries.
        let restored = SearchIndex::from_encrypted_shards(&mk(), &shards, idx.num_shards()).unwrap();
        assert_eq!(restored.file_count(), 6000);
        assert_eq!(restored.query("shared").len(), 6000);
        assert_eq!(restored.query("file-id-00000042"), idx.query("file-id-00000042"));
    }

    #[test]
    fn incremental_encrypt_only_dirty_buckets() {
        let mut idx = sample_index();
        let dirty = idx.upsert("f6", "newfile_zeta.mp4");
        let partial = idx.encrypt_buckets(&mk(), &dirty).unwrap();
        // Every returned shard is in the dirty set.
        for s in &partial {
            assert!(dirty.contains(&s.bucket));
        }
        // Applying the partial shards over a full prior snapshot is the client's
        // job; here we just assert the partial set is non-empty and bounded.
        assert!(!partial.is_empty());
    }
}
