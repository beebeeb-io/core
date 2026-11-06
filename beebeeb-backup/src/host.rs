//! What the client provides to a pass (spec §4.3): its server calls, its
//! uploader and its record store. The client seals every name; core and this
//! crate only ever see plaintext names inside the device.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::path::PathBuf;

use beebeeb_core::backup::{BackupRecord, FolderPresence, RemoteEntry, UploadReason};
use beebeeb_types::backup::Category;
use uuid::Uuid;

use crate::Fingerprint;

/// One file for the client's own uploader. The source is read where it is:
/// the uploader opens `source_path` read-only, never moves, deletes or stages
/// it, compares `fingerprint` with a fresh one before the first chunk and
/// after the last, and abandons the session on any difference (the file is
/// retried next pass). When the upload completes, the client writes the
/// record for `key`.
///
/// `reason`: [`UploadReason::New`] creates a file named `name` in
/// `parent_id`, also when the paired record was removed elsewhere (it comes
/// back as a new file, ruling A); when it completes the client writes a fresh
/// record for `key` (new `remote_id`, `BackedUp`) and drops the record at
/// `record_key`, if any. [`UploadReason::Changed`] uploads a new version of
/// `remote_id` (the paired record's remote file, live at planning time), so
/// the backup keeps one file with its history, never two; when it completes
/// the client re-keys that record to `key` with `put_record`, which drops the
/// old key. The client never finds the record by looking `key` up: after a
/// normalised pairing the record's own key is `record_key` (review #3). A
/// `Changed` request whose remote file the server reports gone is uploaded as
/// `New`.
///
/// The pass re-checked the attributes just before the handoff, but the file
/// can still go online-only before the uploader opens it: the uploader
/// (desktop D3) reads the attributes on the handle it opens and never reads a
/// placeholder whose recall or offline bit is set (that read would download
/// it); it abandons the session and the file is retried next pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadRequest {
    pub category: Category,
    pub key: String,
    pub source_path: PathBuf,
    /// The server folder it goes into.
    pub parent_id: Uuid,
    /// The plain file name (the last key segment); the client seals it.
    pub name: String,
    pub fingerprint: Fingerprint,
    pub reason: UploadReason,
    /// The paired record's key (`None` for a file with no record).
    pub record_key: Option<String>,
    /// For `Changed`: the remote file to add a version to.
    pub remote_id: Option<Uuid>,
}

/// This device's backup of one category on the server, as the client lists
/// it. Before reporting a `Present` tree the client has resolved the root,
/// found or created this device's folder (`find_device_folder`) and, on a first
/// backup, created the category folder. There is no `Default`: every field is
/// set on purpose, so a host can never say "device folder deleted" by
/// accident (review #9).
///
/// ```compile_fail
/// // A defaulted tree would read as "device folder deleted": it must not build.
/// let _ = beebeeb_backup::DeviceTree::default();
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceTree {
    /// `false` only when this device's folder existed and is now trashed or
    /// gone.
    pub device_folder_live: bool,
    /// `None` when this category never had a folder (a first backup);
    /// `Some(false)` when it had one and it is now trashed or gone.
    pub category_folder_live: Option<bool>,
    /// Live folders by key under the category folder; key `""` is the category
    /// folder itself and must be present whenever the tree is `Present`.
    pub folders: HashMap<String, Uuid>,
    /// Live (not trashed) files under the category folder. A file whose name
    /// is still pending decryption is listed too, with an empty `key`: it is
    /// live by its id, and the pass reads only the id.
    pub files: Vec<RemoteEntry>,
    /// `true` only when the client read every page of the listing and dropped
    /// no entry. A pass marks records removed elsewhere only from a complete
    /// listing (review finding 2); from a partial one it marks nothing.
    pub complete: bool,
}

/// A client failure, in the client's words. It carries a kind or a count,
/// never a name or a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostError(pub String);

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HostError {}

/// The client side of one pass. `Send + Sync` because the pass holds the host
/// across awaits.
pub trait BackupHost: Send + Sync {
    /// List this device's backup of `c` (see [`DeviceTree`]).
    fn device_tree(&self, c: &Category) -> impl Future<Output = Result<DeviceTree, HostError>> + Send;

    /// Find or create the folder `name` (plain; the client seals it) under
    /// `parent`. Idempotent: an existing folder's id is returned.
    fn ensure_folder(&self, parent: Uuid, name: &str) -> impl Future<Output = Result<Uuid, HostError>> + Send;

    /// Move (and rename) the server file `id` to `new_name` under
    /// `new_parent`.
    fn move_file(
        &self,
        id: Uuid,
        new_parent: Uuid,
        new_name: &str,
    ) -> impl Future<Output = Result<(), HostError>> + Send;

    /// Hand one file to the client's uploader. Idempotent per
    /// (category, key): a key already queued is not queued twice, and a
    /// request whose key already has a `BackedUp` record with the request's
    /// fingerprint size and `modified_ms` is dropped (an upload that completed
    /// after the pass last read the records). The pass checks this itself
    /// just before it enqueues; the client closes the window that is left.
    fn enqueue_upload(&self, req: UploadRequest) -> impl Future<Output = Result<(), HostError>> + Send;

    /// This device's records for `c`.
    fn records(&self, c: &Category) -> impl Future<Output = Result<Vec<BackupRecord>, HostError>> + Send;

    /// The keys of `c` the client holds this pass (review #1): an upload that
    /// failed for a lasting reason (locked, too large, refused by the server),
    /// a key a pass reported in [`crate::PassReport::held_back`], and an
    /// upload still in flight. The pass skips them and charges them nothing
    /// against the budget, so one stuck file never starves the rest. The
    /// client releases a key when its file changes or the reason clears.
    fn held_keys(&self, c: &Category) -> impl Future<Output = Result<Vec<String>, HostError>> + Send;

    /// Store `record`: upsert by key, and remove any other record of `c` with
    /// the same `remote_id`, so one remote file never has two keys. A pass
    /// calls it only after a successful [`BackupHost::move_file`] (plan
    /// Amendment 1); an upload's record is written by the client when the
    /// upload completes.
    fn put_record(&self, c: &Category, record: BackupRecord) -> impl Future<Output = Result<(), HostError>> + Send;

    /// Set these records (by key) to `RemovedElsewhere`.
    fn mark_removed_elsewhere(
        &self,
        c: &Category,
        keys: &[String],
    ) -> impl Future<Output = Result<(), HostError>> + Send;

    /// The device or category folder was deleted elsewhere: turn this backup
    /// off on the device, say so, and offer "Back up again" (spec §4.2 rule
    /// 11). Pending uploads of `c` are dropped and their sessions abandoned.
    fn turn_off(&self, c: &Category, why: FolderPresence) -> impl Future<Output = Result<(), HostError>> + Send;
}
