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
}

/// This device's backup of one category on the server, as the client lists
/// it. Before reporting a `Present` tree the client has resolved the root,
/// found or created this device's folder (`find_device_folder`) and, on a first
/// backup, created the category folder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
    /// Live (not trashed) files under the category folder.
    pub files: Vec<RemoteEntry>,
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
    /// (category, key): a key already queued is not queued twice.
    fn enqueue_upload(&self, req: UploadRequest) -> impl Future<Output = Result<(), HostError>> + Send;

    /// This device's records for `c`.
    fn records(&self, c: &Category) -> impl Future<Output = Result<Vec<BackupRecord>, HostError>> + Send;

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
