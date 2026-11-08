//! Share a folder with a person (web `share-dialog.tsx` folder branch, `buildFolderInvite`,
//! `findExistingFolderKey`, `custodyFolderKey`, `ensureOwnerFolderKey`).
//!
//! ```mermaid
//! flowchart TD
//!   S[FolderShare::start] -->|shared folders on| C[GET /shared-folders/id]
//!   C -->|record| O[open custody, L7]
//!   C -->|404, never seen| I1[GET /shares/invites/sent]
//!   I1 -->|active invites| U[refuse: folder_needs_upgrade]
//!   I1 -->|none| R[mint, PUT /shared-folders/id/key]
//!   R -->|key_version_conflict| C2[re-read custody, open it]
//!   S -->|shared folders off| A[ancestor walk: GET /files/id]
//!   A --> I2[GET /shares/invites/sent]
//!   I2 -->|no active invite| M[mint, legacy]
//!   I2 -->|newest blob that opens| E[reuse, legacy]
//!   I2 -->|active, nothing opens| X[refuse: folder_key_unverified]
//!   O --> L[list every descendant]
//!   R --> L
//!   C2 --> L
//!   M --> L
//!   E --> L
//!   L --> P[POST /shares/invites with folder_keys + folder_key_id]
//!   P -->|claimed + key| AP[POST /invites/id/approve]
//! ```
//!
//! The rules that cost data (web `CLAUDE.md` "Never break", task 2133):
//! - one key per folder: the custody record first, then the newest active invite's owner copy that
//!   opens; a key is minted only when the folder has neither;
//! - never mint while an active invite has no owner copy that opens with proof
//!   ([`ShareFlowError::FolderKeyUnverified`]);
//! - only an authentication failure of the purpose-bound owner copy falls through to the legacy
//!   proof; any other failure aborts.
//!
//! Deviation from web, by design: a folder that needs the custody upgrade (it has active flag-off
//! invites and no custody record, shared folders on) is refused with
//! [`ShareFlowError::FolderNeedsUpgrade`]; web runs the upgrade (`folder-custody-upgrade.ts`), which
//! is not ported. Web takes the same refusal when its upgrade runner is absent. Nothing is written.
use std::collections::VecDeque;

use serde_json::{Value, json};

use super::folder_keys::{
    CustodyMemory, FILE_LIST_HARD_CAP, FolderWrapFormat, MAX_ANCESTOR_WALK, OwnerCopyOpen, SHARE_PAGE_LIMIT,
    SentInvite, active_folder_invites, canonical_folder_id, folder_key_id_b64, open_owner_copy, owner_copy_b64,
    proof_rows, seal_folder_child, unique_owner_blobs,
};
use super::member::{INVITES_PATH, InviteOutcome, approve_request, check_email};
use super::{ShareFlowError, b64, b64_decode, own_master, path_id, require_ok, split, str_field};
use crate::auth_flow::{HttpRequest, HttpResponse, RequestAuth};
use crate::kdf::{self, FileKey, MasterKey};

const SENT_PATH: &str = "/api/v1/shares/invites/sent";

/// What a folder invite starts from. `custody` is the device's custody memory (web
/// `custody-memory.ts`); `shared_folders_write` is the `shared_folders_v1` flag, read at send time.
/// A host that cannot read the flag must not start the flow (web `FeatureFlagsUnavailableError`).
pub struct FolderInviteInput<'a> {
    pub folder_id: &'a str,
    pub email: &'a str,
    pub shared_folders_write: bool,
    pub custody: CustodyMemory,
}

/// A request to send. `mark_custody_seen` is a folder id the host must add to its durable custody
/// memory BEFORE it sends the request (L7d: recorded before any key from the record is used).
#[derive(Debug)]
pub struct FolderSend {
    pub request: HttpRequest,
    pub mark_custody_seen: Option<String>,
}

#[derive(Debug)]
pub enum FolderStep {
    Send(FolderSend),
    Done(InviteOutcome),
    /// A folder link was stored; `link` carries `#key=K_c` and never goes to a web view.
    LinkCreated(link::CreatedFolderLink),
}

mod link;
pub use link::{
    CreatedFolderLink, FolderLinkInput, LINK_ID_ATTEMPTS, list_folder_links_request, rebuild_folder_link,
    revoke_folder_link_request,
};

enum Purpose {
    Invite { email: String },
    Link(Box<link::LinkPlan>),
}

struct Child {
    id: String,
    is_folder: bool,
}

enum Stage {
    EnsureRead,
    EnsureSent,
    Register {
        minted: FileKey,
        wrapped: String,
    },
    Reread,
    Ancestor {
        depth: usize,
    },
    FindSent,
    ProofRows {
        blobs: Vec<String>,
        next: usize,
    },
    List {
        parent: String,
        queue: VecDeque<String>,
        children: Vec<Child>,
    },
    AwaitInvite,
    AwaitLink {
        id: String,
        attempt: u32,
    },
    AwaitApprove {
        invite_id: String,
    },
    Done,
}

/// The key the invite will carry, and where its owner copy comes from.
struct Keyed {
    folder_key: FileKey,
    format: FolderWrapFormat,
    /// The custody record (L7 folders): the invite's owner copy is the record itself.
    custody_blob: Option<String>,
}

pub struct FolderShare {
    folder_id: String,
    purpose: Purpose,
    master: MasterKey,
    custody: CustodyMemory,
    stage: Stage,
    keyed: Option<Keyed>,
    active: Vec<SentInvite>,
}

impl std::fmt::Debug for FolderShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FolderShare")
            .field("folder_id", &self.folder_id)
            .finish_non_exhaustive()
    }
}

fn get(path: String) -> HttpRequest {
    HttpRequest::get(path, RequestAuth::Session)
}

fn send(request: HttpRequest) -> FolderStep {
    FolderStep::Send(FolderSend {
        request,
        mark_custody_seen: None,
    })
}

fn custody_path(folder_id: &str) -> String {
    format!("/api/v1/shared-folders/{folder_id}")
}

fn error_code(resp: &HttpResponse) -> Option<&str> {
    resp.body
        .get("code")
        .and_then(Value::as_str)
        .or_else(|| resp.body.get("error").and_then(Value::as_str))
}

fn random_folder_key() -> Result<FileKey, ShareFlowError> {
    use rand::RngCore;
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(&mut *bytes)
        .map_err(|_| ShareFlowError::Crypto)?;
    Ok(FileKey::from_bytes(*bytes))
}

impl FolderShare {
    fn new(
        folder_id: &str,
        purpose: Purpose,
        master: &MasterKey,
        custody: CustodyMemory,
    ) -> Result<Self, ShareFlowError> {
        // A folder id that is no UUID refuses (web `parseFolderId`: it counts as seen). Key
        // derivation, AAD and the invite match read the id's bytes, so a UUID that is not already
        // canonical lower-case is refused, never normalized.
        canonical_folder_id(folder_id).ok_or(ShareFlowError::FolderKeysUnavailable)?;
        let folder_id = super::canonical_item_id(folder_id, "folder id")?.to_owned();
        Ok(Self {
            folder_id,
            purpose,
            master: own_master(master),
            custody,
            stage: Stage::Done,
            keyed: None,
            active: Vec::new(),
        })
    }

    /// A person share of a folder (web `share-dialog.tsx` folder branch).
    pub fn invite(input: FolderInviteInput<'_>, master: &MasterKey) -> Result<(Self, FolderStep), ShareFlowError> {
        let email = check_email(input.email)?;
        let mut flow = Self::new(input.folder_id, Purpose::Invite { email }, master, input.custody)?;
        let step = if input.shared_folders_write {
            flow.stage = Stage::EnsureRead;
            send(get(custody_path(&flow.folder_id)))
        } else {
            flow.ancestor_walk(flow.folder_id.clone(), 0)?
        };
        Ok((flow, step))
    }

    /// The custody memory as the flow left it (the host persists every `mark_custody_seen` anyway).
    pub fn custody(&self) -> &CustodyMemory {
        &self.custody
    }

    pub fn on_response(&mut self, resp: HttpResponse) -> Result<FolderStep, ShareFlowError> {
        let stage = std::mem::replace(&mut self.stage, Stage::Done);
        let step = self.advance(stage, resp);
        if step.is_err() {
            self.stage = Stage::Done;
            self.keyed = None;
        }
        step
    }

    fn advance(&mut self, stage: Stage, resp: HttpResponse) -> Result<FolderStep, ShareFlowError> {
        match stage {
            Stage::EnsureRead => self.on_ensure_read(resp),
            Stage::EnsureSent => {
                require_ok(&resp)?;
                if !active_folder_invites(&resp.body, &self.folder_id)?.is_empty() {
                    return Err(ShareFlowError::FolderNeedsUpgrade);
                }
                let minted = random_folder_key()?;
                let wrapped = kdf::wrap_folder_custody(&self.master, self.folder_id.as_bytes(), &minted)
                    .map(|b| b64(&super::frame(b)))
                    .map_err(|_| ShareFlowError::Crypto)?;
                let request = HttpRequest::put(
                    format!("{}/key", custody_path(&self.folder_id)),
                    json!({ "owner_wrapped_folder_key": wrapped, "key_version": 1 }),
                    RequestAuth::Session,
                );
                self.stage = Stage::Register { minted, wrapped };
                Ok(send(request))
            }
            Stage::Register { minted, wrapped } => {
                if resp.ok() {
                    let seen = self.custody.mark(&self.folder_id)?;
                    self.keyed = Some(Keyed {
                        folder_key: minted,
                        format: FolderWrapFormat::L7,
                        custody_blob: Some(wrapped),
                    });
                    return self.start_listing(Some(seen));
                }
                drop(minted);
                if resp.status == 409 && error_code(&resp) == Some("upgrade_required") {
                    return Err(ShareFlowError::FolderNeedsUpgrade);
                }
                if error_code(&resp) != Some("key_version_conflict") {
                    return Err(ShareFlowError::from_status(&resp));
                }
                // Someone registered a key between our read and our write: theirs is the truth.
                self.stage = Stage::Reread;
                Ok(send(get(custody_path(&self.folder_id))))
            }
            Stage::Reread => {
                require_ok(&resp)?;
                match custody_blob(&resp) {
                    Some(blob) => self.open_custody(blob),
                    None => Err(ShareFlowError::Server { status: 409 }),
                }
            }
            Stage::Ancestor { depth } => {
                let next = if resp.ok() {
                    resp.body.get("parent_id").and_then(Value::as_str).map(str::to_owned)
                } else if matches!(resp.status, 403 | 404) {
                    None
                } else {
                    return Err(ShareFlowError::from_status(&resp));
                };
                match next {
                    Some(parent) => self.ancestor_walk(parent, depth + 1),
                    None => Ok(self.find_existing()),
                }
            }
            Stage::FindSent => {
                require_ok(&resp)?;
                self.active = active_folder_invites(&resp.body, &self.folder_id)?;
                if self.active.is_empty() {
                    self.keyed = Some(Keyed {
                        folder_key: random_folder_key()?,
                        format: FolderWrapFormat::LegacyInvite,
                        custody_blob: None,
                    });
                    return self.start_listing(None);
                }
                let blobs = unique_owner_blobs(&self.active);
                if blobs.is_empty() {
                    return Err(ShareFlowError::FolderKeyUnverified);
                }
                self.try_blobs(blobs, 0, None)
            }
            Stage::ProofRows { blobs, next } => {
                if !resp.ok() {
                    let not_approved = resp.status == 400
                        && resp
                            .body
                            .get("error")
                            .or_else(|| resp.body.get("message"))
                            .and_then(Value::as_str)
                            .is_some_and(|m| m.to_ascii_lowercase().contains("invite not approved"));
                    return Err(if not_approved {
                        ShareFlowError::FolderKeyUnverified
                    } else {
                        ShareFlowError::from_status(&resp)
                    });
                }
                let rows = proof_rows(&resp.body)?;
                self.try_blobs(blobs, next, Some(rows))
            }
            Stage::List {
                parent,
                mut queue,
                mut children,
            } => {
                require_ok(&resp)?;
                let files = resp
                    .body
                    .get("files")
                    .and_then(Value::as_array)
                    .ok_or(ShareFlowError::Protocol("files list"))?;
                let cursor = resp
                    .body
                    .get("next_cursor")
                    .and_then(Value::as_str)
                    .filter(|c| !c.is_empty())
                    .map(str::to_owned);
                // A pre-0739 server: a full page and no cursor may hide children. Refuse, never half-share.
                if cursor.is_none() && files.len() >= SHARE_PAGE_LIMIT {
                    return Err(ShareFlowError::FolderTooLarge);
                }
                for file in files {
                    let id = file
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or(ShareFlowError::Protocol("file id"))?;
                    // The child's id is HKDF info for its key and its wrap.
                    let id = super::canonical_item_id(id, "child id")?.to_owned();
                    let is_folder = file.get("is_folder").and_then(Value::as_bool).unwrap_or(false);
                    if is_folder {
                        queue.push_back(id.clone());
                    }
                    children.push(Child { id, is_folder });
                    if children.len() > FILE_LIST_HARD_CAP {
                        return Err(ShareFlowError::FolderTooLarge);
                    }
                }
                let next_parent = match cursor {
                    Some(c) => Some((parent, Some(c))),
                    None => queue.pop_front().map(|p| (p, None)),
                };
                match next_parent {
                    Some((parent, cursor)) => {
                        let request = list_request(&parent, cursor.as_deref())?;
                        self.stage = Stage::List {
                            parent,
                            queue,
                            children,
                        };
                        Ok(send(request))
                    }
                    None => self.finish(children),
                }
            }
            Stage::AwaitInvite => {
                require_ok(&resp)?;
                let invite_id = path_id(str_field(&resp, "invite_id")?)?.to_owned();
                let status = str_field(&resp, "status")?.to_owned();
                let keyed = self.keyed.take().ok_or(ShareFlowError::WrongState)?;
                let key = resp.body.get("recipient_public_key").and_then(Value::as_str);
                match key {
                    Some(key) if status == "claimed" => {
                        match approve_request(&invite_id, &self.folder_id, key, &self.master, &keyed.folder_key) {
                            Ok(req) => {
                                self.stage = Stage::AwaitApprove { invite_id };
                                Ok(send(req))
                            }
                            Err(_) => Ok(FolderStep::Done(InviteOutcome::AwaitingApproval { invite_id })),
                        }
                    }
                    _ => Ok(FolderStep::Done(InviteOutcome::Invited { invite_id, status })),
                }
            }
            Stage::AwaitLink { id, attempt } => self.on_link_response(resp, id, attempt),
            Stage::AwaitApprove { invite_id } => Ok(FolderStep::Done(if resp.ok() {
                InviteOutcome::Shared { invite_id }
            } else {
                InviteOutcome::AwaitingApproval { invite_id }
            })),
            Stage::Done => Err(ShareFlowError::WrongState),
        }
    }

    /// Web `ensureOwnerFolderKey`, read leg: a 404 (or `not_found`) or an empty record is "none".
    fn on_ensure_read(&mut self, resp: HttpResponse) -> Result<FolderStep, ShareFlowError> {
        if resp.ok() {
            if let Some(blob) = custody_blob(&resp) {
                return self.open_custody(blob);
            }
        } else if !(resp.status == 404 || error_code(&resp) == Some("not_found")) {
            return Err(ShareFlowError::from_status(&resp));
        }
        // L7c: a folder seen with custody before is never re-seeded because the server says "none".
        if self.custody.has_seen(&self.folder_id) {
            return Err(ShareFlowError::FolderKeysUnavailable);
        }
        self.stage = Stage::EnsureSent;
        Ok(send(get(SENT_PATH.to_owned())))
    }

    fn open_custody(&mut self, blob: String) -> Result<FolderStep, ShareFlowError> {
        let bytes = b64_decode(&blob)?;
        if bytes.len() != super::WRAPPED_KEY_LEN {
            return Err(ShareFlowError::Crypto);
        }
        let key = kdf::unwrap_folder_custody(&self.master, self.folder_id.as_bytes(), &split(&bytes)?)
            .map_err(|_| ShareFlowError::Crypto)?;
        let seen = self.custody.mark(&self.folder_id)?;
        self.keyed = Some(Keyed {
            folder_key: key,
            format: FolderWrapFormat::L7,
            custody_blob: Some(blob),
        });
        self.start_listing(Some(seen))
    }

    /// Web `assertNoSeenAncestor` (flag off): legacy only when neither the folder nor an ancestor
    /// was ever seen with custody. A 403/404 parent read ends the walk; any other failure aborts.
    fn ancestor_walk(&mut self, cursor: String, depth: usize) -> Result<FolderStep, ShareFlowError> {
        if !self.custody.has_any() {
            return Ok(self.find_existing());
        }
        if depth >= MAX_ANCESTOR_WALK || self.custody.has_seen(&cursor) {
            return Err(ShareFlowError::FolderKeysUnavailable);
        }
        let id = path_id(&cursor)?.to_owned();
        self.stage = Stage::Ancestor { depth };
        Ok(send(get(format!("/api/v1/files/{id}"))))
    }

    fn find_existing(&mut self) -> FolderStep {
        self.stage = Stage::FindSent;
        send(get(SENT_PATH.to_owned()))
    }

    /// Web `findExistingFolderKey`: the newest blob that opens wins. The folder's rows are fetched
    /// once, through the newest approved invite, and only when a legacy blob needs the proof.
    fn try_blobs(
        &mut self,
        blobs: Vec<String>,
        mut next: usize,
        rows: Option<super::folder_keys::ProofRows>,
    ) -> Result<FolderStep, ShareFlowError> {
        while next < blobs.len() {
            let bytes = b64_decode(&blobs[next])?;
            let key = match open_owner_copy(&self.master, &self.folder_id, &bytes)? {
                OwnerCopyOpen::Opened(key) => Some(key),
                OwnerCopyOpen::AuthFailed => match &rows {
                    Some(rows) => kdf::open_legacy_invite_owner_copy(
                        &self.master,
                        self.folder_id.as_bytes(),
                        &bytes,
                        rows.iter().map(|(f, w)| (f.as_slice(), w.as_slice())),
                    ),
                    None => {
                        let approved = self
                            .active
                            .iter()
                            .find(|i| i.status == "approved")
                            .ok_or(ShareFlowError::FolderKeyUnverified)?;
                        let id = path_id(&approved.id)?.to_owned();
                        self.stage = Stage::ProofRows { blobs, next };
                        return Ok(send(get(format!("{INVITES_PATH}/{id}/folder-keys"))));
                    }
                },
            };
            if let Some(folder_key) = key {
                self.keyed = Some(Keyed {
                    folder_key,
                    format: FolderWrapFormat::LegacyInvite,
                    custody_blob: None,
                });
                return self.start_listing(None);
            }
            next += 1;
        }
        Err(ShareFlowError::FolderKeyUnverified)
    }

    fn start_listing(&mut self, mark: Option<String>) -> Result<FolderStep, ShareFlowError> {
        let request = list_request(&self.folder_id, None)?;
        self.stage = Stage::List {
            parent: self.folder_id.clone(),
            queue: VecDeque::new(),
            children: Vec::new(),
        };
        Ok(FolderStep::Send(FolderSend {
            request,
            mark_custody_seen: mark,
        }))
    }

    /// Web `buildFolderInvite` + `createInvite` (or `createFolderLinkWithKeys`): every child
    /// wrapped, the root's own name key for an L7 folder, then the invite or the link.
    fn finish(&mut self, children: Vec<Child>) -> Result<FolderStep, ShareFlowError> {
        let keyed = self.keyed.as_ref().ok_or(ShareFlowError::WrongState)?;
        let mut folder_keys = Vec::with_capacity(children.len() + 1);
        if keyed.format == FolderWrapFormat::L7 {
            let root_name_key = kdf::derive_file_key(&self.master, self.folder_id.as_bytes());
            let wrap = seal_folder_child(
                keyed.format,
                &keyed.folder_key,
                &self.folder_id,
                &self.folder_id,
                true,
                &root_name_key,
            )?;
            folder_keys.push(json!({ "file_id": self.folder_id, "encrypted_file_key": wrap }));
        }
        for child in &children {
            let child_key = kdf::derive_file_key(&self.master, child.id.as_bytes());
            let wrap = seal_folder_child(
                keyed.format,
                &keyed.folder_key,
                &self.folder_id,
                &child.id,
                child.is_folder,
                &child_key,
            )?;
            folder_keys.push(json!({ "file_id": child.id, "encrypted_file_key": wrap }));
        }
        let email = match &self.purpose {
            Purpose::Invite { email } => email.clone(),
            Purpose::Link(_) => return self.link_request(folder_keys),
        };
        // The owner copy: the custody record, else a fresh purpose-bound copy (2255).
        let owner = match &keyed.custody_blob {
            Some(blob) => blob.clone(),
            None => owner_copy_b64(&self.master, &self.folder_id, &keyed.folder_key)?,
        };
        let mut body = json!({
            "file_id": self.folder_id,
            "recipient_email": email,
            "is_folder_share": true,
            "encrypted_folder_key": "",
            "encrypted_owner_folder_key": owner,
            "folder_keys": folder_keys,
            "folder_key_id": folder_key_id_b64(&keyed.folder_key),
        });
        if keyed.format == FolderWrapFormat::L7 {
            body["format"] = json!("l7");
        }
        self.stage = Stage::AwaitInvite;
        Ok(send(HttpRequest::post(INVITES_PATH, body, RequestAuth::Session)))
    }
}

fn custody_blob(resp: &HttpResponse) -> Option<String> {
    resp.body
        .get("owner_wrapped_folder_key")
        .and_then(Value::as_str)
        .filter(|b| !b.is_empty())
        .map(str::to_owned)
}

fn list_request(parent: &str, cursor: Option<&str>) -> Result<HttpRequest, ShareFlowError> {
    let parent = path_id(parent)?;
    let mut path = format!("/api/v1/files?parent_id={parent}&limit={SHARE_PAGE_LIMIT}");
    if let Some(cursor) = cursor {
        path.push_str("&cursor=");
        path.push_str(&url_encode(cursor));
    }
    Ok(get(path))
}

/// `URLSearchParams` encoding of a cursor (an opaque server string).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
