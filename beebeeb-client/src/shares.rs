//! The account's shares: links to a file or a folder, person shares of a file, file requests, and
//! the lists and revocations around them. Links and person shares are made by core's sans-IO
//! `share_flow`, sent over this client's transport as the flow built them, so a native app and the
//! web send the same bodies; this module adds the account's session and the key of the item.

use beebeeb_api::routes::{file_requests, folder_links, invites, shares};
use beebeeb_core::{
    item_id::{ItemClass, item_class},
    kdf::{FileKey, MasterKey, derive_file_key},
    share_flow::{
        ShareFlowError,
        folder::{CreatedFolderLink, FolderLinkInput, FolderSend, FolderShare, FolderStep},
        link::{CreateLink, CreatedLink, LinkOptions, LinkStep},
        member::{self, InviteOutcome, InviteStep, MemberInvite, PeerKeyExpectation, SealedApproval, ShareTarget},
        safety::key_fingerprint,
    },
};

use crate::{Client, ClientError};

/// The expiry a file request gets when its caller sets none. A link has no default: one created
/// without `expires_in_hours` does not expire.
pub const DEFAULT_LINK_EXPIRY_HOURS: i64 = 30 * 24;

#[derive(Debug, thiserror::Error)]
pub enum ShareServiceError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Store(#[from] beebeeb_store::StoreError),
    /// Core's share flow stopped; `code()` is the stable string an app maps to its words.
    #[error(transparent)]
    Flow(#[from] ShareFlowError),
    #[error("the contact key changed; confirm the new identity before sharing")]
    ContactKeyChanged,
    /// A foreign item's key comes from its owner envelope or a folder wrap, which this service does
    /// not hold. It is never derived, so the item is not shared from here.
    #[error("the key of this item is not available to share it")]
    KeyUnavailable,
    /// The app could not record that it saw a folder's custody record, so the request that would use
    /// the folder's key was not sent.
    #[error("the folder's custody could not be recorded on this device")]
    CustodyNotRecorded,
}

impl Client {
    /// A public link to one of the account's files (core `share_flow::link`). A random link key
    /// `K_c` wraps the file key; the token and `K_c` are also wrapped under the account key, so the
    /// owner can copy the link again later (`share_flow::link::rebuild_link`). `app_url` is the web
    /// origin the link opens. A link without `options.expires_in_hours` does not expire. The
    /// returned `link` carries `K_c` after `#key=`: copy it, show `share_flow::display_form` of it.
    pub async fn create_share_link(
        &self,
        app_url: &str,
        file_id: &str,
        options: &LinkOptions,
    ) -> Result<CreatedLink, ShareServiceError> {
        let session_key = self.session_key()?;
        let (mut flow, mut request) = {
            let file_key = owned_file_key(session_key.master_key(), file_id)?;
            CreateLink::start(app_url, file_id, session_key.master_key(), &file_key, options)?
        };
        loop {
            let response = self.execute_share_flow(request, session_key.generation()).await?;
            match flow.on_response(response)? {
                LinkStep::Send(next) => request = next,
                LinkStep::Created(created) => return Ok(created),
            }
        }
    }

    pub async fn my_share_links(&self) -> Result<shares::List, ClientError> {
        self.execute(&shares::mine(), &()).await
    }

    pub async fn revoke_share_link(&self, id: &str) -> Result<(), ClientError> {
        self.execute(&shares::revoke(id), &()).await.map(|_| ())
    }

    pub async fn incoming_invites(&self) -> Result<invites::List, ClientError> {
        self.execute(&invites::incoming(), &()).await
    }

    pub async fn sent_invites(&self) -> Result<invites::List, ClientError> {
        self.execute(&invites::sent(), &()).await
    }

    /// A person share of one of the account's files (core `share_flow::member`). The invite names
    /// the recipient by `email`; when the server answers that the recipient already has a key, the
    /// file key is sealed for that key and the invite approved (`Shared`). `peer_key` is required:
    /// with `Compared(fingerprint)` (`share_flow::safety::key_fingerprint`) a server key with another
    /// fingerprint has nothing sealed for it, and the outcome is `PeerKeyChanged`.
    pub async fn create_invite(
        &self,
        file_id: &str,
        email: &str,
        peer_key: PeerKeyExpectation,
    ) -> Result<InviteOutcome, ShareServiceError> {
        let session_key = self.session_key()?;
        let (mut flow, mut request) = {
            let file_key = owned_file_key(session_key.master_key(), file_id)?;
            let target = ShareTarget {
                item_id: file_id.to_owned(),
                is_folder: false,
            };
            MemberInvite::start(&target, email, session_key.master_key(), &file_key, peer_key)?
        };
        loop {
            let response = self.execute_share_flow(request, session_key.generation()).await?;
            match flow.on_response(response)? {
                InviteStep::Send(next) => request = next,
                InviteStep::Done(outcome) => return Ok(outcome),
            }
        }
    }

    /// [`Self::create_invite`] to a contact whose key this device remembers (`contacts`). A key that
    /// differs from the remembered one is refused before anything is sent
    /// ([`ShareServiceError::ContactKeyChanged`]); a first key is remembered. The file key is then
    /// sealed only for `presented_public_key`: when the server answers with another key for `email`,
    /// nothing is sealed and the outcome is `PeerKeyChanged`.
    pub async fn create_trusted_invite(
        &self,
        store: &mut beebeeb_store::Store,
        file_id: &str,
        email: &str,
        contact_id: &str,
        presented_public_key: &[u8],
        observed_at: i64,
    ) -> Result<InviteOutcome, ShareServiceError> {
        let fingerprint = key_fingerprint(presented_public_key)?;
        let trust = crate::contacts::observe_contact_key(store, contact_id, presented_public_key, observed_at)?;
        if trust == crate::contacts::ContactTrust::KeyChanged {
            return Err(ShareServiceError::ContactKeyChanged);
        }
        self.create_invite(file_id, email, PeerKeyExpectation::Compared(fingerprint))
            .await
    }

    /// Approve a person share its recipient claimed after it was made
    /// (core `share_flow::member::approve_request`): the file key is sealed for
    /// `recipient_public_key_b64`, the key the server lists with the claim. `peer_key` as for
    /// [`Self::create_invite`]; a key it does not match is `ShareFlowError::PeerKeyChanged`, with
    /// nothing sealed. Returns the key the file key was sealed for.
    pub async fn approve_invite(
        &self,
        invite_id: &str,
        file_id: &str,
        recipient_public_key_b64: &str,
        peer_key: PeerKeyExpectation,
    ) -> Result<[u8; 32], ShareServiceError> {
        let session_key = self.session_key()?;
        let SealedApproval {
            request,
            recipient_public_key,
        } = {
            let file_key = owned_file_key(session_key.master_key(), file_id)?;
            member::approve_request(
                invite_id,
                file_id,
                recipient_public_key_b64,
                session_key.master_key(),
                &file_key,
                peer_key,
            )?
        };
        let response = self.execute_share_flow(request, session_key.generation()).await?;
        if !response.ok() {
            return Err(ShareFlowError::from_status(&response).into());
        }
        Ok(recipient_public_key)
    }

    pub async fn deny_invite(&self, id: &str) -> Result<(), ClientError> {
        self.execute(&invites::deny(id), &()).await.map(|_| ())
    }

    /// A live folder link (core `share_flow::folder::FolderShare::link`): the folder key from its
    /// custody record (minted and registered when the folder has none and no active invite), every
    /// descendant's key wrapped under it, and the link's owner copies sealed under the share id the
    /// flow proposes. `input.custody` is this device's custody memory. `record_custody_seen` gets
    /// every folder the flow sees with a custody record BEFORE the request that uses its key is sent:
    /// persist the id durably there, or return an error (such as
    /// [`ShareServiceError::CustodyNotRecorded`]) to stop with that request unsent. The returned
    /// `link` carries the link key after `#key=`.
    pub async fn create_folder_link(
        &self,
        input: FolderLinkInput<'_>,
        mut record_custody_seen: impl FnMut(&str) -> Result<(), ShareServiceError>,
    ) -> Result<CreatedFolderLink, ShareServiceError> {
        let session_key = self.session_key()?;
        let (mut flow, mut step) = FolderShare::link(input, session_key.master_key())?;
        loop {
            match step {
                FolderStep::Send(FolderSend {
                    request,
                    mark_custody_seen,
                }) => {
                    if let Some(folder_id) = mark_custody_seen {
                        record_custody_seen(&folder_id)?;
                    }
                    let response = self.execute_share_flow(request, session_key.generation()).await?;
                    step = flow.on_response(response)?;
                }
                FolderStep::LinkCreated(created) => return Ok(created),
                // A link flow never ends in an invite's outcome.
                FolderStep::Done(_) => return Err(ShareFlowError::WrongState.into()),
            }
        }
    }

    pub async fn folder_links(&self, folder_id: Option<&str>) -> Result<folder_links::List, ClientError> {
        self.execute(&folder_links::list(folder_id), &()).await
    }

    pub async fn revoke_folder_link(&self, id: &str) -> Result<(), ClientError> {
        self.execute(&folder_links::revoke(id), &()).await.map(|_| ())
    }

    pub async fn create_file_request(
        &self,
        mut request: file_requests::Create,
    ) -> Result<file_requests::Created, ClientError> {
        request
            .expires_in_secs
            .get_or_insert(DEFAULT_LINK_EXPIRY_HOURS.saturating_mul(3600));
        self.execute(&file_requests::create(), &request).await
    }

    pub async fn file_requests(&self) -> Result<file_requests::List, ClientError> {
        self.execute(&file_requests::list(), &()).await
    }

    pub async fn close_file_request(&self, id: &str) -> Result<file_requests::FileRequest, ClientError> {
        self.execute(&file_requests::close(id), &()).await
    }
}

/// The key that opens one of the account's own files (web's `shareFileKey`). An owner id's key is
/// derived from the account key. A foreign (`F`) id's key comes from its owner envelope or a folder
/// wrap and is never derived (core's item-id rule), so it is refused.
fn owned_file_key(master: &MasterKey, file_id: &str) -> Result<FileKey, ShareServiceError> {
    match item_class(file_id) {
        Ok(ItemClass::Owner) => Ok(derive_file_key(master, file_id.as_bytes())),
        Ok(ItemClass::Foreign) => Err(ShareServiceError::KeyUnavailable),
        Err(_) => Err(ShareFlowError::InvalidInput("item id").into()),
    }
}

pub use beebeeb_core::{file_request, share_flow, share_link, share_token};
