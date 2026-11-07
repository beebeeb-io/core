use beebeeb_api::routes::{file_requests, folder_links, invites, shares};

use crate::{Client, ClientError};
use zeroize::Zeroizing;

pub const DEFAULT_LINK_EXPIRY_HOURS: i64 = 30 * 24;

#[derive(Debug, thiserror::Error)]
pub enum ShareServiceError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Store(#[from] beebeeb_store::StoreError),
    #[error("the contact key changed; confirm the new identity before sharing")]
    ContactKeyChanged,
}

impl Client {
    pub async fn create_share_link(
        &self,
        file_id: &str,
        wrapped_file_key: &str,
        expires_in_hours: Option<i64>,
        passphrase: Option<String>,
    ) -> Result<shares::Share, ClientError> {
        self.execute(
            &shares::create_link(),
            &shares::CreateLink {
                file_id: file_id.to_string(),
                share_type: "file".into(),
                wrapped_file_key: wrapped_file_key.to_string(),
                expires_in_hours: Some(expires_in_hours.unwrap_or(DEFAULT_LINK_EXPIRY_HOURS)),
                max_opens: None,
                passphrase: passphrase.map(Zeroizing::new),
                token: None,
                owner_wrapped_key: None,
                owner_wrapped_token: None,
            },
        )
        .await
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

    pub async fn create_invite(&self, request: invites::Create) -> Result<invites::Invite, ClientError> {
        self.execute(&invites::create(), &request).await
    }

    pub async fn create_trusted_invite(
        &self,
        store: &mut beebeeb_store::Store,
        request: invites::Create,
        contact_id: &str,
        presented_public_key: &[u8],
        observed_at: i64,
    ) -> Result<invites::Invite, ShareServiceError> {
        let trust = crate::contacts::observe_contact_key(store, contact_id, presented_public_key, observed_at)?;
        if trust == crate::contacts::ContactTrust::KeyChanged {
            return Err(ShareServiceError::ContactKeyChanged);
        }
        self.create_invite(request).await.map_err(Into::into)
    }

    pub async fn approve_invite(&self, id: &str, encrypted_file_key: String) -> Result<(), ClientError> {
        self.execute(&invites::approve(id), &invites::Approve { encrypted_file_key })
            .await
            .map(|_| ())
    }

    pub async fn deny_invite(&self, id: &str) -> Result<(), ClientError> {
        self.execute(&invites::deny(id), &()).await.map(|_| ())
    }

    pub async fn create_folder_link(
        &self,
        mut request: folder_links::Create,
    ) -> Result<folder_links::Link, ClientError> {
        request.expires_in_hours.get_or_insert(DEFAULT_LINK_EXPIRY_HOURS);
        self.execute(&folder_links::create(), &request).await
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

pub use beebeeb_core::{file_request, share_link, share_token};
