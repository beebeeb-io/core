use beebeeb_client::shares::ShareServiceError;
use beebeeb_core::share_flow::{ShareFlowError, display_form, link::LinkOptions};

use super::*;
use crate::SecretString;

/// A link the server stored. `link` carries the link key after `#key=`: copy it, show `display`.
/// `display` still names the link's token, so it is a secret too: wiped, and never printed.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CreatedLinkData {
    pub share_id: String,
    pub link: SecretString,
    pub display: SecretString,
}

#[derive(uniffi::Object)]
pub struct ShareServiceHandle {
    pub(super) root: Arc<NativeClientHandle>,
}

#[uniffi::export]
impl ShareServiceHandle {
    /// A public link to one of the account's files, made by core's share flow: the owner can copy
    /// it again later, and it does not expire without `expires_in_hours`. `app_url` is the web
    /// origin the link opens. A foreign item id is `invalid_input`: its key comes from an owner
    /// envelope, which this service does not hold.
    pub fn create_link(
        &self,
        app_url: String,
        file_id: String,
        expires_in_hours: Option<u32>,
        max_opens: Option<u32>,
        passphrase: Option<SecretString>,
    ) -> Result<CreatedLinkData, ServiceError> {
        let options = LinkOptions {
            expires_in_hours,
            max_opens,
            passphrase: passphrase.map(SecretString::into_zeroizing),
        };
        let mut created = self
            .root
            .runtime
            .block_on(self.root.client.create_share_link(&app_url, &file_id, &options))
            .map_err(map_share_error)?;
        Ok(CreatedLinkData {
            display: SecretString::from(display_form(&created.link)),
            link: SecretString::from(std::mem::take(&mut *created.link)),
            share_id: created.share_id,
        })
    }

    pub fn revoke_folder_link(&self, id: String) -> Result<(), ServiceError> {
        self.root
            .runtime
            .block_on(self.root.client.revoke_folder_link(&id))
            .map_err(map_client_error)
    }
}

/// A share failure as the service error an app shows: a refusal keeps core's code.
fn map_share_error(error: ShareServiceError) -> ServiceError {
    match error {
        ShareServiceError::Client(error) => map_client_error(error),
        ShareServiceError::Flow(error) => match error {
            ShareFlowError::InvalidInput(_) | ShareFlowError::NotFound => ServiceError::InvalidInput,
            ShareFlowError::Unauthorized => ServiceError::Authentication,
            ShareFlowError::RateLimited { retry_after_secs } => ServiceError::RetryAfter {
                seconds: retry_after_secs,
            },
            ShareFlowError::Crypto => ServiceError::Crypto,
            ShareFlowError::Forbidden { code } => ServiceError::ShareRefused { code },
            ShareFlowError::Refused(_)
            | ShareFlowError::PeerKeyChanged
            | ShareFlowError::FolderKeysUnavailable
            | ShareFlowError::FolderKeyUnverified
            | ShareFlowError::FolderNeedsUpgrade
            | ShareFlowError::FolderTooLarge => ServiceError::ShareRefused {
                code: error.code().to_owned(),
            },
            ShareFlowError::Server { .. } | ShareFlowError::Protocol(_) | ShareFlowError::WrongState => {
                ServiceError::Unavailable
            }
        },
        ShareServiceError::KeyUnavailable => ServiceError::InvalidInput,
        ShareServiceError::ContactKeyChanged => ServiceError::ShareRefused {
            code: "peer_key_changed".to_owned(),
        },
        ShareServiceError::Store(_) | ShareServiceError::CustodyNotRecorded => ServiceError::Storage,
    }
}

#[derive(uniffi::Object)]
pub struct ContactServiceHandle {
    pub(super) root: Arc<NativeClientHandle>,
    pub(super) store: Arc<StoreHandle>,
}

#[uniffi::export]
impl ContactServiceHandle {
    pub fn observe(&self, contact_id: String, observed_at: i64) -> Result<String, ServiceError> {
        let public_key = self
            .root
            .runtime
            .block_on(self.root.client.fetch_contact_public_key(&contact_id))
            .map_err(map_client_error)?;
        let mut store = self.store.store.lock().map_err(|_| ServiceError::unavailable())?;
        let trust = beebeeb_client::contacts::observe_contact_key(&mut store, &contact_id, &public_key, observed_at)
            .map_err(map_client_error)?;
        Ok(match trust {
            ContactTrust::FirstUse => "first_use",
            ContactTrust::Trusted => "trusted",
            ContactTrust::KeyChanged => "key_changed",
        }
        .into())
    }

    pub fn accept(&self, contact_id: String, observed_at: i64) -> Result<(), ServiceError> {
        let public_key = self
            .root
            .runtime
            .block_on(self.root.client.fetch_contact_public_key(&contact_id))
            .map_err(map_client_error)?;
        let mut store = self.store.store.lock().map_err(|_| ServiceError::unavailable())?;
        beebeeb_client::contacts::accept_contact_key(&mut store, &contact_id, &public_key, observed_at)
            .map_err(map_client_error)
    }
}

#[cfg(test)]
mod share_error_tests {
    use super::*;
    use beebeeb_api::ApiError;
    use beebeeb_client::ClientError;
    use beebeeb_core::api_error::ServerError;

    #[test]
    fn share_failures_keep_their_codes_and_typed_cases() {
        assert!(matches!(
            map_share_error(ShareFlowError::Refused("plan_required").into()),
            ServiceError::ShareRefused { code } if code == "plan_required"
        ));
        assert!(matches!(
            map_share_error(ShareFlowError::FolderNeedsUpgrade.into()),
            ServiceError::ShareRefused { code } if code == "folder_needs_upgrade"
        ));
        assert!(matches!(
            map_share_error(ShareFlowError::RateLimited { retry_after_secs: 17 }.into()),
            ServiceError::RetryAfter { seconds: 17 }
        ));
        assert!(matches!(
            map_share_error(ShareServiceError::KeyUnavailable),
            ServiceError::InvalidInput
        ));
        let expired = ClientError::Api(ApiError::Server(ServerError::parse_body(
            401,
            r#"{"error":"session_expired"}"#,
        )));
        assert!(matches!(map_share_error(expired.into()), ServiceError::SessionExpired));
    }

    /// The share-create gates' 403s (`sharing_paused`, `email_unverified`, the account-frozen one
    /// without a code), in the server's bodies: a refusal with the server's code, never the
    /// wrong-password `Authentication`.
    #[test]
    fn a_403_is_a_refusal_with_the_servers_code() {
        use beebeeb_core::auth_flow::HttpResponse;
        let refused = |body: serde_json::Value| {
            map_share_error(ShareFlowError::from_status(&HttpResponse::new(403, body)).into())
        };
        assert!(matches!(
            refused(serde_json::json!({
                "error": "sharing_paused",
                "message": "Sharing is paused on this account while we review it. Your files are unaffected.",
            })),
            ServiceError::ShareRefused { code } if code == "sharing_paused"
        ));
        assert!(matches!(
            refused(serde_json::json!({
                "error": "email_unverified",
                "message": "Verify your email address to upload, share, or receive files. Check your inbox or request a new link.",
            })),
            ServiceError::ShareRefused { code } if code == "email_unverified"
        ));
        assert!(matches!(
            refused(serde_json::json!({
                "error": "Your account is frozen. Unfreeze it in Settings → Privacy to resume.",
            })),
            ServiceError::ShareRefused { code } if code == "forbidden"
        ));
    }

    #[test]
    fn a_created_link_never_prints_its_key_or_token() {
        let link = "https://app.beebeeb.test/s/link-token-secret#key=link-key-secret".to_owned();
        let created = CreatedLinkData {
            share_id: "8d2f0000-0000-4000-8000-000000000001".into(),
            display: SecretString::from(display_form(&link)),
            link: SecretString::from(link),
        };
        let printed = format!("{created:?}");
        assert!(printed.contains("8d2f0000-0000-4000-8000-000000000001"), "{printed}");
        assert!(!printed.contains("link-key-secret"), "{printed}");
        assert!(!printed.contains("link-token-secret"), "{printed}");
    }
}
