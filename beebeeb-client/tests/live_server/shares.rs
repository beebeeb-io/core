//! Links and person shares made by the client's share calls (core's share flow builds every body),
//! as the server stores and serves them.

use beebeeb_client::shares::share_flow::{
    link::{LinkOptions, open_link_file_key, rebuild_link},
    member::InviteOutcome,
    open_member_file_key,
};
use beebeeb_core::share_link;

use super::*;

/// The web origin the links point at. The server never reads it; an owner rebuilds a link for the
/// origin it was made for.
const LIVE_APP_URL: &str = "https://app.beebeeb.test";

/// The public answer for a link's token, as a recipient's browser reads it.
async fn public_share(api_url: &str, token: &str) -> TestResult<Value> {
    let response = reqwest::Client::new()
        .get(format!("{api_url}/api/v1/shares/{token}"))
        .header("X-Beebeeb-Client", "desktop")
        .header("X-Beebeeb-Client-Version", env!("CARGO_PKG_VERSION"))
        .send()
        .await?
        .error_for_status()?;
    Ok(serde_json::from_slice(&response.bytes().await?)?)
}

fn now_secs() -> TestResult<i64> {
    Ok(i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?)
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn new_account_has_no_share_links() -> TestResult {
    let account = provision_account().await?;
    assert!(account.client.my_share_links().await?.shares.is_empty());
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn share_create_public_download_and_revoke() -> TestResult {
    let account = provision_account().await?;
    let root = tempfile::tempdir()?;
    let file_id = drive_upload(&account, &root, b"public-share-live", 32 * 1024 * 1024, false).await?;
    let in_an_hour = LinkOptions {
        expires_in_hours: Some(1),
        ..LinkOptions::default()
    };
    let created = account
        .client
        .create_share_link(LIVE_APP_URL, &file_id, &in_an_hour)
        .await
        .map_err(|error| format!("share creation failed: {error}"))?;
    let token = share_link::parse(&created.link)?.token;
    let entry = account.client.get_file(&file_id).await?;
    let versions = account.client.file_versions(&file_id).await?;
    let version = versions
        .versions
        .iter()
        .find(|version| version.version_number == versions.current_version)
        .ok_or("share source omitted its current version")?;
    let name_encrypted = entry
        .name_encrypted
        .as_deref()
        .ok_or("share source omitted encrypted metadata")?;
    let metadata = beebeeb_core::encrypt::decrypt_file_metadata(&account.master_key, &file_id, name_encrypted)?;
    let file_key = derive_file_key(&account.master_key, file_id.as_bytes());
    let plan = beebeeb_types::plan_chunks(entry.size_bytes, ChunkProfile::Mobile);
    let (anonymous, _) = live_client(&account.api_url)?;
    let anonymous = Arc::new(anonymous);
    let downloads = DownloadService::new(
        anonymous,
        Arc::new(Mutex::new(Store::open_in_memory()?)),
        root.path().join("anonymous-cache"),
        64 * 1024 * 1024,
        MemoryBudget::NATIVE,
    )?;
    let public_root = root.path().join("public");
    std::fs::create_dir(&public_root)?;
    let public_directory = beebeeb_core::path_safety::TrustedDirectory::open(&public_root)?;
    let result = downloads
        .share_view_download(
            &token,
            None,
            &file_id,
            &file_key,
            &metadata,
            version.chunk_count,
            entry.size_bytes,
            plan.chunk_size_bytes,
            &public_directory,
            "shared.bin",
        )
        .await
        .map_err(|error| format!("public share download failed before revoke: {error}"))?;
    assert_eq!(result, DownloadResult::Saved);
    assert_eq!(std::fs::read(public_root.join("shared.bin"))?, b"public-share-live");
    account
        .client
        .revoke_share_link(&created.share_id)
        .await
        .map_err(|error| format!("share revoke failed: {error}"))?;
    assert!(
        downloads
            .share_view_download(
                &token,
                None,
                &file_id,
                &file_key,
                &metadata,
                version.chunk_count,
                entry.size_bytes,
                plan.chunk_size_bytes,
                &public_directory,
                "revoked.bin",
            )
            .await
            .is_err(),
        "revoked share remained publicly downloadable"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn a_link_the_client_creates_is_rebuilt_by_its_owner() -> TestResult {
    let account = provision_account().await?;
    let root = tempfile::tempdir()?;
    let file_id = drive_upload(&account, &root, b"owner-rebuild-live", 32 * 1024 * 1024, false).await?;
    let created = account
        .client
        .create_share_link(LIVE_APP_URL, &file_id, &LinkOptions::default())
        .await
        .map_err(|error| format!("share creation failed: {error}"))?;

    // The owner's listing holds the copies the create body carried, and no expiry was asked for.
    let listing = account.client.my_share_links().await?;
    let stored = listing
        .shares
        .iter()
        .find(|share| share.id == created.share_id)
        .ok_or("the owner's listing omitted the new link")?;
    assert_eq!(stored.expires_at, None, "a link created without an expiry got one");
    let owner_copy = |field: &str| stored.extra.get(field).and_then(Value::as_str);
    let (owner_wrapped_key, owner_wrapped_token) = (owner_copy("owner_wrapped_key"), owner_copy("owner_wrapped_token"));
    assert!(
        owner_wrapped_key.is_some() && owner_wrapped_token.is_some(),
        "the server did not store the link's owner copies"
    );
    // The listing does not carry the stored `wrapped_file_key`; the public answer does.
    let link = share_link::parse(&created.link)?;
    let public = public_share(&account.api_url, &link.token).await?;
    let wrapped_file_key = public["wrapped_file_key"]
        .as_str()
        .ok_or("the public answer omitted wrapped_file_key")?;

    let rebuilt = rebuild_link(
        LIVE_APP_URL,
        &account.master_key,
        owner_wrapped_key,
        owner_wrapped_token,
        wrapped_file_key,
    )
    .ok_or("the owner could not rebuild the link from its stored copies")?;
    assert_eq!(*rebuilt, *created.link, "the rebuilt link differs from the created one");
    let opened = open_link_file_key(&link.key, wrapped_file_key)?;
    assert_eq!(
        opened.as_bytes(),
        derive_file_key(&account.master_key, file_id.as_bytes()).as_bytes(),
        "the link's key does not open the file"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn a_trusted_invite_is_created_approved_and_opened_by_its_recipient() -> TestResult {
    let owner = provision_account().await?;
    let recipient = provision_account().await?;
    let root = tempfile::tempdir()?;
    let file_id = drive_upload(&owner, &root, b"trusted-invite-live", 32 * 1024 * 1024, false).await?;
    let contact_id = recipient.client.account_id()?;
    let presented = owner.client.fetch_contact_public_key(&contact_id).await?;
    let mut contacts = Store::open_in_memory()?;

    let outcome = owner
        .client
        .create_trusted_invite(
            &mut contacts,
            &file_id,
            &recipient.email,
            &contact_id,
            &presented,
            now_secs()?,
        )
        .await
        .map_err(|error| format!("trusted invite failed: {error}"))?;
    let InviteOutcome::Shared {
        invite_id,
        recipient_public_key,
    } = outcome
    else {
        return Err(format!("the invite was not shared: {outcome:?}").into());
    };
    assert_eq!(
        recipient_public_key.as_slice(),
        presented.as_slice(),
        "the file key was sealed for another key"
    );

    // The recipient opens the file key the approval carried, with the owner's public key.
    let incoming = recipient.client.incoming_invites().await?;
    let invite = incoming
        .invites
        .iter()
        .find(|invite| invite.id == invite_id)
        .ok_or("the recipient's inbox omitted the invite")?;
    assert_eq!(invite.status, "approved");
    let field = |name: &str| -> TestResult<Vec<u8>> {
        let value = invite.extra.get(name).and_then(Value::as_str).ok_or(name.to_owned())?;
        Ok(STANDARD.decode(value)?)
    };
    let sender_public_key: [u8; 32] = field("sender_public_key")?
        .try_into()
        .map_err(|_| "the sender key is not 32 bytes")?;
    let opened = open_member_file_key(
        &recipient.master_key,
        &sender_public_key,
        &file_id,
        &field("encrypted_file_key")?,
    )?;
    assert_eq!(
        opened.as_bytes(),
        derive_file_key(&owner.master_key, file_id.as_bytes()).as_bytes(),
        "the recipient's file key does not open the file"
    );
    Ok(())
}
