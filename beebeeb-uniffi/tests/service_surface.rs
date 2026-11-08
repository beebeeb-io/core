use beebeeb_uniffi::{RuntimeProfile, ServiceErrorKind};

fn services_source() -> String {
    [
        include_str!("../src/services.rs"),
        include_str!("../src/services/auth.rs"),
        include_str!("../src/services/client.rs"),
        include_str!("../src/services/files.rs"),
        include_str!("../src/services/settings.rs"),
        include_str!("../src/services/sharing.rs"),
        include_str!("../src/services/transfers.rs"),
    ]
    .concat()
}

#[test]
fn service_surface_has_a_lightweight_extension_profile_and_typed_errors() {
    assert_eq!(RuntimeProfile::Lightweight.as_str(), "lightweight");
    assert_eq!(ServiceErrorKind::SessionRequired.as_str(), "session_required");
}

#[test]
fn device_service_wraps_coordinated_whole_device_sign_out() {
    let source = include_str!("../src/platform_services.rs");
    assert!(source.contains("pub fn sign_out_whole_device"));
    assert!(source.contains("ServiceCoordinator"));
    assert!(source.contains("sign_out_device"));
}

#[test]
fn accepted_password_state_can_install_without_exporting_a_token() {
    let source = services_source();
    assert!(source.contains("pub fn accept_password"));
    assert!(source.contains("pub fn unlock_known_device"));
    assert!(source.contains("pub fn install_new_device_with_passkey"));
    assert!(source.contains("pub fn install_new_device_with_recovery_key"));
    assert!(!source.contains("pub fn session_token"));

    let account = include_str!("../src/account_services.rs");
    assert!(account.contains("pub fn install_device_approval_replacing_account"));
}

#[test]
fn email_code_and_recovery_credentials_stay_in_one_shot_handles() {
    let services = services_source();
    let account = include_str!("../src/account_services.rs");
    for symbol in [
        "EmailCodeChallengeHandle",
        "EmailCodeTicketHandle",
        "pub fn sign_in_on_device",
        "pub fn request_email_code",
        "pub fn submit_email_code",
        "provide_email_code_ticket",
    ] {
        assert!(services.contains(symbol), "missing opaque email-code surface {symbol}");
    }
    for symbol in [
        "RecoveredSessionHandle",
        "pub fn start_recovery_with_password",
        "pub fn install_recovered_session",
        "pub fn install_recovered_session_replacing_account",
        "pub fn start_device_link_for_sign_in",
        "pub fn typed_new_device_message",
        "pub fn typed_approval_message",
    ] {
        assert!(account.contains(symbol), "missing opaque account flow {symbol}");
    }
    for forbidden in [
        "pub fn email_code_ticket",
        "pub fn password_proven",
        "pub fn recovery_token",
        "pub fn session_token",
        "pub fn master_key_bytes",
    ] {
        assert!(
            !services.contains(forbidden),
            "services export raw secret getter {forbidden}"
        );
        assert!(
            !account.contains(forbidden),
            "account services export raw secret getter {forbidden}"
        );
    }
}

#[test]
fn apple_keychain_backend_includes_ios_after_first_unlock() {
    let secrets = include_str!("../../beebeeb-client/src/secrets.rs");
    let manifest = include_str!("../../beebeeb-client/Cargo.toml");
    assert!(secrets.contains("target_os = \"ios\""));
    assert!(secrets.contains("AccessibleAfterFirstUnlockThisDeviceOnly"));
    assert!(secrets.contains("set_access_group"));
    assert!(manifest.contains("target_os = \"ios\""));
}

#[test]
fn mobile_binding_graph_does_not_reenable_core_c_dependencies() {
    let transfer_manifest = include_str!("../../beebeeb-transfer/Cargo.toml");
    assert!(transfer_manifest.contains("beebeeb-core = { path = \"../beebeeb-core\", default-features = false }"));
}

#[test]
fn advanced_account_and_platform_services_are_opaque_handles() {
    let account = include_str!("../src/account_services.rs");
    let platform = include_str!("../src/platform_services.rs");
    for symbol in [
        "DeviceLinkHandle",
        "TypedDeviceApprovalHandle",
        "TypedDeviceReceiverHandle",
        "DeviceApprovalHandle",
        "RecoveryAttemptHandle",
        "SignupServiceHandle",
        "AuthenticatorEnrollmentHandle",
        "list_account_sessions",
        "request_account_deletion",
    ] {
        assert!(account.contains(symbol), "missing account binding {symbol}");
    }
    for symbol in [
        "BackupServiceHandle",
        "pub fn back_up_again",
        "pub fn stopped_reason",
        "fn load_pass_state",
        "fn save_pass_state",
        "BackupPassStateData",
        "RemovedElsewhere",
        "pub modified_ms: Option<i64>",
        "pub size_bytes: Option<u64>",
        "FileProviderServiceHandle",
        "AssetSourceCallback",
        "BackupManifestStoreCallback",
        "DomainNotifierCallback",
        "PlatformTransferCancellerCallback",
        "AccountDataPurgerCallback",
    ] {
        assert!(platform.contains(symbol), "missing platform binding {symbol}");
    }
    for forbidden in [
        "pub fn session_token",
        "pub fn master_key_bytes",
        "pub fn file_key_bytes",
    ] {
        assert!(!account.contains(forbidden), "raw secret getter {forbidden}");
        assert!(!platform.contains(forbidden), "raw secret getter {forbidden}");
    }
}
