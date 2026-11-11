use std::fs;
use std::path::PathBuf;

fn crate_file(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(path)).expect("binding source must be readable")
}

fn assert_no_raw_secret_getters(source: &str, function_marker: &str, raw_return_markers: &[&str]) {
    for line in source.lines() {
        let compact = line.trim().to_ascii_lowercase();
        let looks_like_getter = compact.contains(function_marker)
            && compact.contains("()")
            && ["key", "token", "secret"].iter().any(|word| compact.contains(word));
        let returns_raw_bytes = raw_return_markers.iter().any(|marker| compact.contains(marker));
        // The passkey PRF input and its `hmac-secret` salt are a fixed public label
        // and a hash of it, not secrets: "passkey" and "secret" only name them.
        let safe_identifier = compact.contains("keyid()")
            || compact.contains("passkeyprfevalinput()")
            || compact.contains("passkeyhmacsecretsalt()");
        assert!(
            !(looks_like_getter && returns_raw_bytes && !safe_identifier),
            "generated binding exposes a zero-argument raw secret getter: {line}"
        );
    }
}

#[test]
fn default_surface_does_not_export_legacy_raw_secrets_or_transfers() {
    let source = crate_file("src/lib.rs");
    for function in [
        "derive_master_key",
        "derive_file_key",
        "recover_from_phrase",
        "derive_x25519_private",
        "x25519_shared_secret",
        "derive_share_key",
        "derive_request_wrap_key",
        "unwrap_request_private",
        "open_request_upload",
        "transfer_derive_key",
        "encrypt_chunk",
        "encrypt_metadata",
        "upload_encrypted_file",
        "download_and_decrypt_file",
    ] {
        let signature = format!("pub fn {function}");
        let at = source
            .find(&signature)
            .expect("legacy compatibility function remains available");
        let start = at.saturating_sub(160);
        let annotations = &source[start..at];
        assert!(
            annotations.contains("feature = \"legacy-bindings\""),
            "{function} must be behind the default-off legacy-bindings feature"
        );
    }

    let manifest = crate_file("Cargo.toml");
    assert!(manifest.contains("legacy-bindings = [\"dep:beebeeb-upload\"]"));
    assert!(manifest.contains("beebeeb-upload = { path = \"../beebeeb-upload\", optional = true }"));

    let swift = crate_file("bindings/beebeeb_uniffi.swift");
    let kotlin = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../bindings/kotlin/uniffi/beebeeb_uniffi/beebeeb_uniffi.kt"),
    )
    .expect("generated Kotlin binding must be readable");
    for forbidden in [
        "deriveMasterKey(",
        "exportForKeychain(",
        "fromKeychainBytes(",
        "fromKeyBytes(",
        "uploadEncryptedFile(",
        "downloadAndDecryptFile(",
        "sessionToken()",
        "masterKeyBytes()",
        "fileKeyBytes()",
        "productKeyBytes()",
        "typedCodeChannel()",
    ] {
        assert!(!swift.contains(forbidden), "Swift still exports {forbidden}");
        assert!(!kotlin.contains(forbidden), "Kotlin still exports {forbidden}");
    }
    for factory in ["uploads", "downloads", "thumbnails"] {
        let swift_signature = swift
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("func {factory}(")))
            .expect("Swift service factory must be generated");
        assert!(
            !swift_signature.to_ascii_lowercase().contains("masterkey"),
            "Swift {factory} factory accepts a caller-supplied key: {swift_signature}"
        );
        let kotlin_signature = kotlin
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("fun `{factory}`(")))
            .expect("Kotlin service factory must be generated");
        assert!(
            !kotlin_signature.to_ascii_lowercase().contains("masterkey"),
            "Kotlin {factory} factory accepts a caller-supplied key: {kotlin_signature}"
        );
    }
    for forbidden in ["installDeviceApprovalInner(", "installRecoveredSessionInner("] {
        assert!(
            !swift.contains(forbidden),
            "Swift exports internal replacement helper {forbidden}"
        );
        assert!(
            !kotlin.contains(forbidden),
            "Kotlin exports internal replacement helper {forbidden}"
        );
    }
    assert_no_raw_secret_getters(&swift, "func ", &["-> data", "-> [uint8]"]);
    assert_no_raw_secret_getters(&kotlin, "fun ", &[": bytearray", ": list<ubyte>"]);
}
