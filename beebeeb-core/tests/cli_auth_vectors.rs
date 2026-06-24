//! Cross-binding test vectors + round-trip for the CLI device-authorization handshake.
//!
//! These pin the EXACT derivation the `bb` CLI and the web client
//! (`repos/web/src/pages/cli-auth.tsx`) must agree on: P-256 ECDH → HKDF-SHA256
//! (info = "beebeeb-cli-auth-v1") → AES-256-GCM. A fixed
//! `(cli_priv, browser_priv) -> shared_secret -> aes_key` pin is the drift guard: if
//! anyone changes the HKDF info/salt or the ECDH point encoding, the constants below
//! change and this test fails, catching a wire-format break before it ships and
//! silently bricks live `bb login`.
//!
//! The constants were generated once with the helper at the bottom
//! (`#[ignore] print_vectors`); re-run it only if the protocol is *intentionally*
//! changed (which is a coordinated cross-client migration, not a refactor).

use aes_gcm::aead::Aead;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes256Gcm, KeyInit};
use beebeeb_core::cli_auth::{decrypt_cli_payload, derive_cli_auth_key};
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;

// A fixed CLI ephemeral private scalar (32 bytes). NOT a real OsRng output — a fixed
// value so every binding reproduces the same ECDH + HKDF.
const CLI_PRIV_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
// A fixed BROWSER ephemeral private scalar (32 bytes).
const BROWSER_PRIV_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

// HKDF-SHA256(ikm = ECDH(cli_priv, browser_pub).x, salt = None, info = "beebeeb-cli-auth-v1").
// This is the AES-256 key the current (v1) handshake uses.
const EXPECTED_AES_KEY_HEX: &str = "8bd295090ce8a6412b831704b601b55d60ba3cae056f5e1337a11b5f9eceac35";

// The raw 32-byte ECDH shared secret (X-coordinate). The legacy v0.4 web app used
// THIS directly as the AES key (no HKDF). Pinned so the raw-fallback path is covered.
const EXPECTED_SHARED_HEX: &str = "ccfc261f58193c98ca4ad4a53bbac6f0ee29bc4d48438090446908622ca79af6";

fn hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap();
    v.try_into().unwrap()
}

/// P-256 ECDH shared secret (32-byte X-coordinate) from a private scalar + a peer
/// public key, using the same `p256` primitives the core module uses.
fn ecdh_x(priv_hex: &str, peer_pub_sec1: &[u8]) -> [u8; 32] {
    let sk = SecretKey::from_slice(&hex::decode(priv_hex).unwrap()).unwrap();
    let peer = p256::PublicKey::from_sec1_bytes(peer_pub_sec1).unwrap();
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes().as_slice());
    out
}

fn pub_sec1(priv_hex: &str) -> Vec<u8> {
    let sk = SecretKey::from_slice(&hex::decode(priv_hex).unwrap()).unwrap();
    sk.public_key().to_encoded_point(false).as_bytes().to_vec()
}

#[test]
fn aes_key_matches_fixed_vector() {
    let cli_pub = pub_sec1(CLI_PRIV_HEX);
    // Browser derives the shared secret from its OWN private + the CLI's public.
    let shared = ecdh_x(BROWSER_PRIV_HEX, &cli_pub);
    assert_eq!(
        hex::encode(shared),
        EXPECTED_SHARED_HEX,
        "P-256 ECDH shared secret drifted — clients will no longer agree."
    );

    let key = derive_cli_auth_key(&shared);
    assert_eq!(
        hex::encode(*key),
        EXPECTED_AES_KEY_HEX,
        "CLI-auth AES key derivation drifted — HKDF info MUST be 'beebeeb-cli-auth-v1', salt MUST be None. \
         A live `bb login` would break."
    );
}

#[test]
fn ecdh_is_symmetric_across_clients() {
    // Both sides must reach the same shared secret regardless of which private key
    // they hold — that is the whole point of the handshake.
    let cli_pub = pub_sec1(CLI_PRIV_HEX);
    let browser_pub = pub_sec1(BROWSER_PRIV_HEX);
    let cli_side = ecdh_x(CLI_PRIV_HEX, &browser_pub);
    let browser_side = ecdh_x(BROWSER_PRIV_HEX, &cli_pub);
    assert_eq!(cli_side, browser_side);
    assert_eq!(hex::encode(cli_side), EXPECTED_SHARED_HEX);
}

#[test]
fn full_browser_to_cli_roundtrip_hkdf() {
    // Browser side: derive AES key (HKDF), AES-256-GCM encrypt the credential JSON.
    let cli_pub = pub_sec1(CLI_PRIV_HEX);
    let shared = ecdh_x(BROWSER_PRIV_HEX, &cli_pub);
    let key = *derive_cli_auth_key(&shared);
    let nonce = [0xABu8; 12];
    let plaintext = br#"{"session_token":"s","master_key_b64":"AAAA","email":"a@beebeeb.io"}"#;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let ct = cipher
        .encrypt(GenericArray::from_slice(&nonce), plaintext.as_ref())
        .unwrap();

    // CLI side: decrypt from the same shared secret via the core helper.
    let recovered = decrypt_cli_payload(&hex32(EXPECTED_SHARED_HEX), &nonce, &ct).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn full_browser_to_cli_roundtrip_raw_fallback() {
    // Legacy v0.4 browser: raw shared secret used directly as the AES key (no HKDF).
    let shared = hex32(EXPECTED_SHARED_HEX);
    let nonce = [0xCDu8; 12];
    let plaintext = b"legacy-v0.4";
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&shared));
    let ct = cipher
        .encrypt(GenericArray::from_slice(&nonce), plaintext.as_ref())
        .unwrap();

    // The core decrypt tries HKDF first, then falls back to the raw secret.
    let recovered = decrypt_cli_payload(&shared, &nonce, &ct).unwrap();
    assert_eq!(recovered, plaintext);
}

/// Regenerate the pinned constants. Run with:
///   cargo test -p beebeeb-core --test cli_auth_vectors print_vectors -- --ignored --nocapture
/// Only re-run on an INTENTIONAL protocol change (coordinated cross-client migration).
#[test]
#[ignore]
fn print_vectors() {
    let cli_pub = pub_sec1(CLI_PRIV_HEX);
    let shared = ecdh_x(BROWSER_PRIV_HEX, &cli_pub);
    let key = derive_cli_auth_key(&shared);
    println!("EXPECTED_SHARED_HEX  = {}", hex::encode(shared));
    println!("EXPECTED_AES_KEY_HEX = {}", hex::encode(*key));
}
