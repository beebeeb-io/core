use argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::errors::InternalError;
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters,
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest, RegistrationResponse,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};

use crate::CoreError;

/// Argon2id-based Key Stretching Function for OPAQUE.
///
/// Production parameters: 256 MiB memory, 4 iterations, 2 lanes.
/// These match the rest of the Beebeeb crypto stack (see `recovery.rs`,
/// `kdf.rs`) so an attacker who exfiltrates the OPAQUE password file
/// pays Argon2id cost per password guess instead of a single Ristretto255
/// scalar multiplication.
///
/// SECURITY NOTE: Changing these parameters (or this KSF type at all)
/// invalidates every existing `opaque_password_file` in the database.
/// All affected users must re-register or go through a password reset
/// flow. This is acceptable pre-launch but MUST NOT change post-launch
/// without an explicit migration path.
#[derive(Default)]
pub struct Argon2idKsf;

impl Ksf for Argon2idKsf {
    fn hash<L: ArrayLength<u8>>(&self, input: GenericArray<u8, L>) -> Result<GenericArray<u8, L>, InternalError> {
        // 256 MiB, 4 iterations, 2 parallelism, output length = L (the
        // OPAQUE protocol's KSF expects len(output) == len(input)).
        let params = Params::new(256 * 1024, 4, 2, Some(L::USIZE)).map_err(|_| InternalError::KsfError)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // OPAQUE feeds the KSF a value that already mixes in per-user OPRF
        // output and server-held secrets, so a fixed deterministic salt is
        // safe here — the KSF input itself is unpredictable per user.
        // (Same approach as the upstream `Argon2<'_>: Ksf` blanket impl in
        // opaque-ke, which uses `[0; RECOMMENDED_SALT_LEN]`.)
        let mut output = GenericArray::<u8, L>::default();
        argon2
            .hash_password_into(&input, &[0u8; argon2::RECOMMENDED_SALT_LEN], &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

/// OPAQUE cipher suite, **v1** — the current registration/login suite.
///
/// Uses [`Argon2idKsf`] so an attacker who exfiltrates the password file pays
/// Argon2id cost per guess. New accounts and silent upgrades are always v1.
struct BeebeebCs;

impl CipherSuite for BeebeebCs {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    // Argon2id with production parameters (256 MiB / 4 iter / 2 par).
    // Was `opaque_ke::ksf::Identity` — that left password files brute-forceable
    // at OPRF cost (~ms per guess) instead of Argon2id cost (~seconds per guess).
    type Ksf = Argon2idKsf;
}

/// OPAQUE cipher suite, **v0** — the LEGACY suite, retained only so the ~30
/// production accounts registered before the Argon2id switch can still complete
/// a fresh login (`opaque_ksf_version = 0`). IDENTICAL to [`BeebeebCs`] except
/// `Ksf = opaque_ke::ksf::Identity` (no password stretching).
///
/// Every other associated type (`OprfCs`, `KeyExchange`) is byte-for-byte the
/// same as v1. Because `Ksf` is a zero-sized type that only governs how the
/// OPRF output is stretched inside `ClientLogin::finish`, the serialized
/// `ClientLogin` state and `CredentialResponse` are identical across the two
/// suites — a state produced by `client_login_start` (always v1) can be
/// deserialized and finished under v0. See `v0_identity_ksf_login_roundtrip`.
///
/// SECURITY NOTE: v0 password files are brute-forceable at OPRF cost. The
/// dual-KSF login exists purely to migrate these accounts; on a successful v0
/// login the client re-registers under v1 (auto-upgrade — separate task). Do
/// NOT register new accounts under this suite.
struct BeebeebCsV0;

impl CipherSuite for BeebeebCsV0 {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

pub fn create_server_setup() -> Vec<u8> {
    let mut rng = OsRng;
    let setup = ServerSetup::<BeebeebCs>::new(&mut rng);
    setup.serialize().to_vec()
}

pub struct RegistrationStartResult {
    pub message: Vec<u8>,
    pub state: Vec<u8>,
}

pub fn client_registration_start(password: &[u8]) -> Result<RegistrationStartResult, CoreError> {
    let mut rng = OsRng;
    let result = ClientRegistration::<BeebeebCs>::start(&mut rng, password)
        .map_err(|e| CoreError::Opaque(format!("registration start failed: {e}")))?;
    Ok(RegistrationStartResult {
        message: result.message.serialize().to_vec(),
        state: result.state.serialize().to_vec(),
    })
}

pub fn server_registration_start(
    server_setup_bytes: &[u8],
    registration_request_bytes: &[u8],
    username: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let server_setup = ServerSetup::<BeebeebCs>::deserialize(server_setup_bytes)
        .map_err(|e| CoreError::Opaque(format!("invalid server setup: {e}")))?;
    let request = RegistrationRequest::deserialize(registration_request_bytes)
        .map_err(|e| CoreError::Opaque(format!("invalid registration request: {e}")))?;
    let result = ServerRegistration::<BeebeebCs>::start(&server_setup, request, username)
        .map_err(|e| CoreError::Opaque(format!("server registration start failed: {e}")))?;
    Ok(result.message.serialize().to_vec())
}

pub fn client_registration_finish(
    client_state_bytes: &[u8],
    password: &[u8],
    registration_response_bytes: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let state = ClientRegistration::<BeebeebCs>::deserialize(client_state_bytes)
        .map_err(|e| CoreError::Opaque(format!("invalid client state: {e}")))?;
    let response = RegistrationResponse::deserialize(registration_response_bytes)
        .map_err(|e| CoreError::Opaque(format!("invalid registration response: {e}")))?;
    let mut rng = OsRng;
    let result = state
        .finish(
            &mut rng,
            password,
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|e| CoreError::Opaque(format!("client registration finish failed: {e}")))?;
    Ok(result.message.serialize().to_vec())
}

pub fn server_registration_finish(registration_upload_bytes: &[u8]) -> Result<Vec<u8>, CoreError> {
    let upload = RegistrationUpload::<BeebeebCs>::deserialize(registration_upload_bytes)
        .map_err(|e| CoreError::Opaque(format!("invalid registration upload: {e}")))?;
    let password_file = ServerRegistration::finish(upload);
    Ok(password_file.serialize().to_vec())
}

pub struct LoginStartResult {
    pub message: Vec<u8>,
    pub state: Vec<u8>,
}

pub fn client_login_start(password: &[u8]) -> Result<LoginStartResult, CoreError> {
    let mut rng = OsRng;
    let result = ClientLogin::<BeebeebCs>::start(&mut rng, password)
        .map_err(|e| CoreError::Opaque(format!("login start failed: {e}")))?;
    Ok(LoginStartResult {
        message: result.message.serialize().to_vec(),
        state: result.state.serialize().to_vec(),
    })
}

pub struct ServerLoginStartResult {
    pub message: Vec<u8>,
    pub state: Vec<u8>,
}

pub fn server_login_start(
    server_setup_bytes: &[u8],
    password_file_bytes: &[u8],
    credential_request_bytes: &[u8],
    username: &[u8],
) -> Result<ServerLoginStartResult, CoreError> {
    let server_setup = ServerSetup::<BeebeebCs>::deserialize(server_setup_bytes)
        .map_err(|e| CoreError::Opaque(format!("invalid server setup: {e}")))?;
    let password_file = ServerRegistration::<BeebeebCs>::deserialize(password_file_bytes)
        .map_err(|e| CoreError::Opaque(format!("invalid password file: {e}")))?;
    let request = CredentialRequest::deserialize(credential_request_bytes)
        .map_err(|e| CoreError::Opaque(format!("invalid credential request: {e}")))?;
    let mut rng = OsRng;
    let result = ServerLogin::start(
        &mut rng,
        &server_setup,
        Some(password_file),
        request,
        username,
        ServerLoginParameters::default(),
    )
    .map_err(|e| CoreError::Opaque(format!("server login start failed: {e}")))?;
    Ok(ServerLoginStartResult {
        message: result.message.serialize().to_vec(),
        state: result.state.serialize().to_vec(),
    })
}

pub struct ClientLoginFinishResult {
    pub message: Vec<u8>,
    pub session_key: Vec<u8>,
    pub export_key: Vec<u8>,
}

/// Finish OPAQUE client login, stretching the OPRF output with the KSF that
/// matches the account's `opaque_ksf_version`:
///
/// - `ksf_version == 0` → legacy [`BeebeebCsV0`] (`Identity` KSF, no stretch).
/// - any other value    → current [`BeebeebCs`] (`Argon2idKsf`).
///
/// The caller obtains `ksf_version` from the login-start response (the server
/// reads it from the user row). The KSF MUST match the suite the account's
/// password file was registered under, otherwise the envelope fails to
/// authenticate and finish returns an error (this is what makes a wrong-KSF
/// attempt indistinguishable from a wrong password).
///
/// `client_state_bytes` always comes from [`client_login_start`] (v1), but the
/// `ClientLogin` state is KSF-independent, so it deserializes cleanly under
/// either suite here — proven by `v0_identity_ksf_login_roundtrip`.
pub fn client_login_finish(
    client_state_bytes: &[u8],
    password: &[u8],
    credential_response_bytes: &[u8],
    ksf_version: u32,
) -> Result<ClientLoginFinishResult, CoreError> {
    let mut rng = OsRng;
    if ksf_version == 0 {
        let state = ClientLogin::<BeebeebCsV0>::deserialize(client_state_bytes)
            .map_err(|e| CoreError::Opaque(format!("invalid client login state: {e}")))?;
        let response = CredentialResponse::deserialize(credential_response_bytes)
            .map_err(|e| CoreError::Opaque(format!("invalid credential response: {e}")))?;
        let result = state
            .finish(&mut rng, password, response, ClientLoginFinishParameters::default())
            .map_err(|e| CoreError::Opaque(format!("login finish failed (wrong password?): {e}")))?;
        Ok(ClientLoginFinishResult {
            message: result.message.serialize().to_vec(),
            session_key: result.session_key.to_vec(),
            export_key: result.export_key.to_vec(),
        })
    } else {
        let state = ClientLogin::<BeebeebCs>::deserialize(client_state_bytes)
            .map_err(|e| CoreError::Opaque(format!("invalid client login state: {e}")))?;
        let response = CredentialResponse::deserialize(credential_response_bytes)
            .map_err(|e| CoreError::Opaque(format!("invalid credential response: {e}")))?;
        let result = state
            .finish(&mut rng, password, response, ClientLoginFinishParameters::default())
            .map_err(|e| CoreError::Opaque(format!("login finish failed (wrong password?): {e}")))?;
        Ok(ClientLoginFinishResult {
            message: result.message.serialize().to_vec(),
            session_key: result.session_key.to_vec(),
            export_key: result.export_key.to_vec(),
        })
    }
}

pub fn server_login_finish(
    server_state_bytes: &[u8],
    credential_finalization_bytes: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let state = ServerLogin::<BeebeebCs>::deserialize(server_state_bytes)
        .map_err(|e| CoreError::Opaque(format!("invalid server login state: {e}")))?;
    let finalization = CredentialFinalization::deserialize(credential_finalization_bytes)
        .map_err(|e| CoreError::Opaque(format!("invalid credential finalization: {e}")))?;
    let result = state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(|e| CoreError::Opaque(format!("server login finish failed: {e}")))?;
    Ok(result.session_key.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test-only v0 registration helpers ────────────────────────────────────
    //
    // The public API only registers under v1 (BeebeebCs); these helpers let the
    // dual-KSF login test produce a password file under the LEGACY Identity KSF
    // (BeebeebCsV0), exactly as the ~30 affected production accounts were
    // registered. They mirror the public v1 registration fns with the suite
    // swapped — deliberately NOT exported, so v0 registration stays test-only.

    fn client_registration_start_v0(password: &[u8]) -> RegistrationStartResult {
        let mut rng = OsRng;
        let result = ClientRegistration::<BeebeebCsV0>::start(&mut rng, password).unwrap();
        RegistrationStartResult {
            message: result.message.serialize().to_vec(),
            state: result.state.serialize().to_vec(),
        }
    }

    fn server_registration_start_v0(
        server_setup_bytes: &[u8],
        registration_request_bytes: &[u8],
        username: &[u8],
    ) -> Vec<u8> {
        let server_setup = ServerSetup::<BeebeebCsV0>::deserialize(server_setup_bytes).unwrap();
        let request = RegistrationRequest::deserialize(registration_request_bytes).unwrap();
        let result = ServerRegistration::<BeebeebCsV0>::start(&server_setup, request, username).unwrap();
        result.message.serialize().to_vec()
    }

    fn client_registration_finish_v0(
        client_state_bytes: &[u8],
        password: &[u8],
        registration_response_bytes: &[u8],
    ) -> Vec<u8> {
        let state = ClientRegistration::<BeebeebCsV0>::deserialize(client_state_bytes).unwrap();
        let response = RegistrationResponse::deserialize(registration_response_bytes).unwrap();
        let mut rng = OsRng;
        let result = state
            .finish(
                &mut rng,
                password,
                response,
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();
        result.message.serialize().to_vec()
    }

    fn server_registration_finish_v0(registration_upload_bytes: &[u8]) -> Vec<u8> {
        let upload = RegistrationUpload::<BeebeebCsV0>::deserialize(registration_upload_bytes).unwrap();
        ServerRegistration::<BeebeebCsV0>::finish(upload).serialize().to_vec()
    }

    #[test]
    fn full_registration_and_login_roundtrip() {
        let password = b"correct-horse-battery-staple";
        let username = b"alice@beebeeb.io";

        let server_setup = create_server_setup();

        let reg_start = client_registration_start(password).unwrap();
        let reg_response = server_registration_start(&server_setup, &reg_start.message, username).unwrap();
        let reg_upload = client_registration_finish(&reg_start.state, password, &reg_response).unwrap();
        let password_file = server_registration_finish(&reg_upload).unwrap();

        let login_start = client_login_start(password).unwrap();
        let server_login = server_login_start(&server_setup, &password_file, &login_start.message, username).unwrap();
        let client_finish = client_login_finish(&login_start.state, password, &server_login.message, 1).unwrap();
        let server_session_key = server_login_finish(&server_login.state, &client_finish.message).unwrap();

        assert_eq!(client_finish.session_key, server_session_key);
        assert!(!client_finish.export_key.is_empty());
    }

    #[test]
    fn v0_identity_ksf_login_roundtrip() {
        // Reproduce the production scenario: an account REGISTERED under the
        // legacy Identity KSF (opaque_ksf_version = 0) must still complete a
        // fresh login when the client finishes with ksf_version = 0.
        let password = b"legacy-v0-correct-horse";
        let username = b"dave@beebeeb.io";

        // ServerSetup is KSF-independent (Ksf is a ZST), so the same setup
        // serves both the v0 registration helpers and the v1-suite server login
        // functions below — mirroring production, where one ServerSetup backs
        // accounts of either version.
        let server_setup = create_server_setup();

        // Register the password file under the LEGACY Identity KSF (v0).
        let reg_start = client_registration_start_v0(password);
        let reg_response = server_registration_start_v0(&server_setup, &reg_start.message, username);
        let reg_upload = client_registration_finish_v0(&reg_start.state, password, &reg_response);
        let password_file = server_registration_finish_v0(&reg_upload);

        // Fresh login. client_login_start / server_login_start stay on the v1
        // suite (BeebeebCs) exactly as in production — only the *finish* dispatches
        // on ksf_version.
        let login_start = client_login_start(password).unwrap();
        let server_login = server_login_start(&server_setup, &password_file, &login_start.message, username).unwrap();

        // Finish with ksf_version = 0 → deserialize state as BeebeebCsV0 and
        // stretch with Identity, matching the v0 password file. Proves the
        // v1-produced ClientLogin state is cross-deserializable under v0.
        let client_finish = client_login_finish(&login_start.state, password, &server_login.message, 0).unwrap();
        let server_session_key = server_login_finish(&server_login.state, &client_finish.message).unwrap();

        // Round-trip: client and server derive the SAME session key, and an
        // export key is produced.
        assert_eq!(client_finish.session_key, server_session_key);
        assert!(!client_finish.export_key.is_empty());

        // The dispatch is load-bearing: finishing the SAME v0 exchange under the
        // v1 (Argon2id) KSF must FAIL — the Identity-stretched envelope cannot
        // authenticate under Argon2id stretching.
        let login_start2 = client_login_start(password).unwrap();
        let server_login2 = server_login_start(&server_setup, &password_file, &login_start2.message, username).unwrap();
        let wrong_ksf = client_login_finish(&login_start2.state, password, &server_login2.message, 1);
        assert!(wrong_ksf.is_err(), "v0 password file must NOT finish under the v1 KSF");
    }

    #[test]
    fn wrong_password_fails_login() {
        let password = b"correct-password";
        let wrong_password = b"wrong-password";
        let username = b"bob@beebeeb.io";

        let server_setup = create_server_setup();

        let reg_start = client_registration_start(password).unwrap();
        let reg_response = server_registration_start(&server_setup, &reg_start.message, username).unwrap();
        let reg_upload = client_registration_finish(&reg_start.state, password, &reg_response).unwrap();
        let password_file = server_registration_finish(&reg_upload).unwrap();

        let login_start = client_login_start(wrong_password).unwrap();
        let server_login = server_login_start(&server_setup, &password_file, &login_start.message, username).unwrap();
        let result = client_login_finish(&login_start.state, wrong_password, &server_login.message, 1);

        assert!(result.is_err());
    }

    #[test]
    fn export_key_is_deterministic_for_same_password() {
        let password = b"stable-password";
        let username = b"carol@beebeeb.io";

        let server_setup = create_server_setup();

        let reg_start = client_registration_start(password).unwrap();
        let reg_response = server_registration_start(&server_setup, &reg_start.message, username).unwrap();
        let reg_upload = client_registration_finish(&reg_start.state, password, &reg_response).unwrap();
        let password_file = server_registration_finish(&reg_upload).unwrap();

        let login1 = client_login_start(password).unwrap();
        let server1 = server_login_start(&server_setup, &password_file, &login1.message, username).unwrap();
        let finish1 = client_login_finish(&login1.state, password, &server1.message, 1).unwrap();

        let login2 = client_login_start(password).unwrap();
        let server2 = server_login_start(&server_setup, &password_file, &login2.message, username).unwrap();
        let finish2 = client_login_finish(&login2.state, password, &server2.message, 1).unwrap();

        assert_eq!(finish1.export_key, finish2.export_key);
    }
}
