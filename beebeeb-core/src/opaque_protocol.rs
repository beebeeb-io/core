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
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        // 256 MiB, 4 iterations, 2 parallelism, output length = L (the
        // OPAQUE protocol's KSF expects len(output) == len(input)).
        let params = Params::new(256 * 1024, 4, 2, Some(L::USIZE))
            .map_err(|_| InternalError::KsfError)?;
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

struct BeebeebCs;

impl CipherSuite for BeebeebCs {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    // Argon2id with production parameters (256 MiB / 4 iter / 2 par).
    // Was `opaque_ke::ksf::Identity` — that left password files brute-forceable
    // at OPRF cost (~ms per guess) instead of Argon2id cost (~seconds per guess).
    type Ksf = Argon2idKsf;
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

pub fn client_login_finish(
    client_state_bytes: &[u8],
    password: &[u8],
    credential_response_bytes: &[u8],
) -> Result<ClientLoginFinishResult, CoreError> {
    let state = ClientLogin::<BeebeebCs>::deserialize(client_state_bytes)
        .map_err(|e| CoreError::Opaque(format!("invalid client login state: {e}")))?;
    let response = CredentialResponse::deserialize(credential_response_bytes)
        .map_err(|e| CoreError::Opaque(format!("invalid credential response: {e}")))?;
    let mut rng = OsRng;
    let result = state
        .finish(&mut rng, password, response, ClientLoginFinishParameters::default())
        .map_err(|e| CoreError::Opaque(format!("login finish failed (wrong password?): {e}")))?;
    Ok(ClientLoginFinishResult {
        message: result.message.serialize().to_vec(),
        session_key: result.session_key.to_vec(),
        export_key: result.export_key.to_vec(),
    })
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
        let client_finish = client_login_finish(&login_start.state, password, &server_login.message).unwrap();
        let server_session_key = server_login_finish(&server_login.state, &client_finish.message).unwrap();

        assert_eq!(client_finish.session_key, server_session_key);
        assert!(!client_finish.export_key.is_empty());
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
        let result = client_login_finish(&login_start.state, wrong_password, &server_login.message);

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
        let finish1 = client_login_finish(&login1.state, password, &server1.message).unwrap();

        let login2 = client_login_start(password).unwrap();
        let server2 = server_login_start(&server_setup, &password_file, &login2.message, username).unwrap();
        let finish2 = client_login_finish(&login2.state, password, &server2.message).unwrap();

        assert_eq!(finish1.export_key, finish2.export_key);
    }
}
