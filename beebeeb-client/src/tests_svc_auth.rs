use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use beebeeb_core::onboarding::{BreachPolicy, CeremonyConfig, PasswordPolicy};
use beebeeb_core::{
    device_link::AccountKeyMaterial,
    kdf::MasterKey,
    key_proof::{KeyProofBinding, KeyProofResponse, create_challenge},
    opaque::{derive_x25519_private, derive_x25519_public},
    opaque_protocol::{create_server_setup, server_registration_start},
};
use tokio::sync::broadcast::error::TryRecvError;
use zeroize::Zeroizing;

use crate::{
    Client, ClientConfig, ClientError, EngineEvent, SecretError, SecretStore, Session,
    auth::{
        AuthError, NewDeviceUnlock, PasskeyPrompt, PasskeyPromptError, PasskeyPromptFuture, PasskeyPromptOutput,
        PasswordAccepted, RecoveryCancelToken, RecoveryChanges, RecoveryKitOutput, RecoveryState, SessionKeyState,
        SignInChallenge, SignupService, TwoFactorChallenge, canonical_email, sign_in_state,
    },
    devices::{DeviceError, DeviceLinkPoll, DeviceLinkQr},
    test_support::ScriptedTransport,
    transport::{Transport, TransportError, TransportFuture},
};

mod account;
mod device_link;
mod lock;
mod lock_password;
mod recovery;
mod session;
mod sign_in;

fn session(owner: &str, token: &str, generation: u64) -> Session {
    Session::from_parts_for_test("https://api.example", token, owner, [generation as u8; 32], generation).unwrap()
}
