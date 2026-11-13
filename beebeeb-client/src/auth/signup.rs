use base64::{Engine as _, engine::general_purpose::STANDARD};
use beebeeb_api::routes::onboarding;
use beebeeb_core::onboarding::{BreachCheck, CeremonyConfig, CeremonyStep, PasswordEvaluation, SignupCeremony};
use zeroize::Zeroizing;

use super::{AuthError, PasswordAccepted, SessionKeyState, canonical_email};
use crate::{Client, SecretStore, session::HardwareIdentity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryKitOutput {
    Pdf,
    Text,
    Print,
}

#[derive(Default)]
struct RecoveryKitProgress {
    pdf: bool,
    text: bool,
    print: bool,
}

pub struct RecoveryKitData {
    phrase: Zeroizing<String>,
}

impl RecoveryKitData {
    pub fn filename_stem(&self) -> &'static str {
        "keep-safe"
    }

    pub fn title(&self) -> &'static str {
        "Your Beebeeb account safety key"
    }

    pub fn warnings(&self) -> [&'static str; 3] {
        [
            "Keep this away from your password.",
            "Do not save it inside Beebeeb.",
            "Anyone with these words may be able to recover your account.",
        ]
    }

    pub fn words(&self) -> impl Iterator<Item = &str> {
        self.phrase.split_whitespace()
    }

    pub fn text_file(&self) -> Zeroizing<String> {
        let mut text = String::from(
            "KEEP THIS AWAY FROM YOUR PASSWORD. DO NOT SAVE IT INSIDE BEEBEEB.\n\nYour Beebeeb account safety key:\n",
        );
        text.push_str(&self.phrase);
        text.push('\n');
        Zeroizing::new(text)
    }
}

impl std::fmt::Debug for RecoveryKitData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryKitData")
            .field("phrase", &"[REDACTED]")
            .finish()
    }
}

pub struct SignupService {
    canonical_email: String,
    ticket: Option<Zeroizing<String>>,
    ceremony: SignupCeremony,
    kit: RecoveryKitProgress,
}

impl std::fmt::Debug for SignupService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupService")
            .field("canonical_email", &self.canonical_email)
            .field("ticket", &self.ticket.as_ref().map(|_| "[REDACTED]"))
            .field("step", &self.ceremony.step())
            .finish()
    }
}

impl SignupService {
    pub fn new(email: &str, config: CeremonyConfig) -> Result<Self, AuthError> {
        let canonical_email = canonical_email(email);
        if canonical_email.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        Ok(Self {
            canonical_email,
            ticket: None,
            ceremony: SignupCeremony::new(config),
            kit: RecoveryKitProgress::default(),
        })
    }

    pub fn step(&self) -> CeremonyStep {
        self.ceremony.step()
    }

    pub fn set_password(
        &mut self,
        password: &str,
        confirmation: &str,
        breach: Option<&BreachCheck>,
    ) -> Result<PasswordEvaluation, AuthError> {
        self.ceremony
            .set_password(password, confirmation, breach)
            .map_err(Into::into)
    }

    pub fn begin_recovery_kit(&mut self) -> Result<RecoveryKitData, AuthError> {
        self.ceremony.begin_phrase()?;
        Ok(RecoveryKitData {
            phrase: self.ceremony.phrase()?,
        })
    }

    pub fn mark_recovery_output_saved(&mut self, output: RecoveryKitOutput) {
        match output {
            RecoveryKitOutput::Pdf => self.kit.pdf = true,
            RecoveryKitOutput::Text => self.kit.text = true,
            RecoveryKitOutput::Print => self.kit.print = true,
        }
    }

    pub fn acknowledge_recovery_kit(&mut self) -> Result<(), AuthError> {
        if !(self.kit.pdf && self.kit.text) {
            return Err(AuthError::RecoveryKitIncomplete);
        }
        self.ceremony.acknowledge_phrase().map_err(Into::into)
    }

    pub fn challenge_positions(&self) -> Result<Vec<u32>, AuthError> {
        self.ceremony.challenge_positions().map_err(Into::into)
    }

    pub fn confirm_phrase<S: AsRef<str>>(&mut self, answers: &[S]) -> Result<(), AuthError> {
        self.ceremony.confirm_phrase(answers).map_err(Into::into)
    }

    pub fn wipe(&mut self) {
        self.ticket = None;
        self.ceremony.wipe();
        self.kit = RecoveryKitProgress::default();
    }
}

pub struct CreatedAccount {
    pub sign_in: PasswordAccepted,
    pub master_key: beebeeb_core::kdf::MasterKey,
}

impl CreatedAccount {
    pub fn into_ready(self) -> super::ReadyNewDevice {
        super::ReadyNewDevice {
            accepted: self.sign_in,
            master_key: self.master_key,
            email_code_ticket: None,
        }
    }
}

impl Client {
    pub async fn fetch_onboarding(&self) -> Result<onboarding::OnboardingDocument, AuthError> {
        self.execute(&onboarding::document(false), &())
            .await
            .map_err(Into::into)
    }

    pub async fn start_signup_email(&self, signup: &SignupService) -> Result<(), AuthError> {
        self.execute(
            &onboarding::email_start(),
            &onboarding::EmailStart {
                email: signup.canonical_email.clone(),
                pilot_key: None,
            },
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
    }

    pub async fn verify_signup_email(&self, signup: &mut SignupService, code: String) -> Result<(), AuthError> {
        let answer = self
            .execute(
                &onboarding::email_verify(),
                &onboarding::EmailVerify {
                    email: signup.canonical_email.clone(),
                    code: Zeroizing::new(code),
                },
            )
            .await?;
        if answer.signup_ticket.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        signup.ticket = Some(Zeroizing::new(answer.signup_ticket));
        signup.ceremony.email_verified();
        Ok(())
    }

    pub async fn create_account(
        &self,
        signup: &mut SignupService,
        terms_version: String,
        store: &dyn SecretStore,
    ) -> Result<CreatedAccount, AuthError> {
        let hardware_id = HardwareIdentity::load_or_create(store)?.id().to_owned();
        let ticket = signup.ticket.as_ref().ok_or(AuthError::MalformedAnswer)?;
        let started = signup.ceremony.start_registration()?;
        let start_answer = self
            .execute(
                &onboarding::register_start(),
                &onboarding::RegistrationStart {
                    email: signup.canonical_email.clone(),
                    signup_ticket: ticket.to_string(),
                    client_message: STANDARD.encode(started.message),
                },
            )
            .await?;
        let server_message = STANDARD
            .decode(start_answer.server_message)
            .map_err(|_| AuthError::MalformedAnswer)?;
        let finished = signup.ceremony.finish_registration(&server_message)?;
        let answer = self
            .execute(
                &onboarding::register_finish(),
                &onboarding::RegistrationFinish {
                    email: signup.canonical_email.clone(),
                    client_message: STANDARD.encode(finished.upload),
                    hardware_id: hardware_id.clone(),
                    x25519_public_key: STANDARD.encode(finished.x25519_public),
                    recovery_check: STANDARD.encode(finished.recovery_check),
                    signup_ticket: ticket.to_string(),
                    terms_version,
                },
            )
            .await;
        let answer = match answer {
            Ok(answer) => answer,
            Err(error) => {
                signup.ceremony.registration_failed();
                return Err(error.into());
            }
        };
        if answer.user_id.is_empty() || answer.session_token.is_empty() {
            signup.ceremony.registration_failed();
            return Err(AuthError::MalformedAnswer);
        }
        let key_state = match SessionKeyState::parse(answer.key_state.as_deref()) {
            Ok(state) => state,
            Err(error) => {
                signup.ceremony.registration_failed();
                return Err(error);
            }
        };
        let master_key = signup.ceremony.account_created()?;
        Ok(CreatedAccount {
            sign_in: PasswordAccepted {
                session_token: Zeroizing::new(answer.session_token),
                canonical_email: signup.canonical_email.clone(),
                owner: answer.user_id,
                key_state,
                legacy_upgrade_required: false,
                factor_satisfied: false,
                email_code_satisfied: true,
                authenticator_required: false,
                hardware_id: Some(hardware_id),
                hardware_identity_secret: None,
                screen_check: None,
            },
            master_key,
        })
    }
}
