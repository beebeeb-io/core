use super::*;

pub struct PasskeyPromptOutput {
    pub credential_id: String,
    pub prf_output: Zeroizing<Vec<u8>>,
}

pub type PasskeyPromptFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PasskeyPromptOutput, PasskeyPromptError>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("the passkey prompt did not complete")]
pub struct PasskeyPromptError;

pub trait PasskeyPrompt: Send + Sync {
    fn create<'a>(&'a self) -> PasskeyPromptFuture<'a>;
    fn authenticate<'a>(&'a self) -> PasskeyPromptFuture<'a>;
}

impl Client {
    pub async fn create_passkey_copy(&self, prompt: &dyn PasskeyPrompt) -> Result<String, AuthError> {
        self.person_call(crate::LockedAction::ManageFactors)?;
        let session_key = self.held_key()?;
        let account_id = self.authenticated_owner()?;
        let output = prompt.create().await.map_err(|_| AuthError::PasskeyPrompt)?;
        let sealed = seal_master_key(
            session_key.master_key(),
            &output.prf_output,
            account_id.as_bytes(),
            output.credential_id.as_bytes(),
        )
        .map_err(|_| AuthError::KeyProof)?;
        self.execute(
            &proposed::store_passkey_copy(),
            &proposed::PasskeyCopyStore {
                credential_id: output.credential_id.clone(),
                encrypted_vault_key: STANDARD.encode(sealed.to_bytes()),
            },
        )
        .await?;
        Ok(output.credential_id)
    }

    pub async fn open_with_passkey(
        &self,
        accepted: &PasswordAccepted,
        prompt: &dyn PasskeyPrompt,
    ) -> Result<MasterKey, AuthError> {
        self.set_authentication(accepted.session_token.to_string(), accepted.owner.clone())?;
        let account_id = &accepted.owner;
        let output = prompt.authenticate().await.map_err(|_| AuthError::PasskeyPrompt)?;
        let copy = self
            .execute(&proposed::get_passkey_copy(&output.credential_id), &())
            .await?;
        if copy.credential_id != output.credential_id {
            return Err(AuthError::MalformedAnswer);
        }
        let wire = STANDARD
            .decode(copy.encrypted_vault_key)
            .map_err(|_| AuthError::MalformedAnswer)?;
        let sealed = PasskeySealedMasterKey::from_bytes(&wire).map_err(|_| AuthError::MalformedAnswer)?;
        open_master_key(
            &sealed,
            &output.prf_output,
            account_id.as_bytes(),
            output.credential_id.as_bytes(),
        )
        .map_err(|_| AuthError::KeyProof)
    }
}
