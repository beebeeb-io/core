use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
#[cfg(all(feature = "store", any(feature = "downloads", feature = "thumbnails")))]
use std::time::Duration;

#[cfg(any(
    feature = "sync",
    all(feature = "store", any(feature = "downloads", feature = "thumbnails"))
))]
use beebeeb_api::RawEndpoint;
use beebeeb_api::flows::{LockFlow, LockState, StartFacts};
use beebeeb_api::{ApiError, ClientIdentity, Endpoint, RequestBuilder};
use beebeeb_core::kdf::MasterKey;
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::Session;
use crate::{EngineEvent, EngineEvents, Transport, TransportError};
#[cfg(feature = "sync")]
use crate::{StreamBatch, StreamLimits, StreamResponse};

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub identity: ClientIdentity,
    pub app_id: String,
    pub event_capacity: usize,
    /// The password path of the screen lock: the offline check record, the online password
    /// check and the "ask for my password at start" setting. Off by default, and to be turned
    /// on only for a server that has the grant-nothing password proof and reports the password
    /// counter. While off, no record is enrolled and no proof route is called; the screen lock
    /// (platform verification) and the vault lock work without it.
    pub lock_password_path: bool,
}

impl ClientConfig {
    pub fn new(name: impl Into<String>, version: impl Into<String>, app_id: impl Into<String>) -> Self {
        Self {
            identity: ClientIdentity::new(name, version),
            app_id: app_id.into(),
            event_capacity: 64,
            lock_password_path: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self::new("test-client", "1", "test-app")
    }
}

struct Authentication {
    token: Zeroizing<String>,
    expected_user: String,
    master_key: Option<MasterKey>,
    generation: u64,
}

/// A zeroizing snapshot of the installed account key and the account
/// generation it belongs to.
pub struct SessionKey {
    master_key: MasterKey,
    generation: u64,
}

impl SessionKey {
    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn is_current(&self, client: &Client) -> bool {
        self.generation == client.generation()
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("master_key", &"[REDACTED]")
            .field("generation", &self.generation)
            .finish()
    }
}

enum RequestAuthentication<'a> {
    CurrentSession,
    Bearer(&'a str),
}

pub struct Client {
    config: ClientConfig,
    transport: Arc<dyn Transport>,
    authentication: Mutex<Option<Authentication>>,
    generation: AtomicU64,
    events: EngineEvents,
    /// The two-level lock of this app process. Never locked together with `authentication`.
    lock: Mutex<LockFlow>,
}

/// What a native client declares. The request builder attaches it only to the
/// routes whose server behaviour it gates (`Endpoint::capabilities`), never to
/// every request.
const NATIVE_CAPABILITIES: [&str; 2] = ["file-write-v2", "version-metadata-v1"];

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("the account changed while work was running")]
    StaleAccount,
    #[error("client state is unavailable")]
    State,
    #[error("authentication values are invalid")]
    InvalidAuthentication,
    #[error("the application identifier is invalid")]
    InvalidAppId,
    /// The vault is closed: only the strong unlock installs a session.
    #[error("the vault is closed until the account password is proven")]
    VaultClosed,
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Api(#[from] ApiError),
}

impl Client {
    /// The client labels every request carries.
    pub(crate) fn identity(&self) -> &beebeeb_api::ClientIdentity {
        &self.config.identity
    }

    fn request_builder(&self) -> RequestBuilder {
        RequestBuilder::new(self.config.identity.clone()).with_capabilities(NATIVE_CAPABILITIES)
    }

    pub fn new(config: ClientConfig, transport: Arc<dyn Transport>) -> Result<Self, ClientError> {
        if !crate::session::valid_app_id(&config.app_id) {
            return Err(ClientError::InvalidAppId);
        }
        Ok(Self {
            events: EngineEvents::new(config.event_capacity),
            config,
            transport,
            authentication: Mutex::new(None),
            generation: AtomicU64::new(0),
            lock: Mutex::new(LockFlow::at_start(StartFacts {
                session_stored: false,
                ask_password_at_start: Some(false),
                vault_closed: Some(false),
            })),
        })
    }

    #[cfg(feature = "native-transport")]
    pub fn with_reqwest(config: ClientConfig, api_base: &str) -> Result<Self, ClientError> {
        Self::new(config, Arc::new(crate::ReqwestTransport::new(api_base)?))
    }

    pub fn events(&self) -> EngineEvents {
        self.events.clone()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(crate) fn app_id(&self) -> &str {
        &self.config.app_id
    }

    pub(crate) fn reported_device_name(&self) -> &str {
        self.config.identity.name()
    }

    pub(crate) fn reported_client_version(&self) -> &str {
        self.config.identity.version()
    }

    pub(crate) fn reported_platform(&self) -> &str {
        self.config.identity.os().unwrap_or(std::env::consts::OS)
    }

    pub(crate) fn set_authentication(
        &self,
        token: impl Into<String>,
        expected_user: impl Into<String>,
    ) -> Result<u64, ClientError> {
        let token = token.into();
        let expected_user = expected_user.into();
        if token.is_empty() || expected_user.is_empty() {
            return Err(ClientError::InvalidAuthentication);
        }
        let mut authentication = self.authentication.lock().map_err(|_| ClientError::State)?;
        let generation = self.advance_generation();
        *authentication = Some(Authentication {
            token: Zeroizing::new(token),
            expected_user,
            master_key: None,
            generation,
        });
        Ok(generation)
    }

    /// The lock state of this app process. A host that installs sessions itself with
    /// [`Self::set_session`] and never starts the lock (`start_from_store`) reads `SignedOut`
    /// here until a sign-in or unlock runs through core. A poisoned state reads as closed.
    pub fn lock_state(&self) -> LockState {
        self.lock
            .lock()
            .map(|flow| flow.state())
            .unwrap_or(LockState::VaultClosed)
    }

    pub(crate) fn lock_password_path(&self) -> bool {
        self.config.lock_password_path
    }

    pub(crate) fn with_lock_flow<R>(&self, step: impl FnOnce(&mut LockFlow) -> R) -> Result<R, ClientError> {
        let mut flow = self.lock.lock().map_err(|_| ClientError::State)?;
        Ok(step(&mut flow))
    }

    /// Installs a restored session. Refused while the vault is closed: a closed vault is
    /// opened only by the strong unlock (`unlock_known_device`), never by a restore.
    pub fn set_session(&self, session: &Session) -> Result<u64, ClientError> {
        if self.lock_state() == LockState::VaultClosed {
            return Err(ClientError::VaultClosed);
        }
        self.install_session(session)
    }

    pub(crate) fn install_session(&self, session: &Session) -> Result<u64, ClientError> {
        let mut authentication = self.authentication.lock().map_err(|_| ClientError::State)?;
        let generation = self.advance_generation();
        let key_bytes = Zeroizing::new(*session.master_key().to_bytes());
        *authentication = Some(Authentication {
            token: Zeroizing::new(session.token().to_owned()),
            expected_user: session.owner().to_owned(),
            master_key: Some(MasterKey::from_bytes(*key_bytes)),
            generation,
        });
        Ok(generation)
    }

    pub fn session_key(&self) -> Result<SessionKey, ClientError> {
        let authentication = self.authentication.lock().map_err(|_| ClientError::State)?;
        let authentication = authentication.as_ref().ok_or(ClientError::InvalidAuthentication)?;
        if authentication.generation != self.generation() {
            return Err(ClientError::StaleAccount);
        }
        let master_key = authentication
            .master_key
            .as_ref()
            .ok_or(ClientError::InvalidAuthentication)?;
        let key_bytes = Zeroizing::new(*master_key.to_bytes());
        Ok(SessionKey {
            master_key: MasterKey::from_bytes(*key_bytes),
            generation: authentication.generation,
        })
    }

    #[cfg(test)]
    pub(crate) fn set_session_key_for_test(&self, key: Arc<MasterKey>) -> Result<(), ClientError> {
        let key_bytes = Zeroizing::new(*key.to_bytes());
        let mut authentication = self.authentication.lock().map_err(|_| ClientError::State)?;
        match authentication.as_mut() {
            Some(authentication) => {
                authentication.master_key = Some(MasterKey::from_bytes(*key_bytes));
                authentication.generation = self.generation();
            }
            None => {
                *authentication = Some(Authentication {
                    token: Zeroizing::new("test-token".into()),
                    expected_user: "test-owner".into(),
                    master_key: Some(MasterKey::from_bytes(*key_bytes)),
                    generation: self.generation(),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn authenticated_owner(&self) -> Result<String, ClientError> {
        self.authentication
            .lock()
            .map_err(|_| ClientError::State)?
            .as_ref()
            .map(|authentication| authentication.expected_user.clone())
            .ok_or(ClientError::InvalidAuthentication)
    }

    pub fn account_id(&self) -> Result<String, ClientError> {
        self.authenticated_owner()
    }

    /// Drops the key and the token. An app that held the key (`Open`, `ScreenLocked`) is left
    /// with a closed vault: the stored session is still there, and only the strong unlock
    /// loads its key again. A sign-out follows with [`Self::sign_out_authentication`].
    pub(crate) fn clear_authentication(&self) -> Result<u64, ClientError> {
        *self.authentication.lock().map_err(|_| ClientError::State)? = None;
        let generation = self.advance_generation();
        self.with_lock_flow(LockFlow::session_ended)?;
        self.events.emit(EngineEvent::WorkStopped);
        Ok(generation)
    }

    /// [`Self::clear_authentication`] for a sign-out: the app is signed out, not closed.
    pub(crate) fn sign_out_authentication(&self) -> Result<u64, ClientError> {
        let generation = self.clear_authentication();
        self.with_lock_flow(LockFlow::signed_out)?;
        generation
    }

    /// Takes the session out of this process for a vault lock: the key is wiped here, the
    /// generation advances (every key copy handed out is stale and wiped when its holder
    /// drops it), work stops. Returns the new generation and the token, which the caller may
    /// use for one request only: ending that session at the server.
    #[cfg(feature = "auth")]
    pub(crate) fn drop_key_for_vault_lock(&self) -> Result<(u64, Option<Zeroizing<String>>), ClientError> {
        let taken = self.authentication.lock().map_err(|_| ClientError::State)?.take();
        let token = taken.map(|mut authentication| {
            authentication.master_key = None;
            std::mem::take(&mut authentication.token)
        });
        let generation = self.advance_generation();
        self.events.emit(EngineEvent::WorkStopped);
        Ok((generation, token))
    }

    /// The server no longer accepts this session. The event is the host's signal; the arrow
    /// is core's: an app that held the key drops it and is left with a closed vault. A host
    /// that never ran a sign-in or the lock start through core (`SignedOut`) is left as it is.
    fn session_expired(&self) {
        if matches!(self.lock_state(), LockState::Open | LockState::ScreenLocked) {
            if let Ok(mut authentication) = self.authentication.lock() {
                *authentication = None;
            }
            self.advance_generation();
            let _ = self.with_lock_flow(LockFlow::session_ended);
            self.events.emit(EngineEvent::WorkStopped);
        }
        self.events.emit(EngineEvent::SessionExpired);
    }

    /// Invalidate in-flight work while retaining the current credentials long
    /// enough to finish the server-side sign-out request.
    #[cfg(all(
        feature = "store",
        feature = "uploads",
        feature = "downloads",
        feature = "thumbnails",
        feature = "backup",
        feature = "search",
        feature = "auth"
    ))]
    pub(crate) fn stop_account_work(&self) -> u64 {
        let generation = self.advance_generation();
        self.events.emit(EngineEvent::WorkStopped);
        generation
    }

    fn advance_generation(&self) -> u64 {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel).saturating_add(1);
        self.events.emit(EngineEvent::AccountChanged { generation });
        generation
    }

    pub(crate) async fn execute<Req, Res>(&self, endpoint: &Endpoint<Req, Res>, body: &Req) -> Result<Res, ClientError>
    where
        Req: Serialize,
        Res: DeserializeOwned,
    {
        self.execute_inner(endpoint, body, None, RequestAuthentication::CurrentSession, None)
            .await
    }

    pub(crate) async fn execute_for_generation<Req, Res>(
        &self,
        endpoint: &Endpoint<Req, Res>,
        body: &Req,
        generation: u64,
    ) -> Result<Res, ClientError>
    where
        Req: Serialize,
        Res: DeserializeOwned,
    {
        self.execute_inner(
            endpoint,
            body,
            None,
            RequestAuthentication::CurrentSession,
            Some(generation),
        )
        .await
    }

    /// Sends only the server-side logout after account work has already been
    /// invalidated. No other request may use retired credentials.
    #[cfg(any(feature = "auth", feature = "devices"))]
    pub(crate) async fn execute_retired_logout(
        &self,
    ) -> Result<beebeeb_api::routes::auth::LogoutResponse, ClientError> {
        let endpoint = beebeeb_api::routes::auth::logout();
        let builder = {
            let authentication = self.authentication.lock().map_err(|_| ClientError::State)?;
            let authentication = authentication.as_ref().ok_or(ClientError::InvalidAuthentication)?;
            self.request_builder()
                .with_auth(authentication.token.as_str(), authentication.expected_user.clone())
        };
        let request = endpoint.build(&builder, &())?;
        let answer = self.transport.send(request, endpoint.max_response_bytes()).await?;
        endpoint.parse(answer).map_err(ClientError::Api)
    }

    pub(crate) async fn execute_confirmed<Req, Res>(
        &self,
        endpoint: &Endpoint<Req, Res>,
        body: &Req,
        confirmation: &str,
    ) -> Result<Res, ClientError>
    where
        Req: Serialize,
        Res: DeserializeOwned,
    {
        self.execute_inner(
            endpoint,
            body,
            Some(confirmation),
            RequestAuthentication::CurrentSession,
            None,
        )
        .await
    }

    pub(crate) async fn execute_bearer<Req, Res>(
        &self,
        endpoint: &Endpoint<Req, Res>,
        body: &Req,
        bearer: &str,
    ) -> Result<Res, ClientError>
    where
        Req: Serialize,
        Res: DeserializeOwned,
    {
        self.execute_inner(endpoint, body, None, RequestAuthentication::Bearer(bearer), None)
            .await
    }

    /// [`Self::execute`], with the answer's `Date` header: the server's clock
    /// when it answered (second precision), `None` when the answer had none.
    #[cfg(feature = "backup")]
    pub(crate) async fn execute_with_date<Req, Res>(
        &self,
        endpoint: &Endpoint<Req, Res>,
        body: &Req,
    ) -> Result<(Res, Option<String>), ClientError>
    where
        Req: Serialize,
        Res: DeserializeOwned,
    {
        let (answer, headers) = self
            .execute_inner_with_headers(endpoint, body, None, RequestAuthentication::CurrentSession, None)
            .await?;
        let date = headers
            .into_iter()
            .find(|header| header.name.eq_ignore_ascii_case("date"))
            .map(|header| header.value);
        Ok((answer, date))
    }

    async fn execute_inner<Req, Res>(
        &self,
        endpoint: &Endpoint<Req, Res>,
        body: &Req,
        confirmation: Option<&str>,
        request_authentication: RequestAuthentication<'_>,
        required_generation: Option<u64>,
    ) -> Result<Res, ClientError>
    where
        Req: Serialize,
        Res: DeserializeOwned,
    {
        self.execute_inner_with_headers(
            endpoint,
            body,
            confirmation,
            request_authentication,
            required_generation,
        )
        .await
        .map(|(answer, _)| answer)
    }

    async fn execute_inner_with_headers<Req, Res>(
        &self,
        endpoint: &Endpoint<Req, Res>,
        body: &Req,
        confirmation: Option<&str>,
        request_authentication: RequestAuthentication<'_>,
        required_generation: Option<u64>,
    ) -> Result<(Res, Vec<beebeeb_api::Header>), ClientError>
    where
        Req: Serialize,
        Res: DeserializeOwned,
    {
        let captured_generation = required_generation.unwrap_or_else(|| self.generation());
        let (mut builder, session_credentials_present) = match request_authentication {
            RequestAuthentication::CurrentSession => {
                let authentication = self.authentication.lock().map_err(|_| ClientError::State)?;
                match authentication.as_ref() {
                    Some(authentication) if authentication.generation != captured_generation => {
                        return Err(ClientError::StaleAccount);
                    }
                    Some(authentication) => (
                        self.request_builder()
                            .with_auth(authentication.token.as_str(), authentication.expected_user.clone()),
                        true,
                    ),
                    None => (self.request_builder(), false),
                }
            }
            RequestAuthentication::Bearer(token) => (self.request_builder().with_bearer(token), false),
        };
        if let Some(confirmation) = confirmation {
            builder = builder.with_confirmation(confirmation);
        }
        let request = endpoint.build(&builder, body)?;
        let carried_session_authentication = session_credentials_present && request.header("Authorization").is_some();
        let answer = self.transport.send(request, endpoint.max_response_bytes()).await?;
        if captured_generation != self.generation() {
            return Err(ClientError::StaleAccount);
        }
        let headers = answer.headers.clone();
        match endpoint.parse(answer) {
            Err(ApiError::Server(error)) if error.is_code("account_mismatch") => {
                self.events.emit(EngineEvent::AccountMismatch);
                Err(ClientError::Api(ApiError::Server(error)))
            }
            Err(ApiError::Server(error))
                if error.status == 401 && carried_session_authentication && !endpoint.is_step_up() =>
            {
                self.session_expired();
                Err(ClientError::Api(ApiError::Server(error)))
            }
            result => result.map(|parsed| (parsed, headers)).map_err(ClientError::Api),
        }
    }

    /// Send one request of a core share flow (`beebeeb_core::share_flow`) as the flow built it, on
    /// the session of account `generation`, and give the flow the server's answer whatever its
    /// status: the flow reads its own refusals. An account mismatch, or a 401 to the session's
    /// credentials, is the client's to report as on every other request, and never reaches the flow.
    #[cfg(feature = "shares")]
    pub(crate) async fn execute_share_flow(
        &self,
        request: beebeeb_core::auth_flow::HttpRequest,
        generation: u64,
    ) -> Result<beebeeb_core::auth_flow::HttpResponse, ClientError> {
        let flow = beebeeb_api::FlowRequest::new(request);
        let (builder, session_credentials_present) = {
            let authentication = self.authentication.lock().map_err(|_| ClientError::State)?;
            match authentication.as_ref() {
                Some(authentication) if authentication.generation != generation => {
                    return Err(ClientError::StaleAccount);
                }
                Some(authentication) => (
                    self.request_builder()
                        .with_auth(authentication.token.as_str(), authentication.expected_user.clone()),
                    true,
                ),
                None => (self.request_builder(), false),
            }
        };
        let request = flow.build(builder)?;
        let carried_session_authentication = session_credentials_present && request.header("Authorization").is_some();
        let answer = self.transport.send(request, flow.max_response_bytes()).await?;
        if generation != self.generation() {
            return Err(ClientError::StaleAccount);
        }
        if !(200..=299).contains(&answer.status) {
            let error =
                beebeeb_core::api_error::ServerError::parse_body(answer.status, &String::from_utf8_lossy(&answer.body));
            if error.is_code("account_mismatch") {
                self.events.emit(EngineEvent::AccountMismatch);
                return Err(ClientError::Api(ApiError::Server(error)));
            }
            if error.status == 401 && carried_session_authentication {
                self.session_expired();
                return Err(ClientError::Api(ApiError::Server(error)));
            }
        }
        flow.answer(answer).map_err(ClientError::Api)
    }

    #[cfg(all(feature = "store", any(feature = "downloads", feature = "thumbnails")))]
    pub(crate) async fn execute_raw<Req>(&self, endpoint: &RawEndpoint<Req>, body: &Req) -> Result<Vec<u8>, ClientError>
    where
        RawEndpoint<Req>: RawRequest<Req>,
    {
        self.execute_raw_inner(endpoint, body, None).await
    }

    #[cfg(all(feature = "store", any(feature = "downloads", feature = "thumbnails")))]
    pub(crate) async fn execute_raw_for_generation<Req>(
        &self,
        endpoint: &RawEndpoint<Req>,
        body: &Req,
        generation: u64,
    ) -> Result<Vec<u8>, ClientError>
    where
        RawEndpoint<Req>: RawRequest<Req>,
    {
        self.execute_raw_inner(endpoint, body, Some(generation)).await
    }

    #[cfg(all(feature = "store", any(feature = "downloads", feature = "thumbnails")))]
    async fn execute_raw_inner<Req>(
        &self,
        endpoint: &RawEndpoint<Req>,
        body: &Req,
        required_generation: Option<u64>,
    ) -> Result<Vec<u8>, ClientError>
    where
        RawEndpoint<Req>: RawRequest<Req>,
    {
        let captured_generation = required_generation.unwrap_or_else(|| self.generation());
        let builder = {
            let authentication = self.authentication.lock().map_err(|_| ClientError::State)?;
            match authentication.as_ref() {
                Some(authentication) if authentication.generation != captured_generation => {
                    return Err(ClientError::StaleAccount);
                }
                Some(authentication) => self
                    .request_builder()
                    .with_auth(authentication.token.as_str(), authentication.expected_user.clone()),
                None => self.request_builder(),
            }
        };
        let request = endpoint.build_raw(&builder, body)?;
        let answer = self.transport.send(request, endpoint.max_response_bytes()).await?;
        if captured_generation != self.generation() {
            return Err(ClientError::StaleAccount);
        }
        match endpoint.parse(answer) {
            Err(ApiError::Server(error)) if error.is_code("account_mismatch") => {
                self.events.emit(EngineEvent::AccountMismatch);
                Err(ClientError::Api(ApiError::Server(error)))
            }
            Err(ApiError::Server(error)) if error.status == 401 => {
                self.session_expired();
                Err(ClientError::Api(ApiError::Server(error)))
            }
            result => result.map_err(ClientError::Api),
        }
    }

    #[cfg(all(feature = "store", any(feature = "downloads", feature = "thumbnails")))]
    pub(crate) async fn execute_raw_bounded_for_generation<Req>(
        &self,
        endpoint: &RawEndpoint<Req>,
        body: &Req,
        max_response_bytes: usize,
        generation: u64,
    ) -> Result<Vec<u8>, ClientError>
    where
        RawEndpoint<Req>: RawRequest<Req>,
    {
        let captured_generation = generation;
        let builder = {
            let authentication = self.authentication.lock().map_err(|_| ClientError::State)?;
            match authentication.as_ref() {
                Some(authentication) if authentication.generation != captured_generation => {
                    return Err(ClientError::StaleAccount);
                }
                Some(authentication) => self
                    .request_builder()
                    .with_auth(authentication.token.as_str(), authentication.expected_user.clone()),
                None => self.request_builder(),
            }
        };
        let request = endpoint.build_raw(&builder, body)?;
        let answer = self
            .transport
            .send_progress(request, max_response_bytes, Duration::from_secs(30))
            .await?;
        if captured_generation != self.generation() {
            return Err(ClientError::StaleAccount);
        }
        match endpoint.parse(answer) {
            Err(ApiError::Server(error)) if error.is_code("account_mismatch") => {
                self.events.emit(EngineEvent::AccountMismatch);
                Err(ClientError::Api(ApiError::Server(error)))
            }
            Err(ApiError::Server(error)) if error.status == 401 => {
                self.session_expired();
                Err(ClientError::Api(ApiError::Server(error)))
            }
            result => result.map_err(ClientError::Api),
        }
    }

    #[cfg(feature = "sync")]
    pub(crate) async fn execute_stream(
        &self,
        endpoint: &RawEndpoint<()>,
        limits: StreamLimits,
    ) -> Result<StreamBatch, ClientError> {
        let captured_generation = self.generation();
        let builder = {
            let authentication = self.authentication.lock().map_err(|_| ClientError::State)?;
            match authentication.as_ref() {
                Some(authentication) if authentication.generation != captured_generation => {
                    return Err(ClientError::StaleAccount);
                }
                Some(authentication) => self
                    .request_builder()
                    .with_auth(authentication.token.as_str(), authentication.expected_user.clone()),
                None => self.request_builder(),
            }
        };
        let request = endpoint.build(&builder, &())?;
        let carried_session_authentication = request.header("Authorization").is_some();
        let response = self.transport.stream(request, limits).await?;
        if captured_generation != self.generation() {
            return Err(ClientError::StaleAccount);
        }
        match response {
            StreamResponse::Batch(batch) => Ok(batch),
            StreamResponse::Http(answer) => match endpoint.parse(answer) {
                Err(ApiError::Server(error)) if error.is_code("account_mismatch") => {
                    self.events.emit(EngineEvent::AccountMismatch);
                    Err(ClientError::Api(ApiError::Server(error)))
                }
                Err(ApiError::Server(error)) if error.status == 401 && carried_session_authentication => {
                    self.session_expired();
                    Err(ClientError::Api(ApiError::Server(error)))
                }
                Err(error) => Err(ClientError::Api(error)),
                Ok(_) => Err(ClientError::State),
            },
        }
    }
}

#[cfg(all(feature = "store", any(feature = "downloads", feature = "thumbnails")))]
pub(crate) trait RawRequest<Req> {
    fn build_raw(&self, builder: &RequestBuilder, body: &Req) -> Result<beebeeb_api::Request, ApiError>;
}

#[cfg(all(feature = "store", any(feature = "downloads", feature = "thumbnails")))]
impl RawRequest<()> for RawEndpoint<()> {
    fn build_raw(&self, builder: &RequestBuilder, body: &()) -> Result<beebeeb_api::Request, ApiError> {
        self.build(builder, body)
    }
}

#[cfg(all(feature = "store", any(feature = "downloads", feature = "thumbnails")))]
impl RawRequest<Vec<u8>> for RawEndpoint<Vec<u8>> {
    fn build_raw(&self, builder: &RequestBuilder, body: &Vec<u8>) -> Result<beebeeb_api::Request, ApiError> {
        self.build(builder, body)
    }
}
