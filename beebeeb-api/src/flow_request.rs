//! The requests of core's sans-IO flows (`beebeeb_core::share_flow`).
//!
//! A flow decides the verb, the path and the JSON body of every request it needs. [`FlowRequest`]
//! carries one to a transport as the flow built it, so a share body is never rebuilt from a record
//! of this crate, and hands the flow the server's answer whatever its status
//! ([`FlowRequest::answer`]): a flow reads its own refusals (a taken token or id, a typed `409`).

use beebeeb_core::auth_flow::{self, HttpRequest, HttpResponse, RequestAuth};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::{Answer, ApiError, Endpoint, Method, Request, RequestBuilder, endpoint::enforce_limit};

/// One request of a core flow, ready for a transport.
pub struct FlowRequest {
    endpoint: Endpoint<Value, ()>,
    body: Value,
    confirm_token: Option<Zeroizing<String>>,
}

impl FlowRequest {
    /// `request` as the flow built it, with the confirm token a step-up put on it, if any.
    pub fn new(mut request: HttpRequest) -> Self {
        let method = match request.method {
            auth_flow::Method::Get => Method::Get,
            auth_flow::Method::Post => Method::Post,
            auth_flow::Method::Put => Method::Put,
            auth_flow::Method::Patch => Method::Patch,
            auth_flow::Method::Delete => Method::Delete,
        };
        let body = request.body.take();
        let mut endpoint = Endpoint::new(method, std::mem::take(&mut request.path), body.is_some());
        if request.auth == RequestAuth::None {
            endpoint = endpoint.public();
        }
        Self {
            endpoint,
            body: body.unwrap_or(Value::Null),
            confirm_token: request
                .confirm_token_header()
                .map(|token| Zeroizing::new(token.to_owned())),
        }
    }

    /// The transport-neutral request, on `builder`'s session when the flow asks for it. A confirm
    /// token goes through `builder` (`X-Confirm-Token`), the one path every confirmed request takes.
    pub fn build(&self, builder: RequestBuilder) -> Result<Request, ApiError> {
        let builder = match &self.confirm_token {
            Some(token) => builder.with_confirmation(token.as_str()),
            None => builder,
        };
        self.endpoint.build(&builder, &self.body)
    }

    pub fn max_response_bytes(&self) -> usize {
        self.endpoint.max_response_bytes()
    }

    /// The server's answer for the flow, whatever its status: the JSON body (`Null` when it is empty
    /// or not JSON) and the `Retry-After` delay.
    pub fn answer(&self, answer: Answer) -> Result<HttpResponse, ApiError> {
        enforce_limit(&answer, self.endpoint.max_response_bytes())?;
        let retry_after_secs = answer
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("retry-after"))
            .and_then(|header| beebeeb_core::retry::parse_retry_after(&header.value));
        Ok(HttpResponse {
            status: answer.status,
            body: serde_json::from_slice(&answer.body).unwrap_or(Value::Null),
            retry_after_secs,
        })
    }
}

impl Drop for FlowRequest {
    /// A share body carries a link's token and passphrase; the bytes sent are wiped by [`Request`].
    fn drop(&mut self) {
        wipe_strings(&mut self.body);
    }
}

fn wipe_strings(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe_strings),
        Value::Object(fields) => fields.values_mut().for_each(wipe_strings),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientIdentity, Header};
    use beebeeb_core::share_flow::{self, link::CreateLink, link::LinkOptions};
    use serde_json::json;

    const FILE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn builder() -> RequestBuilder {
        RequestBuilder::new(ClientIdentity::new("desktop", "1"))
            .with_auth("session-token", "32e1e894-5249-4ca1-995b-0f031d52b26f")
    }

    #[test]
    fn a_flow_request_is_sent_as_the_flow_built_it_on_the_session() {
        let master = beebeeb_core::kdf::MasterKey::from_bytes([1; 32]);
        let file_key = beebeeb_core::kdf::FileKey::from_bytes([7; 32]);
        let (_, request) = CreateLink::start(
            "https://app.beebeeb.test",
            FILE,
            &master,
            &file_key,
            &LinkOptions::default(),
        )
        .unwrap();
        let expected = request.body.clone().unwrap();

        let sent = FlowRequest::new(request).build(builder()).unwrap();

        assert_eq!(sent.method(), Method::Post);
        assert_eq!(sent.path(), share_flow::link::SHARES_PATH);
        assert_eq!(sent.header("Authorization"), Some("Bearer session-token"));
        assert_eq!(sent.header("Content-Type"), Some("application/json"));
        assert_eq!(sent.header("X-Beebeeb-Capabilities"), None);
        let body: Value = serde_json::from_slice(sent.body()).unwrap();
        assert_eq!(body, expected);
        let printed = format!("{sent:?}");
        assert!(!printed.contains(expected["token"].as_str().unwrap()), "{printed}");
    }

    #[test]
    fn a_body_less_flow_request_sends_no_body() {
        let revoke = share_flow::revoke_link_request("7a1d1c2e-0000-4000-8000-000000000001").unwrap();

        let sent = FlowRequest::new(revoke).build(builder()).unwrap();

        assert_eq!(sent.method(), Method::Delete);
        assert_eq!(sent.path(), "/api/v1/shares/7a1d1c2e-0000-4000-8000-000000000001");
        assert!(sent.body().is_empty());
    }

    #[test]
    fn every_answer_reaches_the_flow_with_its_status_body_and_delay() {
        let flow = FlowRequest::new(share_flow::revoke_link_request("7a1d1c2e-0000-4000-8000-000000000001").unwrap());

        let refused = flow
            .answer(Answer::new(
                429,
                vec![Header::new("Retry-After", "17")],
                br#"{"error":"rate_limited"}"#.to_vec(),
            ))
            .unwrap();
        assert_eq!((refused.status, refused.retry_after_secs), (429, Some(17)));
        assert_eq!(refused.body, json!({"error": "rate_limited"}));

        let empty = flow.answer(Answer::new(204, vec![], Vec::new())).unwrap();
        assert_eq!((empty.status, empty.body), (204, Value::Null));
        let not_json = flow
            .answer(Answer::new(502, vec![], b"<html>bad gateway</html>".to_vec()))
            .unwrap();
        assert_eq!((not_json.status, not_json.body), (502, Value::Null));

        let oversized = Answer::new(200, vec![], vec![b' '; flow.max_response_bytes() + 1]);
        assert!(matches!(flow.answer(oversized), Err(ApiError::ResponseTooLarge { .. })));
    }

    #[test]
    fn every_string_of_a_body_is_wiped() {
        let mut body = json!({
            "token": "link-token-secret",
            "passphrase": "pass-phrase-secret",
            "folder_keys": [{"file_id": FILE, "encrypted_file_key": "wrap"}],
            "max_opens": 5,
        });

        wipe_strings(&mut body);

        assert_eq!(
            body,
            json!({
                "token": "",
                "passphrase": "",
                "folder_keys": [{"file_id": "", "encrypted_file_key": ""}],
                "max_opens": 5,
            })
        );
    }
}
