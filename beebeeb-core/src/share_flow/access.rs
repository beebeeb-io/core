//! Changing a member's access on a person share: one `PATCH /shares/invites/{id}`.
use serde_json::json;

use super::{ShareFlowError, path_id};
use crate::auth_flow::{HttpRequest, RequestAuth};

/// The request that sets an invite's permission to `write` (can edit) or `read` (can view).
pub fn set_member_access_request(invite_id: &str, can_edit: bool) -> Result<HttpRequest, ShareFlowError> {
    let id = path_id(invite_id)?;
    Ok(HttpRequest::patch(
        format!("/api/v1/shares/invites/{id}"),
        json!({ "permission": if can_edit { "write" } else { "read" } }),
        RequestAuth::Session,
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::set_member_access_request;
    use crate::auth_flow::{Method, RequestAuth};
    use crate::share_flow::ShareFlowError;

    #[test]
    fn access_change_is_a_patch_with_the_permission() {
        let id = "7f9e2d14-3a6b-4c8d-8e1f-2b4a6c8d0e12";
        let r = set_member_access_request(id, true).unwrap();
        assert_eq!(r.method, Method::Patch);
        assert_eq!(r.method.as_str(), "PATCH");
        assert_eq!(r.path, format!("/api/v1/shares/invites/{id}"));
        assert_eq!(r.body, Some(json!({ "permission": "write" })));
        assert_eq!(r.auth, RequestAuth::Session);
        let r = set_member_access_request(id, false).unwrap();
        assert_eq!(r.body, Some(json!({ "permission": "read" })));
    }

    #[test]
    fn a_bad_invite_id_is_refused() {
        assert_eq!(
            set_member_access_request("../x", true).unwrap_err(),
            ShareFlowError::Protocol("bad id")
        );
    }
}
