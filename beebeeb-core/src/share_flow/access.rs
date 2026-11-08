//! Changing a member's access on a person share: one `PATCH /shares/invites/{id}`.
use serde_json::json;

use super::{ShareFlowError, path_id};
use crate::auth_flow::{HttpRequest, RequestAuth};

/// A member's access, as the server accepts it (`read`, `add`, `write`, `admin`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberPermission {
    /// Can view.
    Read,
    /// Can add files, not change existing ones.
    Add,
    /// Can edit.
    Write,
    /// Can edit and manage members.
    Admin,
}

impl MemberPermission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Add => "add",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }

    /// The wire string back to the enum; anything else is `InvalidInput`.
    pub fn parse(s: &str) -> Result<Self, ShareFlowError> {
        match s {
            "read" => Ok(Self::Read),
            "add" => Ok(Self::Add),
            "write" => Ok(Self::Write),
            "admin" => Ok(Self::Admin),
            _ => Err(ShareFlowError::InvalidInput("permission")),
        }
    }
}

/// The request that sets an invite's permission.
pub fn set_member_access_request(invite_id: &str, permission: MemberPermission) -> Result<HttpRequest, ShareFlowError> {
    let id = path_id(invite_id)?;
    Ok(HttpRequest::patch(
        format!("/api/v1/shares/invites/{id}"),
        json!({ "permission": permission.as_str() }),
        RequestAuth::Session,
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{MemberPermission, set_member_access_request};
    use crate::auth_flow::{Method, RequestAuth};
    use crate::share_flow::ShareFlowError;

    #[test]
    fn access_change_is_a_patch_with_the_permission() {
        let id = "7f9e2d14-3a6b-4c8d-8e1f-2b4a6c8d0e12";
        let r = set_member_access_request(id, MemberPermission::Write).unwrap();
        assert_eq!(r.method, Method::Patch);
        assert_eq!(r.method.as_str(), "PATCH");
        assert_eq!(r.path, format!("/api/v1/shares/invites/{id}"));
        assert_eq!(r.body, Some(json!({ "permission": "write" })));
        assert_eq!(r.auth, RequestAuth::Session);
        let mut n = 0;
        for (p, s) in [
            (MemberPermission::Read, "read"),
            (MemberPermission::Add, "add"),
            (MemberPermission::Write, "write"),
            (MemberPermission::Admin, "admin"),
        ] {
            let r = set_member_access_request(id, p).unwrap();
            assert_eq!(r.body, Some(json!({ "permission": s })));
            assert_eq!(MemberPermission::parse(s), Ok(p));
            n += 1;
        }
        assert_eq!(n, 4);
        assert!(MemberPermission::parse("owner").is_err());
    }

    #[test]
    fn a_bad_invite_id_is_refused() {
        assert_eq!(
            set_member_access_request("../x", MemberPermission::Read).unwrap_err(),
            ShareFlowError::Protocol("bad id")
        );
    }
}
