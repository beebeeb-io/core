//! What a client does with an unfinished upload it finds on disk (task 2173, clients plan A1, decision D25).
//!
//! A session's transport never changes after init, so a recorded **direct** session is continued
//! direct and given up only on a *definite no*: the user forced the API, or the server says it offers
//! no direct uploads (a discovery that lists none, or a JSON 404). It is **never** given up because
//! discovery could not be read this time: a 5xx, a timeout or a bare 404 says nothing about the
//! session, and abandoning a half-finished upload for it would throw its progress away (cli#105
//! P2-2). A 401/403 on discovery keeps the record and sends the user to sign in again. One pure
//! function, so four clients do not each write this by hand.

/// The transport a resume record names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordedTransport {
    Api,
    Direct,
}

impl RecordedTransport {
    /// `"api"` or `"direct"` (bindings and vectors); anything else is `None`.
    pub fn from_code(code: &str) -> Option<RecordedTransport> {
        match code {
            "api" => Some(RecordedTransport::Api),
            "direct" => Some(RecordedTransport::Direct),
            _ => None,
        }
    }
}

/// What the client learned from discovery when it asked just now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryState {
    /// The server answered. `upload`: it lists the direct upload transport.
    Offers { upload: bool },
    /// A JSON 404: the server has no direct transfer at all.
    NotSupported,
    /// No usable answer (a 5xx, a timeout, a bare 404, a body that did not decode).
    Unknown,
    /// 401 or 403: the login is not valid.
    Unauthorized,
}

impl DiscoveryState {
    /// Build one from the machine names bindings use: `offers` (needs `upload`), `not_supported`,
    /// `unknown`, `unauthorized`. `None` for anything else, or for `offers` with no flag.
    pub fn from_parts(kind: &str, upload: Option<bool>) -> Option<DiscoveryState> {
        match (kind, upload) {
            ("offers", Some(upload)) => Some(DiscoveryState::Offers { upload }),
            ("not_supported", _) => Some(DiscoveryState::NotSupported),
            ("unknown", _) => Some(DiscoveryState::Unknown),
            ("unauthorized", _) => Some(DiscoveryState::Unauthorized),
            _ => None,
        }
    }
}

/// What to do with the unfinished upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeAction {
    /// Continue the session on the API.
    ContinueApi,
    /// Continue the session direct.
    ContinueDirect,
    /// Give the direct session up: abandon it, clear the record, and start again on the API.
    AbandonToApi,
    /// Keep the record and fail the file for this run; the next run asks again.
    KeepRecordAndFail,
    /// Keep the record and ask the user to sign in again.
    KeepRecordAndReauthenticate,
}

impl ResumeAction {
    /// Stable machine name (bindings and vectors).
    pub fn code(self) -> &'static str {
        match self {
            ResumeAction::ContinueApi => "continue_api",
            ResumeAction::ContinueDirect => "continue_direct",
            ResumeAction::AbandonToApi => "abandon_to_api",
            ResumeAction::KeepRecordAndFail => "keep_record_and_fail",
            ResumeAction::KeepRecordAndReauthenticate => "keep_record_and_reauthenticate",
        }
    }
}

/// The rule: see the module docs. `forced_api` is the user's own switch (`--transport api`,
/// `BB_TRANSPORT=api`, a support setting).
pub fn resume_transport(recorded: RecordedTransport, discovery: DiscoveryState, forced_api: bool) -> ResumeAction {
    match recorded {
        RecordedTransport::Api => ResumeAction::ContinueApi,
        RecordedTransport::Direct if forced_api => ResumeAction::AbandonToApi,
        RecordedTransport::Direct => match discovery {
            DiscoveryState::Offers { upload: true } => ResumeAction::ContinueDirect,
            DiscoveryState::Offers { upload: false } | DiscoveryState::NotSupported => ResumeAction::AbandonToApi,
            DiscoveryState::Unknown => ResumeAction::KeepRecordAndFail,
            DiscoveryState::Unauthorized => ResumeAction::KeepRecordAndReauthenticate,
        },
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    const ALL_DISCOVERY: [DiscoveryState; 5] = [
        DiscoveryState::Offers { upload: true },
        DiscoveryState::Offers { upload: false },
        DiscoveryState::NotSupported,
        DiscoveryState::Unknown,
        DiscoveryState::Unauthorized,
    ];

    #[test]
    fn only_a_definite_no_abandons_a_recorded_direct_session() {
        use RecordedTransport::Direct;
        let go = |d, forced| resume_transport(Direct, d, forced);
        assert_eq!(
            go(DiscoveryState::Offers { upload: true }, false),
            ResumeAction::ContinueDirect
        );
        assert_eq!(
            go(DiscoveryState::Offers { upload: false }, false),
            ResumeAction::AbandonToApi
        );
        assert_eq!(go(DiscoveryState::NotSupported, false), ResumeAction::AbandonToApi);
        assert_eq!(
            go(DiscoveryState::Unknown, false),
            ResumeAction::KeepRecordAndFail,
            "a 5xx, a timeout or a bare 404 is not a no"
        );
        assert_eq!(
            go(DiscoveryState::Unauthorized, false),
            ResumeAction::KeepRecordAndReauthenticate
        );
    }

    #[test]
    fn forcing_the_api_abandons_a_direct_session_whatever_discovery_says() {
        for d in ALL_DISCOVERY {
            assert_eq!(
                resume_transport(RecordedTransport::Direct, d, true),
                ResumeAction::AbandonToApi,
                "{d:?}"
            );
        }
    }

    #[test]
    fn an_api_session_always_continues_on_the_api() {
        for d in ALL_DISCOVERY {
            for forced in [false, true] {
                assert_eq!(
                    resume_transport(RecordedTransport::Api, d, forced),
                    ResumeAction::ContinueApi,
                    "{d:?} forced={forced}"
                );
            }
        }
    }

    #[test]
    fn the_codes_are_stable_and_round_trip() {
        assert_eq!(RecordedTransport::from_code("api"), Some(RecordedTransport::Api));
        assert_eq!(RecordedTransport::from_code("direct"), Some(RecordedTransport::Direct));
        for bad in ["", "Api", "object-upload-v1", "s3"] {
            assert_eq!(RecordedTransport::from_code(bad), None, "{bad:?}");
        }
        assert_eq!(
            DiscoveryState::from_parts("offers", Some(true)),
            Some(DiscoveryState::Offers { upload: true })
        );
        assert_eq!(
            DiscoveryState::from_parts("offers", Some(false)),
            Some(DiscoveryState::Offers { upload: false })
        );
        assert_eq!(
            DiscoveryState::from_parts("offers", None),
            None,
            "offers needs its flag"
        );
        assert_eq!(
            DiscoveryState::from_parts("not_supported", None),
            Some(DiscoveryState::NotSupported)
        );
        assert_eq!(
            DiscoveryState::from_parts("unknown", None),
            Some(DiscoveryState::Unknown)
        );
        assert_eq!(
            DiscoveryState::from_parts("unauthorized", None),
            Some(DiscoveryState::Unauthorized)
        );
        assert_eq!(DiscoveryState::from_parts("nope", None), None);
        let codes: Vec<&str> = [
            ResumeAction::ContinueApi,
            ResumeAction::ContinueDirect,
            ResumeAction::AbandonToApi,
            ResumeAction::KeepRecordAndFail,
            ResumeAction::KeepRecordAndReauthenticate,
        ]
        .iter()
        .map(|a| a.code())
        .collect();
        assert_eq!(
            codes,
            [
                "continue_api",
                "continue_direct",
                "abandon_to_api",
                "keep_record_and_fail",
                "keep_record_and_reauthenticate"
            ]
        );
    }
}
