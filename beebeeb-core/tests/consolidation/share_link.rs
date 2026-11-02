//! Move 9 — one share-link grammar (spec §16.2).
//!
//! Cases live in `test-vectors/consolidation/share_link.json`. The guard is
//! the legacy host and the standard-base64 `#key=` value: an old link must
//! parse, and `build` must not re-encode a value it was handed (§5.3 move 9).

use beebeeb_core::share_link::{ShareRoute, build, build_for, key_bytes, parse};

pub const CONCEPT: &str = "share_link";

fn hex_bytes(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap_or_else(|e| panic!("{value} is not hex: {e}"))
}

#[test]
fn share_link_cases_match_core() {
    let cases = super::cases(CONCEPT);
    let (mut built, mut parsed, mut rejected, mut keys) = (0, 0, 0, 0);

    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        match case["kind"].as_str().expect("case kind") {
            "build" => {
                built += 1;
                let app_url = case["app_url"].as_str().expect("app_url");
                let token = case["token"].as_str().expect("token");
                let key = case["key"].as_str().expect("key");
                let route = match case["route"].as_str().unwrap_or("s") {
                    "s" => ShareRoute::Single,
                    "f" => ShareRoute::Folder,
                    other => panic!("{id}: unknown route {other:?}"),
                };
                let expected = case["expected"].as_str().expect("expected link");
                assert_eq!(build_for(app_url, token, key, route), expected, "{id}: build_for");
                if route == ShareRoute::Single {
                    assert_eq!(build(app_url, token, key), expected, "{id}: build is the /s/ form");
                }
            }
            "parse" => {
                parsed += 1;
                let link = parse(case["url"].as_str().expect("url")).unwrap_or_else(|e| panic!("{id}: {e}"));
                let expected = &case["expected"];
                let route = match expected["route"].as_str().expect("route") {
                    "s" => ShareRoute::Single,
                    "f" => ShareRoute::Folder,
                    other => panic!("{id}: unknown expected route {other:?}"),
                };
                assert_eq!(
                    link.base_url,
                    expected["base_url"].as_str().expect("base_url"),
                    "{id}: base_url"
                );
                assert_eq!(link.route, route, "{id}: route");
                assert_eq!(link.token, expected["token"].as_str().expect("token"), "{id}: token");
                assert_eq!(link.key, expected["key"].as_str().expect("key"), "{id}: key");
                if let Some(key_hex) = expected["key_hex"].as_str() {
                    assert_eq!(key_bytes(&link.key), Some(hex_bytes(key_hex)), "{id}: key_bytes");
                }
                // The Debug impl is a log surface: the key never goes there.
                let debug = format!("{link:?}");
                assert!(
                    !debug.contains(link.key.as_str()),
                    "{id}: Debug must not contain the key: {debug}"
                );
                assert!(debug.contains("key: <redacted>"), "{id}: Debug must mark the key redacted");
            }
            "parse-error" => {
                rejected += 1;
                let err = parse(case["url"].as_str().expect("url")).expect_err("this link must be rejected");
                assert_eq!(
                    err.code(),
                    case["expected"].as_str().expect("error code"),
                    "{id}: error code"
                );
            }
            "key-bytes" => {
                keys += 1;
                let got = key_bytes(case["key"].as_str().expect("key"));
                match case["expected"].as_str() {
                    Some(expected) => assert_eq!(got, Some(hex_bytes(expected)), "{id}: key_bytes"),
                    None => assert_eq!(got, None, "{id}: key_bytes must reject this value"),
                }
            }
            other => panic!("{id}: unknown case kind {other:?}"),
        }
    }

    assert_eq!(
        (built, parsed, rejected, keys),
        (5, 7, 7, 5),
        "the named cases of move 9 are all present"
    );
    for required in ["share_parse_raw_s", "share_parse_b64url_f", "share_parse_legacy_host"] {
        assert!(
            cases.iter().any(|case| case["id"] == required),
            "{required} is a named compatibility case"
        );
    }
}
