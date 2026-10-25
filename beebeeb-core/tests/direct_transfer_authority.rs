//! Table-driven tests of the storage-link authority check, `redact` and `scrub`
//! (task 2173, amendment R1.12). Public API only. They live here, not inline,
//! because they are full of hostile and placeholder hostnames by design; the
//! claims guard does not scan `tests/` for hosts.

mod direct_transfer {
    use beebeeb_core::direct_transfer::{
        Discovery, MAX_URL_LEN, Refusal, StorageBucket, check_storage_url, redact, scrub,
    };

    const PROD: &str = "https://api.example.net";
    const DEV: &str = "http://127.0.0.1:3001";

    fn discovery(buckets: &[(&str, &str)]) -> Discovery {
        let mut hosts: Vec<String> = buckets.iter().map(|(h, _)| h.to_string()).collect();
        hosts.sort();
        hosts.dedup();
        Discovery {
            download: vec!["object-download-v1".into()],
            storage_hosts: hosts,
            storage_buckets: buckets
                .iter()
                .map(|(h, b)| StorageBucket {
                    host: h.to_string(),
                    bucket: b.to_string(),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn real() -> Discovery {
        discovery(&[
            ("s3.example.net", "bb-01"),
            ("s3.example.net", "bb-02"),
            ("eu.example.org", "vault"),
        ])
    }

    struct Row {
        why: &'static str,
        url: &'static str,
        api: &'static str,
        disc: fn() -> Discovery,
        want: Result<(), Refusal>,
    }

    fn ok(why: &'static str, url: &'static str) -> Row {
        Row {
            why,
            url,
            api: PROD,
            disc: real,
            want: Ok(()),
        }
    }
    fn no(why: &'static str, url: &'static str, want: Refusal) -> Row {
        Row {
            why,
            url,
            api: PROD,
            disc: real,
            want: Err(want),
        }
    }

    #[test]
    fn production_shapes_pass_and_hostile_shapes_fail() {
        let rows: Vec<Row> = vec![
            ok(
                "plain presigned GET",
                "https://s3.example.net/bb-01/tenant/versions/v/0.bin?X-Amz-Signature=abc&X-Amz-Expires=300",
            ),
            ok("second bucket on the same host", "https://s3.example.net/bb-02/k?x=1"),
            ok("another listed host", "https://eu.example.org/vault/a/b/c"),
            ok("upper-case scheme and host", "HTTPS://S3.Example.NET/bb-01/k?x=1"),
            ok(
                "explicit default port is the same authority",
                "https://s3.example.net:443/bb-01/k",
            ),
            ok("bucket-looking key part", "https://s3.example.net/bb-01/bb-02/k"),
            // Scheme.
            no(
                "http to a public host",
                "http://s3.example.net/bb-01/k",
                Refusal::NotHttps,
            ),
            no("ftp", "ftp://s3.example.net/bb-01/k", Refusal::NotHttps),
            no("scheme-relative", "//s3.example.net/bb-01/k", Refusal::NotHttps),
            no(
                "one slash (WHATWG repairs it)",
                "https:/s3.example.net/bb-01/k",
                Refusal::NotHttps,
            ),
            no(
                "no slashes (WHATWG repairs it)",
                "https:s3.example.net/bb-01/k",
                Refusal::NotHttps,
            ),
            no("javascript", "javascript:alert(1)", Refusal::NotHttps),
            no("data", "data:text/plain,hi", Refusal::NotHttps),
            no("empty", "", Refusal::Malformed),
            no(
                "extra slashes before the host (WHATWG skips them)",
                "https:///s3.example.net/bb-01/k",
                Refusal::BadHost,
            ),
            // Credentials and authority tricks.
            no("userinfo", "https://user:pw@s3.example.net/bb-01/k", Refusal::Userinfo),
            no(
                "listed host as userinfo of another host",
                "https://s3.example.net@evil.example.com/bb-01/k",
                Refusal::Userinfo,
            ),
            no(
                "listed host with port as userinfo",
                "https://s3.example.net:443@evil.example.com/bb-01/k",
                Refusal::Userinfo,
            ),
            no("empty userinfo", "https://@s3.example.net/bb-01/k", Refusal::Userinfo),
            no(
                "backslash host confusion",
                "https://evil.example.com\\@s3.example.net/bb-01/k",
                Refusal::Malformed,
            ),
            no(
                "backslash as slash",
                "https://s3.example.net\\bb-01\\k",
                Refusal::Malformed,
            ),
            no(
                "fragment hides the real host",
                "https://evil.example.com#@s3.example.net/bb-01/k",
                Refusal::Malformed,
            ),
            no(
                "fragment anywhere",
                "https://s3.example.net/bb-01/k#x",
                Refusal::Malformed,
            ),
            no(
                "percent in authority",
                "https://s3%2eexample.net/bb-01/k",
                Refusal::BadHost,
            ),
            no(
                "percent-encoded @",
                "https://s3.example.net%40evil.example.com/bb-01/k",
                Refusal::BadHost,
            ),
            // Characters WHATWG strips or normalizes.
            no(
                "tab inside the host",
                "https://s3.exam\tple.net/bb-01/k",
                Refusal::Malformed,
            ),
            no(
                "newline inside the host",
                "https://s3.example.net\n.evil.example.com/bb-01/k",
                Refusal::Malformed,
            ),
            no("leading space", " https://s3.example.net/bb-01/k", Refusal::Malformed),
            no("trailing space", "https://s3.example.net/bb-01/k ", Refusal::Malformed),
            no("NUL", "https://s3.example.net/bb-01/k\0", Refusal::Malformed),
            no(
                "non-ASCII lookalike dot",
                "https://s3\u{3002}example.net/bb-01/k",
                Refusal::Malformed,
            ),
            no(
                "non-ASCII host letter",
                "https://s3.exаmple.net/bb-01/k",
                Refusal::Malformed,
            ),
            no(
                "full-width letters",
                "https://ｓ3.example.net/bb-01/k",
                Refusal::Malformed,
            ),
            // Hosts that are not listed or not plain names.
            no(
                "unlisted host",
                "https://evil.example.com/bb-01/k",
                Refusal::HostNotListed,
            ),
            no(
                "listed host as a prefix of another",
                "https://s3.example.net.evil.example.com/bb-01/k",
                Refusal::HostNotListed,
            ),
            no(
                "listed host as a suffix of another",
                "https://evil-s3.example.net/bb-01/k",
                Refusal::HostNotListed,
            ),
            no(
                "subdomain of a listed host",
                "https://x.s3.example.net/bb-01/k",
                Refusal::HostNotListed,
            ),
            no(
                "virtual-hosted bucket form",
                "https://bb-01.s3.example.net/k",
                Refusal::HostNotListed,
            ),
            no("trailing dot", "https://s3.example.net./bb-01/k", Refusal::BadHost),
            no("underscore", "https://s3_example.net/bb-01/k", Refusal::BadHost),
            no("empty label", "https://s3..example.net/bb-01/k", Refusal::BadHost),
            no(
                "leading hyphen label",
                "https://-s3.example.net/bb-01/k",
                Refusal::BadHost,
            ),
            no("empty port", "https://s3.example.net:/bb-01/k", Refusal::BadHost),
            no(
                "alphabetic port",
                "https://s3.example.net:abc/bb-01/k",
                Refusal::BadHost,
            ),
            no("port 0", "https://s3.example.net:0/bb-01/k", Refusal::BadHost),
            no(
                "port above u16",
                "https://s3.example.net:65536/bb-01/k",
                Refusal::BadHost,
            ),
            no("two colons", "https://s3.example.net:1:2/bb-01/k", Refusal::BadHost),
            // IP literals in every spelling a parser may normalize.
            no("ipv4", "https://203.0.113.9/bb-01/k", Refusal::IpLiteral),
            no(
                "ipv4 loopback, production api",
                "https://127.0.0.1/bb-01/k",
                Refusal::Loopback,
            ),
            no("ipv6", "https://[2001:db8::1]/bb-01/k", Refusal::IpLiteral),
            no("ipv6 loopback", "https://[::1]/bb-01/k", Refusal::IpLiteral),
            no("decimal ipv4", "https://2130706433/bb-01/k", Refusal::IpLiteral),
            no("hex ipv4", "https://0x7f000001/bb-01/k", Refusal::IpLiteral),
            no("short ipv4", "https://127.1/bb-01/k", Refusal::IpLiteral),
            no("dotted hex ipv4", "https://0x7f.0.0.1/bb-01/k", Refusal::IpLiteral),
            no(
                "localhost on a production api base",
                "https://localhost/bb-01/k",
                Refusal::Loopback,
            ),
            no(
                "LOCALHOST on a production api base",
                "https://LOCALHOST/bb-01/k",
                Refusal::Loopback,
            ),
            no(
                "localhost with a port on a production api base",
                "https://localhost:9000/bb-01/k",
                Refusal::Loopback,
            ),
            // Ports.
            no(
                "non-default port on a listed host",
                "https://s3.example.net:8443/bb-01/k",
                Refusal::Port,
            ),
            no(
                "non-default port on an unlisted host",
                "https://evil.example.com:8443/bb-01/k",
                Refusal::Port,
            ),
            // Buckets and paths.
            no(
                "unlisted bucket",
                "https://s3.example.net/other/k",
                Refusal::BucketNotListed,
            ),
            no(
                "bucket of another host",
                "https://eu.example.org/bb-01/k",
                Refusal::BucketNotListed,
            ),
            no(
                "bucket case differs",
                "https://s3.example.net/BB-01/k",
                Refusal::BucketNotListed,
            ),
            no("no path", "https://s3.example.net", Refusal::BucketNotListed),
            no(
                "query but no path",
                "https://s3.example.net?x=1",
                Refusal::BucketNotListed,
            ),
            no("bucket only", "https://s3.example.net/bb-01", Refusal::BucketNotListed),
            no(
                "bucket with empty key",
                "https://s3.example.net/bb-01/",
                Refusal::BadPath,
            ),
            no(
                "bucket prefix only",
                "https://s3.example.net/bb-01x/k",
                Refusal::BucketNotListed,
            ),
            no(
                "dot-dot escapes to another bucket",
                "https://s3.example.net/bb-01/../other/k",
                Refusal::BadPath,
            ),
            no(
                "dot-dot at the end",
                "https://s3.example.net/bb-01/k/..",
                Refusal::BadPath,
            ),
            no(
                "encoded dot-dot",
                "https://s3.example.net/bb-01/%2e%2e/other/k",
                Refusal::BadPath,
            ),
            no(
                "mixed-case encoded dot-dot",
                "https://s3.example.net/bb-01/%2E./other/k",
                Refusal::BadPath,
            ),
            no(
                "single dot segment",
                "https://s3.example.net/bb-01/./k",
                Refusal::BadPath,
            ),
            no("empty segment", "https://s3.example.net/bb-01//k", Refusal::BadPath),
            no(
                "encoded bucket separator",
                "https://s3.example.net/bb-01%2Fk",
                Refusal::BucketNotListed,
            ),
        ];
        for row in rows {
            let got = check_storage_url(row.url, &(row.disc)(), row.api);
            assert_eq!(got, row.want, "{}: {:?}", row.why, redact(row.url));
        }
    }

    #[test]
    fn a_deep_key_and_an_oversized_url() {
        let deep = format!("https://s3.example.net/bb-01/{}obj?x=1", "k/".repeat(100));
        assert_eq!(check_storage_url(&deep, &real(), PROD), Ok(()));
        let huge = format!("https://s3.example.net/bb-01/{}", "k".repeat(MAX_URL_LEN));
        assert_eq!(check_storage_url(&huge, &real(), PROD), Err(Refusal::Malformed));
    }

    #[test]
    fn local_development_exceptions_need_a_loopback_api_base() {
        let d = discovery(&[
            ("127.0.0.1:9000", "bb-dev"),
            ("localhost:9000", "bb-dev"),
            ("s3.example.net", "bb-01"),
        ]);
        // Allowed only when the API itself is loopback http.
        for api in [
            "http://127.0.0.1:3001",
            "http://localhost:3001",
            "http://localhost",
            "http://127.0.0.1:3001/",
        ] {
            assert_eq!(
                check_storage_url("http://127.0.0.1:9000/bb-dev/k?x=1", &d, api),
                Ok(()),
                "{api}"
            );
            assert_eq!(
                check_storage_url("http://localhost:9000/bb-dev/k", &d, api),
                Ok(()),
                "{api}"
            );
            assert_eq!(
                check_storage_url("https://127.0.0.1:9000/bb-dev/k", &d, api),
                Ok(()),
                "{api}"
            );
        }
        // The same URLs against a production API base are refused.
        for api in [
            PROD,
            "http://api.example.net",
            "https://127.0.0.1",
            "http://127.0.0.2:3001",
            "http://localhost.evil.example.com",
        ] {
            assert!(
                check_storage_url("http://127.0.0.1:9000/bb-dev/k", &d, api).is_err(),
                "{api}"
            );
            assert!(
                check_storage_url("https://127.0.0.1:9000/bb-dev/k", &d, api).is_err(),
                "{api}"
            );
        }
        // The loopback exceptions never apply to a production API base, for names as well as addresses.
        let names = discovery(&[("localhost:9000", "bb-dev"), ("127.0.0.1:9000", "bb-dev")]);
        for api in [
            PROD,
            "http://api.example.net",
            "https://localhost",
            "http://localhost.evil.example.com",
        ] {
            for url in ["http://localhost:9000/bb-dev/k", "http://127.0.0.1:9000/bb-dev/k"] {
                assert_eq!(
                    check_storage_url(url, &names, api),
                    Err(Refusal::NotHttps),
                    "{api} {url}"
                );
            }
        }
        // Even in dev: http only to loopback, never to a public host; other IPs stay refused.
        assert_eq!(
            check_storage_url("http://s3.example.net/bb-01/k", &d, DEV),
            Err(Refusal::NotHttps)
        );
        let any = discovery(&[("10.0.0.5:9000", "b"), ("127.0.0.2:9000", "b")]);
        assert_eq!(
            check_storage_url("http://10.0.0.5:9000/b/k", &any, DEV),
            Err(Refusal::NotHttps)
        );
        assert_eq!(
            check_storage_url("https://10.0.0.5:9000/b/k", &any, DEV),
            Err(Refusal::IpLiteral)
        );
        assert_eq!(
            check_storage_url("https://127.0.0.2:9000/b/k", &any, DEV),
            Err(Refusal::IpLiteral)
        );
        // Dev still requires the host AND the bucket to be listed.
        assert_eq!(
            check_storage_url("http://127.0.0.1:9001/bb-dev/k", &d, DEV),
            Err(Refusal::HostNotListed)
        );
    }

    #[test]
    fn nothing_listed_means_nothing_allowed() {
        let empty = Discovery::default();
        assert_eq!(
            check_storage_url("https://s3.example.net/bb-01/k", &empty, PROD),
            Err(Refusal::HostNotListed)
        );
        // Hosts listed but no bucket pairs (an older or partial answer): fail closed.
        let hosts_only = Discovery {
            storage_hosts: vec!["s3.example.net".into()],
            ..Default::default()
        };
        assert_eq!(
            check_storage_url("https://s3.example.net/bb-01/k", &hosts_only, PROD),
            Err(Refusal::BucketNotListed)
        );
        // Buckets listed but the host missing from storage_hosts: also closed.
        let buckets_only = Discovery {
            storage_buckets: vec![StorageBucket {
                host: "s3.example.net".into(),
                bucket: "bb-01".into(),
            }],
            ..Default::default()
        };
        assert_eq!(
            check_storage_url("https://s3.example.net/bb-01/k", &buckets_only, PROD),
            Err(Refusal::HostNotListed)
        );
    }

    #[test]
    fn a_non_default_port_is_refused_even_when_discovery_lists_it() {
        // R1.12: the server's own list is not independent approval of a port.
        let d = discovery(&[("minio.example.net:9443", "bb"), ("evil.example.com:8443", "bb")]);
        for url in [
            "https://minio.example.net:9443/bb/k",
            "https://evil.example.com:8443/bb/k?X-Amz-Signature=x",
        ] {
            assert_eq!(check_storage_url(url, &d, PROD), Err(Refusal::Port), "{url}");
        }
        // Listed WITHOUT the port and sent WITH one: also refused. Never silently normalized away.
        let bare = discovery(&[("minio.example.net", "bb")]);
        assert_eq!(
            check_storage_url("https://minio.example.net:9443/bb/k", &bare, PROD),
            Err(Refusal::Port)
        );
        // The default port, spelled out, is the default port.
        assert_eq!(
            check_storage_url("https://minio.example.net:443/bb/k", &bare, PROD),
            Ok(())
        );
    }

    #[test]
    fn loopback_names_and_addresses_are_one_rule() {
        let d = discovery(&[
            ("localhost:9000", "bb"),
            ("127.0.0.1:9000", "bb"),
            ("localhost", "bb"),
            ("127.0.0.1", "bb"),
        ]);
        for host in ["localhost", "LocalHost", "LOCALHOST", "127.0.0.1"] {
            for url in [
                format!("https://{host}/bb/k"),
                format!("https://{host}:9000/bb/k"),
                format!("http://{host}:9000/bb/k"),
            ] {
                // A production API base: never, whatever the spelling, scheme or port.
                assert!(
                    check_storage_url(&url, &d, PROD).is_err(),
                    "{url} on a production API base"
                );
            }
        }
        assert_eq!(
            check_storage_url("https://localhost/bb/k", &d, PROD),
            Err(Refusal::Loopback)
        );
        assert_eq!(
            check_storage_url("https://127.0.0.1/bb/k", &d, PROD),
            Err(Refusal::Loopback)
        );
        // A loopback http API base (development): name and address alike, with a port.
        for host in ["localhost", "LocalHost", "127.0.0.1"] {
            let url = format!("http://{host}:9000/bb/k");
            assert_eq!(check_storage_url(&url, &d, DEV), Ok(()), "{url} in development");
        }
    }

    #[test]
    fn refusal_text_never_contains_the_url() {
        let hostile = "https://user:pw@evil.example.com/b/k?X-Amz-Signature=TOPSECRET";
        let err = check_storage_url(hostile, &real(), PROD).unwrap_err();
        let text = format!("{err} {err:?}");
        assert!(
            !text.contains("TOPSECRET") && !text.contains("evil.example.com") && !text.contains("pw"),
            "{text}"
        );
    }

    /// What the `url` crate (the WHATWG parser reqwest connects with) makes of an
    /// accepted URL must be exactly a listed `{host, bucket}` over https with no
    /// credentials: what was checked is what gets fetched.
    fn assert_connects_to_a_listed_target(d: &Discovery, text: &str) {
        let parsed =
            url::Url::parse(text).unwrap_or_else(|e| panic!("accepted but unparseable ({e}): {}", redact(text)));
        assert_eq!(parsed.scheme(), "https", "{}", redact(text));
        assert!(
            parsed.username().is_empty() && parsed.password().is_none(),
            "credentials: {}",
            redact(text)
        );
        let host = parsed.host_str().unwrap_or_default();
        let authority = match parsed.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        };
        let bucket = parsed.path_segments().and_then(|mut s| s.next()).unwrap_or_default();
        assert!(
            d.storage_buckets
                .iter()
                .any(|b| b.host == authority && b.bucket == bucket),
            "accepted a URL that connects to {authority}/{bucket}: {}",
            redact(text)
        );
        assert!(
            parsed.path().starts_with(&format!("/{bucket}/")) && parsed.path().len() > bucket.len() + 2,
            "path left the bucket after normalization: {}",
            redact(text)
        );
    }

    #[test]
    fn accepted_urls_mean_the_same_to_a_whatwg_parser() {
        let d = real();
        let accepted = [
            "https://s3.example.net/bb-01/tenant/versions/v/0.bin?X-Amz-Signature=abc&X-Amz-Expires=300",
            "HTTPS://S3.Example.NET/bb-01/k?x=1",
            "https://s3.example.net:443/bb-01/k",
            "https://eu.example.org/vault/a/b/c",
            "https://s3.example.net/bb-02/a%20b/k",
        ];
        for text in accepted {
            assert_eq!(check_storage_url(text, &d, PROD), Ok(()), "{}", redact(text));
            assert_connects_to_a_listed_target(&d, text);
        }
    }

    /// Differential fuzz: insert, replace or delete every character a parser might
    /// treat specially at every position of valid URLs. Whenever the check still
    /// accepts the result, the WHATWG parser must agree on where it connects.
    #[test]
    fn no_single_character_mutation_of_a_valid_url_changes_where_it_connects() {
        let d = real();
        let bases = [
            "https://s3.example.net/bb-01/t/versions/v/0.bin?X-Amz-Signature=abc",
            "https://eu.example.org:443/vault/a/b",
            "https://s3.example.net/bb-02/k",
        ];
        let specials = [
            "\\", "\t", "\n", "\r", " ", "\0", "@", "#", "%", "%2e", "%2E", "%40", "%2f", "%5c", ".", "..", "/", "//",
            ":", ":80", "?", "[", "]", "\u{ff0e}", "\u{3002}", "\u{ff20}", "\u{2028}", "é", "x", "-", "_", "0",
        ];
        let mut tried = 0usize;
        let mut accepted = 0usize;
        for base in bases {
            assert_connects_to_a_listed_target(&d, base);
            let positions: Vec<usize> = base.char_indices().map(|(i, _)| i).chain([base.len()]).collect();
            for &at in &positions {
                for special in specials {
                    let mut candidates = vec![format!("{}{}{}", &base[..at], special, &base[at..])];
                    if at < base.len() {
                        let next = at + base[at..].chars().next().map_or(0, char::len_utf8);
                        candidates.push(format!("{}{}{}", &base[..at], special, &base[next..]));
                        candidates.push(format!("{}{}", &base[..at], &base[next..]));
                    }
                    for candidate in candidates {
                        tried += 1;
                        if check_storage_url(&candidate, &d, PROD).is_ok() {
                            accepted += 1;
                            assert_connects_to_a_listed_target(&d, &candidate);
                        }
                    }
                }
            }
        }
        assert!(tried > 3000, "the corpus ran ({tried} candidates)");
        assert!(
            accepted > 50,
            "some mutations stay valid ({accepted}), so the agreement check ran"
        );
    }

    #[test]
    fn redact_keeps_scheme_and_host_only() {
        for url in [
            "https://s3.example.net/bb-01/tenant-0000/versions/v-1111/0.bin?X-Amz-Signature=abc&x=1",
            "https://s3.example.net/bb-01/k#frag?x",
            "https://user:pw@s3.example.net/b/k?q",
            "https://a@b@s3.example.net/b/k",
        ] {
            assert_eq!(redact(url), "https://s3.example.net/<redacted>", "{url}");
        }
        // A bare host, with or without a trailing slash, has nothing to hide.
        assert_eq!(redact("https://s3.example.net"), "https://s3.example.net");
        assert_eq!(redact("https://s3.example.net/"), "https://s3.example.net/");
        assert_eq!(redact("https://s3.example.net?x=1"), "https://s3.example.net");
        assert_eq!(redact("not a url?secret=1"), "not a url");
        assert_eq!(redact("?only=query"), "");
        // Nothing past the host survives, however long, and multi-byte text is not split.
        let long = format!("https://s3.example.net/{}", "a".repeat(1000));
        assert_eq!(redact(&long), "https://s3.example.net/<redacted>");
        let wide = format!("https://{}.example.net/x", "é".repeat(400));
        let shown = redact(&wide);
        assert!(
            shown.is_char_boundary(shown.len()) && shown.chars().count() <= 257,
            "{}",
            shown.len()
        );
        for secret in ["tenant-0000", "versions", "0.bin", "X-Amz", "pw", "bb-01"] {
            assert!(
                !redact("https://u:pw@h.example.net/bb-01/tenant-0000/versions/0.bin?X-Amz-Signature=1")
                    .contains(secret)
            );
        }
    }

    #[test]
    fn scrub_removes_urls_and_amz_parameters_from_free_text() {
        let err = "error sending request for url (https://s3.example.net/bb-01/k?X-Amz-Signature=SECRETSIG&X-Amz-Credential=AKID): connection reset";
        let shown = scrub(err);
        assert!(!shown.contains("SECRETSIG") && !shown.contains("AKID"), "{shown}");
        assert!(
            shown.contains("https://s3.example.net/<redacted>") && shown.contains("connection reset"),
            "{shown}"
        );

        let two = scrub("a http://h/p?s=1 b HTTPS://h2/q?t=2 c");
        assert_eq!(two, "a http://h/<redacted> b HTTPS://h2/<redacted> c");

        // A parameter dump with no URL around it.
        let bare = scrub("retrying with X-Amz-Signature=SECRETSIG next");
        assert!(!bare.contains("SECRETSIG"), "{bare}");
        assert_eq!(scrub("nothing to hide"), "nothing to hide");
        assert_eq!(scrub(""), "");
        // Quoted URL inside JSON-ish text.
        let q = scrub(r#"{"url":"https://h/p?sig=SECRETSIG","n":1}"#);
        assert!(!q.contains("SECRETSIG") && q.contains(r#""n":1"#), "{q}");
    }
}
