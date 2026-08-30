use oab_providers::cookie::{
    CookieDomainKind, CookieError, CookieHeaderNormalizer, CookieImport, CookieImportOrder,
    CookieJar, CookieRecord, CookieRecordSpec, CookieSourceId, CookieUrlPolicy,
    MAX_COOKIE_HEADER_BYTES, MAX_COOKIES_PER_IMPORT,
};
use time::{Duration, OffsetDateTime};

const FIRST: CookieSourceId = CookieSourceId::new(1);
const SECOND: CookieSourceId = CookieSourceId::new(2);
const THIRD: CookieSourceId = CookieSourceId::new(3);

fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::days(20_000)
}

fn target(raw: &str) -> oab_providers::cookie::ValidatedCookieUrl {
    oab_providers::cookie::ValidatedCookieUrl::parse(raw, CookieUrlPolicy::HttpsOnly)
        .expect("valid fixture URL")
}

fn record(
    name: &str,
    value: &str,
    domain: &str,
    domain_kind: CookieDomainKind,
    path: &str,
    secure: bool,
    expires_at: Option<OffsetDateTime>,
) -> CookieRecord {
    CookieRecord::new(CookieRecordSpec {
        name,
        value,
        domain,
        domain_kind,
        path,
        secure,
        expires_at,
    })
    .expect("valid fixture cookie")
}

fn import(source: CookieSourceId, records: Vec<CookieRecord>) -> CookieImport {
    CookieImport::new(source, records).expect("bounded fixture import")
}

fn jar(order: &[CookieSourceId], imports: Vec<CookieImport>) -> CookieJar {
    let order = CookieImportOrder::new(order.iter().copied()).expect("fixture order");
    CookieJar::from_imports(&order, imports).expect("fixture jar")
}

fn header(jar: &CookieJar, target: &oab_providers::cookie::ValidatedCookieUrl) -> Option<String> {
    jar.header_for(target, now())
        .expect("header selection")
        .map(|header| header.expose().to_owned())
}

#[test]
fn domain_and_host_only_records_respect_dot_delimited_host_boundaries() {
    let jar = jar(
        &[FIRST],
        vec![import(
            FIRST,
            vec![
                record(
                    "domain_session",
                    "domain-value",
                    ".Example.COM",
                    CookieDomainKind::Domain,
                    "/",
                    true,
                    None,
                ),
                record(
                    "host_session",
                    "host-value",
                    "API.EXAMPLE.COM",
                    CookieDomainKind::HostOnly,
                    "/",
                    true,
                    None,
                ),
            ],
        )],
    );

    let exact = header(&jar, &target("https://api.example.com/"))
        .expect("exact host receives both records");
    assert!(exact.contains("domain_session=domain-value"));
    assert!(exact.contains("host_session=host-value"));

    assert_eq!(
        header(&jar, &target("https://child.api.example.com/")),
        Some("domain_session=domain-value".to_owned())
    );
    assert_eq!(header(&jar, &target("https://evil-example.com/")), None);
    assert_eq!(
        header(&jar, &target("https://example.com.evil.test/")),
        None
    );
}

#[test]
fn paths_use_rfc_boundaries_and_longest_paths_sort_first() {
    let jar = jar(
        &[FIRST],
        vec![import(
            FIRST,
            vec![
                record(
                    "root",
                    "r",
                    "example.com",
                    CookieDomainKind::HostOnly,
                    "/",
                    true,
                    None,
                ),
                record(
                    "api",
                    "a",
                    "example.com",
                    CookieDomainKind::HostOnly,
                    "/api",
                    true,
                    None,
                ),
                record(
                    "nested",
                    "n",
                    "example.com",
                    CookieDomainKind::HostOnly,
                    "/api/v1",
                    true,
                    None,
                ),
            ],
        )],
    );

    assert_eq!(
        header(&jar, &target("https://example.com/api/v1/users")),
        Some("nested=n; api=a; root=r".to_owned())
    );
    assert_eq!(
        header(&jar, &target("https://example.com/apix")),
        Some("root=r".to_owned())
    );
}

#[test]
fn secure_records_are_not_sent_to_explicit_loopback_http() {
    let loopback = oab_providers::cookie::ValidatedCookieUrl::parse(
        "http://127.0.0.1:8042/usage",
        CookieUrlPolicy::LoopbackHttp,
    )
    .expect("typed loopback HTTP");
    let jar = jar(
        &[FIRST],
        vec![import(
            FIRST,
            vec![
                record(
                    "secure_only",
                    "hidden",
                    "127.0.0.1",
                    CookieDomainKind::HostOnly,
                    "/",
                    true,
                    None,
                ),
                record(
                    "development",
                    "visible",
                    "127.0.0.1",
                    CookieDomainKind::HostOnly,
                    "/",
                    false,
                    None,
                ),
            ],
        )],
    );

    assert_eq!(
        header(&jar, &loopback),
        Some("development=visible".to_owned())
    );
}

#[test]
fn ineligible_selected_source_cookie_never_falls_back_to_another_source() {
    let identity = |value, expires_at| {
        record(
            "session",
            value,
            "example.com",
            CookieDomainKind::HostOnly,
            "/",
            true,
            expires_at,
        )
    };
    let jar = jar(
        &[FIRST, SECOND],
        vec![
            import(SECOND, vec![identity("fallback", None)]),
            import(FIRST, vec![identity("preferred", Some(now()))]),
        ],
    );
    let request = target("https://example.com/");

    assert_eq!(header(&jar, &request), None);
    let before_expiry = jar
        .header_for(&request, now() - Duration::SECOND)
        .expect("header")
        .expect("active preferred cookie");
    assert_eq!(before_expiry.expose(), "session=preferred");
}

#[test]
fn source_priority_is_input_order_independent_and_same_source_is_last_writer() {
    let same_identity = |value| {
        record(
            "session",
            value,
            "example.com",
            CookieDomainKind::HostOnly,
            "/",
            true,
            None,
        )
    };
    let jar = jar(
        &[FIRST, SECOND],
        vec![
            import(SECOND, vec![same_identity("lower-priority")]),
            import(
                FIRST,
                vec![same_identity("old"), same_identity("preferred")],
            ),
        ],
    );

    assert_eq!(
        header(&jar, &target("https://example.com/")),
        Some("session=preferred".to_owned())
    );
    assert_eq!(jar.record_count(), 2);
}

#[test]
fn highest_priority_nonempty_source_is_isolated_as_a_whole_profile() {
    let source_cookie = |name, value| {
        record(
            name,
            value,
            "example.com",
            CookieDomainKind::HostOnly,
            "/",
            true,
            None,
        )
    };
    let isolated = jar(
        &[FIRST, SECOND],
        vec![
            import(SECOND, vec![source_cookie("profile_b", "b-canary")]),
            import(FIRST, vec![source_cookie("profile_a", "a-canary")]),
        ],
    );

    assert_eq!(
        header(&isolated, &target("https://example.com/")),
        Some("profile_a=a-canary".to_owned())
    );
    assert_eq!(isolated.record_count(), 1);
    assert_eq!(isolated.byte_count(), 29);

    let skips_empty = jar(
        &[FIRST, SECOND],
        vec![
            import(SECOND, vec![source_cookie("profile_b", "b-canary")]),
            import(FIRST, Vec::new()),
        ],
    );
    assert_eq!(
        header(&skips_empty, &target("https://example.com/")),
        Some("profile_b=b-canary".to_owned())
    );
}

#[test]
fn secure_ineligible_selected_profile_does_not_mix_with_loopback_fallback() {
    let loopback = oab_providers::cookie::ValidatedCookieUrl::parse(
        "http://127.0.0.1:8042/",
        CookieUrlPolicy::LoopbackHttp,
    )
    .expect("typed loopback URL");
    let source_cookie = |value, secure| {
        record(
            "session",
            value,
            "127.0.0.1",
            CookieDomainKind::HostOnly,
            "/",
            secure,
            None,
        )
    };
    let isolated = jar(
        &[FIRST, SECOND],
        vec![
            import(SECOND, vec![source_cookie("fallback-canary", false)]),
            import(FIRST, vec![source_cookie("selected-canary", true)]),
        ],
    );

    assert_eq!(header(&isolated, &loopback), None);
}

#[test]
fn invalid_source_orders_and_duplicate_batches_fail_closed() {
    assert_eq!(
        CookieImportOrder::new([]).expect_err("empty order"),
        CookieError::InvalidImportOrder
    );
    assert_eq!(
        CookieImportOrder::new([FIRST, FIRST]).expect_err("duplicate source"),
        CookieError::InvalidImportOrder
    );

    let order = CookieImportOrder::new([FIRST, SECOND]).expect("order");
    let duplicate = CookieJar::from_imports(
        &order,
        [import(FIRST, Vec::new()), import(FIRST, Vec::new())],
    )
    .expect_err("duplicate batches");
    assert_eq!(duplicate, CookieError::InvalidImportOrder);

    let unknown =
        CookieJar::from_imports(&order, [import(THIRD, Vec::new())]).expect_err("unknown source");
    assert_eq!(unknown, CookieError::InvalidImportOrder);
}

#[test]
fn stable_sorting_does_not_depend_on_hash_or_record_insertion_order() {
    let records = || {
        vec![
            record(
                "zeta",
                "1",
                "example.com",
                CookieDomainKind::HostOnly,
                "/",
                true,
                None,
            ),
            record(
                "alpha",
                "2",
                "example.com",
                CookieDomainKind::HostOnly,
                "/",
                true,
                None,
            ),
            record(
                "deep",
                "3",
                "example.com",
                CookieDomainKind::HostOnly,
                "/account",
                true,
                None,
            ),
        ]
    };
    let mut reversed = records();
    reversed.reverse();
    let first = jar(&[FIRST], vec![import(FIRST, records())]);
    let second = jar(&[FIRST], vec![import(FIRST, reversed)]);
    let request = target("https://example.com/account/settings");

    assert_eq!(header(&first, &request), header(&second, &request));
    assert_eq!(
        header(&first, &request),
        Some("deep=3; alpha=2; zeta=1".to_owned())
    );
}

#[test]
fn idn_domains_canonicalize_to_ascii_without_weakening_host_boundaries() {
    let jar = jar(
        &[FIRST],
        vec![import(
            FIRST,
            vec![record(
                "idn_session",
                "valid",
                ".BÜCHER.Example",
                CookieDomainKind::Domain,
                "/",
                true,
                None,
            )],
        )],
    );

    assert_eq!(
        header(&jar, &target("https://shop.bücher.example/")),
        Some("idn_session=valid".to_owned())
    );
    assert_eq!(
        header(&jar, &target("https://bücher.example.evil.test/")),
        None
    );
}

#[test]
fn public_suffix_style_and_ip_domain_cookies_are_rejected() {
    for unsafe_domain in [".com", ".co.uk", ".github.io", "localhost"] {
        let error = CookieRecord::new(CookieRecordSpec {
            name: "session",
            value: "secret",
            domain: unsafe_domain,
            domain_kind: CookieDomainKind::Domain,
            path: "/",
            secure: true,
            expires_at: None,
        })
        .expect_err("unsafe domain cookie");
        assert_eq!(error, CookieError::InvalidRecord);
    }

    for numeric in ["127.0.0.1", "127.1", "0x7f000001", "[::1]"] {
        assert_eq!(
            CookieRecord::new(CookieRecordSpec {
                name: "session",
                value: "secret",
                domain: numeric,
                domain_kind: CookieDomainKind::Domain,
                path: "/",
                secure: true,
                expires_at: None,
            })
            .expect_err("IP domain cookie"),
            CookieError::InvalidRecord
        );
    }

    let host_only = jar(
        &[FIRST],
        vec![import(
            FIRST,
            vec![record(
                "loopback",
                "canonical",
                "127.1",
                CookieDomainKind::HostOnly,
                "/",
                true,
                None,
            )],
        )],
    );
    assert_eq!(
        header(&host_only, &target("https://127.0.0.1/")),
        Some("loopback=canonical".to_owned())
    );
}

#[test]
fn invalid_names_values_domains_and_paths_are_rejected() {
    let invalid_specs = [
        CookieRecordSpec {
            name: "bad name",
            value: "value",
            domain: "example.com",
            domain_kind: CookieDomainKind::HostOnly,
            path: "/",
            secure: true,
            expires_at: None,
        },
        CookieRecordSpec {
            name: "name",
            value: "line\nvalue",
            domain: "example.com",
            domain_kind: CookieDomainKind::HostOnly,
            path: "/",
            secure: true,
            expires_at: None,
        },
        CookieRecordSpec {
            name: "name",
            value: "value",
            domain: "example.com\n.evil.test",
            domain_kind: CookieDomainKind::Domain,
            path: "/",
            secure: true,
            expires_at: None,
        },
        CookieRecordSpec {
            name: "name",
            value: "value",
            domain: "example.com",
            domain_kind: CookieDomainKind::HostOnly,
            path: "relative",
            secure: true,
            expires_at: None,
        },
        CookieRecordSpec {
            name: "name",
            value: "value",
            domain: ".example.com",
            domain_kind: CookieDomainKind::HostOnly,
            path: "/",
            secure: true,
            expires_at: None,
        },
        CookieRecordSpec {
            name: "name",
            value: "value",
            domain: "%65xample.com",
            domain_kind: CookieDomainKind::HostOnly,
            path: "/",
            secure: true,
            expires_at: None,
        },
        CookieRecordSpec {
            name: "name",
            value: "value",
            domain: "example.com",
            domain_kind: CookieDomainKind::HostOnly,
            path: "/ambiguous path",
            secure: true,
            expires_at: None,
        },
    ];

    for spec in invalid_specs {
        assert_eq!(
            CookieRecord::new(spec).expect_err("invalid field"),
            CookieError::InvalidRecord
        );
    }
}

#[test]
fn imports_jars_and_request_headers_are_bounded() {
    let sample = record(
        "sample",
        "value",
        "example.com",
        CookieDomainKind::HostOnly,
        "/",
        true,
        None,
    );
    assert_eq!(
        CookieImport::new(FIRST, vec![sample.clone(); MAX_COOKIES_PER_IMPORT + 1])
            .expect_err("source record cap"),
        CookieError::JarTooLarge
    );

    let order = CookieImportOrder::new([FIRST, SECOND, THIRD]).expect("order");
    let isolated_jar = CookieJar::from_imports(
        &order,
        [
            import(FIRST, vec![sample.clone(); 3_000]),
            import(SECOND, vec![sample.clone(); 3_000]),
            import(THIRD, vec![sample; 3_000]),
        ],
    )
    .expect("only one bounded source is retained");
    assert_eq!(isolated_jar.record_count(), 3_000);

    let large_value = "x".repeat(14_000);
    let records = (0..5)
        .map(|index| {
            let name = format!("cookie{index}");
            record(
                &name,
                &large_value,
                "example.com",
                CookieDomainKind::HostOnly,
                "/",
                true,
                None,
            )
        })
        .collect();
    let header_jar = jar(&[FIRST], vec![import(FIRST, records)]);
    assert_eq!(
        header_jar
            .header_for(&target("https://example.com/"), now())
            .expect_err("header byte cap"),
        CookieError::HeaderTooLarge
    );
    assert!(MAX_COOKIE_HEADER_BYTES < 5 * (large_value.len() + 8));
}

#[test]
fn normalizer_supports_pinned_curl_forms_and_requires_host_binding() {
    let request = target("https://example.com/account");
    let cases = [
        "curl https://example.com -bfoo=bar",
        "curl https://example.com -b 'foo=bar'",
        "curl https://example.com --cookie=foo=bar",
        "curl https://example.com -H 'Cookie: foo=bar'",
        "Cookie: \"foo=bar\"",
        "'foo=bar'",
    ];

    for raw in cases {
        let import = CookieImport::from_host_only_capture(FIRST, raw, &request, None)
            .expect("normalized capture");
        let jar = jar(&[FIRST], vec![import]);
        assert_eq!(header(&jar, &request), Some("foo=bar".to_owned()));
        assert_eq!(
            header(&jar, &target("https://sub.example.com/account")),
            None
        );
    }

    let prioritized = CookieImport::from_host_only_capture(
        FIRST,
        "curl -b fallback=x -H 'Cookie: chosen=y' https://example.com",
        &request,
        None,
    )
    .expect("header form wins over cookie form");
    assert_eq!(
        header(&jar(&[FIRST], vec![prioritized]), &request),
        Some("chosen=y".to_owned())
    );
}

#[test]
fn filtered_normalization_is_exact_and_invalid_captures_fail_closed() {
    let normalized =
        CookieHeaderNormalizer::filtered(Some("Cookie: wanted=yes; unwanted=no"), &["wanted"])
            .expect("filter")
            .expect("matching cookie");
    assert_eq!(normalized.len(), 1);

    for invalid in [
        "Cookie: ok=yes\r\nInjected=x",
        "Cookie: bad name=value",
        "Cookie: name=has;semicolon",
        "Cookie: name=unicode-🐈",
        "curl -H 'Cookie: unterminated=value",
    ] {
        assert_eq!(
            CookieHeaderNormalizer::normalize(Some(invalid)).expect_err("invalid capture"),
            CookieError::InvalidRecord
        );
    }
    assert!(
        CookieHeaderNormalizer::normalize(None)
            .expect("none")
            .is_none()
    );
    assert!(
        CookieHeaderNormalizer::normalize(Some("  "))
            .expect("empty")
            .is_none()
    );

    let excessive_tokens = vec!["x"; 600].join(" ");
    assert_eq!(
        CookieHeaderNormalizer::normalize(Some(&excessive_tokens)).expect_err("capture token cap"),
        CookieError::JarTooLarge
    );
}

#[test]
fn request_urls_require_https_or_an_explicit_exact_loopback_allowance() {
    use oab_providers::cookie::ValidatedCookieUrl;

    for invalid in [
        "http://example.com/",
        "ftp://example.com/",
        "https://user:password@example.com/",
        "https://example.com/#private-fragment",
        "https://example.com./",
        "https://example.com/\nignored",
    ] {
        assert_eq!(
            ValidatedCookieUrl::parse(invalid, CookieUrlPolicy::HttpsOnly)
                .expect_err("invalid request URL"),
            CookieError::InvalidRequestUrl
        );
    }
    assert!(
        ValidatedCookieUrl::parse("http://localhost:3000/", CookieUrlPolicy::HttpsOnly).is_err()
    );
    assert!(
        ValidatedCookieUrl::parse("http://localhost:3000/", CookieUrlPolicy::LoopbackHttp).is_ok()
    );
    assert!(ValidatedCookieUrl::parse("http://127.0.0.2/", CookieUrlPolicy::LoopbackHttp).is_ok());
    assert!(
        ValidatedCookieUrl::parse("http://192.168.1.2/", CookieUrlPolicy::LoopbackHttp).is_err()
    );
    let oversized = format!("https://example.com/{}", "x".repeat(17 * 1024));
    assert_eq!(
        ValidatedCookieUrl::parse(&oversized, CookieUrlPolicy::HttpsOnly)
            .expect_err("oversized URL"),
        CookieError::InvalidRequestUrl
    );
}

#[test]
fn debug_and_errors_never_reveal_cookie_or_account_fields() {
    const NAME: &str = "name_canary";
    const VALUE: &str = "value-canary";
    const DOMAIN: &str = "account-canary.example.com";
    const PATH: &str = "/private/path-canary";

    let spec = CookieRecordSpec {
        name: NAME,
        value: VALUE,
        domain: DOMAIN,
        domain_kind: CookieDomainKind::HostOnly,
        path: PATH,
        secure: true,
        expires_at: None,
    };
    let record = CookieRecord::new(spec).expect("record");
    let import = import(FIRST, vec![record.clone()]);
    let order = CookieImportOrder::new([FIRST]).expect("order");
    let jar = CookieJar::from_imports(&order, [import]).expect("jar");
    let request = target("https://account-canary.example.com/private/path-canary?account=canary");
    let header = jar
        .header_for(&request, now())
        .expect("selection")
        .expect("header");
    let normalized = CookieHeaderNormalizer::normalize(Some("Cookie: name_canary=value-canary"))
        .expect("normalize")
        .expect("pairs");
    let error = CookieRecord::new(CookieRecordSpec {
        name: "bad name canary",
        ..spec
    })
    .expect_err("invalid record");

    let rendered = format!(
        "{spec:?} {record:?} {order:?} {jar:?} {request:?} {header:?} {normalized:?} {error:?} {error}"
    );
    for canary in [
        NAME,
        VALUE,
        DOMAIN,
        PATH,
        "account=canary",
        "bad name canary",
    ] {
        assert!(!rendered.contains(canary), "debug leaked a secret canary");
    }
}
