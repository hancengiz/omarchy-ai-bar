use oab_providers::manual_capture::{
    CaptureHeader, LoopbackCaptureHost, ManualCaptureError, ManualCapturePolicy,
};

const COOKIE_CANARY: &str = "session=manual-cookie-canary; account=42";
const AUTH_CANARY: &str = "Bearer manual-authorization-canary";

fn cookie_policy() -> ManualCapturePolicy {
    ManualCapturePolicy::new(["usage.example.com"], [CaptureHeader::Cookie]).expect("cookie policy")
}

fn both_policy() -> ManualCapturePolicy {
    ManualCapturePolicy::new(
        ["usage.example.com", "account.example.com"],
        [CaptureHeader::Cookie, CaptureHeader::Authorization],
    )
    .expect("combined policy")
}

#[test]
fn raw_cookie_and_header_forms_are_normalized_without_a_shell() {
    let policy = cookie_policy();
    for raw in [
        COOKIE_CANARY,
        " Cookie: session=manual-cookie-canary; account=42 ",
        "Cookie: 'session=manual-cookie-canary; account=42'",
        "'session=manual-cookie-canary; account=42'",
        "\"session=manual-cookie-canary; account=42\"",
    ] {
        let capture = policy.parse(raw).expect("raw cookie capture");
        assert_eq!(capture.header(CaptureHeader::Cookie), Some(COOKIE_CANARY));
        assert_eq!(capture.header(CaptureHeader::Authorization), None);
        assert!(capture.url().is_none());
    }

    let auth = both_policy()
        .parse("aUtHoRiZaTiOn: Bearer manual-authorization-canary")
        .expect("raw authorization capture");
    assert_eq!(auth.header(CaptureHeader::Authorization), Some(AUTH_CANARY));
}

#[test]
fn common_curl_header_and_cookie_forms_are_supported() {
    let policy = both_policy();
    let captures = [
        "curl 'https://usage.example.com/v1/usage' -H 'Cookie: session=manual-cookie-canary; account=42' -H 'Authorization: Bearer manual-authorization-canary'",
        "curl \"https://usage.example.com/v1/usage\" --header=\"Cookie: session=manual-cookie-canary; account=42\" --header \"Authorization: Bearer manual-authorization-canary\"",
        "curl https://usage.example.com/v1/usage -HCookie:session=manual-cookie-canary -HAuthorization:'Bearer manual-authorization-canary'",
        "curl https://usage.example.com/v1/usage --cookie 'session=manual-cookie-canary; account=42' -H 'Authorization: Bearer manual-authorization-canary'",
        "curl https://usage.example.com/v1/usage -b'session=manual-cookie-canary; account=42' -H $'Authorization: Bearer manual-authorization-canary'",
    ];

    for raw in captures {
        let capture = policy.parse(raw).expect("cURL capture");
        let expected_cookie = if raw.contains("-HCookie:session=") {
            "session=manual-cookie-canary"
        } else {
            COOKIE_CANARY
        };
        assert_eq!(capture.header(CaptureHeader::Cookie), Some(expected_cookie));
        assert_eq!(
            capture.header(CaptureHeader::Authorization),
            Some(AUTH_CANARY)
        );
        assert_eq!(
            capture.url().and_then(|url| url.host_str()),
            Some("usage.example.com")
        );
        assert_eq!(capture.url().map(url::Url::path), Some("/v1/usage"));
    }
}

#[test]
fn curl_url_is_optional_and_benign_devtools_flags_are_bounded() {
    let policy = cookie_policy();
    let capture = policy
        .parse(
            "curl -fsS --compressed --no-progress-meter -H 'Cookie: session=manual-cookie-canary'",
        )
        .expect("capture without URL");
    assert!(capture.url().is_none());

    let multiline = policy
        .parse(
            "curl --url https://usage.example.com/v1/usage \\\n             --silent \\\r\n-H 'Cookie: session=manual-cookie-canary'",
        )
        .expect("line-continuation capture");
    assert_eq!(
        multiline.header(CaptureHeader::Cookie),
        Some("session=manual-cookie-canary")
    );
}

#[test]
fn only_exact_allowed_headers_are_retained() {
    let capture = cookie_policy()
        .parse(
            "curl https://usage.example.com -H 'X-Api-Key: ignored-canary' -H 'Authorization: Bearer ignored-canary' -H 'Cookie: session=manual-cookie-canary'",
        )
        .expect("cookie-only capture");
    assert_eq!(
        capture.header(CaptureHeader::Cookie),
        Some("session=manual-cookie-canary")
    );
    assert_eq!(capture.header(CaptureHeader::Authorization), None);

    assert_eq!(
        cookie_policy()
            .parse("Authorization: Bearer rejected-canary")
            .expect_err("raw disallowed header must fail"),
        ManualCaptureError::DisallowedHeader
    );
}

#[test]
fn explicitly_allowlisted_browser_metadata_is_preserved_deterministically() {
    let policy = both_policy()
        .with_forwarded_headers([
            "accept",
            "accept-language",
            "cache-control",
            "pragma",
            "priority",
            "referer",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "trpc-accept",
            "user-agent",
            "x-client-context",
            "x-deployment-id",
            "x-trpc-batch",
            "x-trpc-source",
        ])
        .expect("metadata policy");
    let capture = policy
        .parse(
            "curl https://usage.example.com/v1/usage \
             -H 'Cookie: session=manual-cookie-canary' \
             -H 'User-Agent: fixture-agent' \
             -H 'ACCEPT: application/json' \
             -H 'x-client-context: sensitive-context-canary' \
             -H 'X-Ignored: ignored-value-canary' \
             -H 'accept: application/json'",
        )
        .expect("metadata capture");

    assert_eq!(
        capture.forwarded_headers().collect::<Vec<_>>(),
        vec![
            ("accept", "application/json"),
            ("user-agent", "fixture-agent"),
            ("x-client-context", "sensitive-context-canary"),
        ]
    );
    assert!(!format!("{capture:?}").contains("sensitive-context-canary"));
    assert!(!format!("{capture:?}").contains("fixture-agent"));
}

#[test]
fn conflicting_forwarded_metadata_and_unsafe_grants_fail_closed() {
    let policy = cookie_policy()
        .with_forwarded_headers(["accept", "x-client-context"])
        .expect("metadata policy");
    assert_eq!(
        policy
            .parse(
                "curl https://usage.example.com -b session=canary -H 'Accept: one' -H 'accept: two'",
            )
            .expect_err("conflicting values"),
        ManualCaptureError::ConflictingHeader
    );

    for reserved in [
        "Cookie",
        "Authorization",
        "Host",
        "Proxy-Authorization",
        "X-Api-Key",
        "Connection",
        "Content-Length",
        "Transfer-Encoding",
    ] {
        assert_eq!(
            cookie_policy()
                .with_forwarded_headers([reserved])
                .expect_err("reserved header must remain ungrantable"),
            ManualCaptureError::InvalidPolicy
        );
    }
}

#[test]
fn raw_input_never_becomes_forwarded_browser_metadata() {
    let policy = cookie_policy()
        .with_forwarded_headers(["user-agent"])
        .expect("metadata policy");
    assert!(policy.parse("User-Agent: secret-like-value").is_err());
}

#[test]
fn duplicate_or_conflicting_secrets_fail_closed() {
    let policy = both_policy();
    for raw in [
        "curl https://usage.example.com -H 'Cookie: a=one' -H 'cookie: a=one'",
        "curl https://usage.example.com -b a=one --cookie a=two",
        "curl https://usage.example.com -H 'Authorization: Bearer one' --header 'AUTHORIZATION: Bearer two'",
        "curl https://usage.example.com -b a=one -H 'Cookie: b=two'",
    ] {
        assert_eq!(
            policy.parse(raw).expect_err("duplicate must fail"),
            ManualCaptureError::DuplicateSecret
        );
    }
}

#[test]
fn url_authority_is_exact_https_and_credential_free() {
    let policy = cookie_policy();
    let accepted = policy
        .parse("curl https://usage.example.com:443/safe/path -b session=manual-cookie-canary")
        .expect("exact HTTPS host");
    assert_eq!(
        accepted.url().map(url::Url::as_str),
        Some("https://usage.example.com/safe/path")
    );

    for raw in [
        "curl http://usage.example.com/path -b session=manual-cookie-canary",
        "curl https://usage.example.com:8443/path -b session=manual-cookie-canary",
        "curl https://evilusage.example.com/path -b session=manual-cookie-canary",
        "curl https://usage.example.com.evil.test/path -b session=manual-cookie-canary",
        "curl https://user:password@usage.example.com/path -b session=manual-cookie-canary",
        "curl 'https://usage.example.com/path?token=canary' -b session=manual-cookie-canary",
        "curl 'https://usage.example.com/path#canary' -b session=manual-cookie-canary",
        "curl ftp://usage.example.com/path -b session=manual-cookie-canary",
        "curl https://usage.example.com/a https://usage.example.com/b -b session=manual-cookie-canary",
    ] {
        assert!(
            matches!(
                policy.parse(raw),
                Err(ManualCaptureError::DisallowedUrl | ManualCaptureError::InvalidSyntax)
            ),
            "unsafe URL must fail: {raw}"
        );
    }
}

#[test]
fn explicit_query_capability_validates_origin_then_discards_the_query() {
    let policy = cookie_policy().with_ignored_url_query();
    let capture = policy
        .parse(
            "curl 'https://usage.example.com/api?input=public-shape&token=query-canary' \
             -b session=manual-cookie-canary",
        )
        .expect("query-bearing browser capture");

    assert_eq!(
        capture.url().map(url::Url::as_str),
        Some("https://usage.example.com/api")
    );
    let debug = format!("{capture:?}");
    assert!(!debug.contains("query-canary"));
    assert!(!debug.contains("manual-cookie-canary"));
    assert!(
        policy
            .parse("curl 'https://evil.example/api?input=x' -b session=manual-cookie-canary")
            .is_err()
    );
}

#[test]
fn loopback_http_requires_a_separate_typed_capability() {
    assert_eq!(
        ManualCapturePolicy::new(["localhost"], [CaptureHeader::Cookie])
            .expect_err("normal hosts cannot grant loopback"),
        ManualCaptureError::InvalidPolicy
    );
    assert_eq!(
        LoopbackCaptureHost::new("example.com").expect_err("public host is not loopback"),
        ManualCaptureError::InvalidPolicy
    );

    let denied = cookie_policy()
        .parse("curl http://127.0.0.1:32123/usage -b session=manual-cookie-canary")
        .expect_err("implicit loopback must fail");
    assert_eq!(denied, ManualCaptureError::DisallowedUrl);

    let policy = cookie_policy()
        .with_loopback_host(LoopbackCaptureHost::new("127.0.0.1").expect("typed loopback"))
        .expect("loopback seam");
    let capture = policy
        .parse("curl http://127.0.0.1:32123/usage -b session=manual-cookie-canary")
        .expect("explicit loopback URL");
    assert_eq!(capture.url().and_then(url::Url::port), Some(32123));

    let ipv6 = cookie_policy()
        .with_loopback_host(LoopbackCaptureHost::new("[::1]").expect("typed IPv6 loopback"))
        .expect("IPv6 loopback seam")
        .parse("curl 'http://[::1]:32124/usage' -b session=manual-cookie-canary")
        .expect("explicit IPv6 loopback URL");
    assert_eq!(ipv6.url().and_then(url::Url::port), Some(32124));
}

#[test]
fn options_that_redirect_mutate_or_read_files_are_rejected() {
    let policy = cookie_policy();
    for option in [
        "--location",
        "--location-trusted",
        "--output out.txt",
        "-o out.txt",
        "-O",
        "--remote-name",
        "--upload-file payload",
        "-T payload",
        "--request POST",
        "-X GET",
        "--data secret",
        "--data-binary @payload",
        "--form a=@payload",
        "--config curlrc",
        "-K curlrc",
        "--cookie-jar cookies",
        "-c cookies",
        "--netrc",
        "--netrc-file netrc",
        "--proxy https://proxy.example",
        "--variable name=value",
        "--expand-header 'Cookie:{{name}}'",
    ] {
        let raw = format!(
            "curl https://usage.example.com {option} -H 'Cookie: session=manual-cookie-canary'"
        );
        assert_eq!(
            policy.parse(&raw).expect_err("unsafe option must fail"),
            ManualCaptureError::UnsafeOption,
            "option {option}"
        );
    }
}

#[test]
fn shell_expansion_control_operators_and_response_files_are_rejected() {
    let policy = cookie_policy();
    for raw in [
        "curl https://usage.example.com -H \"Cookie: $COOKIE\"",
        "curl https://usage.example.com -H 'Cookie: a='$(printf canary)",
        "curl https://usage.example.com -H `printf Cookie:a=canary`",
        "curl https://usage.example.com -H @headers.txt",
        "curl https://usage.example.com --header=@-",
        "curl https://usage.example.com -b @cookies.txt",
        "curl https://usage.example.com -H @<(printf Cookie:a=canary)",
        "curl https://usage.example.com -H 'Cookie: a=canary' ; echo injected",
        "curl https://usage.example.com -H 'Cookie: a=canary' | cat",
        "curl https://usage.example.com -H 'Cookie: a=canary' > output",
        "curl https://usage.example.com/* -H 'Cookie: a=canary'",
        "curl https://usage.example.com/~user -H 'Cookie: a=canary'",
    ] {
        assert!(
            matches!(
                policy.parse(raw),
                Err(ManualCaptureError::UnsafeSyntax | ManualCaptureError::UnsafeOption)
            ),
            "shell or file syntax must fail"
        );
    }
}

#[test]
fn controls_malformed_quotes_and_ansi_escape_injection_are_rejected() {
    let policy = both_policy();
    for raw in [
        "Cookie: session=canary\r\nAuthorization: Bearer injected",
        "curl https://usage.example.com -H 'Cookie: session=canary\nX-Evil: yes'",
        "curl https://usage.example.com -H $'Cookie: session=canary\\nX-Evil: yes'",
        "curl https://usage.example.com -H \"Cookie: session=canary",
        "curl https://usage.example.com -H 'Cookie: session=canary'\0",
        "curl https://usage.example.com -H Cookie:",
        "curl https://usage.example.com -H Host; -b session=canary",
    ] {
        assert!(policy.parse(raw).is_err(), "malformed capture must fail");
    }
}

#[test]
fn cookie_and_authorization_values_are_structurally_validated() {
    let policy = both_policy();
    for raw in [
        "Cookie: not-a-cookie",
        "Cookie: =missing-name",
        "Cookie: okay=one; missing-equals",
        "Authorization:",
    ] {
        assert_eq!(
            policy.parse(raw).expect_err("invalid credential"),
            ManualCaptureError::InvalidSecret
        );
    }

    assert_eq!(
        policy
            .parse("Authorization: Custom opaque:value")
            .expect("opaque authorization syntax")
            .header(CaptureHeader::Authorization),
        Some("Custom opaque:value")
    );
}

#[test]
fn all_parser_dimensions_have_hard_bounds() {
    let policy = cookie_policy();

    let oversized = format!("Cookie: a={}", "x".repeat(64 * 1024));
    assert_eq!(
        policy.parse(&oversized).expect_err("input bound"),
        ManualCaptureError::InputTooLarge
    );

    let oversized_secret = format!("Cookie: a={}", "x".repeat(33 * 1024));
    assert_eq!(
        policy.parse(&oversized_secret).expect_err("secret bound"),
        ManualCaptureError::InvalidSecret
    );

    let many_tokens = format!(
        "curl {} -H 'Cookie: a=canary'",
        (0..256)
            .map(|_| "https://usage.example.com")
            .collect::<Vec<_>>()
            .join(" ")
    );
    assert_eq!(
        policy.parse(&many_tokens).expect_err("token bound"),
        ManualCaptureError::TooManyTokens
    );

    let many_headers = format!(
        "curl https://usage.example.com {} -H 'Cookie: a=canary'",
        (0..32)
            .map(|_| "-H 'Accept: */*'")
            .collect::<Vec<_>>()
            .join(" ")
    );
    assert_eq!(
        policy.parse(&many_headers).expect_err("header bound"),
        ManualCaptureError::TooManyHeaders
    );

    let deep_quotes = format!(
        "curl https://usage.example.com -H '{}Cookie: a=canary'",
        "''".repeat(257)
    );
    assert_eq!(
        policy.parse(&deep_quotes).expect_err("quote bound"),
        ManualCaptureError::InvalidSyntax
    );
}

#[test]
fn policy_host_lists_are_exact_and_bounded() {
    for host in [
        "",
        "https://usage.example.com",
        "usage.example.com/path",
        "usage.example.com:443",
        "*.example.com",
        "user@usage.example.com",
        "usage.example.com?x=1",
        "usage.example.com#fragment",
    ] {
        assert_eq!(
            ManualCapturePolicy::new([host], [CaptureHeader::Cookie]).expect_err("invalid host"),
            ManualCaptureError::InvalidPolicy
        );
    }

    let too_many = (0..33)
        .map(|index| format!("host-{index}.example.com"))
        .collect::<Vec<_>>();
    assert_eq!(
        ManualCapturePolicy::new(&too_many, [CaptureHeader::Cookie]).expect_err("host bound"),
        ManualCaptureError::InvalidPolicy
    );
    assert_eq!(
        ManualCapturePolicy::new(["usage.example.com"], [])
            .expect_err("header authority cannot be empty"),
        ManualCaptureError::InvalidPolicy
    );
    assert_eq!(
        ManualCapturePolicy::new(
            ["usage.example.com"],
            [CaptureHeader::Cookie, CaptureHeader::Cookie],
        )
        .expect_err("duplicate header authority"),
        ManualCaptureError::InvalidPolicy
    );
    assert_eq!(
        cookie_policy()
            .with_forwarded_headers(["x".repeat(129)])
            .expect_err("forwarded header-name bound"),
        ManualCaptureError::InvalidPolicy
    );
}

#[test]
fn debug_and_error_surfaces_are_fully_redacted() {
    let policy = both_policy();
    let capture = policy
        .parse(
            "curl 'https://usage.example.com/manual-url-canary' -H 'Cookie: session=manual-cookie-canary' -H 'Authorization: Bearer manual-authorization-canary'",
        )
        .expect("redaction fixture");

    let debug = format!("{policy:?} {capture:?}");
    for canary in [
        "manual-cookie-canary",
        "manual-authorization-canary",
        "manual-url-canary",
        "usage.example.com",
    ] {
        assert!(!debug.contains(canary));
    }

    let error = policy
        .parse("curl https://evil.example/manual-error-canary -b session=error-canary")
        .expect_err("disallowed URL");
    let diagnostics = format!("{error:?} {error}");
    assert!(!diagnostics.contains("error-canary"));
    assert!(!diagnostics.contains("evil.example"));
    assert!(!diagnostics.contains("manual-error-canary"));
}
