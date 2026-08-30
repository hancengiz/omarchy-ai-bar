use reqwest::Method;
use time::{Date, Month, OffsetDateTime, Time, UtcOffset};
use url::Url;

use oab_providers::cloud_signing::{
    AwsCredentials, AwsSigV4Signer, SigningError, SigningRequest, VolcengineCredentials,
    VolcengineV4Signer,
};

fn timestamp() -> OffsetDateTime {
    OffsetDateTime::new_utc(
        Date::from_calendar_date(2026, Month::June, 17).expect("date"),
        Time::MIDNIGHT,
    )
}

fn aws_credentials(session_token: Option<&str>) -> AwsCredentials {
    AwsCredentials::new(
        "AKIDEXAMPLE",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        session_token,
    )
    .expect("AWS credentials")
}

fn aws_signer() -> AwsSigV4Signer {
    AwsSigV4Signer::new("us-east-1", "ce").expect("AWS signer")
}

#[test]
fn aws_cost_explorer_known_answer_matches_upstream() {
    let request = SigningRequest::new(
        Method::POST,
        Url::parse("https://ce.us-east-1.amazonaws.com/").expect("URL"),
        br#"{"Granularity":"MONTHLY"}"#.to_vec(),
    )
    .expect("request")
    .with_header("Content-Type", "application/x-amz-json-1.1")
    .expect("content type")
    .with_header("X-Amz-Target", "AWSInsightsIndexService.GetCostAndUsage")
    .expect("target");

    let signed = aws_signer()
        .sign(request, &aws_credentials(None), timestamp())
        .expect("signed request");

    assert_eq!(signed.method(), Method::POST);
    assert_eq!(signed.body(), br#"{"Granularity":"MONTHLY"}"#);
    assert!(
        signed
            .headers()
            .iter()
            .all(|header| header.to_header_value().is_sensitive())
    );
    assert_eq!(
        signed.header("x-amz-content-sha256"),
        Some("412486d71b67ac35ce7b3d0f9b85f309291d25172c913abda180644baf343123")
    );
    assert_eq!(signed.header("x-amz-date"), Some("20260617T000000Z"));
    assert_eq!(
        signed.canonical_request_hash_hex(),
        "aa8e907d16ad8979b6a1e78c6ebc730c8a5eb8b7c01b10d0f481c40e8f19fe7a"
    );
    assert_eq!(
        signed.header("authorization"),
        Some(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260617/us-east-1/ce/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target, Signature=0c7d90f333961c1c44f9be3fc4144e5085bf1aadd5c08680e2e6bdc5577db0c9"
        )
    );
}

#[test]
fn volcengine_coding_plan_known_answer_matches_upstream() {
    let request = SigningRequest::new(
        Method::POST,
        Url::parse("https://open.volcengineapi.com/?Action=GetCodingPlanUsage&Version=2024-01-01")
            .expect("URL"),
        Vec::new(),
    )
    .expect("request")
    .with_header(
        "Content-Type",
        "application/x-www-form-urlencoded; charset=utf-8",
    )
    .expect("content type");
    let credentials =
        VolcengineCredentials::new("AKLTTEST", "secret", "cn-beijing").expect("credentials");

    let signed =
        VolcengineV4Signer::sign(request, &credentials, timestamp()).expect("signed request");

    assert_eq!(
        signed.header("x-content-sha256"),
        Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(signed.header("x-date"), Some("20260617T000000Z"));
    assert_eq!(
        signed.canonical_request_hash_hex(),
        "7d7c7791a50129fed5c897fd0a89d8c92e6b8ab9b466b49979cfab29ea4d0f26"
    );
    assert_eq!(
        signed.header("authorization"),
        Some(
            "HMAC-SHA256 Credential=AKLTTEST/20260617/cn-beijing/ark/request, SignedHeaders=content-type;host;x-content-sha256;x-date, Signature=220f360943ab513c639db31ee72aeee7fa8b915812cde28ce104d6496b0bd24d"
        )
    );
}

#[test]
fn aws_session_token_is_signed_and_all_debug_output_is_redacted() {
    let secret = "not-a-debug-secret";
    let token = "not-a-debug-session-token";
    let credentials =
        AwsCredentials::new("NOTADEBUGACCESSKEY", secret, Some(token)).expect("credentials");
    let request = SigningRequest::new(
        Method::GET,
        Url::parse("https://example.com/private?api_key=not-a-debug-query").expect("URL"),
        b"not-a-debug-body".to_vec(),
    )
    .expect("request")
    .with_header("X-Custom", "not-a-debug-header")
    .expect("header");
    let signed = aws_signer()
        .sign(request, &credentials, timestamp())
        .expect("signed request");
    let authorization = signed.header("authorization").expect("authorization");

    assert_eq!(signed.header("x-amz-security-token"), Some(token));
    assert!(authorization.contains("x-amz-security-token"));
    let credential_debug = format!("{credentials:?}");
    let request_debug = format!("{signed:?}");
    for sensitive in [
        "NOTADEBUGACCESSKEY",
        secret,
        token,
        "not-a-debug-query",
        "not-a-debug-body",
        "not-a-debug-header",
        authorization,
    ] {
        assert!(!credential_debug.contains(sensitive));
        assert!(!request_debug.contains(sensitive));
    }
    assert!(credential_debug.contains("<redacted>"));
    assert!(request_debug.contains("<redacted>"));
}

#[test]
fn duplicate_queries_are_sorted_by_encoded_key_then_value_without_plus_decoding() {
    let first = SigningRequest::new(
        Method::GET,
        Url::parse("https://example.com/path?z=last&a=two&a=one&q=a+b").expect("URL"),
        Vec::new(),
    )
    .expect("request");
    let second = SigningRequest::new(
        Method::GET,
        Url::parse("https://example.com/path?q=a%2Bb&a=one&z=last&a=two").expect("URL"),
        Vec::new(),
    )
    .expect("request");

    let first = aws_signer()
        .sign(first, &aws_credentials(None), timestamp())
        .expect("first signature");
    let second = aws_signer()
        .sign(second, &aws_credentials(None), timestamp())
        .expect("second signature");

    assert_eq!(
        first.header("authorization"),
        second.header("authorization")
    );
    assert_eq!(
        first.canonical_request_hash_hex(),
        second.canonical_request_hash_hex()
    );
}

#[test]
fn unicode_and_percent_encoded_paths_have_one_rfc3986_canonical_form() {
    let raw = SigningRequest::new(
        Method::GET,
        Url::parse("https://example.com/café/~user/a%2fb").expect("URL"),
        Vec::new(),
    )
    .expect("request");
    let encoded = SigningRequest::new(
        Method::GET,
        Url::parse("https://example.com/caf%C3%A9/%7Euser/a%2Fb").expect("URL"),
        Vec::new(),
    )
    .expect("request");

    let raw = aws_signer()
        .sign(raw, &aws_credentials(None), timestamp())
        .expect("raw path signature");
    let encoded = aws_signer()
        .sign(encoded, &aws_credentials(None), timestamp())
        .expect("encoded path signature");

    assert_eq!(raw.header("authorization"), encoded.header("authorization"));
}

#[test]
fn aws_folds_header_whitespace_and_sorts_header_names() {
    let spaced = SigningRequest::new(
        Method::POST,
        Url::parse("https://example.com/").expect("URL"),
        Vec::new(),
    )
    .expect("request")
    .with_header("Z-Last", "  alpha\t\t beta  ")
    .expect("header")
    .with_header("A-First", "value")
    .expect("header");
    let folded = SigningRequest::new(
        Method::POST,
        Url::parse("https://example.com/").expect("URL"),
        Vec::new(),
    )
    .expect("request")
    .with_header("a-first", "value")
    .expect("header")
    .with_header("z-last", "alpha beta")
    .expect("header");

    let spaced = aws_signer()
        .sign(spaced, &aws_credentials(None), timestamp())
        .expect("spaced signature");
    let folded = aws_signer()
        .sign(folded, &aws_credentials(None), timestamp())
        .expect("folded signature");
    assert_eq!(
        spaced.header("authorization"),
        folded.header("authorization")
    );
    assert_eq!(spaced.header("z-last"), Some("alpha beta"));
}

#[test]
fn host_includes_only_non_default_ports_and_ipv6_brackets() {
    for (url, expected) in [
        ("https://example.com:443/", "example.com"),
        ("https://example.com:8443/", "example.com:8443"),
        ("https://[2001:db8::1]:9443/", "[2001:db8::1]:9443"),
    ] {
        let request = SigningRequest::new(Method::GET, Url::parse(url).expect("URL"), Vec::new())
            .expect("request");
        let signed = aws_signer()
            .sign(request, &aws_credentials(None), timestamp())
            .expect("signed request");
        assert_eq!(signed.header("host"), Some(expected));
    }
}

#[test]
fn volcengine_signs_exactly_the_required_headers_and_defaults_content_type() {
    let request = SigningRequest::new(
        Method::POST,
        Url::parse("https://open.volcengineapi.com/?b=2&a=3&a=1").expect("URL"),
        Vec::new(),
    )
    .expect("request")
    .with_header("X-Trace", "allowed-but-not-signed")
    .expect("trace header");
    let credentials =
        VolcengineCredentials::new("AKLTTEST", "secret", "cn-beijing").expect("credentials");
    let signed =
        VolcengineV4Signer::sign(request, &credentials, timestamp()).expect("signed request");

    assert_eq!(
        signed.header("content-type"),
        Some("application/x-www-form-urlencoded; charset=utf-8")
    );
    let authorization = signed.header("authorization").expect("authorization");
    assert!(authorization.contains("SignedHeaders=content-type;host;x-content-sha256;x-date"));
    assert!(!authorization.contains("x-trace"));
}

#[test]
fn unsafe_unbounded_and_non_utc_inputs_are_rejected_without_echoing_values() {
    let unsafe_secret = "unsafe secret with spaces";
    let credential_error = AwsCredentials::new("key", unsafe_secret, None::<String>)
        .expect_err("unsafe credential must fail");
    assert_eq!(credential_error, SigningError::InvalidCredential);
    assert!(!credential_error.to_string().contains(unsafe_secret));

    assert_eq!(
        AwsSigV4Signer::new("US_EAST_1", "ce").expect_err("invalid scope"),
        SigningError::InvalidScope
    );
    assert_eq!(
        SigningRequest::new(
            Method::GET,
            Url::parse("http://example.com/").expect("URL"),
            Vec::new(),
        )
        .expect_err("HTTP must fail"),
        SigningError::InvalidUrl
    );
    assert_eq!(
        SigningRequest::new(
            Method::POST,
            Url::parse("https://example.com/").expect("URL"),
            vec![0; 8 * 1024 * 1024 + 1],
        )
        .expect_err("oversized body must fail"),
        SigningError::BodyTooLarge
    );

    let request = SigningRequest::new(
        Method::GET,
        Url::parse("https://example.com/").expect("URL"),
        Vec::new(),
    )
    .expect("request");
    let non_utc = timestamp().to_offset(UtcOffset::from_hms(3, 0, 0).expect("offset"));
    assert_eq!(
        aws_signer()
            .sign(request, &aws_credentials(None), non_utc)
            .expect_err("non-UTC time must fail"),
        SigningError::InvalidTimestamp
    );
}

#[test]
fn caller_cannot_override_signer_managed_headers() {
    let request = SigningRequest::new(
        Method::GET,
        Url::parse("https://example.com/").expect("URL"),
        Vec::new(),
    )
    .expect("request")
    .with_header("X-Amz-Date", "20200101T000000Z")
    .expect("syntactically valid header");
    assert_eq!(
        aws_signer()
            .sign(request, &aws_credentials(None), timestamp())
            .expect_err("managed header must fail"),
        SigningError::InvalidHeaders
    );
}

#[test]
fn exact_custom_method_changes_the_signature_without_case_normalization() {
    let lower_method = Method::from_bytes(b"m-search").expect("custom method");
    let upper_method = Method::from_bytes(b"M-SEARCH").expect("custom method");
    let lower = SigningRequest::new(
        lower_method,
        Url::parse("https://example.com/").expect("URL"),
        Vec::new(),
    )
    .expect("lower request");
    let upper = SigningRequest::new(
        upper_method,
        Url::parse("https://example.com/").expect("URL"),
        Vec::new(),
    )
    .expect("upper request");
    let lower = aws_signer()
        .sign(lower, &aws_credentials(None), timestamp())
        .expect("lower signature");
    let upper = aws_signer()
        .sign(upper, &aws_credentials(None), timestamp())
        .expect("upper signature");

    assert_ne!(lower.header("authorization"), upper.header("authorization"));
}
