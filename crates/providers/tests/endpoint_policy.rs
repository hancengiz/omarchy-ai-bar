use oab_providers::endpoint::{
    EndpointClass, EndpointError, EndpointPolicy, classify_https_endpoint,
};
use url::Url;

#[test]
fn public_policy_requires_exact_credential_free_https_origins() {
    let policy = EndpointPolicy::new([("https://api.example.com", EndpointClass::PublicHttps)])
        .expect("public policy");

    let accepted = policy
        .validate(
            &Url::parse("https://api.example.com/v1/usage?window=weekly").expect("accepted URL"),
        )
        .expect("validate exact origin");
    assert_eq!(accepted.url().path(), "/v1/usage");

    for rejected in [
        "http://api.example.com/v1/usage",
        "https://user:secret@api.example.com/v1/usage",
        "https://other.example.com/v1/usage",
        "https://api.example.com/v1/usage#secret",
        "https://api.example.com/v1/usage?api_key=secret",
    ] {
        assert!(
            policy
                .validate(&Url::parse(rejected).expect("syntactically valid rejected URL"))
                .is_err(),
            "accepted {rejected}"
        );
    }
}

#[test]
fn public_origins_reject_local_and_private_network_authority() {
    for origin in [
        "https://localhost",
        "https://service.local",
        "https://127.0.0.1",
        "https://10.0.0.1",
        "https://192.168.1.1",
        "https://[::1]",
    ] {
        assert!(
            EndpointPolicy::new([(origin, EndpointClass::PublicHttps)]).is_err(),
            "accepted public origin {origin}"
        );
    }
}

#[test]
fn loopback_http_requires_an_exact_typed_approval() {
    let policy =
        EndpointPolicy::new([("http://127.0.0.1:18443", EndpointClass::LoopbackDevelopment)])
            .expect("explicit loopback policy");
    assert!(
        policy
            .validate(&Url::parse("http://127.0.0.1:18443/usage").expect("loopback URL"))
            .is_ok()
    );
    assert!(
        policy
            .validate(&Url::parse("http://127.0.0.1:18444/usage").expect("other port"))
            .is_err()
    );
    assert!(
        EndpointPolicy::new([("http://api.example.com", EndpointClass::LoopbackDevelopment)])
            .is_err()
    );
}

#[test]
fn configured_https_endpoints_are_classified_without_weakening_host_policy() {
    for (endpoint, expected) in [
        ("https://api.example.com/base", EndpointClass::PublicHttps),
        ("https://10.0.0.4/base", EndpointClass::PrivateHttps),
        (
            "https://localhost:8443/base",
            EndpointClass::LoopbackDevelopment,
        ),
    ] {
        assert_eq!(
            classify_https_endpoint(&Url::parse(endpoint).expect("endpoint URL"))
                .expect("classified endpoint"),
            expected
        );
    }
    for rejected in [
        "http://api.example.com",
        "https://user:secret@api.example.com",
        "https://api.example.com?api_key=secret",
    ] {
        assert!(
            classify_https_endpoint(&Url::parse(rejected).expect("rejected URL")).is_err(),
            "accepted {rejected}"
        );
    }
}

#[test]
fn endpoint_debug_output_never_contains_url_credentials_or_query_values() {
    let error = EndpointError::UnapprovedOrigin;
    let debug = format!("{error:?}");
    assert!(!debug.contains("fixture-secret"));

    let policy = EndpointPolicy::new([("https://api.example.com", EndpointClass::PublicHttps)])
        .expect("public policy");
    let endpoint = policy
        .validate(
            &Url::parse("https://api.example.com/private/account?note=fixture-secret")
                .expect("URL"),
        )
        .expect("validated URL");
    let debug = format!("{endpoint:?}");
    assert!(!debug.contains("private"));
    assert!(!debug.contains("fixture-secret"));
}
