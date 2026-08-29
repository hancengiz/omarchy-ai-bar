use oab_domain::ErrorKind;
use oab_providers::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy, clean_setting};
use oab_providers::endpoint::EndpointClass;

#[test]
fn settings_are_trimmed_unquoted_and_require_an_explicit_scheme() {
    assert_eq!(
        clean_setting("  'https://proxy.example/v1'  "),
        Some("https://proxy.example/v1")
    );
    assert_eq!(clean_setting("  "), None);
    assert_eq!(
        ConfiguredEndpoint::parse("proxy.example", ConfiguredHttpPolicy::PrivateNetworkHttp)
            .expect_err("missing scheme")
            .kind(),
        ErrorKind::Api
    );
}

#[test]
fn https_origins_retain_explicit_public_private_and_loopback_classes() {
    for (raw, class) in [
        ("https://proxy.example/base", EndpointClass::PublicHttps),
        ("https://10.0.0.4/base", EndpointClass::PrivateHttps),
        (
            "https://localhost:8443/base",
            EndpointClass::LoopbackDevelopment,
        ),
    ] {
        let endpoint = ConfiguredEndpoint::parse(raw, ConfiguredHttpPolicy::HttpsOnly)
            .expect("HTTPS endpoint");
        assert_eq!(endpoint.class(), class);
    }
}

#[test]
fn loopback_http_requires_the_loopback_or_private_policy() {
    for raw in [
        "http://127.0.0.1:4000/base",
        "http://localhost/base",
        "http://[::1]/base",
    ] {
        assert_eq!(
            ConfiguredEndpoint::parse(raw, ConfiguredHttpPolicy::HttpsOnly)
                .expect_err("HTTPS-only policy")
                .kind(),
            ErrorKind::Api
        );
        assert_eq!(
            ConfiguredEndpoint::parse(raw, ConfiguredHttpPolicy::LoopbackHttp)
                .expect("loopback HTTP")
                .class(),
            EndpointClass::LoopbackDevelopment
        );
    }
}

#[test]
fn private_http_is_typed_and_public_http_is_always_rejected() {
    for raw in [
        "http://10.0.0.4/base",
        "http://172.16.5.1/base",
        "http://192.168.1.8/base",
        "http://169.254.10.2/base",
        "http://[fc00::1]/base",
        "http://[fe80::1]/base",
        "http://litellm.local/base",
        "http://litellm.local./base",
    ] {
        let endpoint = ConfiguredEndpoint::parse(raw, ConfiguredHttpPolicy::PrivateNetworkHttp)
            .expect("private HTTP");
        assert_eq!(endpoint.class(), EndpointClass::PrivateHttp, "{raw}");
    }
    for raw in [
        "http://proxy.example/base",
        "http://8.8.8.8/base",
        "http://litellm/base",
        "http://192.0.2.1/base",
    ] {
        assert_eq!(
            ConfiguredEndpoint::parse(raw, ConfiguredHttpPolicy::PrivateNetworkHttp)
                .expect_err("public/non-private HTTP")
                .kind(),
            ErrorKind::Api,
            "{raw}"
        );
    }
}

#[test]
fn credentials_query_fragments_and_non_http_schemes_fail_before_transport() {
    for raw in [
        "https://user:secret@proxy.example",
        "https://proxy.example?token=secret",
        "https://proxy.example#fragment",
        "ftp://proxy.example",
        "http://user@127.0.0.1",
    ] {
        let error = ConfiguredEndpoint::parse(raw, ConfiguredHttpPolicy::PrivateNetworkHttp)
            .expect_err("unsafe configured endpoint");
        assert_eq!(error.kind(), ErrorKind::Api);
        assert!(!format!("{error:?}").contains("secret"));
    }
}

#[test]
fn provider_paths_preserve_nested_bases_and_strip_only_terminal_v1() {
    for (raw, expected) in [
        ("https://proxy.example", "https://proxy.example/key/info"),
        ("https://proxy.example/v1", "https://proxy.example/key/info"),
        (
            "https://proxy.example/v1/",
            "https://proxy.example/key/info",
        ),
        (
            "https://gateway.example/litellm/v1/",
            "https://gateway.example/litellm/user/info",
        ),
    ] {
        let endpoint = ConfiguredEndpoint::parse(raw, ConfiguredHttpPolicy::HttpsOnly)
            .expect("configured endpoint");
        let segments = if expected.ends_with("user/info") {
            &["user", "info"][..]
        } else {
            &["key", "info"][..]
        };
        assert_eq!(
            endpoint
                .path(Some("v1"), segments)
                .expect("provider path")
                .as_str(),
            expected
        );
    }
}

#[test]
fn configured_endpoint_debug_never_exposes_authority_or_path() {
    let endpoint = ConfiguredEndpoint::parse(
        "https://private-host-canary.example/private-path-canary",
        ConfiguredHttpPolicy::HttpsOnly,
    )
    .expect("configured endpoint");
    let debug = format!("{endpoint:?}");
    assert!(!debug.contains("private-host-canary"));
    assert!(!debug.contains("private-path-canary"));
}
