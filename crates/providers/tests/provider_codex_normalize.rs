use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oab_domain::{
    AccountKey, AccountScope, DataConfidence, ExactDecimal, ProviderId, ProviderInstanceId,
    Timestamp, WindowDuration,
};
use oab_providers::providers::codex::{
    CodexCredentialSource, parse_codex_bearer, parse_native_codex_pat,
};
use oab_providers::providers::codex_http::{
    CodexHttpClient, CodexHttpError, CodexHttpRoutes, parse_codex_usage_response,
};
use oab_providers::providers::codex_normalize::{
    normalize_codex_oauth_usage, normalize_codex_pat_usage,
};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use serde_json::json;
use tokio_util::sync::CancellationToken;

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::Codex,
        ProviderInstanceId::new("codex-primary").expect("provider instance"),
        AccountKey::new("account-one").expect("account key"),
    )
}

fn foreign_scope() -> AccountScope {
    AccountScope::new(
        ProviderId::Claude,
        ProviderInstanceId::new("claude-primary").expect("provider instance"),
        AccountKey::new("account-one").expect("account key"),
    )
}

fn fetched_at() -> Timestamp {
    Timestamp::parse("2026-08-30T12:00:00Z").expect("test timestamp")
}

fn jwt(payload: &serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("JWT payload"));
    format!("{header}.{payload}.signature")
}

fn bearer(id_token: Option<&str>) -> oab_providers::providers::codex::CodexBearerCredentials {
    parse_codex_bearer(
        serde_json::to_string(&json!({
            "tokens": {
                "access_token": "access",
                "refresh_token": "refresh",
                "id_token": id_token,
                "account_id": "credential-account"
            }
        }))
        .expect("bearer JSON")
        .as_bytes(),
        CodexCredentialSource::Native,
    )
    .expect("bearer")
}

#[test]
fn oauth_projection_normalizes_roles_identity_credits_and_provenance() {
    let response = parse_codex_usage_response(
        br#"{
            "account_id":"response-account",
            "plan_type":"pro",
            "rate_limit":{
                "primary_window":{"used_percent":80,"reset_at":1788220800,"limit_window_seconds":604800},
                "secondary_window":{"used_percent":20,"reset_at":1782864000,"limit_window_seconds":18000}
            },
            "credits":{"has_credits":false,"unlimited":true,"balance":"12.5"},
            "individual_limit":{"limit":1000,"remaining_percent":25,"reset_at":1788220800}
        }"#,
    )
    .expect("usage response");
    let id_token = jwt(&json!({
        "email": "owner@example.test",
        "chatgpt_plan_type": "jwt-plan"
    }));
    let credentials = bearer(Some(&id_token));
    let sample = normalize_codex_oauth_usage(
        &response,
        &credentials,
        Some("managed-account"),
        scope(),
        fetched_at(),
    )
    .expect("normalized OAuth sample");

    let session_usage = sample
        .primary()
        .and_then(oab_domain::RateWindow::used_percent)
        .expect("session usage")
        .get();
    assert!((session_usage - 20.0).abs() <= f64::EPSILON);
    assert_eq!(
        sample
            .primary()
            .and_then(oab_domain::RateWindow::duration)
            .map(WindowDuration::seconds),
        Some(18_000)
    );
    assert_eq!(
        sample
            .secondary()
            .and_then(oab_domain::RateWindow::duration)
            .map(WindowDuration::seconds),
        Some(604_800)
    );
    assert_eq!(
        sample
            .identity()
            .provider_account_id()
            .expect("managed account")
            .as_str(),
        "managed-account"
    );
    assert_eq!(
        sample.identity().email().expect("JWT email").as_str(),
        "owner@example.test"
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("response plan")
            .as_str(),
        "pro"
    );
    let credits = sample.credits().expect("credits");
    assert_eq!(
        credits.remaining(),
        ExactDecimal::parse("12.5").expect("expected balance")
    );
    let limit = credits.limit().expect("monthly limit");
    assert_eq!(limit.used(), ExactDecimal::parse("750").expect("used"));
    assert!((limit.remaining_percent().get() - 25.0).abs() <= f64::EPSILON);
    assert_eq!(sample.confidence(), DataConfidence::Exact);
    assert_eq!(sample.provenance()[0].source(), "codex");
    assert_eq!(sample.provenance()[0].strategy(), "oauth");
}

#[test]
fn additional_limits_map_spark_generic_deduplicate_and_mark_lossy() {
    let response = parse_codex_usage_response(
        br#"{
            "rate_limit":{"primary_window":{"used_percent":22,"reset_at":1766948068,"limit_window_seconds":18000}},
            "additional_rate_limits":[
                "malformed",
                {
                    "limit_name":"GPT-5.3-Codex-Spark",
                    "metered_feature":"gpt_5_3_codex_spark",
                    "rate_limit":{
                        "primary_window":{"used_percent":30,"reset_at":1766948068,"limit_window_seconds":18000},
                        "secondary_window":{"used_percent":100,"reset_at":1767407914,"limit_window_seconds":604800}
                    }
                },
                {
                    "limit_name":"GPT-5.3-Codex-Mini",
                    "metered_feature":"gpt_5_3_codex_mini",
                    "rate_limit":{"primary_window":{"used_percent":12,"reset_at":1766948068,"limit_window_seconds":18000}}
                },
                {
                    "limit_name":"duplicate",
                    "metered_feature":"gpt_5_3_codex_mini",
                    "rate_limit":{"primary_window":{"used_percent":99,"reset_at":1766948068,"limit_window_seconds":18000}}
                }
            ]
        }"#,
    )
    .expect("lossy additional response");
    let sample = normalize_codex_oauth_usage(&response, &bearer(None), None, scope(), fetched_at())
        .expect("normalized extras");

    let ids = sample
        .extra_windows()
        .iter()
        .map(|window| window.id().as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        [
            "codex-gpt-5-3-codex-mini",
            "codex-spark",
            "codex-spark-weekly"
        ]
    );
    let spark = sample
        .extra_windows()
        .iter()
        .find(|window| window.id().as_str() == "codex-spark")
        .expect("Spark session");
    assert_eq!(spark.title().as_str(), "Codex Spark 5-hour");
    assert_eq!(
        spark.window().duration().map(WindowDuration::seconds),
        Some(18_000)
    );
    assert_eq!(sample.confidence(), DataConfidence::Unknown);
}

#[test]
fn extra_windows_never_resurrect_an_otherwise_empty_response() {
    let response = parse_codex_usage_response(
        br#"{
            "additional_rate_limits":[{
                "metered_feature":"gpt_5_3_codex_spark",
                "rate_limit":{"primary_window":{"used_percent":30,"reset_at":1766948068,"limit_window_seconds":18000}}
            }]
        }"#,
    )
    .expect("extras-only response");
    let error = normalize_codex_oauth_usage(&response, &bearer(None), None, scope(), fetched_at())
        .expect_err("supplemental windows must not create a sample");
    assert_eq!(error, CodexHttpError::InvalidResponse);
}

#[test]
fn foreign_provider_scope_is_rejected_before_projection() {
    let response = parse_codex_usage_response(
        br#"{
            "rate_limit":{"primary_window":{
                "used_percent":22,"reset_at":1766948068,"limit_window_seconds":18000
            }}
        }"#,
    )
    .expect("usage response");
    let error = normalize_codex_oauth_usage(
        &response,
        &bearer(None),
        None,
        foreign_scope(),
        fetched_at(),
    )
    .expect_err("foreign scope");

    assert_eq!(error, CodexHttpError::Configuration);
}

#[test]
fn parser_bound_identity_fallbacks_are_marked_lossy() {
    let response = serde_json::to_vec(&json!({
        "account_id": "a".repeat(1025),
        "plan_type": "p".repeat(129),
        "rate_limit": {
            "primary_window": {
                "used_percent": 22,
                "reset_at": 1_766_948_068_i64,
                "limit_window_seconds": 18_000
            }
        }
    }))
    .expect("overbound identity response");
    let response = parse_codex_usage_response(&response).expect("lossy identity response");
    let id_token = jwt(&json!({"chatgpt_plan_type": "jwt-plan"}));
    let sample = normalize_codex_oauth_usage(
        &response,
        &bearer(Some(&id_token)),
        None,
        scope(),
        fetched_at(),
    )
    .expect("bounded identity fallback sample");

    assert_eq!(
        sample
            .identity()
            .provider_account_id()
            .expect("credential account fallback")
            .as_str(),
        "credential-account"
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("JWT plan fallback")
            .as_str(),
        "jwt-plan"
    );
    assert_eq!(sample.confidence(), DataConfidence::Unknown);
}

#[test]
fn credit_only_response_builds_an_empty_credited_sample() {
    let response = parse_codex_usage_response(
        br#"{
            "plan_type":"team",
            "rate_limit":{"primary_window":null,"secondary_window":null},
            "credits":{"has_credits":false,"unlimited":true,"balance":0}
        }"#,
    )
    .expect("credits-only response");
    let sample = normalize_codex_oauth_usage(&response, &bearer(None), None, scope(), fetched_at())
        .expect("credits-only sample");

    assert!(sample.primary().is_none());
    assert!(sample.secondary().is_none());
    assert!(sample.extra_windows().is_empty());
    assert_eq!(
        sample.credits().expect("zero balance").remaining(),
        ExactDecimal::parse("0").expect("zero")
    );
    assert_eq!(sample.confidence(), DataConfidence::Unknown);
}

#[test]
fn negative_credit_balance_is_safely_clamped_and_marked_lossy() {
    let response = parse_codex_usage_response(br#"{"credits":{"balance":-4.5}}"#)
        .expect("negative credit response");
    let sample = normalize_codex_oauth_usage(&response, &bearer(None), None, scope(), fetched_at())
        .expect("clamped credit sample");

    assert_eq!(
        sample.credits().expect("credits").remaining(),
        ExactDecimal::parse("0").expect("zero")
    );
    assert_eq!(sample.confidence(), DataConfidence::Unknown);
}

#[test]
fn role_and_spark_classification_use_pinned_whole_minutes() {
    let response = parse_codex_usage_response(
        br#"{
            "rate_limit":{
                "primary_window":{"used_percent":80,"reset_at":1788220800,"limit_window_seconds":604859},
                "secondary_window":{"used_percent":20,"reset_at":1782864000,"limit_window_seconds":18059}
            },
            "additional_rate_limits":[{
                "metered_feature":"codex_spark",
                "rate_limit":{
                    "primary_window":{"used_percent":30,"reset_at":1766948068,"limit_window_seconds":21659},
                    "secondary_window":{"used_percent":90,"reset_at":1767407914,"limit_window_seconds":59}
                }
            }]
        }"#,
    )
    .expect("whole-minute response");
    let sample = normalize_codex_oauth_usage(&response, &bearer(None), None, scope(), fetched_at())
        .expect("whole-minute normalization");

    assert_eq!(
        sample
            .primary()
            .and_then(oab_domain::RateWindow::duration)
            .map(WindowDuration::seconds),
        Some(18_000)
    );
    assert_eq!(
        sample
            .secondary()
            .and_then(oab_domain::RateWindow::duration)
            .map(WindowDuration::seconds),
        Some(604_800)
    );
    assert_eq!(
        sample
            .extra_windows()
            .iter()
            .map(|window| window.id().as_str())
            .collect::<Vec<_>>(),
        ["codex-spark", "codex-spark-weekly"]
    );
    assert_eq!(sample.confidence(), DataConfidence::Unknown);
}

#[test]
fn positive_out_of_domain_resets_downgrade_confidence_without_dropping_usage() {
    let response = parse_codex_usage_response(
        br#"{
            "rate_limit":{"primary_window":{
                "used_percent":22,
                "reset_at":9223372036854775807,
                "limit_window_seconds":18000
            }}
        }"#,
    )
    .expect("out-of-domain reset response");
    let sample = normalize_codex_oauth_usage(&response, &bearer(None), None, scope(), fetched_at())
        .expect("usage survives invalid reset");

    assert!(sample.primary().expect("primary").resets_at().is_none());
    assert_eq!(sample.confidence(), DataConfidence::Unknown);
}

#[test]
fn core_windows_preserve_representable_epoch_and_pre_epoch_resets() {
    let response = parse_codex_usage_response(
        br#"{
            "rate_limit":{
                "primary_window":{"used_percent":10,"reset_at":0,"limit_window_seconds":18000},
                "secondary_window":{"used_percent":20,"reset_at":-1,"limit_window_seconds":604800}
            }
        }"#,
    )
    .expect("representable reset response");
    let sample = normalize_codex_oauth_usage(&response, &bearer(None), None, scope(), fetched_at())
        .expect("representable resets");

    assert_eq!(
        sample.primary().expect("primary").resets_at(),
        Some(Timestamp::from_unix_timestamp(0).expect("epoch"))
    );
    assert_eq!(
        sample.secondary().expect("secondary").resets_at(),
        Some(Timestamp::from_unix_timestamp(-1).expect("pre-epoch"))
    );
    assert_eq!(sample.confidence(), DataConfidence::Exact);
}

#[tokio::test]
async fn pat_projection_uses_token_owned_identity_and_response_plan() {
    let server = FakeHttpServer::start(vec![
        FakeHttpResponse::new(
            200,
            br#"{"chatgpt_account_id":"token-account","email":"pat@example.test","chatgpt_plan_type":"whoami-plan"}"#.to_vec(),
        ),
        FakeHttpResponse::new(
            200,
            br#"{
                "account_id":"untrusted-response-account",
                "plan_type":"response-plan",
                "rate_limit":{"primary_window":{"used_percent":7,"reset_at":1782864000,"limit_window_seconds":18000}}
            }"#.to_vec(),
        ),
    ])
    .await;
    let routes = CodexHttpRoutes::loopback(
        server.url("/api/accounts/v1/user-auth-credential/whoami"),
        server.url("/backend-api/wham/usage"),
    )
    .expect("loopback routes");
    let config = TransportConfig::new(
        Duration::from_millis(500),
        Duration::from_millis(500),
        1024 * 1024,
        3,
        RetryPolicy::none(),
    )
    .expect("transport config");
    let client = CodexHttpClient::with_transport_config(routes, config).expect("HTTP client");
    let credentials =
        parse_native_codex_pat(br#"{"personal_access_token":"pat"}"#).expect("PAT credentials");
    let fetch = client
        .fetch_pat_usage(&credentials, Some("1.2.3"), &CancellationToken::new())
        .await
        .expect("PAT fetch");
    let sample = normalize_codex_pat_usage(&fetch, scope(), fetched_at()).expect("PAT sample");

    assert_eq!(
        sample
            .identity()
            .provider_account_id()
            .expect("token account")
            .as_str(),
        "token-account"
    );
    assert_eq!(
        sample.identity().email().expect("PAT email").as_str(),
        "pat@example.test"
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("response plan")
            .as_str(),
        "response-plan"
    );
    assert_eq!(sample.provenance()[0].strategy(), "pat");
}
