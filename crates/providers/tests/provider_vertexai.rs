use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::vertexai::{
    VertexAiProvider, VertexCredentialKind, VertexSettings, parse_quota_usage,
};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const ISSUE_USAGE: &[u8] =
    include_bytes!("../../../fixtures/providers/vertexai/issue-2958-usage-without-limit-name.json");
const ISSUE_LIMITS: &[u8] = include_bytes!(
    "../../../fixtures/providers/vertexai/issue-2958-regional-and-global-limits.json"
);
const EXACT_USAGE: &[u8] =
    include_bytes!("../../../fixtures/providers/vertexai/exact-named-usage.json");
const EXACT_LIMITS: &[u8] =
    include_bytes!("../../../fixtures/providers/vertexai/exact-named-limits.json");
const AMBIGUOUS_LIMITS: &[u8] =
    include_bytes!("../../../fixtures/providers/vertexai/ambiguous-regional-limits.json");
const NO_DATA: &[u8] = include_bytes!("../../../fixtures/providers/vertexai/no-data.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/vertexai/malformed.json");

const CLIENT_ID_CANARY: &str = "fixture-vertex-client-id-canary";
const CLIENT_SECRET_CANARY: &str = "fixture-vertex-client-secret-canary";
const REFRESH_TOKEN_CANARY: &str = "fixture-vertex-refresh-token-canary";
const ACCESS_TOKEN_CANARY: &str = "fixture-vertex-access-token-canary";
const CACHED_TOKEN_CANARY: &str = "fixture-vertex-cached-token-canary";
const ACCESS_AUTHORIZATION: &str = "Bearer fixture-vertex-access-token-canary";
const CACHED_AUTHORIZATION: &str = "Bearer fixture-vertex-cached-token-canary";
const SERVICE_AUTHORIZATION: &str = "Bearer fixture-vertex-service-token-canary";
const REFRESHED_ID_TOKEN: &str = "header.eyJlbWFpbCI6InJlZnJlc2hlZEBleGFtcGxlLmNvbSJ9.signature";
const ADC_ID_TOKEN: &str = "header.eyJlbWFpbCI6ImFkY0BleGFtcGxlLmNvbSJ9.signature";

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("omarchy-ai-bar-vertex-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).expect("test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::VertexAi,
        ProviderInstanceId::new("vertex-primary").expect("instance"),
        AccountKey::new(account).expect("account"),
    )
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn base_environment(directory: &TestDirectory) -> BTreeMap<String, String> {
    let config = directory.path().join("gcloud");
    fs::create_dir_all(config.join("configurations")).expect("gcloud config directory");
    BTreeMap::from([
        (
            "HOME".to_owned(),
            directory.path().to_string_lossy().into_owned(),
        ),
        (
            "CLOUDSDK_CONFIG".to_owned(),
            config.to_string_lossy().into_owned(),
        ),
    ])
}

fn write_user_adc(
    directory: &TestDirectory,
    environment: &mut BTreeMap<String, String>,
    cached_token: bool,
) {
    let config = PathBuf::from(&environment["CLOUDSDK_CONFIG"]);
    fs::write(
        config.join("configurations/config_default"),
        "[core]\nproject = configured-project\n",
    )
    .expect("project config");
    let access = if cached_token {
        format!(
            ",\n  \"access_token\": \"{CACHED_TOKEN_CANARY}\",\n  \"token_expiry\": \"2030-01-01T00:00:00Z\""
        )
    } else {
        String::new()
    };
    let adc = format!(
        "{{\n  \"client_id\": \"{CLIENT_ID_CANARY}\",\n  \"client_secret\": \"{CLIENT_SECRET_CANARY}\",\n  \"refresh_token\": \"{REFRESH_TOKEN_CANARY}\",\n  \"id_token\": \"{ADC_ID_TOKEN}\"{access}\n}}"
    );
    let path = directory.path().join("user-adc.json");
    fs::write(&path, adc).expect("user ADC");
    environment.insert(
        "GOOGLE_APPLICATION_CREDENTIALS".to_owned(),
        path.to_string_lossy().into_owned(),
    );
}

fn write_service_adc(directory: &TestDirectory, environment: &mut BTreeMap<String, String>) {
    let adc = r#"{
      "type": "service_account",
      "project_id": "service-project",
      "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
      "client_email": "vertex-service@example.iam.gserviceaccount.com"
    }"#;
    let path = directory.path().join("service-adc.json");
    fs::write(&path, adc).expect("service ADC");
    environment.insert(
        "GOOGLE_APPLICATION_CREDENTIALS".to_owned(),
        path.to_string_lossy().into_owned(),
    );
    environment.insert(
        "OMARCHY_AI_BAR_GCLOUD_PATH".to_owned(),
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/providers/vertexai/fake-gcloud")
            .to_string_lossy()
            .into_owned(),
    );
}

fn write_executable(directory: &TestDirectory, name: &str, body: &str) -> PathBuf {
    let path = directory.path().join(name);
    fs::write(&path, body).expect("test executable");
    let mut permissions = fs::metadata(&path)
        .expect("executable metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).expect("executable permissions");
    path
}

fn provider(server: &FakeHttpServer, settings: VertexSettings, account: &str) -> VertexAiProvider {
    VertexAiProvider::with_loopback_endpoints(
        scope(account),
        settings,
        server.url("/token"),
        server.url("/"),
    )
    .expect("loopback Vertex provider")
}

fn oauth_response() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "access_token": ACCESS_TOKEN_CANARY,
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": REFRESHED_ID_TOKEN,
    }))
    .expect("OAuth response")
}

fn parse_form(body: &[u8]) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(body)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

#[test]
fn quota_matching_preserves_exact_and_unambiguous_fallback_contracts() {
    assert_eq!(
        parse_quota_usage(ISSUE_USAGE, ISSUE_LIMITS).expect("issue 2958 fixture"),
        Some(1.0)
    );
    assert_eq!(
        parse_quota_usage(EXACT_USAGE, EXACT_LIMITS).expect("exact match fixture"),
        Some(25.0)
    );
    assert_eq!(
        parse_quota_usage(ISSUE_USAGE, AMBIGUOUS_LIMITS).expect("ambiguous is no data"),
        None
    );
    assert_eq!(
        parse_quota_usage(NO_DATA, EXACT_LIMITS).expect("empty is no data"),
        None
    );
    assert_eq!(
        parse_quota_usage(MALFORMED, EXACT_LIMITS)
            .expect_err("malformed numeric type")
            .kind(),
        ErrorKind::Parse
    );
}

#[test]
fn adc_resolution_honors_precedence_and_redacts_every_secret_and_path() {
    let directory = TestDirectory::new();
    let mut environment = base_environment(&directory);
    environment.insert(
        "GOOGLE_CLOUD_PROJECT".to_owned(),
        "environment-project".to_owned(),
    );
    write_user_adc(&directory, &mut environment, false);
    let settings = VertexSettings::resolve(&environment).expect("user settings");

    assert_eq!(settings.credential_kind(), VertexCredentialKind::User);
    assert_eq!(settings.project_id(), "configured-project");
    assert_eq!(
        settings.adc_path(),
        Path::new(&environment["GOOGLE_APPLICATION_CREDENTIALS"])
    );
    assert!(settings.gcloud_path().is_none());
    let debug = format!("{settings:?}");
    for secret in [
        CLIENT_ID_CANARY,
        CLIENT_SECRET_CANARY,
        REFRESH_TOKEN_CANARY,
        directory.path().to_string_lossy().as_ref(),
        "configured-project",
    ] {
        assert!(!debug.contains(secret));
    }

    environment.insert(
        "GOOGLE_APPLICATION_CREDENTIALS".to_owned(),
        "relative-adc.json".to_owned(),
    );
    assert_eq!(
        VertexSettings::resolve(&environment)
            .expect_err("relative ADC path")
            .kind(),
        ErrorKind::Api
    );
}

#[test]
fn missing_project_is_actionable_and_file_limits_accept_only_the_exact_boundary() {
    const ADC_LIMIT: usize = 1024 * 1024;
    const CONFIG_LIMIT: usize = 64 * 1024;

    let directory = TestDirectory::new();
    let mut environment = base_environment(&directory);
    write_user_adc(&directory, &mut environment, false);
    let adc_path = PathBuf::from(&environment["GOOGLE_APPLICATION_CREDENTIALS"]);
    let config_path =
        PathBuf::from(&environment["CLOUDSDK_CONFIG"]).join("configurations/config_default");

    fs::remove_file(&config_path).expect("remove configured project");
    assert_eq!(
        VertexSettings::resolve(&environment)
            .expect_err("missing project must request configuration")
            .kind(),
        ErrorKind::MissingCredential
    );

    let base_adc = fs::read(&adc_path).expect("base ADC");
    let mut exact_adc = base_adc.clone();
    exact_adc.resize(ADC_LIMIT, b' ');
    fs::write(&adc_path, &exact_adc).expect("boundary ADC");
    fs::write(&config_path, "[core]\nproject = boundary-project\n").expect("project config");
    VertexSettings::resolve(&environment).expect("exact ADC byte boundary");

    exact_adc.push(b' ');
    fs::write(&adc_path, &exact_adc).expect("oversized ADC");
    assert_eq!(
        VertexSettings::resolve(&environment)
            .expect_err("ADC above byte boundary")
            .kind(),
        ErrorKind::Parse
    );

    fs::write(&adc_path, base_adc).expect("restore ADC");
    let mut exact_config = b"[core]\nproject = boundary-project\n".to_vec();
    exact_config.resize(CONFIG_LIMIT, b' ');
    fs::write(&config_path, &exact_config).expect("boundary project config");
    VertexSettings::resolve(&environment).expect("exact config byte boundary");

    exact_config.push(b' ');
    fs::write(&config_path, exact_config).expect("oversized project config");
    assert_eq!(
        VertexSettings::resolve(&environment)
            .expect_err("config above byte boundary")
            .kind(),
        ErrorKind::Parse
    );
}

#[tokio::test]
async fn user_adc_refresh_and_monitoring_wire_contract_are_exact() {
    let directory = TestDirectory::new();
    let mut environment = base_environment(&directory);
    write_user_adc(&directory, &mut environment, false);
    let settings = VertexSettings::resolve(&environment).expect("user settings");
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, oauth_response()),
        FakeHttpResponse::new(200, EXACT_USAGE.to_vec()),
        FakeHttpResponse::new(200, EXACT_LIMITS.to_vec()),
    ])
    .await;
    let provider = provider(&server, settings, "user-account");
    let fetched_at = timestamp(1_700_000_000);
    let sample = provider
        .fetch_at(
            &context("user-account", ProviderSource::CloudCredentials),
            fetched_at,
        )
        .await
        .expect("Vertex usage");

    let primary = sample.primary().expect("projected quota window");
    assert!((primary.used_percent().expect("known percent").get() - 25.0).abs() < f64::EPSILON);
    assert_eq!(
        primary.duration().expect("24 hour duration").seconds(),
        86_400
    );
    assert_eq!(
        sample.identity().email().expect("refreshed email").as_str(),
        "refreshed@example.com"
    );
    assert_eq!(
        sample
            .identity()
            .organization()
            .expect("project identity")
            .as_str(),
        "configured-project"
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("login method")
            .as_str(),
        "gcloud"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].method(), "POST");
    assert_eq!(requests[0].target(), "/token");
    assert_eq!(
        requests[0].header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        parse_form(requests[0].body()),
        BTreeMap::from([
            ("client_id".to_owned(), CLIENT_ID_CANARY.to_owned()),
            ("client_secret".to_owned(), CLIENT_SECRET_CANARY.to_owned()),
            ("grant_type".to_owned(), "refresh_token".to_owned()),
            ("refresh_token".to_owned(), REFRESH_TOKEN_CANARY.to_owned()),
        ])
    );
    for request in &requests[1..] {
        assert_eq!(request.header("authorization"), Some(ACCESS_AUTHORIZATION));
        assert!(
            request
                .target()
                .starts_with("/v3/projects/configured-project/timeSeries?")
        );
        let url = url::Url::parse(&format!("{}{}", server.origin(), request.target()))
            .expect("captured URL");
        let query = url.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(
            query.get("aggregation.alignmentPeriod").map(AsRef::as_ref),
            Some("3600s")
        );
        assert_eq!(
            query.get("aggregation.perSeriesAligner").map(AsRef::as_ref),
            Some("ALIGN_MAX")
        );
        assert_eq!(query.get("view").map(AsRef::as_ref), Some("FULL"));
        assert_eq!(
            query.get("interval.endTime").map(AsRef::as_ref),
            Some("2023-11-14T22:13:20Z")
        );
        assert_eq!(
            query.get("interval.startTime").map(AsRef::as_ref),
            Some("2023-11-13T22:13:20Z")
        );
    }
    let usage_target = url::Url::parse(&format!("{}{}", server.origin(), requests[1].target()))
        .expect("usage URL");
    assert_eq!(
        usage_target
            .query_pairs()
            .find(|(name, _)| name == "filter")
            .map(|(_, value)| value.into_owned()),
        Some("metric.type=\"serviceruntime.googleapis.com/quota/allocation/usage\" AND resource.type=\"consumer_quota\" AND resource.label.service=\"aiplatform.googleapis.com\"".to_owned())
    );
}

#[tokio::test]
async fn cached_user_token_skips_oauth_and_no_data_is_identity_only_success() {
    let directory = TestDirectory::new();
    let mut environment = base_environment(&directory);
    write_user_adc(&directory, &mut environment, true);
    let settings = VertexSettings::resolve(&environment).expect("cached user settings");
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, NO_DATA.to_vec()),
        FakeHttpResponse::new(200, NO_DATA.to_vec()),
    ])
    .await;
    let provider = provider(&server, settings, "cached-account");
    let sample = provider
        .fetch_at(
            &context("cached-account", ProviderSource::CloudCredentials),
            timestamp(1_700_000_000),
        )
        .await
        .expect("identity-only no-data success");

    assert!(sample.primary().is_none());
    assert_eq!(
        sample.identity().email().expect("ADC email").as_str(),
        "adc@example.com"
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].target().starts_with("/v3/projects/"));
    assert_eq!(
        requests[0].header("authorization"),
        Some(CACHED_AUTHORIZATION)
    );
}

#[tokio::test]
async fn monitoring_successfully_aggregates_distinct_usage_and_limit_pages() {
    let directory = TestDirectory::new();
    let mut environment = base_environment(&directory);
    write_user_adc(&directory, &mut environment, true);
    let settings = VertexSettings::resolve(&environment).expect("cached user settings");
    let usage_page = serde_json::to_vec(&serde_json::json!({
        "timeSeries": [],
        "nextPageToken": "usage-page-two",
    }))
    .expect("usage page");
    let limit_page = serde_json::to_vec(&serde_json::json!({
        "timeSeries": [],
        "nextPageToken": "limit-page-two",
    }))
    .expect("limit page");
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, usage_page),
        FakeHttpResponse::new(200, EXACT_USAGE.to_vec()),
        FakeHttpResponse::new(200, limit_page),
        FakeHttpResponse::new(200, EXACT_LIMITS.to_vec()),
    ])
    .await;
    let provider = provider(&server, settings, "multipage-account");
    let sample = provider
        .fetch_at(
            &context("multipage-account", ProviderSource::CloudCredentials),
            timestamp(1_700_000_000),
        )
        .await
        .expect("multi-page quota usage");

    assert_eq!(
        sample
            .primary()
            .and_then(oab_domain::RateWindow::used_percent)
            .map(oab_domain::UsagePercent::get),
        Some(25.0)
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert!(requests[1].target().contains("pageToken=usage-page-two"));
    assert!(requests[3].target().contains("pageToken=limit-page-two"));
}

#[tokio::test]
async fn service_account_uses_exact_gcloud_command_and_pinned_adc_environment() {
    let directory = TestDirectory::new();
    let mut environment = base_environment(&directory);
    write_service_adc(&directory, &mut environment);
    environment.insert(
        "VERTEX_ENV_LEAK_CANARY".to_owned(),
        "must-not-reach-gcloud".to_owned(),
    );
    let settings = VertexSettings::resolve(&environment).expect("service settings");
    assert_eq!(
        settings.credential_kind(),
        VertexCredentialKind::ServiceAccount
    );
    assert_eq!(settings.project_id(), "service-project");
    assert!(settings.gcloud_path().is_some());
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, EXACT_USAGE.to_vec()),
        FakeHttpResponse::new(200, EXACT_LIMITS.to_vec()),
    ])
    .await;
    let provider = provider(&server, settings, "service-account");
    let sample = provider
        .fetch_at(
            &context("service-account", ProviderSource::CloudCredentials),
            timestamp(1_700_000_000),
        )
        .await
        .expect("service account usage");

    assert_eq!(
        sample.identity().email().expect("service email").as_str(),
        "vertex-service@example.iam.gserviceaccount.com"
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2, "service accounts do not use OAuth POST");
    assert_eq!(
        requests[0].header("authorization"),
        Some(SERVICE_AUTHORIZATION)
    );
}

#[tokio::test]
async fn service_account_discards_tokens_when_the_adc_changes_during_gcloud() {
    let directory = TestDirectory::new();
    let mut environment = base_environment(&directory);
    write_service_adc(&directory, &mut environment);
    let mutating_gcloud = write_executable(
        &directory,
        "mutating-gcloud",
        r#"#!/bin/sh
set -eu
if [ "$#" -ne 3 ] || [ "$1" != "auth" ] || [ "$2" != "application-default" ] || [ "$3" != "print-access-token" ]; then
  exit 64
fi
printf '%s\n' '{"type":"service_account","project_id":"replacement-project","private_key":"replacement-key","client_email":"replacement@example.iam.gserviceaccount.com"}' > "$GOOGLE_APPLICATION_CREDENTIALS"
printf '%s\n' 'fixture-vertex-replacement-token-canary'
"#,
    );
    environment.insert(
        "OMARCHY_AI_BAR_GCLOUD_PATH".to_owned(),
        mutating_gcloud.to_string_lossy().into_owned(),
    );
    let settings = VertexSettings::resolve(&environment).expect("service settings");
    let server = FakeHttpServer::start([]).await;
    let provider = provider(&server, settings, "rotated-service-account");

    let error = provider
        .fetch_at(
            &context("rotated-service-account", ProviderSource::CloudCredentials),
            timestamp(1_700_000_000),
        )
        .await
        .expect_err("token from replaced ADC must be discarded");
    assert_eq!(error.kind(), ErrorKind::MissingCredential);
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn gcloud_nonzero_and_oversized_output_are_safely_classified() {
    let expired_directory = TestDirectory::new();
    let mut expired_environment = base_environment(&expired_directory);
    write_service_adc(&expired_directory, &mut expired_environment);
    let expired_gcloud = write_executable(
        &expired_directory,
        "expired-gcloud",
        "#!/bin/sh\nprintf '%s\\n' 'credentials have expired' >&2\nexit 1\n",
    );
    expired_environment.insert(
        "OMARCHY_AI_BAR_GCLOUD_PATH".to_owned(),
        expired_gcloud.to_string_lossy().into_owned(),
    );
    let expired_settings =
        VertexSettings::resolve(&expired_environment).expect("expired service settings");
    let expired_server = FakeHttpServer::start([]).await;
    let expired_provider = provider(&expired_server, expired_settings, "expired-service-account");
    let expired_error = expired_provider
        .fetch_at(
            &context("expired-service-account", ProviderSource::CloudCredentials),
            timestamp(1_700_000_000),
        )
        .await
        .expect_err("expired gcloud credentials");
    assert_eq!(expired_error.kind(), ErrorKind::AuthenticationExpired);
    assert!(expired_server.requests().is_empty());

    let oversized_directory = TestDirectory::new();
    let mut oversized_environment = base_environment(&oversized_directory);
    write_service_adc(&oversized_directory, &mut oversized_environment);
    let oversized_gcloud = write_executable(
        &oversized_directory,
        "oversized-gcloud",
        &format!("#!/bin/sh\nprintf '%s' '{}'\n", "x".repeat(16 * 1024 + 1)),
    );
    oversized_environment.insert(
        "OMARCHY_AI_BAR_GCLOUD_PATH".to_owned(),
        oversized_gcloud.to_string_lossy().into_owned(),
    );
    let oversized_settings =
        VertexSettings::resolve(&oversized_environment).expect("oversized service settings");
    let oversized_server = FakeHttpServer::start([]).await;
    let oversized_provider = provider(
        &oversized_server,
        oversized_settings,
        "oversized-service-account",
    );
    let oversized_error = oversized_provider
        .fetch_at(
            &context(
                "oversized-service-account",
                ProviderSource::CloudCredentials,
            ),
            timestamp(1_700_000_000),
        )
        .await
        .expect_err("oversized gcloud output");
    assert_eq!(oversized_error.kind(), ErrorKind::Parse);
    assert!(oversized_server.requests().is_empty());
}

#[tokio::test]
async fn exact_scope_and_cloud_source_are_checked_before_credentials_leave_process() {
    let directory = TestDirectory::new();
    let mut environment = base_environment(&directory);
    write_service_adc(&directory, &mut environment);
    let settings = VertexSettings::resolve(&environment).expect("service settings");
    let server = FakeHttpServer::start([]).await;
    let provider = provider(&server, settings, "isolated-account");

    let wrong_source = provider
        .fetch_at(
            &context("isolated-account", ProviderSource::Cli),
            timestamp(1_700_000_000),
        )
        .await
        .expect_err("CLI source cannot cross into ADC account");
    assert_eq!(wrong_source.kind(), ErrorKind::Api);
    let wrong_scope = provider
        .fetch_at(
            &context("different-account", ProviderSource::CloudCredentials),
            timestamp(1_700_000_000),
        )
        .await
        .expect_err("account cannot cross scope");
    assert_eq!(wrong_scope.kind(), ErrorKind::Api);
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn oauth_and_monitoring_errors_are_classified_without_secret_text() {
    let directory = TestDirectory::new();
    let mut environment = base_environment(&directory);
    write_user_adc(&directory, &mut environment, false);
    let settings = VertexSettings::resolve(&environment).expect("user settings");
    let body =
        format!("{{\"error\":\"invalid_grant\",\"error_description\":\"{REFRESH_TOKEN_CANARY}\"}}");
    let server = FakeHttpServer::start([FakeHttpResponse::new(400, body.into_bytes())]).await;
    let expired_provider = provider(&server, settings, "expired-account");
    let error = expired_provider
        .fetch_at(
            &context("expired-account", ProviderSource::CloudCredentials),
            timestamp(1_700_000_000),
        )
        .await
        .expect_err("expired refresh token");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    assert!(!format!("{error:?}").contains(REFRESH_TOKEN_CANARY));

    let mut cached_environment = base_environment(&directory);
    write_user_adc(&directory, &mut cached_environment, true);
    let cached_settings = VertexSettings::resolve(&cached_environment).expect("cached settings");
    let forbidden = FakeHttpServer::start([FakeHttpResponse::new(
        403,
        format!("denied {CACHED_TOKEN_CANARY}").into_bytes(),
    )])
    .await;
    let provider = provider(&forbidden, cached_settings, "forbidden-account");
    let error = provider
        .fetch_at(
            &context("forbidden-account", ProviderSource::CloudCredentials),
            timestamp(1_700_000_000),
        )
        .await
        .expect_err("Monitoring permission denied");
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert!(!format!("{error:?}").contains(CACHED_TOKEN_CANARY));
}

#[tokio::test]
async fn monitoring_pagination_is_bounded_and_repeated_tokens_fail_closed() {
    let directory = TestDirectory::new();
    let mut environment = base_environment(&directory);
    write_user_adc(&directory, &mut environment, true);
    let settings = VertexSettings::resolve(&environment).expect("cached settings");
    let repeated = serde_json::to_vec(&serde_json::json!({
        "timeSeries": [],
        "nextPageToken": "same-page",
    }))
    .expect("pagination fixture");
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, repeated.clone()),
        FakeHttpResponse::new(200, repeated),
    ])
    .await;
    let provider = provider(&server, settings, "paged-account");
    let error = provider
        .fetch_at(
            &context("paged-account", ProviderSource::CloudCredentials),
            timestamp(1_700_000_000),
        )
        .await
        .expect_err("repeated page token");
    assert_eq!(error.kind(), ErrorKind::Parse);
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].target().contains("pageToken=same-page"));

    let retained = preserve_last_good(Some(42_u8), Err(error));
    assert!(matches!(
        retained,
        oab_providers::context::FetchOutcome::Retained { last_good: 42, .. }
    ));
}

#[test]
fn production_endpoints_are_fixed_and_loopback_seam_rejects_non_loopback() {
    let directory = TestDirectory::new();
    let mut environment = base_environment(&directory);
    write_user_adc(&directory, &mut environment, true);
    let settings = VertexSettings::resolve(&environment).expect("cached settings");
    VertexAiProvider::new(scope("production-account"), settings).expect("fixed production URLs");

    let mut environment = base_environment(&directory);
    write_user_adc(&directory, &mut environment, true);
    let settings = VertexSettings::resolve(&environment).expect("cached settings");
    let rejected = VertexAiProvider::with_loopback_endpoints(
        scope("rejected-account"),
        settings,
        url::Url::parse("https://oauth2.googleapis.com/token").expect("OAuth URL"),
        url::Url::parse("https://monitoring.googleapis.com").expect("Monitoring URL"),
    )
    .err()
    .expect("test seam rejects public endpoints");
    assert_eq!(rejected.kind(), ErrorKind::Api);
}
