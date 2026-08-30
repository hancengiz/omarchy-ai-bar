use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use oab_auth::browser_safe_storage::{
    BrowserKeyringAccess, BrowserSafeStorageBackend, BrowserSafeStorageConnector,
    BrowserSafeStorageError, BrowserSafeStorageFuture, BrowserSafeStorageItem,
    BrowserSafeStorageProduct, BrowserSafeStorageReader, MAX_BROWSER_SAFE_STORAGE_CANDIDATES,
    MAX_BROWSER_SAFE_STORAGE_SECRET_BYTES,
};
use zeroize::Zeroizing;

#[derive(Default)]
struct Trace {
    connects: AtomicUsize,
    events: Mutex<Vec<String>>,
}

impl Trace {
    fn record(&self, event: impl Into<String>) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event.into());
    }

    fn events(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

struct FakeItem {
    id: String,
    label: Result<String, BrowserSafeStorageError>,
    unlock: Result<(), BrowserSafeStorageError>,
    secret: Result<Vec<u8>, BrowserSafeStorageError>,
    trace: Arc<Trace>,
}

impl FakeItem {
    fn valid(id: impl Into<String>, label: impl Into<String>, secret: impl Into<Vec<u8>>) -> Self {
        Self {
            id: id.into(),
            label: Ok(label.into()),
            unlock: Ok(()),
            secret: Ok(secret.into()),
            trace: Arc::new(Trace::default()),
        }
    }

    fn with_trace(mut self, trace: &Arc<Trace>) -> Self {
        self.trace = Arc::clone(trace);
        self
    }
}

impl BrowserSafeStorageItem for FakeItem {
    fn label(&self) -> BrowserSafeStorageFuture<'_, Result<String, BrowserSafeStorageError>> {
        Box::pin(async {
            self.trace.record(format!("label:{}", self.id));
            self.label.clone()
        })
    }

    fn unlock(&self) -> BrowserSafeStorageFuture<'_, Result<(), BrowserSafeStorageError>> {
        Box::pin(async {
            self.trace.record(format!("unlock:{}", self.id));
            self.unlock
        })
    }

    fn secret(
        &self,
    ) -> BrowserSafeStorageFuture<'_, Result<Zeroizing<Vec<u8>>, BrowserSafeStorageError>> {
        Box::pin(async {
            self.trace.record(format!("secret:{}", self.id));
            self.secret.clone().map(Zeroizing::new)
        })
    }
}

struct FakeBackend {
    items: Arc<Mutex<Option<Vec<FakeItem>>>>,
    trace: Arc<Trace>,
    search_error: Option<BrowserSafeStorageError>,
}

impl BrowserSafeStorageBackend for FakeBackend {
    fn search(
        &self,
        application: &'static str,
    ) -> BrowserSafeStorageFuture<
        '_,
        Result<Vec<Box<dyn BrowserSafeStorageItem>>, BrowserSafeStorageError>,
    > {
        Box::pin(async move {
            self.trace.record(format!("search:{application}"));
            if let Some(error) = self.search_error {
                return Err(error);
            }
            Ok(self
                .items
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
                .unwrap_or_default()
                .into_iter()
                .map(|item| Box::new(item) as Box<dyn BrowserSafeStorageItem>)
                .collect())
        })
    }
}

struct FakeConnector {
    items: Arc<Mutex<Option<Vec<FakeItem>>>>,
    trace: Arc<Trace>,
    connect_error: bool,
    search_error: Option<BrowserSafeStorageError>,
}

impl FakeConnector {
    fn new(items: Vec<FakeItem>, trace: &Arc<Trace>) -> Self {
        Self {
            items: Arc::new(Mutex::new(Some(items))),
            trace: Arc::clone(trace),
            connect_error: false,
            search_error: None,
        }
    }
}

impl BrowserSafeStorageConnector for FakeConnector {
    fn connect(
        &self,
    ) -> BrowserSafeStorageFuture<
        '_,
        Result<Box<dyn BrowserSafeStorageBackend>, BrowserSafeStorageError>,
    > {
        Box::pin(async {
            self.trace.connects.fetch_add(1, Ordering::SeqCst);
            self.trace.record("connect");
            if self.connect_error {
                return Err(BrowserSafeStorageError::Operation);
            }
            Ok(Box::new(FakeBackend {
                items: Arc::clone(&self.items),
                trace: Arc::clone(&self.trace),
                search_error: self.search_error,
            }) as Box<dyn BrowserSafeStorageBackend>)
        })
    }
}

fn traced_items(trace: &Arc<Trace>, items: impl IntoIterator<Item = FakeItem>) -> Vec<FakeItem> {
    items
        .into_iter()
        .map(|item| item.with_trace(trace))
        .collect()
}

#[tokio::test]
async fn disabled_is_default_connects_without_probing_and_reads_disabled() {
    let trace = Arc::new(Trace::default());
    let connector = FakeConnector::new(Vec::new(), &trace);

    assert_eq!(
        BrowserKeyringAccess::default(),
        BrowserKeyringAccess::Disabled
    );
    let reader =
        BrowserSafeStorageReader::connect_with(BrowserKeyringAccess::default(), &connector)
            .await
            .expect("disabled construction must not need a keyring service");
    assert_eq!(trace.connects.load(Ordering::SeqCst), 0);
    assert!(trace.events().is_empty());
    assert_eq!(
        reader
            .read(BrowserSafeStorageProduct::Chromium)
            .await
            .expect_err("disabled read must fail"),
        BrowserSafeStorageError::Disabled
    );

    BrowserSafeStorageReader::connect(BrowserKeyringAccess::Disabled)
        .await
        .expect("the production disabled branch must also be headless-safe");
}

#[test]
fn product_specs_are_exact_and_have_no_cross_product_fallbacks() {
    let cases = [
        (
            BrowserSafeStorageProduct::GoogleChrome,
            "chrome",
            "Chrome Safe Storage",
        ),
        (
            BrowserSafeStorageProduct::Chromium,
            "chromium",
            "Chromium Safe Storage",
        ),
        (
            BrowserSafeStorageProduct::Brave,
            "brave",
            "Brave Safe Storage",
        ),
        (
            BrowserSafeStorageProduct::BraveOrigin,
            "brave",
            "Brave Safe Storage",
        ),
        (
            BrowserSafeStorageProduct::MicrosoftEdge,
            "microsoft-edge",
            "Microsoft Edge Safe Storage",
        ),
    ];

    for (product, application, label) in cases {
        let spec = product.spec();
        assert_eq!(spec.application(), application);
        assert_eq!(spec.label(), label);
        assert!(!product.to_string().is_empty());
    }
}

#[tokio::test]
async fn exact_label_is_selected_before_only_that_item_is_unlocked_and_read() {
    let trace = Arc::new(Trace::default());
    let items = traced_items(
        &trace,
        [
            FakeItem::valid("beta", "Chrome Beta Safe Storage", b"wrong"),
            FakeItem::valid("exact", "Chrome Safe Storage", b"selected-secret"),
            FakeItem::valid("chromium", "Chromium Safe Storage", b"wrong"),
        ],
    );
    let connector = FakeConnector::new(items, &trace);
    let reader = BrowserSafeStorageReader::connect_with(BrowserKeyringAccess::Enabled, &connector)
        .await
        .expect("fake backend should connect");

    let secret = reader
        .read(BrowserSafeStorageProduct::GoogleChrome)
        .await
        .expect("read should succeed")
        .expect("the exact label should be present");
    assert_eq!(secret.expose_secret(), b"selected-secret");
    assert_eq!(
        trace.events(),
        [
            "connect",
            "search:chrome",
            "label:beta",
            "label:exact",
            "label:chromium",
            "unlock:exact",
            "secret:exact",
        ]
    );
}

#[tokio::test]
async fn mismatched_labels_return_none_without_unlocking_or_reading() {
    let trace = Arc::new(Trace::default());
    let items = traced_items(
        &trace,
        [
            FakeItem::valid("chrome", "Chrome Safe storage", b"case-mismatch"),
            FakeItem::valid("edge", "Microsoft Edge Safe Storage", b"wrong-product"),
        ],
    );
    let connector = FakeConnector::new(items, &trace);
    let reader = BrowserSafeStorageReader::connect_with(BrowserKeyringAccess::Enabled, &connector)
        .await
        .expect("fake backend should connect");

    assert!(
        reader
            .read(BrowserSafeStorageProduct::GoogleChrome)
            .await
            .expect("mismatches are not backend errors")
            .is_none()
    );
    assert_eq!(
        trace.events(),
        ["connect", "search:chrome", "label:chrome", "label:edge"]
    );
}

#[tokio::test]
async fn duplicate_exact_labels_are_ambiguous_before_any_secret_access() {
    let trace = Arc::new(Trace::default());
    let items = traced_items(
        &trace,
        [
            FakeItem::valid("first", "Brave Safe Storage", b"first-secret"),
            FakeItem::valid("second", "Brave Safe Storage", b"second-secret"),
        ],
    );
    let connector = FakeConnector::new(items, &trace);
    let reader = BrowserSafeStorageReader::connect_with(BrowserKeyringAccess::Enabled, &connector)
        .await
        .expect("fake backend should connect");

    assert_eq!(
        reader
            .read(BrowserSafeStorageProduct::BraveOrigin)
            .await
            .expect_err("duplicate exact labels must be ambiguous"),
        BrowserSafeStorageError::Ambiguous
    );
    assert_eq!(
        trace.events(),
        ["connect", "search:brave", "label:first", "label:second"]
    );
}

#[tokio::test]
async fn candidate_and_label_bounds_fail_before_unlock() {
    let trace = Arc::new(Trace::default());
    let items = (0..=MAX_BROWSER_SAFE_STORAGE_CANDIDATES)
        .map(|index| FakeItem::valid(format!("item-{index}"), "mismatch", b"unused"));
    let connector = FakeConnector::new(traced_items(&trace, items), &trace);
    let reader = BrowserSafeStorageReader::connect_with(BrowserKeyringAccess::Enabled, &connector)
        .await
        .expect("fake backend should connect");
    assert_eq!(
        reader
            .read(BrowserSafeStorageProduct::Chromium)
            .await
            .expect_err("excessive candidates must fail"),
        BrowserSafeStorageError::InvalidData
    );
    assert_eq!(trace.events(), ["connect", "search:chromium"]);

    let trace = Arc::new(Trace::default());
    let item = FakeItem::valid("oversized-label", "x".repeat(257), b"unused").with_trace(&trace);
    let connector = FakeConnector::new(vec![item], &trace);
    let reader = BrowserSafeStorageReader::connect_with(BrowserKeyringAccess::Enabled, &connector)
        .await
        .expect("fake backend should connect");
    assert_eq!(
        reader
            .read(BrowserSafeStorageProduct::Chromium)
            .await
            .expect_err("oversized labels must fail"),
        BrowserSafeStorageError::InvalidData
    );
    assert_eq!(
        trace.events(),
        ["connect", "search:chromium", "label:oversized-label"]
    );
}

#[tokio::test]
async fn empty_and_oversized_secrets_are_invalid_after_exact_item_unlock() {
    for secret in [
        Vec::new(),
        vec![b'x'; MAX_BROWSER_SAFE_STORAGE_SECRET_BYTES + 1],
    ] {
        let trace = Arc::new(Trace::default());
        let item = FakeItem::valid("exact", "Chromium Safe Storage", secret).with_trace(&trace);
        let connector = FakeConnector::new(vec![item], &trace);
        let reader =
            BrowserSafeStorageReader::connect_with(BrowserKeyringAccess::Enabled, &connector)
                .await
                .expect("fake backend should connect");

        assert_eq!(
            reader
                .read(BrowserSafeStorageProduct::Chromium)
                .await
                .expect_err("invalid secret size must fail"),
            BrowserSafeStorageError::InvalidData
        );
        assert_eq!(
            trace.events(),
            [
                "connect",
                "search:chromium",
                "label:exact",
                "unlock:exact",
                "secret:exact"
            ]
        );
    }
}

#[tokio::test]
async fn raw_non_utf8_and_maximum_sized_secrets_are_accepted_exactly() {
    for secret in [
        vec![0xff, 0x00, 0x80],
        vec![b'x'; MAX_BROWSER_SAFE_STORAGE_SECRET_BYTES],
    ] {
        let trace = Arc::new(Trace::default());
        let item =
            FakeItem::valid("exact", "Chromium Safe Storage", secret.clone()).with_trace(&trace);
        let connector = FakeConnector::new(vec![item], &trace);
        let reader =
            BrowserSafeStorageReader::connect_with(BrowserKeyringAccess::Enabled, &connector)
                .await
                .expect("fake backend should connect");

        let value = reader
            .read(BrowserSafeStorageProduct::Chromium)
            .await
            .expect("raw bounded secret should be valid")
            .expect("exact item should be present");
        assert_eq!(value.expose_secret(), secret);
    }
}

#[tokio::test]
async fn backend_failures_have_stable_categories_and_connect_failure_is_unavailable() {
    let trace = Arc::new(Trace::default());
    let mut locked = FakeItem::valid("locked", "Microsoft Edge Safe Storage", b"unused");
    locked.unlock = Err(BrowserSafeStorageError::Locked);
    let connector = FakeConnector::new(vec![locked.with_trace(&trace)], &trace);
    let reader = BrowserSafeStorageReader::connect_with(BrowserKeyringAccess::Enabled, &connector)
        .await
        .expect("fake backend should connect");
    assert_eq!(
        reader
            .read(BrowserSafeStorageProduct::MicrosoftEdge)
            .await
            .expect_err("locked item must fail"),
        BrowserSafeStorageError::Locked
    );

    let trace = Arc::new(Trace::default());
    let connector = FakeConnector {
        search_error: Some(BrowserSafeStorageError::Locked),
        ..FakeConnector::new(Vec::new(), &trace)
    };
    let reader = BrowserSafeStorageReader::connect_with(BrowserKeyringAccess::Enabled, &connector)
        .await
        .expect("fake backend should connect");
    assert_eq!(
        reader
            .read(BrowserSafeStorageProduct::Chromium)
            .await
            .expect_err("locked collection must not appear empty"),
        BrowserSafeStorageError::Locked
    );
    assert_eq!(trace.events(), ["connect", "search:chromium"]);

    let trace = Arc::new(Trace::default());
    let connector = FakeConnector {
        connect_error: true,
        ..FakeConnector::new(Vec::new(), &trace)
    };
    let error = BrowserSafeStorageReader::connect_with(BrowserKeyringAccess::Enabled, &connector)
        .await
        .expect_err("connector failure should be redacted");
    assert_eq!(error, BrowserSafeStorageError::Unavailable);
}

#[tokio::test]
async fn diagnostics_never_include_candidate_or_secret_canaries() {
    let trace = Arc::new(Trace::default());
    let mut item = FakeItem::valid(
        "candidate-canary",
        "Chrome Safe Storage",
        b"secret-canary".to_vec(),
    );
    item.secret = Err(BrowserSafeStorageError::Operation);
    let connector = FakeConnector::new(vec![item.with_trace(&trace)], &trace);
    let reader = BrowserSafeStorageReader::connect_with(BrowserKeyringAccess::Enabled, &connector)
        .await
        .expect("fake backend should connect");
    let error = reader
        .read(BrowserSafeStorageProduct::GoogleChrome)
        .await
        .expect_err("fixture secret operation should fail");

    let diagnostics = format!("{reader:?} {error:?} {error}");
    assert!(!diagnostics.contains("candidate-canary"));
    assert!(!diagnostics.contains("secret-canary"));
    assert!(diagnostics.len() < 256);
}
