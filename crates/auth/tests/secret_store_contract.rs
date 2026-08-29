use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use oab_auth::secret_store::{
    SecretFuture, SecretKey, SecretServiceStore, SecretStore, SecretStoreError, SecretValue,
};

#[derive(Debug, Default)]
struct MemorySecretStore {
    values: Mutex<HashMap<SecretKey, Vec<u8>>>,
}

impl SecretStore for MemorySecretStore {
    fn get<'a>(
        &'a self,
        key: &'a SecretKey,
    ) -> SecretFuture<'a, Result<Option<SecretValue>, SecretStoreError>> {
        Box::pin(async move {
            self.values
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(key)
                .cloned()
                .map(SecretValue::new)
                .transpose()
                .map_err(|_| SecretStoreError::InvalidData)
        })
    }

    fn put<'a>(
        &'a self,
        key: &'a SecretKey,
        secret: SecretValue,
    ) -> SecretFuture<'a, Result<(), SecretStoreError>> {
        Box::pin(async move {
            self.values
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(key.clone(), secret.expose_secret().to_vec());
            Ok(())
        })
    }

    fn delete<'a>(&'a self, key: &'a SecretKey) -> SecretFuture<'a, Result<(), SecretStoreError>> {
        Box::pin(async move {
            self.values
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(key);
            Ok(())
        })
    }
}

async fn assert_secret_store_contract(store: &dyn SecretStore) {
    let first = SecretKey::new("codex", "account-a", "api-token").expect("key");
    let second = SecretKey::new("claude", "account-b", "session").expect("key");
    assert!(store.get(&first).await.expect("get missing").is_none());

    store
        .put(&first, SecretValue::new(b"first".to_vec()).expect("secret"))
        .await
        .expect("put first");
    assert_eq!(
        store
            .get(&first)
            .await
            .expect("get first")
            .expect("present")
            .expose_secret(),
        b"first"
    );

    store
        .put(
            &first,
            SecretValue::new(b"replacement".to_vec()).expect("secret"),
        )
        .await
        .expect("replace first");
    store
        .put(
            &second,
            SecretValue::new(b"second".to_vec()).expect("secret"),
        )
        .await
        .expect("put second");
    assert_eq!(
        store
            .get(&first)
            .await
            .expect("get replacement")
            .expect("present")
            .expose_secret(),
        b"replacement"
    );
    assert_eq!(
        store
            .get(&second)
            .await
            .expect("get second")
            .expect("present")
            .expose_secret(),
        b"second"
    );

    store.delete(&first).await.expect("delete first");
    store.delete(&first).await.expect("idempotent delete");
    assert!(store.get(&first).await.expect("get deleted").is_none());
    assert!(store.get(&second).await.expect("get retained").is_some());
}

#[tokio::test]
async fn fake_implementation_passes_common_contract() {
    assert_secret_store_contract(&MemorySecretStore::default()).await;
}

#[test]
fn identifiers_and_values_have_redacted_debug_output() {
    let key = SecretKey::new("provider-canary", "account-canary", "purpose-canary").expect("key");
    let secret = SecretValue::new(b"secret-canary".to_vec()).expect("secret");
    let output = format!("{key:?} {secret:?}");
    for canary in [
        "provider-canary",
        "account-canary",
        "purpose-canary",
        "secret-canary",
    ] {
        assert!(!output.contains(canary), "debug output leaked {canary}");
    }
}

#[tokio::test]
#[ignore = "requires a live desktop Secret Service and may show an unlock prompt"]
async fn live_secret_service_adapter_connects() {
    let _store = SecretServiceStore::connect()
        .await
        .expect("desktop Secret Service connection");
}
