use std::sync::atomic::{AtomicUsize, Ordering};

use oab_auth::precedence::{
    CredentialCandidate, CredentialPersistence, CredentialPersistenceError, CredentialSource,
    persist_resolved, resolve,
};
use oab_auth::secret_store::{SecretFuture, SecretKey, SecretStore, SecretStoreError, SecretValue};

#[derive(Debug, Default)]
struct CountingStore {
    puts: AtomicUsize,
}

impl SecretStore for CountingStore {
    fn get<'a>(
        &'a self,
        _key: &'a SecretKey,
    ) -> SecretFuture<'a, Result<Option<SecretValue>, SecretStoreError>> {
        Box::pin(async { Ok(None) })
    }

    fn put<'a>(
        &'a self,
        _key: &'a SecretKey,
        _secret: SecretValue,
    ) -> SecretFuture<'a, Result<(), SecretStoreError>> {
        Box::pin(async move {
            self.puts.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
    }

    fn delete<'a>(&'a self, _key: &'a SecretKey) -> SecretFuture<'a, Result<(), SecretStoreError>> {
        Box::pin(async { Ok(()) })
    }
}

fn candidate(source: CredentialSource, value: &[u8]) -> CredentialCandidate {
    CredentialCandidate::new(source, SecretValue::new(value.to_vec()).expect("secret"))
}

#[test]
fn resolution_order_is_fixed_independent_of_candidate_order() {
    let resolved = resolve(vec![
        candidate(CredentialSource::ProviderCli, b"cli"),
        candidate(CredentialSource::SecretService, b"keyring"),
        candidate(CredentialSource::Environment, b"environment"),
        candidate(CredentialSource::OneShotOverride, b"one-shot"),
    ])
    .expect("resolved");
    assert_eq!(resolved.source(), CredentialSource::OneShotOverride);
    assert_eq!(resolved.expose_secret(), b"one-shot");
    assert_eq!(resolved.persistence(), CredentialPersistence::Persistable);
}

#[tokio::test]
async fn environment_override_is_ephemeral_and_store_is_never_called() {
    let candidate = CredentialCandidate::from_environment(Some("environment-canary".to_owned()))
        .expect("valid environment value")
        .expect("candidate");
    let resolved = resolve(vec![candidate]).expect("resolved");
    assert_eq!(resolved.source(), CredentialSource::Environment);
    assert_eq!(resolved.persistence(), CredentialPersistence::Ephemeral);

    let store = CountingStore::default();
    let key = SecretKey::new("codex", "personal", "token").expect("key");
    let error = persist_resolved(&store, &key, resolved)
        .await
        .expect_err("environment persistence must be blocked");
    assert_eq!(error, CredentialPersistenceError::EphemeralSource);
    assert_eq!(store.puts.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn explicitly_submitted_value_can_use_an_authorized_store() {
    let store = CountingStore::default();
    let key = SecretKey::new("codex", "personal", "token").expect("key");
    let resolved = resolve(vec![candidate(
        CredentialSource::OneShotOverride,
        b"user-submitted",
    )])
    .expect("resolved");
    persist_resolved(&store, &key, resolved)
        .await
        .expect("persist explicit input");
    assert_eq!(store.puts.load(Ordering::Acquire), 1);
}
