use oab_domain::{AuthImplication, ClassifiedError, ErrorKind, RetryEligibility, WindowDuration};

#[test]
fn error_classification_derives_retry_and_auth_semantics() {
    let missing = ClassifiedError::new(ErrorKind::MissingCredential);
    assert_eq!(missing.retry(), RetryEligibility::Manual);
    assert_eq!(
        missing.auth_implication(),
        AuthImplication::ConfigureCredential
    );

    let expired = ClassifiedError::new(ErrorKind::AuthenticationExpired);
    assert_eq!(expired.retry(), RetryEligibility::Manual);
    assert_eq!(expired.auth_implication(), AuthImplication::Reauthenticate);

    let limited = ClassifiedError::new(ErrorKind::RateLimited)
        .with_retry_after(WindowDuration::from_seconds(30).expect("duration"))
        .expect("rate limits accept retry-after");
    assert_eq!(limited.retry(), RetryEligibility::Automatic);
    assert_eq!(limited.auth_implication(), AuthImplication::None);

    let serialized = serde_json::to_string(&limited).expect("error should encode");
    let contradictory = serialized.replace("\"automatic\"", "\"never\"");
    assert!(serde_json::from_str::<ClassifiedError>(&contradictory).is_err());
}

#[test]
fn errors_reject_provider_controlled_wire_text() {
    let canonical = ClassifiedError::new(ErrorKind::Api);
    let mut unsafe_code = serde_json::to_value(&canonical).expect("error serializes");
    unsafe_code["code"] = serde_json::json!("sk-proj-private-canary");
    assert!(serde_json::from_value::<ClassifiedError>(unsafe_code).is_err());

    let mut unsafe_message = serde_json::to_value(&canonical).expect("error serializes");
    unsafe_message["message"] = serde_json::json!("eyJhbGciOiJIUzI1NiJ9.private.signature");
    assert!(serde_json::from_value::<ClassifiedError>(unsafe_message).is_err());

    let parse_error = ClassifiedError::new(ErrorKind::Parse);
    assert!(
        parse_error
            .with_retry_after(WindowDuration::from_seconds(5).expect("duration"))
            .is_err(),
        "retry-after is invalid for non-automatic errors"
    );
}

#[test]
fn public_error_projection_replaces_all_provider_controlled_text() {
    let public = ClassifiedError::new(ErrorKind::Network).public_projection();
    assert_eq!(public.code().as_str(), "provider.network");
    assert_eq!(
        public.message().as_str(),
        "The provider could not be reached."
    );
    let wire = serde_json::to_string(&public).expect("public error serializes");
    assert!(!wire.contains("sk-proj"));
}
