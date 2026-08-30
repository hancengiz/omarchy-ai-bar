use oab_providers::browser_cookie::{ChromiumCookieDecryptionError, ChromiumCookieDecryptor};
use oab_providers::browser_profile::BrowserKind;
use oab_providers::chromium_crypto::{
    ChromiumCryptoConfigError, ChromiumCryptoError, LinuxChromiumCookieCrypto,
    MAX_CHROMIUM_ENCRYPTED_VALUE_BYTES,
};
use zeroize::Zeroizing;

const V10_KNOWN_ANSWER: [u8; 19] = [
    b'v', b'1', b'0', 0xc7, 0xce, 0x3f, 0xb7, 0xe4, 0x9f, 0xff, 0xc3, 0x5e, 0xef, 0x50, 0x4c, 0x9a,
    0x86, 0x92, 0x5b,
];
const V11_KNOWN_ANSWER: [u8; 35] = [
    b'v', b'1', b'1', 0x92, 0x1a, 0xa6, 0x48, 0xe7, 0xc6, 0x69, 0x19, 0xe7, 0xbd, 0x04, 0x69, 0x9c,
    0x05, 0x62, 0xb3, 0x5a, 0x41, 0x27, 0xae, 0xcf, 0x9c, 0x21, 0x06, 0xc7, 0xef, 0x9c, 0xeb, 0x0c,
    0x92, 0x3a, 0xcb,
];
const V11_SECRET: &[u8] = b"chrome-safe-storage-fixture";
const EMPTY_PASSWORD_KNOWN_ANSWER: [u8; 35] = [
    b'v', b'1', b'0', 0xb8, 0xe6, 0x3c, 0xd0, 0x78, 0xaf, 0x24, 0x6e, 0xa5, 0x97, 0xf4, 0xbc, 0xc7,
    0x40, 0x5a, 0x0d, 0xf7, 0xa6, 0x5e, 0x65, 0x2b, 0x71, 0x17, 0x72, 0xaa, 0x84, 0xea, 0x6d, 0xc4,
    0x03, 0x4c, 0xa5,
];

#[test]
fn decrypts_official_v10_pbkdf2_known_answer_by_default() {
    let crypto = LinuxChromiumCookieCrypto::new();

    let plaintext = crypto
        .decrypt_raw(BrowserKind::GoogleChrome, &V10_KNOWN_ANSWER)
        .expect("the fixed v10 key should decrypt the known-answer vector");

    assert_eq!(plaintext.as_slice(), b"cookie-value");
}

#[test]
fn derives_browser_v11_key_from_injected_safe_storage_secret() {
    let mut crypto = LinuxChromiumCookieCrypto::new();
    crypto
        .set_v11_secret(
            BrowserKind::GoogleChrome,
            Zeroizing::new(V11_SECRET.to_vec()),
        )
        .expect("the bounded Chrome secret should be accepted");

    let plaintext = crypto
        .decrypt_raw(BrowserKind::GoogleChrome, &V11_KNOWN_ANSWER)
        .expect("the derived v11 key should decrypt the known-answer vector");

    assert_eq!(plaintext.as_slice(), b"chrome-v11-cookie");
}

#[test]
fn retries_current_chromium_empty_password_compatibility_key_for_both_tags() {
    let mut crypto = LinuxChromiumCookieCrypto::new();
    crypto
        .set_v11_secret(
            BrowserKind::GoogleChrome,
            Zeroizing::new(V11_SECRET.to_vec()),
        )
        .expect("the selected v11 key should be available before fallback");

    for tag in [b"v10", b"v11"] {
        let mut envelope = EMPTY_PASSWORD_KNOWN_ANSWER;
        envelope[..3].copy_from_slice(tag);
        assert_eq!(
            crypto
                .decrypt_raw(BrowserKind::GoogleChrome, &envelope)
                .expect("the exact empty-password fallback vector should decrypt")
                .as_slice(),
            b"legacy-empty-key"
        );
    }
}

#[test]
fn v11_is_unavailable_by_default_and_keys_are_browser_isolated() {
    let mut crypto = LinuxChromiumCookieCrypto::new();
    assert_eq!(
        crypto.decrypt_raw(BrowserKind::GoogleChrome, &V11_KNOWN_ANSWER),
        Err(ChromiumCryptoError::Unavailable)
    );

    crypto
        .set_v11_secret(
            BrowserKind::GoogleChrome,
            Zeroizing::new(V11_SECRET.to_vec()),
        )
        .expect("the bounded Chrome secret should be accepted");
    assert!(crypto.has_v11_secret(BrowserKind::GoogleChrome));
    assert!(!crypto.has_v11_secret(BrowserKind::Brave));
    assert_eq!(
        crypto.decrypt_raw(BrowserKind::Brave, &V11_KNOWN_ANSWER),
        Err(ChromiumCryptoError::Unavailable)
    );

    crypto
        .set_v11_secret(
            BrowserKind::Brave,
            Zeroizing::new(b"different-brave-safe-storage-secret".to_vec()),
        )
        .expect("the bounded Brave secret should be accepted");
    assert_eq!(
        crypto.decrypt_raw(BrowserKind::Brave, &V11_KNOWN_ANSWER),
        Err(ChromiumCryptoError::InvalidPadding)
    );
    assert_eq!(
        crypto
            .decrypt_raw(BrowserKind::GoogleChrome, &V11_KNOWN_ANSWER)
            .expect("the Chrome mapping must remain intact")
            .as_slice(),
        b"chrome-v11-cookie"
    );
}

#[test]
fn replacement_and_clear_are_scoped_to_one_browser() {
    let mut crypto = LinuxChromiumCookieCrypto::new();
    crypto
        .set_v11_secret(
            BrowserKind::GoogleChrome,
            Zeroizing::new(b"wrong-secret".to_vec()),
        )
        .expect("the bounded secret should be accepted");
    assert_eq!(
        crypto.decrypt_raw(BrowserKind::GoogleChrome, &V11_KNOWN_ANSWER),
        Err(ChromiumCryptoError::InvalidPadding)
    );

    crypto
        .set_v11_secret(
            BrowserKind::GoogleChrome,
            Zeroizing::new(V11_SECRET.to_vec()),
        )
        .expect("replacement should be accepted");
    assert_eq!(
        crypto
            .decrypt_raw(BrowserKind::GoogleChrome, &V11_KNOWN_ANSWER)
            .expect("replacement must take effect")
            .as_slice(),
        b"chrome-v11-cookie"
    );
    assert!(crypto.clear_v11_secret(BrowserKind::GoogleChrome));
    assert!(!crypto.clear_v11_secret(BrowserKind::GoogleChrome));
    assert_eq!(
        crypto.decrypt_raw(BrowserKind::GoogleChrome, &V11_KNOWN_ANSWER),
        Err(ChromiumCryptoError::Unavailable)
    );
}

#[test]
fn rejects_unsupported_browsers_and_invalid_secrets() {
    let mut crypto = LinuxChromiumCookieCrypto::new();

    assert_eq!(
        crypto.set_v11_secret(BrowserKind::Firefox, Zeroizing::new(b"secret".to_vec())),
        Err(ChromiumCryptoConfigError::UnsupportedBrowser)
    );
    assert_eq!(
        crypto.set_v11_secret(BrowserKind::Chromium, Zeroizing::new(Vec::new())),
        Err(ChromiumCryptoConfigError::InvalidSecret)
    );
    assert_eq!(
        crypto.set_v11_secret(
            BrowserKind::Chromium,
            Zeroizing::new(vec![b'x'; 4 * 1024 + 1]),
        ),
        Err(ChromiumCryptoConfigError::InvalidSecret)
    );
    assert_eq!(
        crypto.decrypt_raw(BrowserKind::Zen, &V10_KNOWN_ANSWER),
        Err(ChromiumCryptoError::UnsupportedBrowser)
    );
}

#[test]
fn rejects_unknown_or_truncated_tags() {
    let crypto = LinuxChromiumCookieCrypto::new();

    for malformed in [
        &b""[..],
        &b"v"[..],
        &b"v1"[..],
        &b"V100123456789abcdef"[..],
        &b"v120123456789abcdef"[..],
        &b"x100123456789abcdef"[..],
    ] {
        assert_eq!(
            crypto.decrypt_raw(BrowserKind::Chromium, malformed),
            Err(ChromiumCryptoError::InvalidTag)
        );
    }
}

#[test]
fn rejects_empty_unaligned_and_oversized_ciphertexts() {
    let crypto = LinuxChromiumCookieCrypto::new();

    for malformed in [
        b"v10".to_vec(),
        [b"v10".as_slice(), &[0_u8; 1]].concat(),
        [b"v10".as_slice(), &[0_u8; 15]].concat(),
        [b"v10".as_slice(), &[0_u8; 17]].concat(),
    ] {
        assert_eq!(
            crypto.decrypt_raw(BrowserKind::Chromium, &malformed),
            Err(ChromiumCryptoError::InvalidSize)
        );
    }

    let mut oversized = vec![0_u8; MAX_CHROMIUM_ENCRYPTED_VALUE_BYTES + 1];
    oversized[..3].copy_from_slice(b"v10");
    assert_eq!(
        crypto.decrypt_raw(BrowserKind::Chromium, &oversized),
        Err(ChromiumCryptoError::InvalidSize)
    );
}

#[test]
fn rejects_invalid_pkcs7_padding() {
    let crypto = LinuxChromiumCookieCrypto::new();
    let mut tampered = V10_KNOWN_ANSWER;
    tampered[18] ^= 0xff;

    assert_eq!(
        crypto.decrypt_raw(BrowserKind::Chromium, &tampered),
        Err(ChromiumCryptoError::InvalidPadding)
    );
}

#[test]
fn importer_trait_preserves_unavailable_and_collapses_invalid_inputs() {
    let crypto = LinuxChromiumCookieCrypto::new();

    assert_eq!(
        ChromiumCookieDecryptor::decrypt(&crypto, BrowserKind::GoogleChrome, &V11_KNOWN_ANSWER,),
        Err(ChromiumCookieDecryptionError::Unavailable)
    );
    assert_eq!(
        ChromiumCookieDecryptor::decrypt(&crypto, BrowserKind::GoogleChrome, b"v12"),
        Err(ChromiumCookieDecryptionError::Failed)
    );
    assert_eq!(
        ChromiumCookieDecryptor::decrypt(&crypto, BrowserKind::Firefox, &V10_KNOWN_ANSWER),
        Err(ChromiumCookieDecryptionError::Failed)
    );
}

#[test]
fn diagnostics_are_bounded_and_redact_secrets_and_values() {
    let secret_canary = b"never-print-this-safe-storage-secret";
    let ciphertext_canary = "c7ce3fb7e49fffc35eef504c9a86925b";
    let plaintext_canary = "cookie-value";
    let mut crypto = LinuxChromiumCookieCrypto::new();
    crypto
        .set_v11_secret(
            BrowserKind::GoogleChrome,
            Zeroizing::new(secret_canary.to_vec()),
        )
        .expect("the bounded secret should be accepted");

    let diagnostic = format!(
        "{crypto:?} {:?} {}",
        crypto
            .decrypt_raw(BrowserKind::Chromium, b"v10bad")
            .expect_err("unaligned ciphertext must fail"),
        ChromiumCryptoError::InvalidPadding,
    );

    assert!(diagnostic.contains("configured_v11_key_count"));
    assert!(!diagnostic.contains(std::str::from_utf8(secret_canary).expect("ASCII canary")));
    assert!(!diagnostic.contains(ciphertext_canary));
    assert!(!diagnostic.contains(plaintext_canary));
    assert!(diagnostic.len() < 256);
}
