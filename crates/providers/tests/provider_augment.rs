use oab_domain::{
    AccountKey, AccountScope, BoundedText, ProviderId, ProviderInstanceId, RateWindow, Timestamp,
    UsagePercent,
};
use oab_providers::providers::augment::AugmentProvider;

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::Augment,
        ProviderInstanceId::new("default").expect("instance"),
        AccountKey::new("fixture").expect("account"),
    )
}

#[test]
fn current_cli_report_is_normalized() {
    let sample = AugmentProvider::parse_report_at(
        scope(),
        Timestamp::parse("2026-08-31T12:00:00Z").expect("time"),
        "319,054 credits remaining                     Max Plan\n\
         450,000 credits / month\n\
         9 days remaining in this billing cycle (ends 9/9/2026)\n",
    )
    .expect("sample");

    let used = sample
        .primary()
        .and_then(RateWindow::used_percent)
        .map(UsagePercent::get)
        .expect("percent");
    assert!((used - 29.099_111_111_111_11).abs() < 0.000_000_1);
    assert_eq!(
        sample
            .primary()
            .and_then(RateWindow::reset_description)
            .map(BoundedText::as_str),
        Some("319054 / 450000 credits remaining")
    );
    assert_eq!(
        sample.primary().and_then(RateWindow::resets_at),
        Some(Timestamp::parse("2026-09-09T00:00:00Z").expect("reset"))
    );
}

#[test]
fn legacy_cli_report_uses_explicit_used_and_total_values() {
    let sample = AugmentProvider::parse_report_at(
        scope(),
        Timestamp::parse("2026-01-06T12:00:00Z").expect("time"),
        "Max Plan 450,000 credits / month\n\
         11,657 remaining · 953,170 / 964,827 credits used\n\
         2 days remaining in this billing cycle (ends 1/8/2026)\n",
    )
    .expect("sample");
    let used = sample
        .primary()
        .and_then(RateWindow::used_percent)
        .map(UsagePercent::get)
        .expect("percent");
    assert!((used - 98.791_804_126_542_9).abs() < 0.000_000_1);
}
