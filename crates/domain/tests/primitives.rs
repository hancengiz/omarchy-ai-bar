#![allow(clippy::float_cmp)]

use std::str::FromStr;

use oab_domain::{
    AccountKey, BoundedText, CostAmount, CostUnit, CurrencyCode, DisplayPercent, ExactDecimal,
    Money, ProviderInstanceId, Timestamp, UsagePercent, WindowDuration,
};
use rust_decimal::Decimal;
use time::{Date, Month};

#[test]
fn bounded_text_enforces_utf8_byte_bounds_and_single_line_canonicalization() {
    let trimmed = BoundedText::<4>::new("  é  ").expect("surrounding spaces are canonicalized");
    assert_eq!(trimmed.as_str(), "é");

    let exact = BoundedText::<4>::new("éé").expect("four UTF-8 bytes fit exactly");
    assert_eq!(exact.len(), 4);
    assert!(BoundedText::<4>::new("ééa").is_err());
    assert!(BoundedText::<8>::new("line\nbreak").is_err());
    assert!(BoundedText::<8>::new("line\n").is_err());
    assert!(BoundedText::<8>::new("\tline").is_err());
    assert!(BoundedText::<8>::new("   ").is_err());
    assert!(serde_json::from_str::<BoundedText<4>>(r#""ééa""#).is_err());
}

#[test]
fn timestamps_normalize_offsets_and_fractional_seconds_to_utc() {
    let offset = Timestamp::parse("2026-08-29T13:00:00+03:00").expect("valid offset timestamp");
    assert_eq!(offset.to_string(), "2026-08-29T10:00:00Z");
    assert_eq!(
        serde_json::to_string(&offset).expect("serialize"),
        r#""2026-08-29T10:00:00Z""#
    );

    let fractional =
        Timestamp::parse("2026-08-29T10:00:00.123000000Z").expect("fractional timestamp");
    assert_eq!(fractional.to_string(), "2026-08-29T10:00:00.123Z");
    assert!(Timestamp::parse(" 2026-08-29T10:00:00Z").is_err());
    assert!(serde_json::from_str::<Timestamp>("1724925600").is_err());

    let negative_year = Date::from_calendar_date(-1, Month::January, 1)
        .expect("time supports negative years")
        .midnight()
        .assume_utc();
    assert!(Timestamp::new(negative_year).is_err());
}

#[test]
fn exact_decimals_are_string_only_and_canonically_normalized() {
    let decimal = ExactDecimal::parse("1.2300").expect("exact decimal");
    assert_eq!(decimal.to_string(), "1.23");
    assert_eq!(
        serde_json::to_string(&decimal).expect("serialize"),
        r#""1.23""#
    );
    assert_eq!(
        serde_json::from_str::<ExactDecimal>(r#""1.2300""#)
            .expect("deserialize exact decimal")
            .to_string(),
        "1.23"
    );

    let negative_zero = ExactDecimal::parse("-0.000").expect("decimal negative zero");
    assert_eq!(negative_zero.to_string(), "0");
    assert!(serde_json::from_str::<ExactDecimal>("1.23").is_err());
    assert!(ExactDecimal::parse(" 1.23").is_err());

    let direct = ExactDecimal::new(Decimal::from_str("2.500").expect("rust decimal"));
    assert_eq!(direct.to_string(), "2.5");
}

#[test]
fn currency_codes_are_uppercase_and_strictly_three_ascii_letters() {
    let currency = CurrencyCode::new("usd").expect("currency code");
    assert_eq!(currency.as_str(), "USD");
    assert_eq!(
        serde_json::to_string(&currency).expect("serialize"),
        r#""USD""#
    );
    assert!(CurrencyCode::new("US").is_err());
    assert!(CurrencyCode::new("USDT").is_err());
    assert!(CurrencyCode::new(" USD").is_err());
    assert!(CurrencyCode::new("€UR").is_err());
}

#[test]
fn cost_amounts_distinguish_currency_from_provider_units_losslessly() {
    let amount = ExactDecimal::parse("123.4500").expect("exact amount");
    let points = CostAmount::provider(amount, "  Points  ").expect("bounded provider unit");
    assert_eq!(points.amount().to_string(), "123.45");
    assert_eq!(points.unit().as_str(), "Points");
    assert!(points.unit().currency_code().is_none());
    assert_eq!(
        points
            .unit()
            .provider_unit()
            .expect("provider unit")
            .as_str(),
        "Points"
    );

    let points_json = r#"{"amount":"123.45","provider_unit":"Points"}"#;
    assert_eq!(
        serde_json::to_string(&points).expect("serialize provider amount"),
        points_json
    );
    assert_eq!(
        serde_json::from_str::<CostAmount>(points_json).expect("deserialize provider amount"),
        points
    );

    let money = Money::new(
        ExactDecimal::parse("9.990").expect("exact money"),
        CurrencyCode::new("usd").expect("currency code"),
    );
    let cost: CostAmount = money.into();
    assert_eq!(cost.unit().as_str(), "USD");
    assert!(matches!(cost.unit(), CostUnit::Currency(_)));
    assert_eq!(
        serde_json::to_string(&cost).expect("serialize currency cost"),
        r#"{"amount":"9.99","currency":"USD"}"#,
        "currency cost wire format remains compatible with Money"
    );

    assert!(CurrencyCode::new("Points").is_err());
    assert!(CostAmount::provider(amount, "line\nbreak").is_err());
    assert!(CostAmount::provider(amount, "x".repeat(33)).is_err());
    assert!(serde_json::from_str::<CostAmount>(r#"{"amount":"1"}"#).is_err());
    assert!(
        serde_json::from_str::<CostAmount>(
            r#"{"amount":"1","currency":"USD","provider_unit":"Points"}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<CostAmount>(r#"{"amount":"1","currency":"USD","unexpected":true}"#)
            .is_err()
    );
    assert!(serde_json::from_str::<CostAmount>(r#"{"amount":"1","currency":"Points"}"#).is_err());
    assert!(
        serde_json::from_str::<CostAmount>(r#"{"amount":1,"provider_unit":"Points"}"#).is_err()
    );
}

#[test]
fn raw_percentages_and_finite_numbers_canonicalize_negative_zero() {
    let raw_negative = UsagePercent::new(-12.5).expect("finite diagnostic percentage");
    assert_eq!(raw_negative.get(), -12.5);
    assert_eq!(raw_negative.remaining().get(), 112.5);

    let negative_zero = UsagePercent::new(-0.0).expect("finite negative zero");
    assert_eq!(negative_zero.get().to_bits(), 0.0_f64.to_bits());
    assert_eq!(
        serde_json::to_string(&negative_zero).expect("serialize"),
        "0.0"
    );
    assert_eq!(DisplayPercent::clamped(raw_negative).get(), 0.0);

    let finite = oab_domain::FiniteNumber::new(-0.0).expect("finite number");
    assert_eq!(finite.get().to_bits(), 0.0_f64.to_bits());
    assert!(oab_domain::FiniteNumber::new(f64::NAN).is_err());
    assert!(oab_domain::FiniteNumber::new(f64::INFINITY).is_err());
    assert_eq!(
        serde_json::from_str::<oab_domain::FiniteNumber>("12.5")
            .expect("finite number should decode")
            .get(),
        12.5
    );
}

#[test]
fn provider_window_minutes_map_only_to_positive_nonoverflowing_seconds() {
    assert_eq!(
        WindowDuration::from_provider_minutes(5)
            .expect("provider duration")
            .seconds(),
        300
    );
    assert!(WindowDuration::from_provider_minutes(0).is_err());
    assert_eq!(
        WindowDuration::optional_from_provider_minutes(0).expect("zero means absent"),
        None
    );
    assert_eq!(
        WindowDuration::optional_from_provider_minutes(5)
            .expect("positive provider duration")
            .expect("present duration")
            .seconds(),
        300
    );
    assert!(WindowDuration::from_provider_minutes(-1).is_err());
    assert!(WindowDuration::from_provider_minutes(i64::MAX).is_err());
    assert!(serde_json::from_str::<WindowDuration>("0").is_err());
}

#[test]
fn account_keys_are_opaque_and_reject_email_addresses() {
    let account = AccountKey::new("acct_fixture_7m3j").expect("opaque account key");
    assert!(!format!("{account:?}").contains(account.as_str()));
    assert!(AccountKey::new("ada@example.com").is_err());
    assert!(serde_json::from_str::<AccountKey>(r#""ada@example.com""#).is_err());

    // Provider instance labels are routing configuration and remain a distinct type.
    let instance = ProviderInstanceId::new("ada@example.com").expect("valid routing instance");
    assert!(!format!("{instance:?}").contains("ada@example.com"));
}
