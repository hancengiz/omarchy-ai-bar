//! Bounded, account-scoped projection of Codex's banked reset inventory.

use oab_domain::{
    AccountScope, PrivacyKey, ResetCredit, ResetCreditStatus, ResetCreditsSnapshot, Timestamp,
};
use serde::Deserialize;

use super::codex_http::CodexHttpError;

#[derive(Deserialize)]
struct Inventory {
    credits: Vec<Credit>,
    available_count: u16,
}

#[derive(Deserialize)]
struct Credit {
    id: String,
    reset_type: String,
    status: ResetCreditStatus,
    granted_at: Timestamp,
    expires_at: Option<Timestamp>,
    redeem_started_at: Option<Timestamp>,
    redeemed_at: Option<Timestamp>,
    title: Option<String>,
    description: Option<String>,
}

/// Parses a reset inventory without exposing provider IDs in stored or displayed data.
///
/// # Errors
/// Returns a redacted error for malformed, oversized, or inconsistent inventory.
pub fn parse_codex_reset_credits(
    data: &[u8],
    key: &PrivacyKey,
    scope: AccountScope,
    fetched_at: Timestamp,
) -> Result<ResetCreditsSnapshot, CodexHttpError> {
    if data.len() > 1024 * 1024 || scope.provider() != oab_domain::ProviderId::Codex {
        return Err(CodexHttpError::InvalidResponse);
    }
    let inventory: Inventory =
        serde_json::from_slice(data).map_err(|_| CodexHttpError::InvalidResponse)?;
    if inventory.credits.len() > 64 {
        return Err(CodexHttpError::InvalidResponse);
    }
    let credits = inventory
        .credits
        .into_iter()
        .map(|credit| {
            ResetCredit::from_provider(
                key,
                &scope,
                credit.id,
                credit.reset_type,
                credit.status,
                credit.granted_at,
                credit.expires_at,
                credit.redeem_started_at,
                credit.redeemed_at,
                credit.title,
                credit.description,
            )
            .map_err(|_| CodexHttpError::InvalidResponse)
        })
        .collect::<Result<Vec<_>, _>>()?;
    ResetCreditsSnapshot::new(scope, credits, inventory.available_count, fetched_at)
        .map_err(|_| CodexHttpError::InvalidResponse)
}
