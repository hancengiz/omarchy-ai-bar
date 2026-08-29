use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{AccountScope, BoundedText};

pub const MAX_IDENTITY_TEXT_BYTES: usize = 256;

/// Identity data returned by a provider for one exact account scope.
///
/// The scope is deliberately repeated here (rather than inferred from a
/// surrounding snapshot) so identity data cannot be accidentally reused for a
/// different provider, instance, or account.
///
/// ```compile_fail
/// # use oab_domain::IdentitySnapshot;
/// fn cannot_serialize_private_identity(identity: &IdentitySnapshot) {
///     let _ = serde_json::to_string(identity);
/// }
/// ```
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySnapshot {
    scope: AccountScope,
    provider_account_id: Option<BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
    email: Option<BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
    organization: Option<BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
    account_label: Option<BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
    plan: Option<BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
    login_method: Option<BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
}

impl IdentitySnapshot {
    #[must_use]
    pub const fn new(
        scope: AccountScope,
        provider_account_id: Option<BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
        email: Option<BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
        organization: Option<BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
        account_label: Option<BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
        plan: Option<BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
        login_method: Option<BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
    ) -> Self {
        Self {
            scope,
            provider_account_id,
            email,
            organization,
            account_label,
            plan,
            login_method,
        }
    }

    #[must_use]
    pub const fn scope(&self) -> &AccountScope {
        &self.scope
    }

    #[must_use]
    pub const fn provider_account_id(&self) -> Option<&BoundedText<MAX_IDENTITY_TEXT_BYTES>> {
        self.provider_account_id.as_ref()
    }

    #[must_use]
    pub const fn email(&self) -> Option<&BoundedText<MAX_IDENTITY_TEXT_BYTES>> {
        self.email.as_ref()
    }

    #[must_use]
    pub const fn organization(&self) -> Option<&BoundedText<MAX_IDENTITY_TEXT_BYTES>> {
        self.organization.as_ref()
    }

    #[must_use]
    pub const fn account_label(&self) -> Option<&BoundedText<MAX_IDENTITY_TEXT_BYTES>> {
        self.account_label.as_ref()
    }

    #[must_use]
    pub const fn plan(&self) -> Option<&BoundedText<MAX_IDENTITY_TEXT_BYTES>> {
        self.plan.as_ref()
    }

    #[must_use]
    pub const fn login_method(&self) -> Option<&BoundedText<MAX_IDENTITY_TEXT_BYTES>> {
        self.login_method.as_ref()
    }

    pub(crate) const fn private_view(&self) -> PrivateIdentitySnapshot<'_> {
        PrivateIdentitySnapshot {
            scope: &self.scope,
            provider_account_id: self.provider_account_id.as_ref(),
            email: self.email.as_ref(),
            organization: self.organization.as_ref(),
            account_label: self.account_label.as_ref(),
            plan: self.plan.as_ref(),
            login_method: self.login_method.as_ref(),
        }
    }

    pub(crate) const fn redacted_for_scope(scope: AccountScope) -> Self {
        Self {
            scope,
            provider_account_id: None,
            email: None,
            organization: None,
            account_label: None,
            plan: None,
            login_method: None,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct PrivateIdentitySnapshot<'a> {
    scope: &'a AccountScope,
    provider_account_id: Option<&'a BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
    email: Option<&'a BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
    organization: Option<&'a BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
    account_label: Option<&'a BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
    plan: Option<&'a BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
    login_method: Option<&'a BoundedText<MAX_IDENTITY_TEXT_BYTES>>,
}

impl fmt::Debug for IdentitySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("IdentitySnapshot");
        debug.field("scope", &self.scope);
        debug.field(
            "provider_account_id",
            &self.provider_account_id.as_ref().map(|_| "[redacted]"),
        );
        debug.field("email", &self.email.as_ref().map(|_| "[redacted]"));
        debug.field(
            "organization",
            &self.organization.as_ref().map(|_| "[redacted]"),
        );
        debug.field(
            "account_label",
            &self.account_label.as_ref().map(|_| "[redacted]"),
        );
        debug.field("plan", &self.plan);
        debug.field("login_method", &self.login_method);
        debug.finish()
    }
}
