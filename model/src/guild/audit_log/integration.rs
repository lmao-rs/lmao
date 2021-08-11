use crate::{guild::IntegrationAccount, id::IntegrationId, user::User};
use serde::{Deserialize, Serialize};

/// Information about a [guild integration] provided in an [audit log].
///
/// [audit log]: super::AuditLog
/// [guild integration]: super::super::GuildIntegration
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AuditLogGuildIntegration {
    /// Account of the integration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<IntegrationAccount>,
    /// Whether the integration is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Behavior of expiring subscribers to the integration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire_behavior: Option<u64>,
    /// Grace period before expiring users, in days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire_grace_period: Option<u64>,
    /// ID of the integration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<IntegrationId>,
    /// Type of integration.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name of the integration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// ID that the integration uses for subscribers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_id: Option<IntegrationId>,
    /// When the integration was last synced.
    ///
    /// This is an ISO 8601 timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synced_at: Option<String>,
    /// Whether the integration is syncing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syncing: Option<bool>,
    /// User for the integration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
}

#[cfg(test)]
mod tests {
    use super::AuditLogGuildIntegration;
    use serde::{Deserialize, Serialize};
    use static_assertions::{assert_fields, assert_impl_all};
    use std::{fmt::Debug, hash::Hash};

    assert_fields!(
        AuditLogGuildIntegration: account,
        enabled,
        expire_behavior,
        expire_grace_period,
        id,
        kind,
        name,
        role_id,
        synced_at,
        syncing,
        user
    );
    assert_impl_all!(
        AuditLogGuildIntegration: Clone,
        Debug,
        Deserialize<'static>,
        Eq,
        Hash,
        PartialEq,
        Send,
        Serialize,
        Sync
    );
}
