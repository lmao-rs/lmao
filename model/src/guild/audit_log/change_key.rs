use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum AuditLogChangeKey {
    AfkChannelId,
    AfkTimeout,
    Allow,
    ApplicationId,
    AvatarHash,
    BannerHash,
    Bitrate,
    ChannelId,
    Code,
    Color,
    Deaf,
    DefaultMessageNotifications,
    Deny,
    Description,
    DiscoverySplashHash,
    EnableEmoticons,
    ExpireBehavior,
    ExpireGracePeriod,
    ExplicitContentFilter,
    Hoist,
    IconHash,
    Id,
    InviterId,
    MaxAge,
    MaxUses,
    Mentionable,
    MfaLevel,
    Mute,
    Name,
    Nick,
    NsfwLevel,
    OwnerId,
    PermissionOverwrites,
    Permissions,
    Position,
    PreferredLocale,
    PruneDeleteDays,
    PublicUpdatesChannelId,
    RateLimitPerUser,
    #[serde(rename = "$add")]
    RoleAdded,
    #[serde(rename = "$remove")]
    RoleRemoved,
    Region,
    RulesChannelId,
    SplashHash,
    SystemChannelId,
    PrivacyLevel,
    Temporary,
    Topic,
    Type,
    Uses,
    UserLimit,
    VanityUrlCode,
    VerificationLevel,
    WidgetChannelId,
    WidgetEnabled,
}
