//! Calculate the permissions for members in on a guild- or channel-level with
//! information from the cache.
//!
//! # Required Configuration
//!
//! Calculating permissions required that some information relevant to the
//! member, their roles, and the channel or guild is available in the cache.
//! These will only be stored in the cache when certain [`ResourceType`]s are
//! enabled. To enable the configurations for both the
//! [`InMemoryCachePermissions::in_channel`] and
//! [`InMemoryCachePermissions::root`] operations you must enable
//! their required [`ResourceType`]s like so:
//!
//! ```
//! use twilight_cache_inmemory::{InMemoryCache, ResourceType};
//!
//! let resource_types = ResourceType::CHANNEL
//!     | ResourceType::MEMBER
//!     | ResourceType::ROLE;
//!
//! let cache = InMemoryCache::builder().resource_types(resource_types).build();
//! ```
//!
//! [`ResourceType`]: crate::ResourceType

use super::InMemoryCache;
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};
use twilight_model::{
    channel::GuildChannel,
    guild::Permissions,
    id::{ChannelId, GuildId, RoleId, UserId},
};
use twilight_util::permission_calculator::PermissionCalculator;

/// Error calculating permissions with the information in a cache.
#[derive(Debug)]
pub struct ChannelError {
    kind: ChannelErrorType,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl ChannelError {
    /// Immutable reference to the type of error that occurred.
    #[must_use = "retrieving the type has no effect if left unused"]
    pub const fn kind(&self) -> &ChannelErrorType {
        &self.kind
    }

    /// Consume the error, returning the source error if there is any.
    #[must_use = "consuming the error and retrieving the source has no effect if left unused"]
    pub fn into_source(self) -> Option<Box<dyn Error + Send + Sync>> {
        self.source
    }

    /// Consume the error, returning the owned error type and the source error.
    #[must_use = "consuming the error into its parts has no effect if left unused"]
    pub fn into_parts(self) -> (ChannelErrorType, Option<Box<dyn Error + Send + Sync>>) {
        (self.kind, self.source)
    }

    /// Create a root error from an error while retrieving a member's roles.
    fn from_member_roles(member_roles_error: MemberRolesErrorType) -> Self {
        Self {
            kind: match member_roles_error {
                MemberRolesErrorType::MemberMissing { guild_id, user_id } => {
                    ChannelErrorType::MemberUnavailable { guild_id, user_id }
                }
                MemberRolesErrorType::RoleMissing { role_id } => {
                    ChannelErrorType::RoleUnavailable { role_id }
                }
            },
            source: None,
        }
    }
}

impl Display for ChannelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self.kind {
            ChannelErrorType::ChannelUnavailable { channel_id } => f.write_fmt(format_args!(
                "channel {} is either not in the cache or is not a guild channel",
                channel_id
            )),
            ChannelErrorType::MemberUnavailable { guild_id, user_id } => f.write_fmt(format_args!(
                "member (guild: {}; user: {}) is not present in the cache",
                guild_id, user_id
            )),
            ChannelErrorType::RoleUnavailable { role_id } => f.write_fmt(format_args!(
                "member has role {} but it is not present in the cache",
                role_id
            )),
        }
    }
}

impl Error for ChannelError {}

/// Type of [`ChannelError`] that occurred.
#[derive(Debug)]
#[non_exhaustive]
pub enum ChannelErrorType {
    /// Guild channel is not present in the cache.
    ChannelUnavailable {
        /// ID of the channel.
        channel_id: ChannelId,
    },
    /// The user's member information is not available in the guild.
    ///
    /// This could be because the user is not currently a member of the guild or
    /// because the member entity has not yet been received by the cache.
    MemberUnavailable {
        /// ID of the guild.
        guild_id: GuildId,
        /// ID of the user.
        user_id: UserId,
    },
    /// One of the user's roles is not available in the guild.
    ///
    /// The reasons this could happen could be due to the cache missing a
    /// [`RoleCreate`] event or a user application race condition.
    ///
    /// [`RoleCreate`]: twilight_model::gateway::payload::RoleCreate
    RoleUnavailable {
        /// ID of the role that the user has but details about is missing.
        role_id: RoleId,
    },
}

/// Error calculating permissions with information in a cache.
#[derive(Debug)]
pub struct RootError {
    kind: RootErrorType,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl RootError {
    /// Immutable reference to the type of error that occurred.
    #[must_use = "retrieving the type has no effect if left unused"]
    pub const fn kind(&self) -> &RootErrorType {
        &self.kind
    }

    /// Consume the error, returning the source error if there is any.
    #[must_use = "consuming the error and retrieving the source has no effect if left unused"]
    pub fn into_source(self) -> Option<Box<dyn Error + Send + Sync>> {
        self.source
    }

    /// Consume the error, returning the owned error type and the source error.
    #[must_use = "consuming the error into its parts has no effect if left unused"]
    pub fn into_parts(self) -> (RootErrorType, Option<Box<dyn Error + Send + Sync>>) {
        (self.kind, self.source)
    }

    /// Create a root error from an error while retrieving a member's roles.
    fn from_member_roles(member_roles_error: MemberRolesErrorType) -> Self {
        Self {
            kind: match member_roles_error {
                MemberRolesErrorType::MemberMissing { guild_id, user_id } => {
                    RootErrorType::MemberUnavailable { guild_id, user_id }
                }
                MemberRolesErrorType::RoleMissing { role_id } => {
                    RootErrorType::RoleUnavailable { role_id }
                }
            },
            source: None,
        }
    }
}

impl Display for RootError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self.kind {
            RootErrorType::MemberUnavailable { guild_id, user_id } => f.write_fmt(format_args!(
                "member (guild: {}; user: {}) is not present in the cache",
                guild_id, user_id
            )),
            RootErrorType::RoleUnavailable { role_id } => f.write_fmt(format_args!(
                "member has role {} but it is not present in the cache",
                role_id
            )),
        }
    }
}

impl Error for RootError {}

/// Type of [`RootError`] that occurred.
#[derive(Debug)]
#[non_exhaustive]
pub enum RootErrorType {
    /// The user's member information is not available in the guild.
    ///
    /// This could be because the user is not currently a member of the guild or
    /// because the member entity has not yet been received by the cache.
    MemberUnavailable {
        /// ID of the guild.
        guild_id: GuildId,
        /// ID of the user.
        user_id: UserId,
    },
    /// One of the user's roles is not available in the guild.
    ///
    /// The reasons this could happen could be due to the cache missing a
    /// [`RoleCreate`] event or a user application race condition.
    ///
    /// [`RoleCreate`]: twilight_model::gateway::payload::RoleCreate
    RoleUnavailable {
        /// ID of the role that the user has but details about is missing.
        role_id: RoleId,
    },
}

/// Error type that occurred while getting a member's assigned roles'
/// permissions as well as the `@everyone` role's permissions.
enum MemberRolesErrorType {
    /// Member is not in the cache.
    MemberMissing {
        /// ID of the guild.
        guild_id: GuildId,
        /// ID of the user.
        user_id: UserId,
    },
    /// Role is missing from the cache.
    RoleMissing { role_id: RoleId },
}

/// Member's roles' permissions and the guild's `@everyone` role's permissions.
struct MemberRoles {
    /// User's roles and their permissions.
    assigned: Vec<(RoleId, Permissions)>,
    /// Permissions of the guild's `@everyone` role.
    everyone: Permissions,
}

/// Calculate the permissions of a member with information from the cache.
#[derive(Clone, Debug)]
pub struct InMemoryCachePermissions<'a>(&'a InMemoryCache);

impl<'a> InMemoryCachePermissions<'a> {
    pub(super) const fn new(cache: &'a InMemoryCache) -> Self {
        Self(cache)
    }

    /// Immutable reference to the underlying cache.
    pub const fn cache_ref(&'a self) -> &'a InMemoryCache {
        self.0
    }

    /// Consume the statistics interface, returning the underlying cache
    /// reference.
    pub const fn into_cache(self) -> &'a InMemoryCache {
        self.0
    }

    /// Calculate the permissions of a member in a guild channel.
    ///
    /// Returns [`Permissions::all`] if the user is the owner of the guild.
    ///
    /// The following [`ResourceType`]s must be enabled:
    ///
    /// - [`ResourceType::CHANNEL`]
    /// - [`ResourceType::MEMBER`]
    /// - [`ResourceType::ROLE`]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use twilight_cache_inmemory::InMemoryCache;
    /// use twilight_model::id::{ChannelId, UserId};
    ///
    /// let cache = InMemoryCache::new();
    ///
    /// // later on...
    ///
    /// let channel_id = ChannelId(4);
    /// let user_id = UserId(5);
    ///
    /// let permissions = cache.permissions().in_channel(user_id, channel_id)?;
    /// println!(
    ///     "User {} in channel {} has permissions {:?}",
    ///     user_id,
    ///     channel_id,
    ///     permissions,
    /// );
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a [`ChannelErrorType::ChannelUnavailable`] error type if the
    /// guild channel is not in the cache.
    ///
    /// Returns a [`ChannelErrorType::MemberUnavailable`] error type if the
    /// member for the user in the guild is not present.
    ///
    /// Returns a [`ChannelErrorType::RoleUnavailable`] error type if one of the
    /// member's roles is not in the cache.
    ///
    /// [`Permissions::all`]: twilight_model::guild::Permissions::all
    /// [`ResourceType::CHANNEL`]: crate::ResourceType::CHANNEL
    /// [`ResourceType::MEMBER`]: crate::ResourceType::MEMBER
    /// [`ResourceType::ROLE`]: crate::ResourceType::ROLE
    /// [`ResourceType`]: crate::ResourceType
    pub fn in_channel(
        &self,
        user_id: UserId,
        channel_id: ChannelId,
    ) -> Result<Permissions, ChannelError> {
        let channel = (self.0)
            .0
            .channels_guild
            .get(&channel_id)
            .ok_or(ChannelError {
                kind: ChannelErrorType::ChannelUnavailable { channel_id },
                source: None,
            })?;

        let guild_id = channel.data.guild_id().ok_or(ChannelError {
            kind: ChannelErrorType::ChannelUnavailable { channel_id },
            source: None,
        })?;

        if self.is_owner(user_id, guild_id) {
            return Ok(Permissions::all());
        }

        let MemberRoles { assigned, everyone } = self
            .member_roles(user_id, guild_id)
            .map_err(ChannelError::from_member_roles)?;

        let overwrites = match &channel.data {
            GuildChannel::Category(c) => &c.permission_overwrites,
            GuildChannel::Stage(c) => &c.permission_overwrites,
            GuildChannel::Text(c) => &c.permission_overwrites,
            GuildChannel::Voice(c) => &c.permission_overwrites,
        };

        let calculator =
            PermissionCalculator::new(guild_id, user_id, everyone, assigned.as_slice());

        Ok(calculator.in_channel(channel.data.kind(), overwrites))
    }

    /// Calculate the guild-level permissions of a member.
    ///
    /// Returns [`Permissions::all`] if the user is the owner of the guild.
    ///
    /// The following [`ResourceType`]s must be enabled:
    ///
    /// - [`ResourceType::MEMBER`]
    /// - [`ResourceType::ROLE`]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use twilight_cache_inmemory::InMemoryCache;
    /// use twilight_model::id::{GuildId, UserId};
    ///
    /// let cache = InMemoryCache::new();
    ///
    /// // later on...
    ///
    /// let guild_id = GuildId(4);
    /// let user_id = UserId(5);
    ///
    /// let permissions = cache.permissions().root(user_id, guild_id)?;
    /// println!(
    ///     "User {} in guild {} has permissions {:?}",
    ///     user_id,
    ///     guild_id,
    ///     permissions,
    /// );
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a [`RootErrorType::MemberUnavailable`] error type if the
    /// member for the user in the guild is not present.
    ///
    /// Returns a [`RootErrorType::RoleUnavailable`] error type if one of the
    /// member's roles is not in the cache.
    ///
    /// [`Permissions::all`]: twilight_model::guild::Permissions::all
    /// [`ResourceType::MEMBER`]: crate::ResourceType::MEMBER
    /// [`ResourceType::ROLE`]: crate::ResourceType::ROLE
    /// [`ResourceType`]: crate::ResourceType
    pub fn root(&self, user_id: UserId, guild_id: GuildId) -> Result<Permissions, RootError> {
        if self.is_owner(user_id, guild_id) {
            return Ok(Permissions::all());
        }

        let MemberRoles { assigned, everyone } = self
            .member_roles(user_id, guild_id)
            .map_err(RootError::from_member_roles)?;
        let calculator =
            PermissionCalculator::new(guild_id, user_id, everyone, assigned.as_slice());

        Ok(calculator.root())
    }

    /// Determine whether a given user is the owner of a guild.
    ///
    /// Returns true if the user is or false if the user is definitively not the
    /// owner of the guild or the guild is not in the cache.
    fn is_owner(&self, user_id: UserId, guild_id: GuildId) -> bool {
        (self.0)
            .0
            .guilds
            .get(&guild_id)
            .map(|r| r.owner_id == user_id)
            .unwrap_or_default()
    }

    /// Retrieve a member's roles' permissions and the guild's `@everyone`
    /// role's permissions.
    ///
    /// # Errors
    ///
    /// Returns [`MemberRolesErrorType::MemberMissing`] if the member is missing
    /// from the cache.
    ///
    /// Returns [`MemberRolesErrorType::RoleMissing`] if a role is missing from
    /// the cache.
    fn member_roles(
        &self,
        user_id: UserId,
        guild_id: GuildId,
    ) -> Result<MemberRoles, MemberRolesErrorType> {
        let member = if let Some(member) = (self.0).0.members.get(&(guild_id, user_id)) {
            member
        } else {
            return Err(MemberRolesErrorType::MemberMissing { guild_id, user_id });
        };

        let mut member_roles = Vec::with_capacity(member.roles.len());

        for role_id in &member.roles {
            let role = if let Some(role) = (self.0).0.roles.get(role_id) {
                role
            } else {
                return Err(MemberRolesErrorType::RoleMissing { role_id: *role_id });
            };

            member_roles.push((*role_id, role.data.permissions));
        }

        // Assume that the `@everyone` role is always present, so do this last.
        let everyone_role_id = RoleId(guild_id.0);

        if let Some(everyone_role) = (self.0).0.roles.get(&everyone_role_id) {
            Ok(MemberRoles {
                assigned: member_roles,
                everyone: everyone_role.data.permissions,
            })
        } else {
            Err(MemberRolesErrorType::RoleMissing {
                role_id: everyone_role_id,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChannelError, ChannelErrorType, InMemoryCachePermissions, RootError, RootErrorType,
    };
    use crate::{test, InMemoryCache};
    use static_assertions::{assert_fields, assert_impl_all};
    use std::{error::Error, fmt::Debug};
    use twilight_model::{
        channel::{
            permission_overwrite::{PermissionOverwrite, PermissionOverwriteType},
            Channel, ChannelType, GuildChannel, TextChannel,
        },
        gateway::payload::{ChannelCreate, GuildCreate, MemberAdd, MemberUpdate, RoleCreate},
        guild::{
            DefaultMessageNotificationLevel, ExplicitContentFilter, Guild, MfaLevel, NSFWLevel,
            Permissions, PremiumTier, Role, SystemChannelFlags, VerificationLevel,
        },
        id::{ChannelId, GuildId, RoleId, UserId},
    };

    assert_fields!(ChannelErrorType::ChannelUnavailable: channel_id);
    assert_fields!(ChannelErrorType::MemberUnavailable: guild_id, user_id);
    assert_fields!(ChannelErrorType::RoleUnavailable: role_id);
    assert_impl_all!(ChannelErrorType: Debug, Send, Sync);
    assert_impl_all!(ChannelError: Debug, Send, Sync);
    assert_impl_all!(InMemoryCachePermissions<'_>: Clone, Debug, Send, Sync);
    assert_fields!(RootErrorType::MemberUnavailable: guild_id, user_id);
    assert_fields!(RootErrorType::RoleUnavailable: role_id);
    assert_impl_all!(RootErrorType: Debug, Send, Sync);
    assert_impl_all!(RootError: Debug, Send, Sync);

    /// Guild ID used in tests.
    const GUILD_ID: GuildId = GuildId(1);

    /// ID of the `@everyone` role.
    const EVERYONE_ROLE_ID: RoleId = RoleId(GUILD_ID.0);

    /// User ID used in tests.
    const USER_ID: UserId = UserId(2);

    /// ID of the `@everyone` role.
    const OTHER_ROLE_ID: RoleId = RoleId(3);

    /// ID of the user that owns the guild with the ID [`GUILD_ID`].
    const OWNER_ID: UserId = UserId(4);

    /// ID of the #general channel in the guild.
    ///
    /// This has the same ID as the [`GUILD_ID`].
    const CHANNEL_ID: ChannelId = ChannelId(GUILD_ID.0);

    fn base_guild() -> Guild {
        Guild {
            id: GUILD_ID,
            afk_channel_id: None,
            afk_timeout: 300,
            application_id: None,
            banner: None,
            channels: Vec::new(),
            default_message_notifications: DefaultMessageNotificationLevel::Mentions,
            description: None,
            discovery_splash: None,
            emojis: Vec::new(),
            explicit_content_filter: ExplicitContentFilter::AllMembers,
            features: Vec::new(),
            icon: None,
            joined_at: None,
            large: false,
            max_members: None,
            max_presences: None,
            member_count: None,
            members: Vec::new(),
            mfa_level: MfaLevel::Elevated,
            name: "this is a guild".to_owned(),
            nsfw_level: NSFWLevel::AgeRestricted,
            owner: Some(false),
            owner_id: OWNER_ID,
            permissions: None,
            preferred_locale: "en-GB".to_owned(),
            premium_subscription_count: Some(0),
            premium_tier: PremiumTier::None,
            presences: Vec::new(),
            roles: Vec::from([
                // Give the `@everyone` role a guild level and channel level
                // permission.
                role_with_permissions(
                    EVERYONE_ROLE_ID,
                    Permissions::CREATE_INVITE | Permissions::VIEW_AUDIT_LOG,
                ),
            ]),
            splash: None,
            stage_instances: Vec::new(),
            system_channel_id: None,
            system_channel_flags: SystemChannelFlags::SUPPRESS_JOIN_NOTIFICATIONS,
            rules_channel_id: None,
            unavailable: false,
            verification_level: VerificationLevel::VeryHigh,
            voice_states: Vec::new(),
            vanity_url_code: None,
            widget_channel_id: None,
            widget_enabled: None,
            max_video_channel_users: None,
            approximate_member_count: None,
            approximate_presence_count: None,
        }
    }

    fn channel() -> Channel {
        Channel::Guild(GuildChannel::Text(TextChannel {
            guild_id: Some(GUILD_ID),
            id: CHANNEL_ID,
            kind: ChannelType::GuildText,
            last_message_id: None,
            last_pin_timestamp: None,
            name: "test".to_owned(),
            nsfw: false,
            parent_id: None,
            permission_overwrites: Vec::from([
                PermissionOverwrite {
                    allow: Permissions::empty(),
                    deny: Permissions::CREATE_INVITE,
                    kind: PermissionOverwriteType::Role(EVERYONE_ROLE_ID),
                },
                PermissionOverwrite {
                    allow: Permissions::EMBED_LINKS,
                    deny: Permissions::empty(),
                    kind: PermissionOverwriteType::Member(USER_ID),
                },
            ]),
            position: 0,
            rate_limit_per_user: None,
            topic: None,
        }))
    }

    fn role_with_permissions(id: RoleId, permissions: Permissions) -> Role {
        let mut role = test::role(id);
        role.permissions = permissions;

        role
    }

    const fn role_create(guild_id: GuildId, role: Role) -> RoleCreate {
        RoleCreate { guild_id, role }
    }

    /// Test that the permissions interface returns the correct errors depending
    /// on what information is unavailable during [`root`] operations.
    ///
    /// [`root`]: super::InMemoryCachePermissions::root
    #[test]
    fn test_root_errors() {
        let cache = InMemoryCache::new();
        let permissions = cache.permissions();
        assert!(matches!(
            permissions.root(USER_ID, GUILD_ID).unwrap_err().kind(),
            &RootErrorType::MemberUnavailable { guild_id, user_id }
            if guild_id == GUILD_ID && user_id == USER_ID
        ));

        cache.update(&MemberAdd(test::member(USER_ID, GUILD_ID)));

        assert!(matches!(
            permissions.root(USER_ID, GUILD_ID).unwrap_err().kind(),
            &RootErrorType::RoleUnavailable { role_id }
            if role_id == EVERYONE_ROLE_ID
        ));
    }

    /// Test that the permissions interface returns the correct permissions for
    /// a member on a root level.
    ///
    /// Notably [`root`] doesn't require that the guild *itself* is in the
    /// cache.
    ///
    /// [`root`]: super::InMemoryCachePermissions::root
    #[test]
    fn test_root() -> Result<(), Box<dyn Error>> {
        let cache = InMemoryCache::new();
        let permissions = cache.permissions();

        cache.update(&GuildCreate(base_guild()));
        cache.update(&MemberAdd(test::member(USER_ID, GUILD_ID)));
        cache.update(&MemberUpdate {
            guild_id: GUILD_ID,
            deaf: None,
            joined_at: "foo".to_owned(),
            mute: None,
            nick: None,
            pending: false,
            premium_since: None,
            roles: Vec::from([OTHER_ROLE_ID]),
            user: test::user(USER_ID),
        });
        cache.update(&role_create(
            GUILD_ID,
            role_with_permissions(
                OTHER_ROLE_ID,
                Permissions::SEND_MESSAGES | Permissions::BAN_MEMBERS,
            ),
        ));

        let expected = Permissions::CREATE_INVITE
            | Permissions::BAN_MEMBERS
            | Permissions::VIEW_AUDIT_LOG
            | Permissions::SEND_MESSAGES;

        assert_eq!(expected, permissions.root(USER_ID, GUILD_ID)?);

        Ok(())
    }

    /// Test that the permissions interface returns the correct errors and
    /// permissions depending on what information is unavailable during
    /// [`in_channel`] operations.
    ///
    /// [`in_channel`]: super::InMemoryCachePermissions::in_channel
    #[test]
    fn test_in_channel() -> Result<(), Box<dyn Error>> {
        let cache = InMemoryCache::new();
        let permissions = cache.permissions();

        cache.update(&GuildCreate(base_guild()));
        assert!(matches!(
            permissions.in_channel(USER_ID, CHANNEL_ID).unwrap_err().kind(),
            ChannelErrorType::ChannelUnavailable { channel_id }
            if *channel_id == CHANNEL_ID
        ));

        cache.update(&ChannelCreate(channel()));
        assert!(matches!(
            permissions.in_channel(USER_ID, CHANNEL_ID).unwrap_err().kind(),
            ChannelErrorType::MemberUnavailable { guild_id, user_id }
            if *guild_id == GUILD_ID && *user_id == USER_ID
        ));

        cache.update(&MemberAdd({
            let mut member = test::member(USER_ID, GUILD_ID);
            member.roles.push(OTHER_ROLE_ID);

            member
        }));
        assert!(matches!(
            permissions.in_channel(USER_ID, CHANNEL_ID).unwrap_err().kind(),
            &ChannelErrorType::RoleUnavailable { role_id }
            if role_id == OTHER_ROLE_ID
        ));

        cache.update(&role_create(
            GUILD_ID,
            role_with_permissions(
                OTHER_ROLE_ID,
                Permissions::SEND_MESSAGES | Permissions::BAN_MEMBERS,
            ),
        ));

        assert_eq!(
            Permissions::EMBED_LINKS | Permissions::SEND_MESSAGES,
            permissions.in_channel(USER_ID, CHANNEL_ID)?,
        );

        Ok(())
    }

    /// Test that [`in_channel`] and [`root`] both return [`Permissions::all`]
    /// if the user is also the owner of the guild.
    ///
    /// Only the guild needs to be in the cache to short-circuit on this
    /// condition.
    ///
    /// [`in_channel`]: super::InMemoryCachePermissions::in_channel
    /// [`root`]: super::InMemoryCachePermissions::root
    #[test]
    fn test_owner() -> Result<(), Box<dyn Error>> {
        let cache = InMemoryCache::new();
        let permissions = cache.permissions();
        cache.update(&GuildCreate(base_guild()));

        assert!(permissions.root(OWNER_ID, GUILD_ID)?.is_all());

        cache.update(&ChannelCreate(channel()));
        assert!(permissions.in_channel(OWNER_ID, CHANNEL_ID)?.is_all());

        Ok(())
    }
}
