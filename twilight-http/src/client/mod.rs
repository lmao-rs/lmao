mod builder;
mod connector;
mod interaction;

pub use self::{builder::ClientBuilder, interaction::InteractionClient};

use crate::request::{
    application::{
        emoji::{
            AddApplicationEmoji, DeleteApplicationEmoji, ListApplicationEmojis,
            UpdateApplicationEmoji,
        },
        monetization::{
            CreateTestEntitlement, CreateTestEntitlementOwner, DeleteTestEntitlement,
            GetEntitlements, GetSKUs,
        },
    },
    guild::user::{GetCurrentUserVoiceState, GetUserVoiceState},
};
#[allow(deprecated)]
use crate::{
    client::connector::Connector,
    error::{Error, ErrorType},
    request::{
        channel::{
            invite::{CreateInvite, DeleteInvite, GetChannelInvites, GetInvite},
            message::{
                CreateMessage, CrosspostMessage, DeleteMessage, DeleteMessages, GetChannelMessages,
                GetMessage, UpdateMessage,
            },
            reaction::{
                delete_reaction::TargetUser, CreateReaction, DeleteAllReaction, DeleteAllReactions,
                DeleteReaction, GetReactions, RequestReactionType,
            },
            stage::{
                CreateStageInstance, DeleteStageInstance, GetStageInstance, UpdateStageInstance,
            },
            thread::{
                AddThreadMember, CreateForumThread, CreateThread, CreateThreadFromMessage,
                GetJoinedPrivateArchivedThreads, GetPrivateArchivedThreads,
                GetPublicArchivedThreads, GetThreadMember, GetThreadMembers, JoinThread,
                LeaveThread, RemoveThreadMember, UpdateThread,
            },
            webhook::{
                CreateWebhook, DeleteWebhook, DeleteWebhookMessage, ExecuteWebhook,
                GetChannelWebhooks, GetWebhook, GetWebhookMessage, UpdateWebhook,
                UpdateWebhookMessage, UpdateWebhookWithToken,
            },
            CreatePin, CreateTypingTrigger, DeleteChannel, DeleteChannelPermission, DeletePin,
            FollowNewsChannel, GetChannel, GetPins, UpdateChannel, UpdateChannelPermission,
        },
        guild::{
            auto_moderation::{
                CreateAutoModerationRule, DeleteAutoModerationRule, GetAutoModerationRule,
                GetGuildAutoModerationRules, UpdateAutoModerationRule,
            },
            ban::{CreateBan, DeleteBan, GetBan, GetBans},
            emoji::{CreateEmoji, DeleteEmoji, GetEmoji, GetEmojis, UpdateEmoji},
            integration::{DeleteGuildIntegration, GetGuildIntegrations},
            member::{
                AddGuildMember, AddRoleToMember, GetGuildMembers, GetMember, RemoveMember,
                RemoveRoleFromMember, SearchGuildMembers, UpdateGuildMember,
            },
            role::{
                CreateRole, DeleteRole, GetGuildRoles, GetRole, UpdateRole, UpdateRolePositions,
            },
            sticker::{
                CreateGuildSticker, DeleteGuildSticker, GetGuildSticker, GetGuildStickers,
                UpdateGuildSticker,
            },
            update_guild_onboarding::{UpdateGuildOnboarding, UpdateGuildOnboardingFields},
            user::{UpdateCurrentUserVoiceState, UpdateUserVoiceState},
            CreateGuild, CreateGuildChannel, CreateGuildPrune, DeleteGuild, GetActiveThreads,
            GetAuditLog, GetGuild, GetGuildChannels, GetGuildInvites, GetGuildOnboarding,
            GetGuildPreview, GetGuildPruneCount, GetGuildVanityUrl, GetGuildVoiceRegions,
            GetGuildWebhooks, GetGuildWelcomeScreen, GetGuildWidget, GetGuildWidgetSettings,
            UpdateCurrentMember, UpdateGuild, UpdateGuildChannelPositions, UpdateGuildMfa,
            UpdateGuildWelcomeScreen, UpdateGuildWidgetSettings,
        },
        poll::{EndPoll, GetAnswerVoters},
        scheduled_event::{
            CreateGuildScheduledEvent, DeleteGuildScheduledEvent, GetGuildScheduledEvent,
            GetGuildScheduledEventUsers, GetGuildScheduledEvents, UpdateGuildScheduledEvent,
        },
        sticker::{GetNitroStickerPacks, GetSticker},
        template::{
            CreateGuildFromTemplate, CreateTemplate, DeleteTemplate, GetTemplate, GetTemplates,
            SyncTemplate, UpdateTemplate,
        },
        user::{
            CreatePrivateChannel, GetCurrentUser, GetCurrentUserConnections,
            GetCurrentUserGuildMember, GetCurrentUserGuilds, GetUser, LeaveGuild,
            UpdateCurrentUser,
        },
        GetCurrentAuthorizationInformation, GetGateway, GetUserApplicationInfo, GetVoiceRegions,
        Method, Request, UpdateCurrentUserApplication,
    },
    response::ResponseFuture,
    API_VERSION,
};
use http::header::{
    HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT,
};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client as HyperClient;
use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    ops::Deref,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::time;
use twilight_http_ratelimiting::RateLimiter;
use twilight_model::{
    channel::{message::AllowedMentions, ChannelType},
    guild::{
        auto_moderation::AutoModerationEventType, scheduled_event::PrivacyLevel, MfaLevel,
        RolePosition,
    },
    http::{channel_position::Position, permission_overwrite::PermissionOverwrite},
    id::{
        marker::{
            ApplicationMarker, AutoModerationRuleMarker, ChannelMarker, EmojiMarker,
            EntitlementMarker, GuildMarker, IntegrationMarker, MessageMarker, RoleMarker,
            ScheduledEventMarker, SkuMarker, StickerMarker, UserMarker, WebhookMarker,
        },
        Id,
    },
};

const TWILIGHT_USER_AGENT: &str = concat!(
    "DiscordBot (",
    env!("CARGO_PKG_HOMEPAGE"),
    ", ",
    env!("CARGO_PKG_VERSION"),
    ") Twilight-rs",
);

/// Wrapper for an authorization token with a debug implementation that redacts
/// the string.
#[derive(Default)]
struct Token {
    /// Authorization token that is redacted in the Debug implementation.
    inner: Box<str>,
}

impl Token {
    /// Create a new authorization wrapper.
    const fn new(token: Box<str>) -> Self {
        Self { inner: token }
    }
}

impl Debug for Token {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("<redacted>")
    }
}

impl Deref for Token {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Twilight's http client.
///
/// Almost all of the client methods require authentication, and as such, the client must be
/// supplied with a Discord Token. Get yours [here].
///
/// # Interactions
///
/// HTTP interaction requests may be accessed via the [`Client::interaction`]
/// method.
///
/// # OAuth2
///
/// To use Bearer tokens prefix the token with `"Bearer "`, including the space
/// at the end like so:
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::env;
/// use twilight_http::Client;
///
/// let bearer = env::var("BEARER_TOKEN")?;
/// let token = format!("Bearer {bearer}");
///
/// let client = Client::new(token);
/// # Ok(()) }
/// ```
///
/// # Using the client in multiple tasks
///
/// To use a client instance in multiple tasks, consider wrapping it in an
/// [`std::sync::Arc`] or [`std::rc::Rc`].
///
/// # Unauthorized behavior
///
/// When the client encounters an Unauthorized response it will take note that
/// the configured token is invalid. This may occur when the token has been
/// revoked or expired. When this happens, you must create a new client with the
/// new token. The client will no longer execute requests in order to
/// prevent API bans and will always return [`ErrorType::Unauthorized`].
///
/// # Examples
///
/// Create a client called `client`:
/// ```no_run
/// use twilight_http::Client;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = Client::new("my token".to_owned());
/// # Ok(()) }
/// ```
///
/// Use [`ClientBuilder`] to create a client called `client`, with a shorter
/// timeout:
/// ```no_run
/// use std::time::Duration;
/// use twilight_http::Client;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = Client::builder()
///     .token("my token".to_owned())
///     .timeout(Duration::from_secs(5))
///     .build();
/// # Ok(()) }
/// ```
///
/// All the examples on this page assume you have already created a client, and have named it
/// `client`.
///
/// [here]: https://discord.com/developers/applications
#[derive(Debug)]
pub struct Client {
    pub(crate) default_allowed_mentions: Option<AllowedMentions>,
    default_headers: Option<HeaderMap>,
    http: HyperClient<Connector, Full<Bytes>>,
    proxy: Option<Box<str>>,
    ratelimiter: Option<RateLimiter>,
    timeout: Duration,
    /// Whether the token has been invalidated.
    ///
    /// Whether an invalid token is tracked can be configured via
    /// [`ClientBuilder::remember_invalid_token`].
    token_invalidated: Option<Arc<AtomicBool>>,
    token: Option<Token>,
    use_http: bool,
}

impl Client {
    /// Create a new client with a token.
    pub fn new(token: String) -> Self {
        ClientBuilder::default().token(token).build()
    }

    /// Create a new builder to create a client.
    ///
    /// Refer to its documentation for more information.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Retrieve an immutable reference to the token used by the client.
    ///
    /// If the initial token provided is not prefixed with `Bot `, it will be, and this method
    /// reflects that.
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Create an interface for using interactions.
    ///
    /// An application ID is required to be passed in to use interactions. The
    /// ID may be retrieved via [`current_user_application`] and cached for use
    /// with this method.
    ///
    /// # Examples
    ///
    /// Retrieve the application ID and then use an interaction request:
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::env;
    /// use twilight_http::Client;
    ///
    /// let client = Client::new(env::var("DISCORD_TOKEN")?);
    ///
    /// // Cache the application ID for repeated use later in the process.
    /// let application_id = {
    ///     let response = client.current_user_application().await?;
    ///
    ///     response.model().await?.id
    /// };
    ///
    /// // Later in the process...
    /// let commands = client
    ///     .interaction(application_id)
    ///     .global_commands()
    ///     .await?
    ///     .models()
    ///     .await?;
    ///
    /// println!("there are {} global commands", commands.len());
    /// # Ok(()) }
    /// ```
    ///
    /// [`current_user_application`]: Self::current_user_application
    pub const fn interaction(
        &self,
        application_id: Id<ApplicationMarker>,
    ) -> InteractionClient<'_> {
        InteractionClient::new(self, application_id)
    }

    /// Get an immutable reference to the default [`AllowedMentions`] for sent
    /// messages.
    pub const fn default_allowed_mentions(&self) -> Option<&AllowedMentions> {
        self.default_allowed_mentions.as_ref()
    }

    /// Get an auto moderation rule in a guild.
    ///
    /// Requires the [`MANAGE_GUILD`] permission.
    ///
    /// [`MANAGE_GUILD`]: twilight_model::guild::Permissions::MANAGE_GUILD
    pub const fn auto_moderation_rule(
        &self,
        guild_id: Id<GuildMarker>,
        auto_moderation_rule_id: Id<AutoModerationRuleMarker>,
    ) -> GetAutoModerationRule<'_> {
        GetAutoModerationRule::new(self, guild_id, auto_moderation_rule_id)
    }

    /// Get the auto moderation rules in a guild.
    ///
    /// Requires the [`MANAGE_GUILD`] permission.
    ///
    /// [`MANAGE_GUILD`]: twilight_model::guild::Permissions::MANAGE_GUILD
    pub const fn auto_moderation_rules(
        &self,
        guild_id: Id<GuildMarker>,
    ) -> GetGuildAutoModerationRules<'_> {
        GetGuildAutoModerationRules::new(self, guild_id)
    }

    /// Create an auto moderation rule within a guild.
    ///
    /// Requires the [`MANAGE_GUILD`] permission.
    ///
    /// # Examples
    ///
    /// Create a rule that deletes messages that contain the word "darn":
    ///
    /// ```no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use twilight_http::Client;
    /// use twilight_model::{guild::auto_moderation::AutoModerationEventType, id::Id};
    ///
    /// let client = Client::new("my token".to_owned());
    ///
    /// let guild_id = Id::new(1);
    /// client
    ///     .create_auto_moderation_rule(guild_id, "no darns", AutoModerationEventType::MessageSend)
    ///     .action_block_message()
    ///     .enabled(true)
    ///     .with_keyword(&["darn"], &["d(?:4|a)rn"], &["darn it"])
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// [`MANAGE_GUILD`]: twilight_model::guild::Permissions::MANAGE_GUILD
    pub const fn create_auto_moderation_rule<'a>(
        &'a self,
        guild_id: Id<GuildMarker>,
        name: &'a str,
        event_type: AutoModerationEventType,
    ) -> CreateAutoModerationRule<'a> {
        CreateAutoModerationRule::new(self, guild_id, name, event_type)
    }

    /// Delete an auto moderation rule in a guild.
    ///
    /// Requires the [`MANAGE_GUILD`] permission.
    ///
    /// [`MANAGE_GUILD`]: twilight_model::guild::Permissions::MANAGE_GUILD
    pub const fn delete_auto_moderation_rule(
        &self,
        guild_id: Id<GuildMarker>,
        auto_moderation_rule_id: Id<AutoModerationRuleMarker>,
    ) -> DeleteAutoModerationRule<'_> {
        DeleteAutoModerationRule::new(self, guild_id, auto_moderation_rule_id)
    }

    /// Update an auto moderation rule in a guild.
    ///
    /// Requires the [`MANAGE_GUILD`] permission.
    ///
    /// [`MANAGE_GUILD`]: twilight_model::guild::Permissions::MANAGE_GUILD
    pub const fn update_auto_moderation_rule(
        &self,
        guild_id: Id<GuildMarker>,
        auto_moderation_rule_id: Id<AutoModerationRuleMarker>,
    ) -> UpdateAutoModerationRule<'_> {
        UpdateAutoModerationRule::new(self, guild_id, auto_moderation_rule_id)
    }

    /// Get the audit log for a guild.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("token".to_owned());
    /// let guild_id = Id::new(101);
    /// let audit_log = client.audit_log(guild_id).await?;
    /// # Ok(()) }
    /// ```
    pub const fn audit_log(&self, guild_id: Id<GuildMarker>) -> GetAuditLog<'_> {
        GetAuditLog::new(self, guild_id)
    }

    /// Retrieve the bans for a guild.
    ///
    /// # Examples
    ///
    /// Retrieve the bans for guild `1`:
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// use twilight_model::id::Id;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let guild_id = Id::new(1);
    ///
    /// let bans = client.bans(guild_id).await?;
    /// # Ok(()) }
    /// ```
    pub const fn bans(&self, guild_id: Id<GuildMarker>) -> GetBans<'_> {
        GetBans::new(self, guild_id)
    }

    /// Get information about a ban of a guild.
    ///
    /// Includes the user banned and the reason.
    pub const fn ban(&self, guild_id: Id<GuildMarker>, user_id: Id<UserMarker>) -> GetBan<'_> {
        GetBan::new(self, guild_id, user_id)
    }

    /// Bans a user from a guild, optionally with the number of seconds' worth of
    /// messages to delete and the reason.
    ///
    /// # Examples
    ///
    /// Ban user `200` from guild `100`, deleting
    /// `86_400` second's (this is equivalent to `1` day) worth of messages, for the reason `"memes"`:
    ///
    /// ```no_run
    /// # use twilight_http::{request::AuditLogReason, Client};
    /// use twilight_model::id::Id;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let guild_id = Id::new(100);
    /// let user_id = Id::new(200);
    /// client
    ///     .create_ban(guild_id, user_id)
    ///     .delete_message_seconds(86_400)
    ///     .reason("memes")
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub const fn create_ban(
        &self,
        guild_id: Id<GuildMarker>,
        user_id: Id<UserMarker>,
    ) -> CreateBan<'_> {
        CreateBan::new(self, guild_id, user_id)
    }

    /// Remove a ban from a user in a guild.
    ///
    /// # Examples
    ///
    /// Unban user `200` from guild `100`:
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// use twilight_model::id::Id;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let guild_id = Id::new(100);
    /// let user_id = Id::new(200);
    ///
    /// client.delete_ban(guild_id, user_id).await?;
    /// # Ok(()) }
    /// ```
    pub const fn delete_ban(
        &self,
        guild_id: Id<GuildMarker>,
        user_id: Id<UserMarker>,
    ) -> DeleteBan<'_> {
        DeleteBan::new(self, guild_id, user_id)
    }

    /// Get a channel by its ID.
    ///
    /// # Examples
    ///
    /// Get channel `100`:
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// # use twilight_model::id::Id;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let channel_id = Id::new(100);
    /// #
    /// let channel = client.channel(channel_id).await?;
    /// # Ok(()) }
    /// ```
    pub const fn channel(&self, channel_id: Id<ChannelMarker>) -> GetChannel<'_> {
        GetChannel::new(self, channel_id)
    }

    /// Delete a channel by ID.
    pub const fn delete_channel(&self, channel_id: Id<ChannelMarker>) -> DeleteChannel<'_> {
        DeleteChannel::new(self, channel_id)
    }

    /// Update a channel.
    pub const fn update_channel(&self, channel_id: Id<ChannelMarker>) -> UpdateChannel<'_> {
        UpdateChannel::new(self, channel_id)
    }

    /// Follows a news channel by [`Id<ChannelMarker>`].
    ///
    /// The type returned is [`FollowedChannel`].
    ///
    /// [`FollowedChannel`]: ::twilight_model::channel::FollowedChannel
    pub const fn follow_news_channel(
        &self,
        channel_id: Id<ChannelMarker>,
        webhook_channel_id: Id<ChannelMarker>,
    ) -> FollowNewsChannel<'_> {
        FollowNewsChannel::new(self, channel_id, webhook_channel_id)
    }

    /// Get the invites for a guild channel.
    ///
    /// Requires the [`MANAGE_CHANNELS`] permission. This method only works if
    /// the channel is a guild channel.
    ///
    /// [`MANAGE_CHANNELS`]: twilight_model::guild::Permissions::MANAGE_CHANNELS
    pub const fn channel_invites(&self, channel_id: Id<ChannelMarker>) -> GetChannelInvites<'_> {
        GetChannelInvites::new(self, channel_id)
    }

    /// Get channel messages, by [`Id<ChannelMarker>`].
    ///
    /// Only one of [`after`], [`around`], and [`before`] can be specified at a time.
    /// Once these are specified, the type returned is [`GetChannelMessagesConfigured`].
    ///
    /// If [`limit`] is unspecified, the default set by Discord is 50.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    /// let channel_id = Id::new(123);
    /// let message_id = Id::new(234);
    /// let limit: u16 = 6;
    ///
    /// let messages = client
    ///     .channel_messages(channel_id)
    ///     .before(message_id)
    ///     .limit(limit)
    ///     .await?;
    ///
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error of type [`ValidationErrorType::GetChannelMessages`] if
    /// the amount is less than 1 or greater than 100.
    ///
    /// [`GetChannelMessagesConfigured`]: crate::request::channel::message::GetChannelMessagesConfigured
    /// [`ValidationErrorType::GetChannelMessages`]: twilight_validate::request::ValidationErrorType::GetChannelMessages
    /// [`after`]: GetChannelMessages::after
    /// [`around`]: GetChannelMessages::around
    /// [`before`]: GetChannelMessages::before
    /// [`limit`]: GetChannelMessages::limit
    pub const fn channel_messages(&self, channel_id: Id<ChannelMarker>) -> GetChannelMessages<'_> {
        GetChannelMessages::new(self, channel_id)
    }

    pub const fn delete_channel_permission(
        &self,
        channel_id: Id<ChannelMarker>,
    ) -> DeleteChannelPermission<'_> {
        DeleteChannelPermission::new(self, channel_id)
    }

    /// Update the permissions for a role or a user in a channel.
    ///
    /// # Examples:
    ///
    /// Create permission overrides for a role to view the channel, but not send
    /// messages:
    ///
    /// ```no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # use twilight_http::Client;
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// use twilight_model::{
    ///     guild::Permissions,
    ///     http::permission_overwrite::{PermissionOverwrite, PermissionOverwriteType},
    ///     id::{marker::RoleMarker, Id},
    /// };
    ///
    /// let channel_id = Id::new(123);
    /// let role_id: Id<RoleMarker> = Id::new(432);
    /// let permission_overwrite = PermissionOverwrite {
    ///     allow: Some(Permissions::VIEW_CHANNEL),
    ///     deny: Some(Permissions::SEND_MESSAGES),
    ///     id: role_id.cast(),
    ///     kind: PermissionOverwriteType::Role,
    /// };
    ///
    /// client
    ///     .update_channel_permission(channel_id, &permission_overwrite)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub const fn update_channel_permission(
        &self,
        channel_id: Id<ChannelMarker>,
        permission_overwrite: &PermissionOverwrite,
    ) -> UpdateChannelPermission<'_> {
        UpdateChannelPermission::new(self, channel_id, permission_overwrite)
    }

    /// Get all the webhooks of a channel.
    pub const fn channel_webhooks(&self, channel_id: Id<ChannelMarker>) -> GetChannelWebhooks<'_> {
        GetChannelWebhooks::new(self, channel_id)
    }

    /// Get information about the current user.
    pub const fn current_user(&self) -> GetCurrentUser<'_> {
        GetCurrentUser::new(self)
    }

    /// Get information about the current user in a guild.
    pub const fn current_user_guild_member(
        &self,
        guild_id: Id<GuildMarker>,
    ) -> GetCurrentUserGuildMember<'_> {
        GetCurrentUserGuildMember::new(self, guild_id)
    }

    /// Get information about the current OAuth2 authorization.
    pub const fn current_authorization(&self) -> GetCurrentAuthorizationInformation<'_> {
        GetCurrentAuthorizationInformation::new(self)
    }

    /// Get information about the current bot application.
    pub const fn current_user_application(&self) -> GetUserApplicationInfo<'_> {
        GetUserApplicationInfo::new(self)
    }

    /// Update the current user's application.
    pub const fn update_current_user_application(&self) -> UpdateCurrentUserApplication<'_> {
        UpdateCurrentUserApplication::new(self)
    }

    /// Update the current user.
    ///
    /// All parameters are optional. If the username is changed, it may cause the discriminator to
    /// be randomized.
    pub const fn update_current_user(&self) -> UpdateCurrentUser<'_> {
        UpdateCurrentUser::new(self)
    }

    /// Get voice state of the current user in a guild.
    ///
    /// # Caveats
    ///
    /// - Current user must already have joined a voice/stage channel in this guild.
    pub const fn current_user_voice_state(
        &self,
        guild_id: Id<GuildMarker>,
    ) -> GetCurrentUserVoiceState<'_> {
        GetCurrentUserVoiceState::new(self, guild_id)
    }

    /// Update the current user's voice state.
    ///
    /// All parameters are optional.
    ///
    /// # Caveats
    ///
    /// - `channel_id` must currently point to a stage channel.
    /// - Current user must have already joined `channel_id`.
    pub const fn update_current_user_voice_state(
        &self,
        guild_id: Id<GuildMarker>,
    ) -> UpdateCurrentUserVoiceState<'_> {
        UpdateCurrentUserVoiceState::new(self, guild_id)
    }

    /// Get the current user's connections.
    ///
    /// Requires the `connections` `OAuth2` scope.
    pub const fn current_user_connections(&self) -> GetCurrentUserConnections<'_> {
        GetCurrentUserConnections::new(self)
    }

    /// Returns a list of guilds for the current user.
    ///
    /// # Examples
    ///
    /// Get the first 25 guilds with an ID after `300` and before
    /// `400`:
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let after = Id::new(300);
    /// let before = Id::new(400);
    /// let guilds = client
    ///     .current_user_guilds()
    ///     .after(after)
    ///     .before(before)
    ///     .limit(25)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub const fn current_user_guilds(&self) -> GetCurrentUserGuilds<'_> {
        GetCurrentUserGuilds::new(self)
    }

    /// Get the emojis for a guild, by the guild's id.
    ///
    /// # Examples
    ///
    /// Get the emojis for guild `100`:
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// # use twilight_model::id::Id;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let guild_id = Id::new(100);
    ///
    /// client.emojis(guild_id).await?;
    /// # Ok(()) }
    /// ```
    pub const fn emojis(&self, guild_id: Id<GuildMarker>) -> GetEmojis<'_> {
        GetEmojis::new(self, guild_id)
    }

    /// Get the entitlements for an application.
    ///
    /// # Examples
    ///
    /// Get emojis for the application `100`:
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// # use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let application_id = Id::new(100);
    ///
    /// client.entitlements(application_id).await?;
    /// # Ok(()) }
    /// ```
    pub const fn entitlements(&self, application_id: Id<ApplicationMarker>) -> GetEntitlements<'_> {
        GetEntitlements::new(self, application_id)
    }

    /// Get an emoji for a guild by the the guild's ID and emoji's ID.
    ///
    /// # Examples
    ///
    /// Get emoji `100` from guild `50`:
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// # use twilight_model::id::Id;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let guild_id = Id::new(50);
    /// let emoji_id = Id::new(100);
    ///
    /// client.emoji(guild_id, emoji_id).await?;
    /// # Ok(()) }
    /// ```
    pub const fn emoji(
        &self,
        guild_id: Id<GuildMarker>,
        emoji_id: Id<EmojiMarker>,
    ) -> GetEmoji<'_> {
        GetEmoji::new(self, guild_id, emoji_id)
    }

    /// Create an emoji in a guild.
    ///
    /// The emoji must be a Data URI, in the form of
    /// `data:image/{type};base64,{data}` where `{type}` is the image MIME type
    /// and `{data}` is the base64-encoded image. See [Discord Docs/Image Data].
    ///
    /// [Discord Docs/Image Data]: https://discord.com/developers/docs/reference#image-data
    pub const fn create_emoji<'a>(
        &'a self,
        guild_id: Id<GuildMarker>,
        name: &'a str,
        image: &'a str,
    ) -> CreateEmoji<'a> {
        CreateEmoji::new(self, guild_id, name, image)
    }

    /// Delete an emoji in a guild, by id.
    pub const fn delete_emoji(
        &self,
        guild_id: Id<GuildMarker>,
        emoji_id: Id<EmojiMarker>,
    ) -> DeleteEmoji<'_> {
        DeleteEmoji::new(self, guild_id, emoji_id)
    }

    /// Update an emoji in a guild, by id.
    pub const fn update_emoji(
        &self,
        guild_id: Id<GuildMarker>,
        emoji_id: Id<EmojiMarker>,
    ) -> UpdateEmoji<'_> {
        UpdateEmoji::new(self, guild_id, emoji_id)
    }

    /// Get information about the gateway, optionally with additional information detailing the
    /// number of shards to use and sessions remaining.
    ///
    /// # Examples
    ///
    /// Get the gateway connection URL without bot information:
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let info = client.gateway().await?;
    /// # Ok(()) }
    /// ```
    ///
    /// Get the gateway connection URL with additional shard and session information, which
    /// requires specifying a bot token:
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let info = client.gateway().authed().await?.model().await?;
    ///
    /// println!("URL: {}", info.url);
    /// println!("Recommended shards to use: {}", info.shards);
    /// # Ok(()) }
    /// ```
    pub const fn gateway(&self) -> GetGateway<'_> {
        GetGateway::new(self)
    }

    /// Get information about a guild.
    pub const fn guild(&self, guild_id: Id<GuildMarker>) -> GetGuild<'_> {
        GetGuild::new(self, guild_id)
    }

    /// Create a new request to create a guild.
    ///
    /// The minimum length of the name is 2 UTF-16 characters and the maximum is 100 UTF-16
    /// characters. This endpoint can only be used by bots in less than 10 guilds.
    ///
    /// # Errors
    ///
    /// Returns a [`CreateGuildErrorType::NameInvalid`] error type if the name
    /// length is too short or too long.
    ///
    /// [`CreateGuildErrorType::NameInvalid`]: crate::request::guild::create_guild::CreateGuildErrorType::NameInvalid
    pub fn create_guild(&self, name: String) -> CreateGuild<'_> {
        CreateGuild::new(self, name)
    }

    /// Delete a guild permanently. The user must be the owner.
    pub const fn delete_guild(&self, guild_id: Id<GuildMarker>) -> DeleteGuild<'_> {
        DeleteGuild::new(self, guild_id)
    }

    /// Update a guild.
    ///
    /// All endpoints are optional. See [Discord Docs/Modify Guild].
    ///
    /// [Discord Docs/Modify Guild]: https://discord.com/developers/docs/resources/guild#modify-guild
    pub const fn update_guild(&self, guild_id: Id<GuildMarker>) -> UpdateGuild<'_> {
        UpdateGuild::new(self, guild_id)
    }

    /// Leave a guild by id.
    pub const fn leave_guild(&self, guild_id: Id<GuildMarker>) -> LeaveGuild<'_> {
        LeaveGuild::new(self, guild_id)
    }

    /// Get the channels in a guild.
    pub const fn guild_channels(&self, guild_id: Id<GuildMarker>) -> GetGuildChannels<'_> {
        GetGuildChannels::new(self, guild_id)
    }

    /// Create a new request to create a guild channel.
    ///
    /// All fields are optional except for name. The minimum length of the name
    /// is 1 UTF-16 character and the maximum is 100 UTF-16 characters.
    ///
    /// # Errors
    ///
    /// Returns an error of type [`NameInvalid`] when the length of the name is
    /// either fewer than 1 UTF-16 character or more than 100 UTF-16 characters.
    ///
    /// Returns an error of type [`RateLimitPerUserInvalid`] when the seconds of
    /// the rate limit per user is more than 21600.
    ///
    /// Returns an error of type [`TopicInvalid`] when the length of the topic
    /// is more than 1024 UTF-16 characters.
    ///
    /// [`NameInvalid`]: twilight_validate::channel::ChannelValidationErrorType::NameInvalid
    /// [`RateLimitPerUserInvalid`]: twilight_validate::channel::ChannelValidationErrorType::RateLimitPerUserInvalid
    /// [`TopicInvalid`]: twilight_validate::channel::ChannelValidationErrorType::TopicInvalid
    pub fn create_guild_channel<'a>(
        &'a self,
        guild_id: Id<GuildMarker>,
        name: &'a str,
    ) -> CreateGuildChannel<'a> {
        CreateGuildChannel::new(self, guild_id, name)
    }

    /// Modify the guild onboarding flow.
    pub const fn update_guild_onboarding(
        &self,
        guild_id: Id<GuildMarker>,
        fields: UpdateGuildOnboardingFields,
    ) -> UpdateGuildOnboarding {
        UpdateGuildOnboarding::new(self, guild_id, fields)
    }

    /// Modify the positions of the channels.
    ///
    /// The minimum amount of channels to modify, is a swap between two channels.
    pub const fn update_guild_channel_positions<'a>(
        &'a self,
        guild_id: Id<GuildMarker>,
        channel_positions: &'a [Position],
    ) -> UpdateGuildChannelPositions<'a> {
        UpdateGuildChannelPositions::new(self, guild_id, channel_positions)
    }

    /// Get a guild's widget.
    ///
    /// See [Discord Docs/Get Guild Widget].
    ///
    /// [Discord Docs/Get Guild Widget]: https://discord.com/developers/docs/resources/guild#get-guild-widget
    pub const fn guild_widget(&self, guild_id: Id<GuildMarker>) -> GetGuildWidget<'_> {
        GetGuildWidget::new(self, guild_id)
    }

    /// Get a guild's widget settings.
    ///
    /// See [Discord Docs/Get Guild Widget Settings].
    ///
    /// [Discord Docs/Get Guild Widget]: https://discord.com/developers/docs/resources/guild#get-guild-widget-settings
    pub const fn guild_widget_settings(
        &self,
        guild_id: Id<GuildMarker>,
    ) -> GetGuildWidgetSettings<'_> {
        GetGuildWidgetSettings::new(self, guild_id)
    }

    /// Modify a guild's widget.
    ///
    /// See [Discord Docs/Modify Guild Widget].
    ///
    /// [Discord Docs/Modify Guild Widget]: https://discord.com/developers/docs/resources/guild#modify-guild-widget
    pub const fn update_guild_widget_settings(
        &self,
        guild_id: Id<GuildMarker>,
    ) -> UpdateGuildWidgetSettings<'_> {
        UpdateGuildWidgetSettings::new(self, guild_id)
    }

    /// Get the guild's integrations.
    pub const fn guild_integrations(&self, guild_id: Id<GuildMarker>) -> GetGuildIntegrations<'_> {
        GetGuildIntegrations::new(self, guild_id)
    }

    /// Delete an integration for a guild, by the integration's id.
    pub const fn delete_guild_integration(
        &self,
        guild_id: Id<GuildMarker>,
        integration_id: Id<IntegrationMarker>,
    ) -> DeleteGuildIntegration<'_> {
        DeleteGuildIntegration::new(self, guild_id, integration_id)
    }

    /// Get information about the invites of a guild.
    ///
    /// Requires the [`MANAGE_GUILD`] permission.
    ///
    /// [`MANAGE_GUILD`]: twilight_model::guild::Permissions::MANAGE_GUILD
    pub const fn guild_invites(&self, guild_id: Id<GuildMarker>) -> GetGuildInvites<'_> {
        GetGuildInvites::new(self, guild_id)
    }

    /// Update a guild's MFA level.
    pub const fn update_guild_mfa(
        &self,
        guild_id: Id<GuildMarker>,
        level: MfaLevel,
    ) -> UpdateGuildMfa<'_> {
        UpdateGuildMfa::new(self, guild_id, level)
    }

    /// Get the members of a guild, by id.
    ///
    /// The upper limit to this request is 1000. If more than 1000 members are needed, the requests
    /// must be chained. Discord defaults the limit to 1.
    ///
    /// # Examples
    ///
    /// Get the first 500 members of guild `100` after user ID `3000`:
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// use twilight_model::id::Id;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let guild_id = Id::new(100);
    /// let user_id = Id::new(3000);
    /// let members = client
    ///     .guild_members(guild_id)
    ///     .after(user_id)
    ///     .limit(500)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error of type [`ValidationErrorType::GetGuildMembers`] if the
    /// limit is invalid.
    ///
    /// [`ValidationErrorType::GetGuildMembers`]: twilight_validate::request::ValidationErrorType::GetGuildMembers
    pub const fn guild_members(&self, guild_id: Id<GuildMarker>) -> GetGuildMembers<'_> {
        GetGuildMembers::new(self, guild_id)
    }

    /// Search the members of a specific guild by a query.
    ///
    /// The upper limit to this request is 1000. Discord defaults the limit to 1.
    ///
    /// # Examples
    ///
    /// Get the first 10 members of guild `100` matching `Wumpus`:
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let guild_id = Id::new(100);
    /// let members = client
    ///     .search_guild_members(guild_id, "Wumpus")
    ///     .limit(10)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error of type [`ValidationErrorType::SearchGuildMembers`] if
    /// the limit is invalid.
    ///
    /// [`GUILD_MEMBERS`]: twilight_model::gateway::Intents::GUILD_MEMBERS
    /// [`ValidationErrorType::SearchGuildMembers`]: twilight_validate::request::ValidationErrorType::SearchGuildMembers
    pub const fn search_guild_members<'a>(
        &'a self,
        guild_id: Id<GuildMarker>,
        query: &'a str,
    ) -> SearchGuildMembers<'a> {
        SearchGuildMembers::new(self, guild_id, query)
    }

    /// Get a member of a guild, by their id.
    pub const fn guild_member(
        &self,
        guild_id: Id<GuildMarker>,
        user_id: Id<UserMarker>,
    ) -> GetMember<'_> {
        GetMember::new(self, guild_id, user_id)
    }

    /// Add a user to a guild.
    ///
    /// An access token for the user with `guilds.join` scope is required. All
    /// other fields are optional. See [Discord Docs/Add Guild Member].
    ///
    /// # Errors
    ///
    /// Returns an error of type [`ValidationErrorType::Nickname`] if the
    /// nickname is too short or too long.
    ///
    /// [`ValidationErrorType::Nickname`]: twilight_validate::request::ValidationErrorType::Nickname
    /// [Discord Docs/Add Guild Member]: https://discord.com/developers/docs/resources/guild#add-guild-member
    pub const fn add_guild_member<'a>(
        &'a self,
        guild_id: Id<GuildMarker>,
        user_id: Id<UserMarker>,
        access_token: &'a str,
    ) -> AddGuildMember<'a> {
        AddGuildMember::new(self, guild_id, user_id, access_token)
    }

    /// Kick a member from a guild.
    pub const fn remove_guild_member(
        &self,
        guild_id: Id<GuildMarker>,
        user_id: Id<UserMarker>,
    ) -> RemoveMember<'_> {
        RemoveMember::new(self, guild_id, user_id)
    }

    /// Update a guild member.
    ///
    /// All fields are optional. See [Discord Docs/Modify Guild Member].
    ///
    /// # Examples
    ///
    /// Update a member's nickname to "pinky pie" and server mute them:
    ///
    /// ```no_run
    /// use std::env;
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new(env::var("DISCORD_TOKEN")?);
    /// let member = client
    ///     .update_guild_member(Id::new(1), Id::new(2))
    ///     .mute(true)
    ///     .nick(Some("pinkie pie"))
    ///     .await?
    ///     .model()
    ///     .await?;
    ///
    /// println!(
    ///     "user {} now has the nickname '{:?}'",
    ///     member.user.id, member.nick,
    /// );
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error of type [`ValidationErrorType::Nickname`] if the
    /// nickname length is too short or too long.
    ///
    /// [`ValidationErrorType::Nickname`]: twilight_validate::request::ValidationErrorType::Nickname
    /// [Discord Docs/Modify Guild Member]: https://discord.com/developers/docs/resources/guild#modify-guild-member
    pub const fn update_guild_member(
        &self,
        guild_id: Id<GuildMarker>,
        user_id: Id<UserMarker>,
    ) -> UpdateGuildMember<'_> {
        UpdateGuildMember::new(self, guild_id, user_id)
    }

    /// Update the user's member in a guild.
    pub const fn update_current_member(
        &self,
        guild_id: Id<GuildMarker>,
    ) -> UpdateCurrentMember<'_> {
        UpdateCurrentMember::new(self, guild_id)
    }

    /// Add a role to a member in a guild.
    ///
    /// # Examples
    ///
    /// In guild `1`, add role `2` to user `3`, for the reason `"test"`:
    ///
    /// ```no_run
    /// # use twilight_http::{request::AuditLogReason, Client};
    /// use twilight_model::id::Id;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let guild_id = Id::new(1);
    /// let role_id = Id::new(2);
    /// let user_id = Id::new(3);
    ///
    /// client
    ///     .add_guild_member_role(guild_id, user_id, role_id)
    ///     .reason("test")
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub const fn add_guild_member_role(
        &self,
        guild_id: Id<GuildMarker>,
        user_id: Id<UserMarker>,
        role_id: Id<RoleMarker>,
    ) -> AddRoleToMember<'_> {
        AddRoleToMember::new(self, guild_id, user_id, role_id)
    }

    /// Remove a role from a member in a guild, by id.
    pub const fn remove_guild_member_role(
        &self,
        guild_id: Id<GuildMarker>,
        user_id: Id<UserMarker>,
        role_id: Id<RoleMarker>,
    ) -> RemoveRoleFromMember<'_> {
        RemoveRoleFromMember::new(self, guild_id, user_id, role_id)
    }

    /// Retrieves the onboarding data for a guild.
    pub const fn guild_onboarding(&self, guild_id: Id<GuildMarker>) -> GetGuildOnboarding<'_> {
        GetGuildOnboarding::new(self, guild_id)
    }

    /// For public guilds, get the guild preview.
    ///
    /// This works even if the user is not in the guild.
    pub const fn guild_preview(&self, guild_id: Id<GuildMarker>) -> GetGuildPreview<'_> {
        GetGuildPreview::new(self, guild_id)
    }

    /// Get the counts of guild members to be pruned.
    pub const fn guild_prune_count(&self, guild_id: Id<GuildMarker>) -> GetGuildPruneCount<'_> {
        GetGuildPruneCount::new(self, guild_id)
    }

    /// Begin a guild prune.
    ///
    /// See [Discord Docs/Begin Guild Prune].
    ///
    /// [Discord Docs/Begin Guild Prune]: https://discord.com/developers/docs/resources/guild#begin-guild-prune
    pub const fn create_guild_prune(&self, guild_id: Id<GuildMarker>) -> CreateGuildPrune<'_> {
        CreateGuildPrune::new(self, guild_id)
    }

    /// Get a guild's vanity url, if there is one.
    pub const fn guild_vanity_url(&self, guild_id: Id<GuildMarker>) -> GetGuildVanityUrl<'_> {
        GetGuildVanityUrl::new(self, guild_id)
    }

    /// Get voice region data for the guild.
    ///
    /// Can return VIP servers if the guild is VIP-enabled.
    pub const fn guild_voice_regions(&self, guild_id: Id<GuildMarker>) -> GetGuildVoiceRegions<'_> {
        GetGuildVoiceRegions::new(self, guild_id)
    }

    /// Get the webhooks of a guild.
    pub const fn guild_webhooks(&self, guild_id: Id<GuildMarker>) -> GetGuildWebhooks<'_> {
        GetGuildWebhooks::new(self, guild_id)
    }

    /// Get the guild's welcome screen.
    ///
    /// If the welcome screen is not enabled, this requires the [`MANAGE_GUILD`]
    /// permission.
    ///
    /// [`MANAGE_GUILD`]: twilight_model::guild::Permissions::MANAGE_GUILD
    pub const fn guild_welcome_screen(
        &self,
        guild_id: Id<GuildMarker>,
    ) -> GetGuildWelcomeScreen<'_> {
        GetGuildWelcomeScreen::new(self, guild_id)
    }

    /// Update the guild's welcome screen.
    ///
    /// Requires the [`MANAGE_GUILD`] permission.
    ///
    /// [`MANAGE_GUILD`]: twilight_model::guild::Permissions::MANAGE_GUILD
    pub const fn update_guild_welcome_screen(
        &self,
        guild_id: Id<GuildMarker>,
    ) -> UpdateGuildWelcomeScreen<'_> {
        UpdateGuildWelcomeScreen::new(self, guild_id)
    }

    /// Get information about an invite by its code.
    ///
    /// If [`with_counts`] is called, the returned invite will contain
    /// approximate member counts.  If [`with_expiration`] is called, it will
    /// contain the expiration date.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let invite = client.invite("code").with_counts().await?;
    /// # Ok(()) }
    /// ```
    ///
    /// [`with_counts`]: crate::request::channel::invite::GetInvite::with_counts
    /// [`with_expiration`]: crate::request::channel::invite::GetInvite::with_expiration
    pub const fn invite<'a>(&'a self, code: &'a str) -> GetInvite<'a> {
        GetInvite::new(self, code)
    }

    /// Create an invite, with options.
    ///
    /// Requires the [`CREATE_INVITE`] permission.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// # use twilight_model::id::Id;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let channel_id = Id::new(123);
    /// let invite = client.create_invite(channel_id).max_uses(3).await?;
    /// # Ok(()) }
    /// ```
    ///
    /// [`CREATE_INVITE`]: twilight_model::guild::Permissions::CREATE_INVITE
    pub const fn create_invite(&self, channel_id: Id<ChannelMarker>) -> CreateInvite<'_> {
        CreateInvite::new(self, channel_id)
    }

    /// Delete an invite by its code.
    ///
    /// Requires the [`MANAGE_CHANNELS`] permission on the channel this invite
    /// belongs to, or [`MANAGE_GUILD`] to remove any invite across the guild.
    ///
    /// [`MANAGE_CHANNELS`]: twilight_model::guild::Permissions::MANAGE_CHANNELS
    /// [`MANAGE_GUILD`]: twilight_model::guild::Permissions::MANAGE_GUILD
    pub const fn delete_invite<'a>(&'a self, code: &'a str) -> DeleteInvite<'a> {
        DeleteInvite::new(self, code)
    }

    /// Get a message by [`Id<ChannelMarker>`] and [`Id<MessageMarker>`].
    pub const fn message(
        &self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
    ) -> GetMessage<'_> {
        GetMessage::new(self, channel_id, message_id)
    }

    /// Send a message to a channel.
    ///
    /// The message must include at least one of [`attachments`],
    /// [`components`], [`content`], [`embeds`], or [`sticker_ids`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// let client = Client::new("my token".to_owned());
    ///
    /// let channel_id = Id::new(123);
    /// let message = client
    ///     .create_message(channel_id)
    ///     .content("Twilight is best pony")
    ///     .tts(true)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// [`attachments`]: CreateMessage::attachments
    /// [`components`]: CreateMessage::components
    /// [`content`]: CreateMessage::content
    /// [`embeds`]: CreateMessage::embeds
    /// [`sticker_ids`]: CreateMessage::sticker_ids
    pub const fn create_message(&self, channel_id: Id<ChannelMarker>) -> CreateMessage<'_> {
        CreateMessage::new(self, channel_id)
    }

    /// Delete a message by [`Id<ChannelMarker>`] and [`Id<MessageMarker>`].
    pub const fn delete_message(
        &self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
    ) -> DeleteMessage<'_> {
        DeleteMessage::new(self, channel_id, message_id)
    }

    /// Delete messages by [`Id<ChannelMarker>`] and Vec<[`Id<MessageMarker>`]>.
    ///
    /// The vec count can be between 2 and 100. If the supplied
    /// [`Id<MessageMarker>`]s are invalid, they still count towards the lower
    /// and upper limits. This method will not delete messages older than two
    /// weeks. See [Discord Docs/Bulk Delete Messages].
    ///
    /// # Errors
    ///
    /// Returns an error of type
    /// [`ChannelValidationErrorType::BulkDeleteMessagesInvalid`] when the number of
    /// messages to delete in bulk is invalid.
    ///
    /// [Discord Docs/Bulk Delete Messages]: https://discord.com/developers/docs/resources/channel#bulk-delete-messages
    /// [`ChannelValidationErrorType::BulkDeleteMessagesInvalid`]: twilight_validate::channel::ChannelValidationErrorType::BulkDeleteMessagesInvalid
    pub fn delete_messages<'a>(
        &'a self,
        channel_id: Id<ChannelMarker>,
        message_ids: &'a [Id<MessageMarker>],
    ) -> DeleteMessages<'a> {
        DeleteMessages::new(self, channel_id, message_ids)
    }

    /// Update a message by [`Id<ChannelMarker>`] and [`Id<MessageMarker>`].
    ///
    /// You can pass [`None`] to any of the methods to remove the associated
    /// field. Pass [`None`] to [`content`] to remove the content. You must
    /// ensure that the message still contains at least one of [`attachments`],
    /// [`components`], [`content`], [`embeds`], or stickers.
    ///
    /// # Examples
    ///
    /// Replace the content with `"test update"`:
    ///
    /// ```no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// let client = Client::new("my token".to_owned());
    /// client
    ///     .update_message(Id::new(1), Id::new(2))
    ///     .content(Some("test update"))
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// Remove the message's content:
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// # use twilight_model::id::Id;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// client
    ///     .update_message(Id::new(1), Id::new(2))
    ///     .content(None)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// [`attachments`]: UpdateMessage::attachments
    /// [`components`]: UpdateMessage::components
    /// [`content`]: UpdateMessage::content
    /// [`embeds`]: UpdateMessage::embeds
    pub const fn update_message(
        &self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
    ) -> UpdateMessage<'_> {
        UpdateMessage::new(self, channel_id, message_id)
    }

    /// Crosspost a message by [`Id<ChannelMarker>`] and [`Id<MessageMarker>`].
    pub const fn crosspost_message(
        &self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
    ) -> CrosspostMessage<'_> {
        CrosspostMessage::new(self, channel_id, message_id)
    }

    /// Get the pins of a channel.
    pub const fn pins(&self, channel_id: Id<ChannelMarker>) -> GetPins<'_> {
        GetPins::new(self, channel_id)
    }

    /// Create a new pin in a channel, by ID.
    pub const fn create_pin(
        &self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
    ) -> CreatePin<'_> {
        CreatePin::new(self, channel_id, message_id)
    }

    /// Delete a pin in a channel, by ID.
    pub const fn delete_pin(
        &self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
    ) -> DeletePin<'_> {
        DeletePin::new(self, channel_id, message_id)
    }

    /// Get a list of users that reacted to a message with an `emoji`.
    ///
    /// This endpoint is limited to 100 users maximum, so if a message has more than 100 reactions,
    /// requests must be chained until all reactions are retrieved.
    pub const fn reactions<'a>(
        &'a self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
        emoji: &'a RequestReactionType<'a>,
    ) -> GetReactions<'a> {
        GetReactions::new(self, channel_id, message_id, emoji)
    }

    /// Create a reaction in a [`Id<ChannelMarker>`] on a [`Id<MessageMarker>`].
    ///
    /// The reaction must be a variant of [`RequestReactionType`].
    ///
    /// # Examples
    /// ```no_run
    /// # use twilight_http::{Client, request::channel::reaction::RequestReactionType};
    /// # use twilight_model::id::Id;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// #
    /// let channel_id = Id::new(123);
    /// let message_id = Id::new(456);
    /// let emoji = RequestReactionType::Unicode { name: "🌃" };
    ///
    /// let reaction = client
    ///     .create_reaction(channel_id, message_id, &emoji)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub const fn create_reaction<'a>(
        &'a self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
        emoji: &'a RequestReactionType<'a>,
    ) -> CreateReaction<'a> {
        CreateReaction::new(self, channel_id, message_id, emoji)
    }

    /// Delete the current user's (`@me`) reaction on a message.
    pub const fn delete_current_user_reaction<'a>(
        &'a self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
        emoji: &'a RequestReactionType<'a>,
    ) -> DeleteReaction<'a> {
        DeleteReaction::new(self, channel_id, message_id, emoji, TargetUser::Current)
    }

    /// Delete a reaction by a user on a message.
    pub const fn delete_reaction<'a>(
        &'a self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
        emoji: &'a RequestReactionType<'a>,
        user_id: Id<UserMarker>,
    ) -> DeleteReaction<'a> {
        DeleteReaction::new(self, channel_id, message_id, emoji, TargetUser::Id(user_id))
    }

    /// Remove all reactions on a message of an emoji.
    pub const fn delete_all_reaction<'a>(
        &'a self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
        emoji: &'a RequestReactionType<'a>,
    ) -> DeleteAllReaction<'a> {
        DeleteAllReaction::new(self, channel_id, message_id, emoji)
    }

    /// Delete all reactions by all users on a message.
    pub const fn delete_all_reactions(
        &self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
    ) -> DeleteAllReactions<'_> {
        DeleteAllReactions::new(self, channel_id, message_id)
    }

    /// Fire a Typing Start event in the channel.
    pub const fn create_typing_trigger(
        &self,
        channel_id: Id<ChannelMarker>,
    ) -> CreateTypingTrigger<'_> {
        CreateTypingTrigger::new(self, channel_id)
    }

    /// Create a DM channel with a user.
    pub const fn create_private_channel(
        &self,
        recipient_id: Id<UserMarker>,
    ) -> CreatePrivateChannel<'_> {
        CreatePrivateChannel::new(self, recipient_id)
    }

    /// Get the roles of a guild.
    pub const fn roles(&self, guild_id: Id<GuildMarker>) -> GetGuildRoles<'_> {
        GetGuildRoles::new(self, guild_id)
    }

    /// Get a role of a guild.
    pub const fn role(&self, guild_id: Id<GuildMarker>, role_id: Id<RoleMarker>) -> GetRole<'_> {
        GetRole::new(self, guild_id, role_id)
    }

    /// Create a role in a guild.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// let guild_id = Id::new(234);
    ///
    /// client
    ///     .create_role(guild_id)
    ///     .color(0xd90083)
    ///     .name("Bright Pink")
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub const fn create_role(&self, guild_id: Id<GuildMarker>) -> CreateRole<'_> {
        CreateRole::new(self, guild_id)
    }

    /// Delete a role in a guild, by id.
    pub const fn delete_role(
        &self,
        guild_id: Id<GuildMarker>,
        role_id: Id<RoleMarker>,
    ) -> DeleteRole<'_> {
        DeleteRole::new(self, guild_id, role_id)
    }

    /// Update a role by guild id and its id.
    pub const fn update_role(
        &self,
        guild_id: Id<GuildMarker>,
        role_id: Id<RoleMarker>,
    ) -> UpdateRole<'_> {
        UpdateRole::new(self, guild_id, role_id)
    }

    /// Modify the position of the roles.
    ///
    /// The minimum amount of roles to modify, is a swap between two roles.
    pub const fn update_role_positions<'a>(
        &'a self,
        guild_id: Id<GuildMarker>,
        roles: &'a [RolePosition],
    ) -> UpdateRolePositions<'a> {
        UpdateRolePositions::new(self, guild_id, roles)
    }

    /// Create a new stage instance associated with a stage channel.
    ///
    /// Requires the user to be a moderator of the stage channel.
    ///
    /// # Errors
    ///
    /// Returns an error of type [`ValidationError::StageTopic`] when the topic
    /// is not between 1 and 120 characters in length.
    ///
    /// [`ValidationError::StageTopic`]: twilight_validate::request::ValidationErrorType::StageTopic
    pub fn create_stage_instance<'a>(
        &'a self,
        channel_id: Id<ChannelMarker>,
        topic: &'a str,
    ) -> CreateStageInstance<'a> {
        CreateStageInstance::new(self, channel_id, topic)
    }

    /// Gets the stage instance associated with a stage channel, if it exists.
    pub const fn stage_instance(&self, channel_id: Id<ChannelMarker>) -> GetStageInstance<'_> {
        GetStageInstance::new(self, channel_id)
    }

    /// Update fields of an existing stage instance.
    ///
    /// Requires the user to be a moderator of the stage channel.
    pub const fn update_stage_instance(
        &self,
        channel_id: Id<ChannelMarker>,
    ) -> UpdateStageInstance<'_> {
        UpdateStageInstance::new(self, channel_id)
    }

    /// Delete the stage instance of a stage channel.
    ///
    /// Requires the user to be a moderator of the stage channel.
    pub const fn delete_stage_instance(
        &self,
        channel_id: Id<ChannelMarker>,
    ) -> DeleteStageInstance<'_> {
        DeleteStageInstance::new(self, channel_id)
    }

    /// Create a new guild based on a template.
    ///
    /// This endpoint can only be used by bots in less than 10 guilds.
    ///
    /// # Errors
    ///
    /// Returns an error of type [`ValidationErrorType::TemplateName`] if the
    /// name is invalid.
    ///
    /// [`ValidationErrorType::TemplateName`]: twilight_validate::request::ValidationErrorType::TemplateName
    pub fn create_guild_from_template<'a>(
        &'a self,
        template_code: &'a str,
        name: &'a str,
    ) -> CreateGuildFromTemplate<'a> {
        CreateGuildFromTemplate::new(self, template_code, name)
    }

    /// Create a template from the current state of the guild.
    ///
    /// Requires the `MANAGE_GUILD` permission. The name must be at least 1 and
    /// at most 100 characters in length.
    ///
    /// # Errors
    ///
    /// Returns an error of type [`ValidationErrorType::TemplateName`] if the
    /// name is invalid.
    ///
    /// [`ValidationErrorType::TemplateName`]: twilight_validate::request::ValidationErrorType::TemplateName
    pub fn create_template<'a>(
        &'a self,
        guild_id: Id<GuildMarker>,
        name: &'a str,
    ) -> CreateTemplate<'a> {
        CreateTemplate::new(self, guild_id, name)
    }

    /// Delete a template by ID and code.
    pub const fn delete_template<'a>(
        &'a self,
        guild_id: Id<GuildMarker>,
        template_code: &'a str,
    ) -> DeleteTemplate<'a> {
        DeleteTemplate::new(self, guild_id, template_code)
    }

    /// Get a template by its code.
    pub const fn get_template<'a>(&'a self, template_code: &'a str) -> GetTemplate<'a> {
        GetTemplate::new(self, template_code)
    }

    /// Get a list of templates in a guild, by ID.
    pub const fn get_templates(&self, guild_id: Id<GuildMarker>) -> GetTemplates<'_> {
        GetTemplates::new(self, guild_id)
    }

    /// Sync a template to the current state of the guild, by ID and code.
    pub const fn sync_template<'a>(
        &'a self,
        guild_id: Id<GuildMarker>,
        template_code: &'a str,
    ) -> SyncTemplate<'a> {
        SyncTemplate::new(self, guild_id, template_code)
    }

    /// Update the template's metadata, by ID and code.
    pub const fn update_template<'a>(
        &'a self,
        guild_id: Id<GuildMarker>,
        template_code: &'a str,
    ) -> UpdateTemplate<'a> {
        UpdateTemplate::new(self, guild_id, template_code)
    }

    /// Returns all active threads in the guild.
    ///
    /// Includes public and private threads. Threads are ordered by their ID in
    /// descending order.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// let client = Client::new("my token".to_owned());
    /// let guild_id = Id::new(234);
    ///
    /// let threads = client.active_threads(guild_id).await?.model().await?;
    /// # Ok(()) }
    /// ```
    pub const fn active_threads(&self, guild_id: Id<GuildMarker>) -> GetActiveThreads<'_> {
        GetActiveThreads::new(self, guild_id)
    }

    /// Add another member to a thread.
    ///
    /// Requires the ability to send messages in the thread, and that the thread
    /// is not archived.
    pub const fn add_thread_member(
        &self,
        channel_id: Id<ChannelMarker>,
        user_id: Id<UserMarker>,
    ) -> AddThreadMember<'_> {
        AddThreadMember::new(self, channel_id, user_id)
    }

    /// Start a thread in a forum channel.
    pub const fn create_forum_thread<'a>(
        &'a self,
        channel_id: Id<ChannelMarker>,
        name: &'a str,
    ) -> CreateForumThread<'a> {
        CreateForumThread::new(self, channel_id, name)
    }

    /// Start a thread that is not connected to a message.
    ///
    /// Automatic archive durations are not locked behind the guild's boost
    /// level.
    ///
    /// To make a [`PrivateThread`], the guild must also have the
    /// `PRIVATE_THREADS` feature.
    ///
    /// # Errors
    ///
    /// Returns an error of type [`NameInvalid`] if the channel's name's length is
    /// incorrect.
    ///
    /// Returns an error of type [`TypeInvalid`] if the channel is not a thread.
    ///
    /// [`NameInvalid`]: twilight_validate::channel::ChannelValidationErrorType::NameInvalid
    /// [`PrivateThread`]: twilight_model::channel::ChannelType::PrivateThread
    /// [`TypeInvalid`]: twilight_validate::channel::ChannelValidationErrorType::TypeInvalid
    pub fn create_thread<'a>(
        &'a self,
        channel_id: Id<ChannelMarker>,
        name: &'a str,
        kind: ChannelType,
    ) -> CreateThread<'a> {
        CreateThread::new(self, channel_id, name, kind)
    }

    /// Create a new thread from an existing message.
    ///
    /// When called on a [`GuildText`] channel, this creates a
    /// [`PublicThread`].
    ///
    /// When called on a [`GuildAnnouncement`] channel, this creates a
    /// [`AnnouncementThread`].
    ///
    /// Automatic archive durations are not locked behind the guild's boost
    /// level.
    ///
    /// The thread's ID will be the same as its parent message. This ensures
    /// only one thread can be created per message.
    ///
    /// # Errors
    ///
    /// Returns an error of type [`NameInvalid`] if the channel's name's length is
    /// incorrect.
    ///
    /// Returns an error of type [`TypeInvalid`] if the channel is not a thread.
    ///
    /// [`AnnouncementThread`]: twilight_model::channel::ChannelType::AnnouncementThread
    /// [`GuildAnnouncement`]: twilight_model::channel::ChannelType::GuildAnnouncement
    /// [`GuildText`]: twilight_model::channel::ChannelType::GuildText
    /// [`NameInvalid`]: twilight_validate::channel::ChannelValidationErrorType::NameInvalid
    /// [`PublicThread`]: twilight_model::channel::ChannelType::PublicThread
    /// [`TypeInvalid`]: twilight_validate::channel::ChannelValidationErrorType::TypeInvalid
    pub fn create_thread_from_message<'a>(
        &'a self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
        name: &'a str,
    ) -> CreateThreadFromMessage<'a> {
        CreateThreadFromMessage::new(self, channel_id, message_id, name)
    }

    /// Add the current user to a thread.
    pub const fn join_thread(&self, channel_id: Id<ChannelMarker>) -> JoinThread<'_> {
        JoinThread::new(self, channel_id)
    }

    /// Returns archived private threads in the channel that the current user
    /// has joined.
    ///
    /// Threads are ordered by their ID in descending order.
    pub const fn joined_private_archived_threads(
        &self,
        channel_id: Id<ChannelMarker>,
    ) -> GetJoinedPrivateArchivedThreads<'_> {
        GetJoinedPrivateArchivedThreads::new(self, channel_id)
    }

    /// Remove the current user from a thread.
    ///
    /// Requires that the thread is not archived.
    pub const fn leave_thread(&self, channel_id: Id<ChannelMarker>) -> LeaveThread<'_> {
        LeaveThread::new(self, channel_id)
    }

    /// Returns archived private threads in the channel.
    ///
    /// Requires both [`READ_MESSAGE_HISTORY`] and [`MANAGE_THREADS`].
    ///
    /// [`MANAGE_THREADS`]: twilight_model::guild::Permissions::MANAGE_THREADS
    /// [`READ_MESSAGE_HISTORY`]: twilight_model::guild::Permissions::READ_MESSAGE_HISTORY
    pub const fn private_archived_threads(
        &self,
        channel_id: Id<ChannelMarker>,
    ) -> GetPrivateArchivedThreads<'_> {
        GetPrivateArchivedThreads::new(self, channel_id)
    }

    /// Returns archived public threads in the channel.
    ///
    /// Requires the [`READ_MESSAGE_HISTORY`] permission.
    ///
    /// Threads are ordered by [`archive_timestamp`] in descending order.
    ///
    /// When called in a [`GuildText`] channel, returns [`PublicThread`]s.
    ///
    /// When called in a [`GuildAnnouncement`] channel, returns [`AnnouncementThread`]s.
    ///
    /// [`AnnouncementThread`]: twilight_model::channel::ChannelType::AnnouncementThread
    /// [`archive_timestamp`]: twilight_model::channel::thread::ThreadMetadata::archive_timestamp
    /// [`GuildAnnouncement`]: twilight_model::channel::ChannelType::GuildAnnouncement
    /// [`GuildText`]: twilight_model::channel::ChannelType::GuildText
    /// [`PublicThread`]: twilight_model::channel::ChannelType::PublicThread
    /// [`READ_MESSAGE_HISTORY`]: twilight_model::guild::Permissions::READ_MESSAGE_HISTORY
    pub const fn public_archived_threads(
        &self,
        channel_id: Id<ChannelMarker>,
    ) -> GetPublicArchivedThreads<'_> {
        GetPublicArchivedThreads::new(self, channel_id)
    }

    /// Remove another member from a thread.
    ///
    /// Requires that the thread is not archived.
    ///
    /// Requires the [`MANAGE_THREADS`] permission, unless both the thread is a
    /// [`PrivateThread`], and the current user is the creator of the
    /// thread.
    ///
    /// [`MANAGE_THREADS`]: twilight_model::guild::Permissions::MANAGE_THREADS
    /// [`PrivateThread`]: twilight_model::channel::ChannelType::PrivateThread
    pub const fn remove_thread_member(
        &self,
        channel_id: Id<ChannelMarker>,
        user_id: Id<UserMarker>,
    ) -> RemoveThreadMember<'_> {
        RemoveThreadMember::new(self, channel_id, user_id)
    }

    /// Returns a [`ThreadMember`] in a thread.
    ///
    /// [`ThreadMember`]: twilight_model::channel::thread::ThreadMember
    pub const fn thread_member(
        &self,
        channel_id: Id<ChannelMarker>,
        user_id: Id<UserMarker>,
    ) -> GetThreadMember<'_> {
        GetThreadMember::new(self, channel_id, user_id)
    }

    /// Returns the [`ThreadMember`]s of the thread.
    ///
    /// [`ThreadMember`]: twilight_model::channel::thread::ThreadMember
    pub const fn thread_members(&self, channel_id: Id<ChannelMarker>) -> GetThreadMembers<'_> {
        GetThreadMembers::new(self, channel_id)
    }

    /// Update a thread.
    ///
    /// All fields are optional. The minimum length of the name is 1 UTF-16
    /// characters and the maximum is 100 UTF-16 characters.
    pub const fn update_thread(&self, channel_id: Id<ChannelMarker>) -> UpdateThread<'_> {
        UpdateThread::new(self, channel_id)
    }

    /// Get a user's information by id.
    pub const fn user(&self, user_id: Id<UserMarker>) -> GetUser<'_> {
        GetUser::new(self, user_id)
    }

    /// Get voice state of a user in a guild.
    ///
    /// # Caveats
    ///
    /// - User must already have joined a voice/stage channel in this guild.
    pub const fn user_voice_state(
        &self,
        guild_id: Id<GuildMarker>,
        user_id: Id<UserMarker>,
    ) -> GetUserVoiceState<'_> {
        GetUserVoiceState::new(self, guild_id, user_id)
    }

    /// Update another user's voice state.
    ///
    /// # Caveats
    ///
    /// - `channel_id` must currently point to a stage channel.
    /// - User must already have joined `channel_id`.
    pub const fn update_user_voice_state(
        &self,
        guild_id: Id<GuildMarker>,
        user_id: Id<UserMarker>,
        channel_id: Id<ChannelMarker>,
    ) -> UpdateUserVoiceState<'_> {
        UpdateUserVoiceState::new(self, guild_id, user_id, channel_id)
    }

    /// Get a list of voice regions that can be used when creating a guild.
    pub const fn voice_regions(&self) -> GetVoiceRegions<'_> {
        GetVoiceRegions::new(self)
    }

    /// Get a webhook by ID.
    pub const fn webhook(&self, id: Id<WebhookMarker>) -> GetWebhook<'_> {
        GetWebhook::new(self, id)
    }

    /// Create a webhook in a channel.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// # use twilight_model::id::Id;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("my token".to_owned());
    /// let channel_id = Id::new(123);
    ///
    /// let webhook = client.create_webhook(channel_id, "Twily Bot").await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error of type [`WebhookUsername`] if the webhook's name is
    /// invalid.
    ///
    /// [`WebhookUsername`]: twilight_validate::request::ValidationErrorType::WebhookUsername
    pub fn create_webhook<'a>(
        &'a self,
        channel_id: Id<ChannelMarker>,
        name: &'a str,
    ) -> CreateWebhook<'a> {
        CreateWebhook::new(self, channel_id, name)
    }

    /// Delete a webhook by its ID.
    pub const fn delete_webhook(&self, id: Id<WebhookMarker>) -> DeleteWebhook<'_> {
        DeleteWebhook::new(self, id)
    }

    /// Update a webhook by ID.
    pub const fn update_webhook(&self, webhook_id: Id<WebhookMarker>) -> UpdateWebhook<'_> {
        UpdateWebhook::new(self, webhook_id)
    }

    /// Update a webhook, with a token, by ID.
    pub const fn update_webhook_with_token<'a>(
        &'a self,
        webhook_id: Id<WebhookMarker>,
        token: &'a str,
    ) -> UpdateWebhookWithToken<'a> {
        UpdateWebhookWithToken::new(self, webhook_id, token)
    }

    /// Execute a webhook, sending a message to its channel.
    ///
    /// The message must include at least one of [`attachments`], [`components`]
    /// [`content`], or [`embeds`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// let client = Client::new("my token".to_owned());
    /// let id = Id::new(432);
    ///
    /// let webhook = client
    ///     .execute_webhook(id, "webhook token")
    ///     .content("Pinkie...")
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// [`attachments`]: ExecuteWebhook::attachments
    /// [`components`]: ExecuteWebhook::components
    /// [`content`]: ExecuteWebhook::content
    /// [`embeds`]: ExecuteWebhook::embeds
    pub const fn execute_webhook<'a>(
        &'a self,
        webhook_id: Id<WebhookMarker>,
        token: &'a str,
    ) -> ExecuteWebhook<'a> {
        ExecuteWebhook::new(self, webhook_id, token)
    }

    /// Get a webhook message by webhook ID, token, and message ID.
    pub const fn webhook_message<'a>(
        &'a self,
        webhook_id: Id<WebhookMarker>,
        token: &'a str,
        message_id: Id<MessageMarker>,
    ) -> GetWebhookMessage<'a> {
        GetWebhookMessage::new(self, webhook_id, token, message_id)
    }

    /// Update a message executed by a webhook.
    ///
    /// You can pass [`None`] to any of the methods to remove the associated
    /// field. Pass [`None`] to [`content`] to remove the content. You must
    /// ensure that the message still contains at least one of [`attachments`],
    /// [`components`], [`content`], or [`embeds`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// let client = Client::new("token".to_owned());
    /// client
    ///     .update_webhook_message(Id::new(1), "token here", Id::new(2))
    ///     .content(Some("new message content"))
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// [`attachments`]: UpdateWebhookMessage::attachments
    /// [`components`]: UpdateWebhookMessage::components
    /// [`content`]: UpdateWebhookMessage::content
    /// [`embeds`]: UpdateWebhookMessage::embeds
    pub const fn update_webhook_message<'a>(
        &'a self,
        webhook_id: Id<WebhookMarker>,
        token: &'a str,
        message_id: Id<MessageMarker>,
    ) -> UpdateWebhookMessage<'a> {
        UpdateWebhookMessage::new(self, webhook_id, token, message_id)
    }

    /// Delete a message executed by a webhook.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("token".to_owned());
    /// client
    ///     .delete_webhook_message(Id::new(1), "token here", Id::new(2))
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub const fn delete_webhook_message<'a>(
        &'a self,
        webhook_id: Id<WebhookMarker>,
        token: &'a str,
        message_id: Id<MessageMarker>,
    ) -> DeleteWebhookMessage<'a> {
        DeleteWebhookMessage::new(self, webhook_id, token, message_id)
    }

    /// Delete a scheduled event in a guild.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// # use twilight_model::id::Id;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("token".to_owned());
    /// let guild_id = Id::new(1);
    /// let scheduled_event_id = Id::new(2);
    ///
    /// client
    ///     .delete_guild_scheduled_event(guild_id, scheduled_event_id)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub const fn delete_guild_scheduled_event(
        &self,
        guild_id: Id<GuildMarker>,
        scheduled_event_id: Id<ScheduledEventMarker>,
    ) -> DeleteGuildScheduledEvent<'_> {
        DeleteGuildScheduledEvent::new(self, guild_id, scheduled_event_id)
    }

    /// Create a scheduled event in a guild.
    ///
    /// Once a guild is selected, you must choose one of three event types to
    /// create. The request builders will ensure you provide the correct data to
    /// Discord. See [Discord Docs/Create Guild Scheduled Event].
    ///
    /// The name must be between 1 and 100 characters in length. For external
    /// events, the location must be between 1 and 100 characters in length.
    ///
    /// # Examples
    ///
    /// Create an event in a stage instance:
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// use twilight_model::{guild::scheduled_event::PrivacyLevel, id::Id, util::Timestamp};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("token".to_owned());
    /// let guild_id = Id::new(1);
    /// let channel_id = Id::new(2);
    /// let garfield_start_time = Timestamp::parse("2022-01-01T14:00:00+00:00")?;
    ///
    /// client
    ///     .create_guild_scheduled_event(guild_id, PrivacyLevel::GuildOnly)
    ///     .stage_instance(
    ///         channel_id,
    ///         "Garfield Appreciation Hour",
    ///         &garfield_start_time,
    ///     )
    ///     .description("Discuss: How important is Garfield to You?")
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// Create an external event:
    ///
    /// ```no_run
    /// # use twilight_http::Client;
    /// use twilight_model::{guild::scheduled_event::PrivacyLevel, id::Id, util::Timestamp};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::new("token".to_owned());
    /// let guild_id = Id::new(1);
    /// let garfield_con_start_time = Timestamp::parse("2022-01-04T08:00:00+00:00")?;
    /// let garfield_con_end_time = Timestamp::parse("2022-01-06T17:00:00+00:00")?;
    ///
    /// client
    ///     .create_guild_scheduled_event(guild_id, PrivacyLevel::GuildOnly)
    ///     .external(
    ///         "Garfield Con 2022",
    ///         "Baltimore Convention Center",
    ///         &garfield_con_start_time,
    ///         &garfield_con_end_time,
    ///     )
    ///     .description(
    ///         "In a spiritual successor to BronyCon, Garfield fans from \
    /// around the globe celebrate all things related to the loveable cat.",
    ///     )
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// [Discord Docs/Create Guild Scheduled Event]: https://discord.com/developers/docs/resources/guild-scheduled-event#create-guild-scheduled-event
    pub const fn create_guild_scheduled_event(
        &self,
        guild_id: Id<GuildMarker>,
        privacy_level: PrivacyLevel,
    ) -> CreateGuildScheduledEvent<'_> {
        CreateGuildScheduledEvent::new(self, guild_id, privacy_level)
    }

    /// Get a scheduled event in a guild.
    pub const fn guild_scheduled_event(
        &self,
        guild_id: Id<GuildMarker>,
        scheduled_event_id: Id<ScheduledEventMarker>,
    ) -> GetGuildScheduledEvent<'_> {
        GetGuildScheduledEvent::new(self, guild_id, scheduled_event_id)
    }

    /// Get a list of users subscribed to a scheduled event.
    ///
    /// Users are returned in ascending order by `user_id`. [`before`] and
    /// [`after`] both take a user id. If both are specified, only [`before`] is
    /// respected. The default [`limit`] is 100. See
    /// [Discord Docs/Get Guild Scheduled Event Users].
    ///
    /// [`after`]: GetGuildScheduledEventUsers::after
    /// [`before`]: GetGuildScheduledEventUsers::before
    /// [`limit`]: GetGuildScheduledEventUsers::limit
    /// [Discord Docs/Get Guild Scheduled Event Users]: https://discord.com/developers/docs/resources/guild-scheduled-event#get-guild-scheduled-event-users
    pub const fn guild_scheduled_event_users(
        &self,
        guild_id: Id<GuildMarker>,
        scheduled_event_id: Id<ScheduledEventMarker>,
    ) -> GetGuildScheduledEventUsers<'_> {
        GetGuildScheduledEventUsers::new(self, guild_id, scheduled_event_id)
    }

    /// Get a list of scheduled events in a guild.
    pub const fn guild_scheduled_events(
        &self,
        guild_id: Id<GuildMarker>,
    ) -> GetGuildScheduledEvents<'_> {
        GetGuildScheduledEvents::new(self, guild_id)
    }

    /// Update a scheduled event in a guild.
    ///
    /// This endpoint supports changing the type of event. When changing the
    /// entity type to either [`EntityType::StageInstance`] or
    /// [`EntityType::Voice`], an [`Id<ChannelMarker>`] must be provided if it
    /// does not already exist.
    ///
    /// When changing the entity type to [`EntityType::External`], the
    /// `channel_id` field is cleared and the [`channel_id`] method has no
    /// effect. Additionally, you must set a location with [`location`].
    ///
    /// [`EntityType::External`]: twilight_model::guild::scheduled_event::EntityType::External
    /// [`EntityType::StageInstance`]: twilight_model::guild::scheduled_event::EntityType::StageInstance
    /// [`EntityType::Voice`]: twilight_model::guild::scheduled_event::EntityType::Voice
    /// [`channel_id`]: UpdateGuildScheduledEvent::channel_id
    /// [`location`]: UpdateGuildScheduledEvent::location
    pub const fn update_guild_scheduled_event(
        &self,
        guild_id: Id<GuildMarker>,
        scheduled_event_id: Id<ScheduledEventMarker>,
    ) -> UpdateGuildScheduledEvent<'_> {
        UpdateGuildScheduledEvent::new(self, guild_id, scheduled_event_id)
    }

    /// Returns a single sticker by its ID.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let id = Id::new(123);
    /// let sticker = client.sticker(id).await?.model().await?;
    ///
    /// println!("{sticker:#?}");
    /// # Ok(()) }
    /// ```
    pub const fn sticker(&self, sticker_id: Id<StickerMarker>) -> GetSticker<'_> {
        GetSticker::new(self, sticker_id)
    }

    /// Returns a list of sticker packs available to Nitro subscribers.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let packs = client.nitro_sticker_packs().await?.model().await?;
    ///
    /// println!("{}", packs.sticker_packs.len());
    /// # Ok(()) }
    /// ```
    pub const fn nitro_sticker_packs(&self) -> GetNitroStickerPacks<'_> {
        GetNitroStickerPacks::new(self)
    }

    /// Returns a list of stickers in a guild.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let guild_id = Id::new(1);
    /// let stickers = client.guild_stickers(guild_id).await?.models().await?;
    ///
    /// println!("{}", stickers.len());
    /// # Ok(()) }
    /// ```
    pub const fn guild_stickers(&self, guild_id: Id<GuildMarker>) -> GetGuildStickers<'_> {
        GetGuildStickers::new(self, guild_id)
    }

    /// Returns a guild sticker by the guild's ID and the sticker's ID.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let guild_id = Id::new(1);
    /// let sticker_id = Id::new(2);
    /// let sticker = client
    ///     .guild_sticker(guild_id, sticker_id)
    ///     .await?
    ///     .model()
    ///     .await?;
    ///
    /// println!("{sticker:#?}");
    /// # Ok(()) }
    /// ```
    pub const fn guild_sticker(
        &self,
        guild_id: Id<GuildMarker>,
        sticker_id: Id<StickerMarker>,
    ) -> GetGuildSticker<'_> {
        GetGuildSticker::new(self, guild_id, sticker_id)
    }

    /// Creates a sticker in a guild, and returns the created sticker.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let guild_id = Id::new(1);
    /// let sticker = client
    ///     .create_guild_sticker(
    ///         guild_id,
    ///         &"sticker name",
    ///         &"sticker description",
    ///         &"sticker,tags",
    ///         &[23, 23, 23, 23],
    ///     )
    ///     .await?
    ///     .model()
    ///     .await?;
    ///
    /// println!("{sticker:#?}");
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error of type [`DescriptionInvalid`] if the length is invalid.
    ///
    /// Returns an error of type [`NameInvalid`] if the length is invalid.
    ///
    /// Returns an error of type [`TagsInvalid`] if the length is invalid.
    ///
    /// [`DescriptionInvalid`]: twilight_validate::sticker::StickerValidationErrorType::DescriptionInvalid
    /// [`NameInvalid`]: twilight_validate::sticker::StickerValidationErrorType::NameInvalid
    /// [`TagsInvalid`]: twilight_validate::sticker::StickerValidationErrorType::TagsInvalid
    pub fn create_guild_sticker<'a>(
        &'a self,
        guild_id: Id<GuildMarker>,
        name: &'a str,
        description: &'a str,
        tags: &'a str,
        file: &'a [u8],
    ) -> CreateGuildSticker<'a> {
        CreateGuildSticker::new(self, guild_id, name, description, tags, file)
    }

    /// Updates a sticker in a guild, and returns the updated sticker.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let guild_id = Id::new(1);
    /// let sticker_id = Id::new(2);
    /// let sticker = client
    ///     .update_guild_sticker(guild_id, sticker_id)
    ///     .description("new description")
    ///     .await?
    ///     .model()
    ///     .await?;
    ///
    /// println!("{sticker:#?}");
    /// # Ok(()) }
    /// ```
    pub const fn update_guild_sticker(
        &self,
        guild_id: Id<GuildMarker>,
        sticker_id: Id<StickerMarker>,
    ) -> UpdateGuildSticker<'_> {
        UpdateGuildSticker::new(self, guild_id, sticker_id)
    }

    /// Deletes a guild sticker by the ID of the guild and its ID.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let guild_id = Id::new(1);
    /// let sticker_id = Id::new(2);
    ///
    /// client.delete_guild_sticker(guild_id, sticker_id).await?;
    /// # Ok(()) }
    /// ```
    pub const fn delete_guild_sticker(
        &self,
        guild_id: Id<GuildMarker>,
        sticker_id: Id<StickerMarker>,
    ) -> DeleteGuildSticker<'_> {
        DeleteGuildSticker::new(self, guild_id, sticker_id)
    }

    /// Creates a test entitlement to a given SKU for a given guild or user. Discord
    /// will act as though that user or guild has entitlement to your premium offering.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::{Client, request::application::monetization::CreateTestEntitlementOwner};
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let application_id = Id::new(1);
    /// let sku_id = Id::new(2);
    /// let owner = CreateTestEntitlementOwner::Guild(Id::new(3));
    ///
    /// client.create_test_entitlement(
    ///    application_id,
    ///    sku_id,
    ///    owner,
    /// ).await?;
    ///
    /// # Ok(()) }
    pub const fn create_test_entitlement(
        &self,
        application_id: Id<ApplicationMarker>,
        sku_id: Id<SkuMarker>,
        owner: CreateTestEntitlementOwner,
    ) -> CreateTestEntitlement<'_> {
        CreateTestEntitlement::new(self, application_id, sku_id, owner)
    }

    /// Ends a poll in a channel.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let channel_id = Id::new(1);
    /// let message_id = Id::new(2);
    ///
    /// client.end_poll(channel_id, message_id).await?;
    /// # Ok(()) }
    /// ```
    pub const fn end_poll(
        &self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
    ) -> EndPoll<'_> {
        EndPoll::new(self, channel_id, message_id)
    }

    /// Deletes a currently-active test entitlement. Discord will act as though that user or
    /// guild no longer has entitlement to your premium offering.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let application_id = Id::new(1);
    /// let entitlement_id = Id::new(2);
    ///
    /// client.delete_test_entitlement(
    ///   application_id,
    ///   entitlement_id,
    /// ).await?;
    ///
    /// # Ok(()) }
    pub const fn delete_test_entitlement(
        &self,
        application_id: Id<ApplicationMarker>,
        entitlement_id: Id<EntitlementMarker>,
    ) -> DeleteTestEntitlement<'_> {
        DeleteTestEntitlement::new(self, application_id, entitlement_id)
    }

    /// /// Get the voters for an answer in a poll.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let channel_id = Id::new(1);
    /// let message_id = Id::new(2);
    /// let answer_id = 1;
    ///
    /// let voters = client.get_answer_voters(channel_id, message_id, answer_id).await?;
    ///
    /// println!("{:?}", voters);
    /// # Ok(()) }
    pub const fn get_answer_voters(
        &self,
        channel_id: Id<ChannelMarker>,
        message_id: Id<MessageMarker>,
        answer_id: u8,
    ) -> GetAnswerVoters<'_> {
        GetAnswerVoters::new(self, channel_id, message_id, answer_id)
    }

    /// Returns all SKUs for a given application.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let application_id = Id::new(1);
    ///
    /// let skus = client.get_skus(application_id).await?;
    ///
    /// # Ok(()) }
    pub const fn get_skus(&self, application_id: Id<ApplicationMarker>) -> GetSKUs<'_> {
        GetSKUs::new(self, application_id)
    }

    /// Gets all emojis associated with an application
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let application_id = Id::new(1);
    ///
    /// let emojis = client.get_application_emojis(application_id).await?;
    ///
    /// # Ok(()) }
    /// ```
    pub const fn get_application_emojis(
        &self,
        application_id: Id<ApplicationMarker>,
    ) -> ListApplicationEmojis<'_> {
        ListApplicationEmojis::new(self, application_id)
    }

    /// Adds an emoji to an application
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let application_id = Id::new(1);
    ///
    /// client
    ///     .add_application_emoji(application_id, "emoji name", "emoji image")
    ///     .await?;
    ///
    /// # Ok(()) }
    /// ```
    pub const fn add_application_emoji<'a>(
        &'a self,
        application_id: Id<ApplicationMarker>,
        name: &'a str,
        image: &'a str,
    ) -> AddApplicationEmoji<'a> {
        AddApplicationEmoji::new(self, application_id, name, image)
    }

    /// Updates an emoji associated with an application.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let application_id = Id::new(1);
    /// let emoji_id = Id::new(2);
    ///
    /// client
    ///     .update_application_emoji(application_id, emoji_id, "new emoji name")
    ///     .await?;
    ///
    /// # Ok(()) }
    /// ```
    pub const fn update_application_emoji<'a>(
        &'a self,
        application_id: Id<ApplicationMarker>,
        emoji_id: Id<EmojiMarker>,
        name: &'a str,
    ) -> UpdateApplicationEmoji<'a> {
        UpdateApplicationEmoji::new(self, application_id, emoji_id, name)
    }

    /// Deletes an emoji associated with an application.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use twilight_http::Client;
    /// use twilight_model::id::Id;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("my token".to_owned());
    ///
    /// let application_id = Id::new(1);
    /// let emoji_id = Id::new(2);
    ///
    /// client
    ///     .delete_application_emoji(application_id, emoji_id)
    ///     .await?;
    ///
    /// # Ok(()) }
    /// ```
    pub const fn delete_application_emoji(
        &self,
        application_id: Id<ApplicationMarker>,
        emoji_id: Id<EmojiMarker>,
    ) -> DeleteApplicationEmoji<'_> {
        DeleteApplicationEmoji::new(self, application_id, emoji_id)
    }

    /// Execute a request, returning a future resolving to a [`Response`].
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorType::Unauthorized`] error type if the configured
    /// token has become invalid due to expiration, revocation, etc.
    ///
    /// [`Response`]: super::response::Response
    pub fn request<T>(&self, request: Request) -> ResponseFuture<T> {
        match self.try_request::<T>(request) {
            Ok(future) => future,
            Err(source) => ResponseFuture::error(source),
        }
    }

    fn try_request<T>(&self, request: Request) -> Result<ResponseFuture<T>, Error> {
        if let Some(token_invalidated) = self.token_invalidated.as_ref() {
            if token_invalidated.load(Ordering::Relaxed) {
                return Err(Error {
                    kind: ErrorType::Unauthorized,
                    source: None,
                });
            }
        }

        let Request {
            body,
            form,
            headers: req_headers,
            method,
            path,
            ratelimit_path,
            use_authorization_token,
        } = request;

        let protocol = if self.use_http { "http" } else { "https" };
        let host = self.proxy.as_deref().unwrap_or("discord.com");

        let url = format!("{protocol}://{host}/api/v{API_VERSION}/{path}");
        tracing::debug!(?url);

        let mut builder = hyper::Request::builder().method(method.name()).uri(&url);

        if use_authorization_token {
            if let Some(token) = self.token.as_deref() {
                let value = HeaderValue::from_str(token).map_err(|source| {
                    let name = AUTHORIZATION.to_string();

                    Error {
                        kind: ErrorType::CreatingHeader { name },
                        source: Some(Box::new(source)),
                    }
                })?;

                if let Some(headers) = builder.headers_mut() {
                    headers.insert(AUTHORIZATION, value);
                }
            }
        }

        if let Some(headers) = builder.headers_mut() {
            if let Some(form) = &form {
                headers.insert(CONTENT_LENGTH, HeaderValue::from(form.len()));
                if let Ok(content_type) = HeaderValue::try_from(form.content_type()) {
                    headers.insert(CONTENT_TYPE, content_type);
                }
            } else if let Some(bytes) = &body {
                headers.insert(CONTENT_LENGTH, HeaderValue::from(bytes.len()));
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            } else if matches!(method, Method::Put | Method::Post | Method::Patch) {
                headers.insert(CONTENT_LENGTH, HeaderValue::from(0));
            }

            #[cfg(feature = "decompression")]
            headers.insert(
                hyper::header::ACCEPT_ENCODING,
                HeaderValue::from_static("br"),
            );

            headers.insert(USER_AGENT, HeaderValue::from_static(TWILIGHT_USER_AGENT));

            if let Some(req_headers) = req_headers {
                for (maybe_name, value) in req_headers {
                    if let Some(name) = maybe_name {
                        headers.insert(name, value);
                    }
                }
            }

            if let Some(default_headers) = &self.default_headers {
                for (name, value) in default_headers {
                    headers.insert(name, value.clone());
                }
            }
        }

        let try_req = if let Some(form) = form {
            builder.body(Full::from(form.build()))
        } else if let Some(bytes) = body {
            builder.body(Full::from(bytes))
        } else {
            builder.body(Full::default())
        };

        let inner = self.http.request(try_req.map_err(|source| Error {
            kind: ErrorType::BuildingRequest,
            source: Some(Box::new(source)),
        })?);

        // For requests that don't use an authorization token we don't need to
        // remember whether the token is invalid. This may be for requests such
        // as webhooks and interactions.
        let invalid_token = use_authorization_token
            .then(|| self.token_invalidated.clone())
            .flatten();

        Ok(if let Some(ratelimiter) = &self.ratelimiter {
            let rx = ratelimiter.acquire(ratelimit_path);

            ResponseFuture::ratelimit(invalid_token, inner, self.timeout, rx)
        } else {
            ResponseFuture::new(Box::pin(time::timeout(self.timeout, inner)), invalid_token)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Client;

    #[test]
    fn client_debug_with_token() {
        assert!(
            format!("{:?}", Client::new("Bot foo".to_owned())).contains("token: Some(<redacted>)")
        );
        assert!(format!("{:?}", Client::builder().build()).contains("token: None"));
    }
}
