use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
pub use twilight_http_ratelimiting::request::{Path, PathParseError, PathParseErrorType};

use crate::{
    query_formatter::{QueryArray, QueryStringFormatter},
    request::{channel::reaction::RequestReactionType, Method},
};
use std::fmt::{Display, Formatter, Result as FmtResult};
use twilight_model::id::{
    marker::{RoleMarker, SkuMarker},
    Id,
};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Route<'a> {
    /// Route information to add an emoji to an application.
    AddApplicationEmoji {
        /// The ID of the application.
        application_id: u64,
    },
    /// Route information to add a user to a guild.
    AddGuildMember {
        guild_id: u64,
        user_id: u64,
    },
    /// Route information to add a role to guild member.
    AddMemberRole {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the role.
        role_id: u64,
        /// The ID of the user.
        user_id: u64,
    },
    /// Route information to add a member to a thread.
    AddThreadMember {
        /// ID of the thread.
        channel_id: u64,
        /// ID of the member.
        user_id: u64,
    },
    /// Route information to create an auto moderation rule.
    CreateAutoModerationRule {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to create a ban on a user in a guild.
    CreateBan {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the user.
        user_id: u64,
    },
    /// Route information to create a channel in a guild.
    CreateChannel {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to create an emoji in a guild.
    CreateEmoji {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to create a thread in a forum channel.
    CreateForumThread {
        /// The ID of the channel.
        channel_id: u64,
    },
    /// Route information to create a global command.
    CreateGlobalCommand {
        /// The ID of the owner application.
        application_id: u64,
    },
    /// Route information to create a guild.
    CreateGuild,
    /// Route information to create a guild command.
    CreateGuildCommand {
        /// The ID of the owner application.
        application_id: u64,
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to create a guild from a template.
    CreateGuildFromTemplate {
        /// Code of the template.
        template_code: &'a str,
    },
    /// Route information to create a guild's integration.
    CreateGuildIntegration {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to create a prune in a guild.
    CreateGuildPrune {
        /// Whether to compute the number of pruned users.
        compute_prune_count: Option<bool>,
        /// The number of days that a user must be offline before being able to
        /// be pruned.
        days: Option<u16>,
        /// The ID of the guild.
        guild_id: u64,
        /// The roles to filter the prune by.
        ///
        /// A user must have at least one of these roles to be able to be
        /// pruned.
        include_roles: &'a [Id<RoleMarker>],
    },
    /// Route information to create a scheduled event in a guild.
    CreateGuildScheduledEvent {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to create a sticker in a guild.
    CreateGuildSticker {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to create an invite to a channel.
    CreateInvite {
        /// The ID of the channel.
        channel_id: u64,
    },
    /// Route information to create a message in a channel.
    CreateMessage {
        /// The ID of the channel.
        channel_id: u64,
    },
    /// Route information to create a private channel.
    CreatePrivateChannel,
    /// Route information to create a reaction on a message.
    CreateReaction {
        /// The ID of the channel.
        channel_id: u64,
        /// The URI encoded custom or unicode emoji.
        emoji: &'a RequestReactionType<'a>,
        /// The ID of the message.
        message_id: u64,
    },
    /// Route information to create a role in a guild.
    CreateRole {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to create a stage instance.
    CreateStageInstance,
    /// Route information to create a guild template.
    CreateTemplate {
        /// The ID of the guild.
        guild_id: u64,
    },
    CreateTestEntitlement {
        /// The ID of the application.
        application_id: u64,
    },
    /// Route information to create a thread in a channel.
    CreateThread {
        /// ID of the channel.
        channel_id: u64,
    },
    /// Route information to create a thread from a message.
    CreateThreadFromMessage {
        /// ID of the channel.
        channel_id: u64,
        /// ID of the message.
        message_id: u64,
    },
    /// Route information to create a typing trigger in a channel.
    CreateTypingTrigger {
        /// The ID of the channel.
        channel_id: u64,
    },
    /// Route information to create a webhook in a channel.
    CreateWebhook {
        /// The ID of the channel.
        channel_id: u64,
    },
    /// Route information to crosspost a message to following guilds.
    CrosspostMessage {
        /// The ID of the channel.
        channel_id: u64,
        /// The ID of the message.
        message_id: u64,
    },
    /// Route information to delete an application emoji.
    DeleteApplicationEmoji {
        /// The ID of the application.
        application_id: u64,
        /// The ID of the emoji.
        emoji_id: u64,
    },
    /// Route information to delete an auto moderation rule for a guild.
    DeleteAutoModerationRule {
        /// ID of the guild.
        guild_id: u64,
        /// ID of the auto moderation rule.
        auto_moderation_rule_id: u64,
    },
    /// Route information to delete a ban on a user in a guild.
    DeleteBan {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the user.
        user_id: u64,
    },
    /// Route information to delete a channel.
    DeleteChannel {
        /// The ID of the channel.
        channel_id: u64,
    },
    /// Route information to delete a guild's custom emoji.
    DeleteEmoji {
        /// The ID of the emoji.
        emoji_id: u64,
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to delete a global command.
    DeleteGlobalCommand {
        /// The ID of the owner application.
        application_id: u64,
        /// The ID of the command.
        command_id: u64,
    },
    /// Route information to delete a guild.
    DeleteGuild {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to delete a guild command.
    DeleteGuildCommand {
        /// The ID of the owner application.
        application_id: u64,
        /// The ID of the command.
        command_id: u64,
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to delete a guild integration.
    DeleteGuildIntegration {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the integration.
        integration_id: u64,
    },
    /// Route information to delete a scheduled event in a guild.
    DeleteGuildScheduledEvent {
        /// ID of the guild.
        guild_id: u64,
        /// ID of the scheduled event.
        scheduled_event_id: u64,
    },
    /// Route information to delete a guild sticker.
    DeleteGuildSticker {
        /// ID of the guild.
        guild_id: u64,
        /// ID of the sticker.
        sticker_id: u64,
    },
    /// Route information to delete the original interaction response.
    DeleteInteractionOriginal {
        /// The ID of the owner application
        application_id: u64,
        /// The token of the interaction.
        interaction_token: &'a str,
    },
    /// Route information to delete an invite.
    DeleteInvite {
        /// The unique invite code.
        code: &'a str,
    },
    /// Route information to delete a channel's message.
    DeleteMessage {
        /// The ID of the channel.
        channel_id: u64,
        /// The ID of the message.
        message_id: u64,
    },
    /// Route information to delete all of the reactions on a message.
    DeleteMessageReactions {
        /// The ID of the channel.
        channel_id: u64,
        /// The ID of the message.
        message_id: u64,
    },
    /// Route information to delete all of the reactions on a message with a
    /// specific emoji.
    DeleteMessageSpecificReaction {
        /// The ID of the channel.
        channel_id: u64,
        /// The URI encoded custom or unicode emoji.
        emoji: &'a RequestReactionType<'a>,
        /// The ID of the message.
        message_id: u64,
    },
    /// Route information to bulk delete messages in a channel.
    DeleteMessages {
        /// The ID of the channel.
        channel_id: u64,
    },
    /// Route information to delete a permission overwrite for a role or user in
    /// a channel.
    DeletePermissionOverwrite {
        /// The ID of the channel.
        channel_id: u64,
        /// The ID of the target role or user.
        target_id: u64,
    },
    /// Route information to delete a user's reaction on a message.
    DeleteReaction {
        /// The ID of the channel.
        channel_id: u64,
        /// The URI encoded custom or unicode emoji.
        emoji: &'a RequestReactionType<'a>,
        /// The ID of the message.
        message_id: u64,
        /// The ID of the user.
        user_id: u64,
    },
    /// Route information to delete the current user's reaction on a message.
    DeleteReactionCurrentUser {
        /// ID of the channel.
        channel_id: u64,
        /// URI encoded custom or unicode emoji.
        emoji: &'a RequestReactionType<'a>,
        /// ID of the message.
        message_id: u64,
    },
    /// Route information to delete a guild's role.
    DeleteRole {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the role.
        role_id: u64,
    },
    /// Route information to delete a stage instance.
    DeleteStageInstance {
        /// ID of the stage channel.
        channel_id: u64,
    },
    /// Route information to delete a guild template.
    DeleteTemplate {
        /// The ID of the guild.
        guild_id: u64,
        /// The target template code.
        template_code: &'a str,
    },
    /// Route information to delete a webhook.
    DeleteWebhook {
        /// The token of the webhook.
        token: Option<&'a str>,
        /// The ID of the webhook.
        webhook_id: u64,
    },
    /// Route information to delete a message created by a webhook.
    DeleteWebhookMessage {
        message_id: u64,
        /// ID of the thread channel, if there is one.
        thread_id: Option<u64>,
        token: &'a str,
        webhook_id: u64,
    },
    /// Route information to delete a test entitlement.
    DeleteTestEntitlement {
        /// The ID of the application.
        application_id: u64,
        /// The ID of the entitlement.
        entitlement_id: u64,
    },
    /// Route information to edit an application emoji.
    UpdateApplicationEmoji {
        /// The ID of the application.
        application_id: u64,
        /// The ID of the emoji.
        emoji_id: u64,
    },
    /// Route information to end a poll.
    EndPoll {
        channel_id: u64,
        message_id: u64,
    },
    /// Route information to execute a webhook by ID and token.
    ExecuteWebhook {
        /// ID of the thread channel, if there is one.
        thread_id: Option<u64>,
        /// The token of the webhook.
        token: &'a str,
        /// Whether to wait for a message response.
        wait: Option<bool>,
        /// The ID of the webhook.
        webhook_id: u64,
    },
    /// Route information to follow a news channel.
    FollowNewsChannel {
        /// The ID of the channel to follow.
        channel_id: u64,
    },
    /// Route information to get active threads in a channel.
    GetActiveThreads {
        /// ID of the guild.
        guild_id: u64,
    },
    GetApplicationEmojis {
        /// The ID of the application.
        application_id: u64,
    },
    /// Route information for fetching poll vote information.
    GetAnswerVoters {
        /// Get users after this user ID.
        after: Option<u64>,
        /// The id of the poll answer.
        answer_id: u8,
        /// The ID of the channel the poll is in.
        channel_id: u64,
        /// The maximum number of users to return (1-100).
        limit: Option<u8>,
        /// The message ID of the poll.
        message_id: u64,
    },
    /// Route information to get a paginated list of audit logs in a guild.
    GetAuditLogs {
        /// The type of action to get audit logs for.
        action_type: Option<u64>,
        /// The minimum ID of audit logs to get.
        after: Option<u64>,
        /// The maximum ID of audit logs to get.
        before: Option<u64>,
        /// The ID of the guild.
        guild_id: u64,
        /// The maximum number of audit logs to get.
        limit: Option<u16>,
        /// The ID of the user, if specified.
        user_id: Option<u64>,
    },
    /// Route information to get an auto moderation rule for a guild.
    GetAutoModerationRule {
        /// ID of the guild.
        guild_id: u64,
        /// ID of the auto moderation rule.
        auto_moderation_rule_id: u64,
    },
    /// Route information to get information about a single ban in a guild.
    GetBan {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the user.
        user_id: u64,
    },
    /// Route information to get a guild's bans.
    GetBans {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a guild's bans with parameters.
    GetBansWithParameters {
        /// User ID after which to retrieve bans.
        after: Option<u64>,
        /// User ID before which to retrieve bans.
        before: Option<u64>,
        /// Maximum number of bans to retrieve.
        limit: Option<u16>,
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a channel.
    GetChannel {
        /// The ID of the channel.
        channel_id: u64,
    },
    /// Route information to get a channel's invites.
    GetChannelInvites {
        /// The ID of the channel.
        channel_id: u64,
    },
    /// Route information to get a channel's webhooks.
    GetChannelWebhooks {
        /// The ID of the channel.
        channel_id: u64,
    },
    /// Route information to get a guild's channels.
    GetChannels {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to get permissions of a specific guild command.
    GetCommandPermissions {
        /// The ID of the application.
        application_id: u64,
        /// The ID of the command.
        command_id: u64,
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to get the current OAuth2 authorization information.
    GetCurrentAuthorizationInformation,
    /// Route information to get the current user.
    GetCurrentUser,
    /// Route information to get info about application the current bot user belongs to
    GetCurrentUserApplicationInfo,
    /// Route information to get the current user as a member object within a guild.
    GetCurrentUserGuildMember {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to get the current user's voice state.
    GetCurrentUserVoiceState {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to get an emoji by ID within a guild.
    GetEmoji {
        /// The ID of the emoji.
        emoji_id: u64,
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a guild's emojis.
    GetEmojis {
        /// The ID of the guild.
        guild_id: u64,
    },
    GetEntitlements {
        /// Retrieve entitlements after this time.
        after: Option<u64>,
        /// The ID of the application.
        application_id: u64,
        /// Retrieve entitlements before this time.
        before: Option<u64>,
        /// Whether to exclude ended entitlements.
        exclude_ended: Option<bool>,
        /// Guild ID to look up entitlements for.
        guild_id: Option<u64>,
        /// Number of entitlements to return. Set to 100 if unspecified.
        limit: Option<u8>,
        /// List of SKU IDs to check entitlements for.
        sku_ids: &'a [Id<SkuMarker>],
        /// User ID to look up entitlements for.
        user_id: Option<u64>,
    },
    /// Route to get a followup message for an interaction.
    GetFollowupMessage {
        /// ID of the application.
        application_id: u64,
        /// Token of the interaction.
        interaction_token: &'a str,
        /// ID of the thread channel, if there is one.
        thread_id: Option<u64>,
        /// ID of the followup message.
        message_id: u64,
    },
    /// Route information to get basic gateway information.
    GetGateway,
    /// Route information to get gateway information tailored to the current
    /// user.
    GetGatewayBot,
    /// Route information to get a global command for an application.
    GetGlobalCommand {
        /// ID of the owner application.
        application_id: u64,
        /// ID of the command.
        command_id: u64,
    },
    GetGlobalCommands {
        /// The ID of the owner application.
        application_id: u64,
        /// Whether to include full localization dictionaries.
        with_localizations: Option<bool>,
    },
    /// Route information to get a guild.
    GetGuild {
        /// The ID of the guild.
        guild_id: u64,
        /// Whether to include approximate member and presence counts for the
        /// guild.
        with_counts: bool,
    },
    /// Route information to get a list of automation rules for a guild.
    GetGuildAutoModerationRules {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a guild command.
    GetGuildCommand {
        /// ID of the owner application.
        application_id: u64,
        /// ID of the command.
        command_id: u64,
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to get permissions of all guild commands.
    GetGuildCommandPermissions {
        /// The ID of the application.
        application_id: u64,
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to get guild commands.
    GetGuildCommands {
        /// The ID of the owner application.
        application_id: u64,
        /// The ID of the guild.
        guild_id: u64,
        /// Whether to include full localization dictionaries.
        with_localizations: Option<bool>,
    },
    /// Route information to get a guild's integrations.
    GetGuildIntegrations {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a guild's invites.
    GetGuildInvites {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a guild's members.
    GetGuildMembers {
        /// The minimum ID of members to get.
        after: Option<u64>,
        /// The ID of the guild.
        guild_id: u64,
        /// The maximum number of members to get.
        limit: Option<u16>,
    },
    /// Route information to get a guild's onboarding information.
    GetGuildOnboarding {
        /// The ID of the guild to get onboarding information for.
        guild_id: u64,
    },
    /// Route information to get a guild's preview.
    GetGuildPreview {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to get the number of members that would be pruned,
    /// filtering by inactivity and users with one of the provided roles.
    GetGuildPruneCount {
        /// The number of days that a user must be offline before being able to
        /// be pruned.
        days: Option<u16>,
        /// The ID of the guild.
        guild_id: u64,
        /// The roles to filter the prune by.
        ///
        /// A user must have at least one of these roles to be able to be
        /// pruned.
        include_roles: &'a [Id<RoleMarker>],
    },
    /// Route information to get guild's roles.
    GetGuildRoles {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a guild scheduled event.
    GetGuildScheduledEvent {
        /// ID of the guild.
        guild_id: u64,
        // ID of the scheduled event.
        scheduled_event_id: u64,
        /// Whether to include user counts.
        with_user_count: bool,
    },
    /// Route information to get a guild scheduled event's members.
    GetGuildScheduledEventUsers {
        /// Get members after this ID.
        after: Option<u64>,
        /// Get members before this ID.
        before: Option<u64>,
        /// ID of the guild.
        guild_id: u64,
        /// Maximum amount of members to get.
        limit: Option<u16>,
        /// ID of the scheduled event.
        scheduled_event_id: u64,
        /// Whether to return a member object.
        with_member: bool,
    },
    /// Route information to get a guild's scheduled events.
    GetGuildScheduledEvents {
        /// ID of the guild.
        guild_id: u64,
        /// Whether to include user counts.
        with_user_count: bool,
    },
    /// Route information to get a guild's sticker.
    GetGuildSticker {
        /// ID of the guild.
        guild_id: u64,
        /// ID of the stickers.
        sticker_id: u64,
    },
    /// Route information to get a guild's stickers.
    GetGuildStickers {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a guild's vanity URL.
    GetGuildVanityUrl {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a guild's available voice regions.
    GetGuildVoiceRegions {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a guild's webhooks.
    GetGuildWebhooks {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a guild's welcome screen.
    GetGuildWelcomeScreen {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a guild's widget.
    GetGuildWidget {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a guild's widget settings.
    GetGuildWidgetSettings {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a paginated list of guilds.
    GetGuilds {
        /// The minimum ID of guilds to get.
        after: Option<u64>,
        /// The maximum ID of guilds to get.
        before: Option<u64>,
        /// The maximum number of guilds to get.
        limit: Option<u16>,
    },
    /// Route information to get an original interaction response message.
    GetInteractionOriginal {
        /// ID of the owner application.
        application_id: u64,
        /// Token of the interaction.
        interaction_token: &'a str,
    },
    /// Route information to get an invite.
    GetInvite {
        /// The unique invite code.
        code: &'a str,
        /// Whether to retrieve statistics about the invite.
        with_counts: bool,
    },
    /// Route information to get an invite with an expiration.
    GetInviteWithExpiration {
        /// The unique invite code.
        code: &'a str,
        /// Whether to retrieve statistics about the invite.
        with_counts: bool,
        /// Whether to retrieve the expiration date of the invite.
        with_expiration: bool,
    },
    /// Route information to get joined private archived threads in a channel.
    GetJoinedPrivateArchivedThreads {
        /// Optional timestamp to return threads before.
        before: Option<u64>,
        /// ID of the channel.
        channel_id: u64,
        /// Optional maximum number of threads to return.
        limit: Option<u64>,
    },
    /// Route information to get a member.
    GetMember {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the user.
        user_id: u64,
    },
    /// Route information to get a single message in a channel.
    GetMessage {
        /// The ID of the channel.
        channel_id: u64,
        /// The ID of the message.
        message_id: u64,
    },
    /// Route information to get a paginated list of messages in a channel.
    GetMessages {
        /// The minimum ID of messages to get.
        after: Option<u64>,
        /// The message ID to get the messages around.
        around: Option<u64>,
        /// The maximum ID of messages to get.
        before: Option<u64>,
        /// The ID of the channel.
        channel_id: u64,
        /// The maximum number of messages to get.
        limit: Option<u16>,
    },
    /// Route information to get a list of sticker packs available to Nitro
    /// subscribers.
    GetNitroStickerPacks,
    /// Route information to get a channel's pins.
    GetPins {
        /// The ID of the channel.
        channel_id: u64,
    },
    /// Route information to get private archived threads in a channel.
    GetPrivateArchivedThreads {
        /// Optional timestamp to return threads before.
        before: Option<&'a str>,
        /// ID of the channel.
        channel_id: u64,
        /// Optional maximum number of threads to return.
        limit: Option<u64>,
    },
    /// Route information to get public archived threads in a channel.
    GetPublicArchivedThreads {
        /// Optional timestamp to return threads before.
        before: Option<&'a str>,
        /// ID of the channel.
        channel_id: u64,
        /// Optional maximum number of threads to return.
        limit: Option<u64>,
    },
    /// Route information to get the users who reacted to a message with a
    /// specified emoji.
    GetReactionUsers {
        /// The minimum ID of users to get.
        after: Option<u64>,
        /// The ID of the channel.
        channel_id: u64,
        /// The URI encoded custom or unicode emoji.
        emoji: &'a RequestReactionType<'a>,
        /// The maximum number of users to retrieve.
        limit: Option<u16>,
        /// The ID of the message.
        message_id: u64,
        /// The type of reactions to fetch.
        kind: Option<u8>,
    },
    /// Route information to get a guild's role.
    GetRole {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the role.
        role_id: u64,
    },
    GetSKUs {
        /// The ID of the application.
        application_id: u64,
    },
    /// Route information to get a stage instance.
    GetStageInstance {
        /// ID of the stage channel.
        channel_id: u64,
    },
    /// Route information to get a sticker.
    GetSticker {
        /// ID of the sticker.
        sticker_id: u64,
    },
    /// Route information to get a template.
    GetTemplate {
        /// The template code.
        template_code: &'a str,
    },
    /// Route information to get a list of templates from a guild.
    GetTemplates {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to get a member of a thread.
    GetThreadMember {
        /// ID of the thread.
        channel_id: u64,
        /// ID of the member.
        user_id: u64,
    },
    /// Route information to get members of a thread.
    GetThreadMembers {
        /// Fetch thread members after this user ID.
        after: Option<u64>,
        /// ID of the thread.
        channel_id: u64,
        /// Maximum number of thread members to return.
        ///
        /// Must be between 1 and 100. Defaults to 100.
        limit: Option<u32>,
        /// Whether to include associated member objects.
        with_member: Option<bool>,
    },
    /// Route information to get a user.
    GetUser {
        /// ID of the target user.
        user_id: u64,
    },
    /// Route information to get the current user's connections.
    GetUserConnections,
    /// Route information to get the current user's private channels and groups.
    GetUserPrivateChannels,
    /// Route information to get a user's voice state.
    GetUserVoiceState {
        /// The ID of the guild.
        guild_id: u64,
        /// ID of the target user.
        user_id: u64,
    },
    /// Route information to get a list of the voice regions.
    GetVoiceRegions,
    /// Route information to get a webhook by ID, optionally with a token if the
    /// current user doesn't have access to it.
    GetWebhook {
        /// The token of the webhook.
        token: Option<&'a str>,
        /// The ID of the webhook.
        webhook_id: u64,
    },
    /// Route information to get a previously-sent webhook message.
    GetWebhookMessage {
        /// ID of the message.
        message_id: u64,
        /// ID of the thread channel, if there is one.
        thread_id: Option<u64>,
        /// Token of the webhook.
        token: &'a str,
        /// ID of the webhook.
        webhook_id: u64,
    },
    /// Route information to respond to an interaction.
    InteractionCallback {
        /// The ID of the interaction.
        interaction_id: u64,
        /// The token for the interaction.
        interaction_token: &'a str,
        /// If response should be retrived.
        with_response: bool,
    },
    /// Route information to join a thread as the current user.
    JoinThread {
        /// ID of the thread.
        channel_id: u64,
    },
    /// Route information to leave the guild.
    LeaveGuild {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to leave a thread as the current user.
    LeaveThread {
        /// ID of the thread.
        channel_id: u64,
    },
    /// Route information to pin a message to a channel.
    PinMessage {
        /// The ID of the channel.
        channel_id: u64,
        /// The ID of the message.
        message_id: u64,
    },
    /// Route information to remove a member from a guild.
    RemoveMember {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the user.
        user_id: u64,
    },
    /// Route information to remove a role from a member.
    RemoveMemberRole {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the role.
        role_id: u64,
        /// The ID of the user.
        user_id: u64,
    },
    /// Route information to remove a member from a thread.
    RemoveThreadMember {
        /// ID of the thread.
        channel_id: u64,
        /// ID of the member.
        user_id: u64,
    },
    /// Route information to search for members in a guild.
    SearchGuildMembers {
        /// ID of the guild to search in.
        guild_id: u64,
        /// Upper limit of members to query for.
        limit: Option<u16>,
        /// Query to search by.
        query: &'a str,
    },
    /// Route information to set global commands.
    SetGlobalCommands {
        /// The ID of the owner application.
        application_id: u64,
    },
    /// Route information to set guild commands.
    SetGuildCommands {
        /// The ID of the owner application.
        application_id: u64,
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to sync a guild's integration.
    SyncGuildIntegration {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the integration.
        integration_id: u64,
    },
    /// Route information to sync a template.
    SyncTemplate {
        /// The ID of the guild.
        guild_id: u64,
        /// The template code.
        template_code: &'a str,
    },
    /// Route information to unpin a message from a channel.
    UnpinMessage {
        /// The ID of the channel.
        channel_id: u64,
        /// The ID of the message.
        message_id: u64,
    },
    /// Route information to update an auto moderation rule for a guild.
    UpdateAutoModerationRule {
        /// ID of the auto moderation rule.
        auto_moderation_rule_id: u64,
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to update a channel, such as a guild channel or group.
    UpdateChannel {
        /// The ID of the channel.
        channel_id: u64,
    },
    /// Route information to edit permissions of a command in a guild.
    UpdateCommandPermissions {
        /// The ID of the application.
        application_id: u64,
        /// The ID of the command.
        command_id: u64,
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to update the current member.
    UpdateCurrentMember {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to update the current user.
    UpdateCurrentUser,
    /// Route information to update the current user's voice state.
    UpdateCurrentUserVoiceState {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to update an emoji.
    UpdateEmoji {
        /// The ID of the emoji.
        emoji_id: u64,
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to update a global command.
    UpdateGlobalCommand {
        /// The ID of the owner application.
        application_id: u64,
        /// The ID of the command.
        command_id: u64,
    },
    /// Route information to update a guild.
    UpdateGuild {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to update a guild channel.
    UpdateGuildChannels {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to update a guild command.
    UpdateGuildCommand {
        /// The ID of the owner application.
        application_id: u64,
        /// The ID of the command.
        command_id: u64,
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to update a guild's integration.
    UpdateGuildIntegration {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the integration.
        integration_id: u64,
    },
    /// Route information to update a guild's MFA level.
    UpdateGuildMfa {
        /// ID of the guild.
        guild_id: u64,
    },
    UpdateGuildOnboarding {
        /// The ID of the guild to update onboarding information for.
        guild_id: u64,
    },
    /// Route information to update a scheduled event in a guild.
    UpdateGuildScheduledEvent {
        /// ID of the guild.
        guild_id: u64,
        /// ID of the scheduled event.
        scheduled_event_id: u64,
    },
    /// Route information to update a guild sticker.
    UpdateGuildSticker {
        /// ID of the guild.
        guild_id: u64,
        /// ID of the sticker.
        sticker_id: u64,
    },
    /// Route information to update a guild's welcome screen.
    UpdateGuildWelcomeScreen {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Route information to update a guild's widget settings.
    UpdateGuildWidgetSettings {
        /// ID of the guild.
        guild_id: u64,
    },
    /// Update the original interaction response.
    UpdateInteractionOriginal {
        /// The ID of the owner application.
        application_id: u64,
        /// The token for the interaction.
        interaction_token: &'a str,
    },
    /// Route information to update a member.
    UpdateMember {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the user.
        user_id: u64,
    },
    /// Route information to update a message.
    UpdateMessage {
        /// The ID of the channel.
        channel_id: u64,
        /// The ID of the message.
        message_id: u64,
    },
    /// Route information to update the current member's nickname.
    UpdateNickname {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to update the permission overwrite of a role or user
    /// in a channel.
    UpdatePermissionOverwrite {
        /// The ID of the channel.
        channel_id: u64,
        /// The ID of the role or user.
        target_id: u64,
    },
    /// Route information to update a role.
    UpdateRole {
        /// The ID of the guild.
        guild_id: u64,
        /// The ID of the role.
        role_id: u64,
    },
    /// Route information to update the positions of roles.
    UpdateRolePositions {
        /// The ID of the guild.
        guild_id: u64,
    },
    /// Route information to update an existing stage instance.
    UpdateStageInstance {
        /// ID of the stage channel.
        channel_id: u64,
    },
    /// Route information to update a template.
    UpdateTemplate {
        /// The ID of the guild.
        guild_id: u64,
        /// The template code.
        template_code: &'a str,
    },
    /// Route information to update a user's voice state.
    UpdateUserVoiceState {
        /// ID of the guild.
        guild_id: u64,
        /// ID of the user.
        user_id: u64,
    },
    /// Route information to update a webhook.
    UpdateWebhook {
        /// The token of the webhook.
        token: Option<&'a str>,
        /// The ID of the webhook.
        webhook_id: u64,
    },
    /// Route information to update a message created by a webhook.
    UpdateWebhookMessage {
        message_id: u64,
        /// ID of the thread channel, if there is one.
        thread_id: Option<u64>,
        token: &'a str,
        webhook_id: u64,
    },
    UpdateCurrentUserApplication,
}

impl Route<'_> {
    /// HTTP method of the route.
    ///
    /// # Examples
    ///
    /// Assert that the [`GetGuild`] route returns [`Method::Get`]:
    ///
    /// ```
    /// use twilight_http::{request::Method, routing::Route};
    ///
    /// let route = Route::GetGuild {
    ///     guild_id: 123,
    ///     with_counts: false,
    /// };
    ///
    /// assert_eq!(Method::Get, route.method());
    /// ```
    ///
    /// [`GetGuild`]: Self::GetGuild
    #[allow(clippy::too_many_lines)]
    pub const fn method(&self) -> Method {
        match self {
            Self::DeleteAutoModerationRule { .. }
            | Self::DeleteApplicationEmoji { .. }
            | Self::DeleteBan { .. }
            | Self::DeleteChannel { .. }
            | Self::DeleteEmoji { .. }
            | Self::DeleteGlobalCommand { .. }
            | Self::DeleteGuild { .. }
            | Self::DeleteGuildCommand { .. }
            | Self::DeleteGuildIntegration { .. }
            | Self::DeleteGuildScheduledEvent { .. }
            | Self::DeleteGuildSticker { .. }
            | Self::DeleteTestEntitlement { .. }
            | Self::DeleteInteractionOriginal { .. }
            | Self::DeleteInvite { .. }
            | Self::DeleteMessageReactions { .. }
            | Self::DeleteMessageSpecificReaction { .. }
            | Self::DeleteMessage { .. }
            | Self::DeletePermissionOverwrite { .. }
            | Self::DeleteReactionCurrentUser { .. }
            | Self::DeleteReaction { .. }
            | Self::DeleteRole { .. }
            | Self::DeleteStageInstance { .. }
            | Self::DeleteTemplate { .. }
            | Self::DeleteWebhookMessage { .. }
            | Self::DeleteWebhook { .. }
            | Self::LeaveGuild { .. }
            | Self::LeaveThread { .. }
            | Self::RemoveMember { .. }
            | Self::RemoveMemberRole { .. }
            | Self::RemoveThreadMember { .. }
            | Self::UnpinMessage { .. } => Method::Delete,
            Self::GetActiveThreads { .. }
            | Self::GetApplicationEmojis { .. }
            | Self::GetAnswerVoters { .. }
            | Self::GetAuditLogs { .. }
            | Self::GetAutoModerationRule { .. }
            | Self::GetBan { .. }
            | Self::GetBans { .. }
            | Self::GetBansWithParameters { .. }
            | Self::GetGatewayBot
            | Self::GetChannel { .. }
            | Self::GetChannelInvites { .. }
            | Self::GetChannelWebhooks { .. }
            | Self::GetChannels { .. }
            | Self::GetCommandPermissions { .. }
            | Self::GetCurrentAuthorizationInformation
            | Self::GetCurrentUserApplicationInfo
            | Self::GetCurrentUser
            | Self::GetCurrentUserGuildMember { .. }
            | Self::GetCurrentUserVoiceState { .. }
            | Self::GetEmoji { .. }
            | Self::GetEmojis { .. }
            | Self::GetEntitlements { .. }
            | Self::GetGateway
            | Self::GetFollowupMessage { .. }
            | Self::GetGlobalCommand { .. }
            | Self::GetGlobalCommands { .. }
            | Self::GetGuild { .. }
            | Self::GetGuildAutoModerationRules { .. }
            | Self::GetGuildCommand { .. }
            | Self::GetGuildCommandPermissions { .. }
            | Self::GetGuildCommands { .. }
            | Self::GetGuildIntegrations { .. }
            | Self::GetGuildInvites { .. }
            | Self::GetGuildMembers { .. }
            | Self::GetGuildOnboarding { .. }
            | Self::GetGuildPreview { .. }
            | Self::GetGuildPruneCount { .. }
            | Self::GetGuildRoles { .. }
            | Self::GetGuildScheduledEvent { .. }
            | Self::GetGuildScheduledEventUsers { .. }
            | Self::GetGuildScheduledEvents { .. }
            | Self::GetGuildSticker { .. }
            | Self::GetGuildStickers { .. }
            | Self::GetGuildVanityUrl { .. }
            | Self::GetGuildVoiceRegions { .. }
            | Self::GetGuildWelcomeScreen { .. }
            | Self::GetGuildWebhooks { .. }
            | Self::GetGuildWidget { .. }
            | Self::GetGuildWidgetSettings { .. }
            | Self::GetGuilds { .. }
            | Self::GetInteractionOriginal { .. }
            | Self::GetInvite { .. }
            | Self::GetInviteWithExpiration { .. }
            | Self::GetMember { .. }
            | Self::GetMessage { .. }
            | Self::GetMessages { .. }
            | Self::GetNitroStickerPacks { .. }
            | Self::GetPins { .. }
            | Self::GetJoinedPrivateArchivedThreads { .. }
            | Self::GetPrivateArchivedThreads { .. }
            | Self::GetPublicArchivedThreads { .. }
            | Self::GetReactionUsers { .. }
            | Self::GetRole { .. }
            | Self::GetSKUs { .. }
            | Self::GetStageInstance { .. }
            | Self::GetSticker { .. }
            | Self::GetTemplate { .. }
            | Self::GetTemplates { .. }
            | Self::GetThreadMember { .. }
            | Self::GetThreadMembers { .. }
            | Self::GetUser { .. }
            | Self::GetUserConnections
            | Self::GetUserPrivateChannels
            | Self::GetUserVoiceState { .. }
            | Self::GetVoiceRegions
            | Self::GetWebhook { .. }
            | Self::GetWebhookMessage { .. }
            | Self::SearchGuildMembers { .. } => Method::Get,
            Self::UpdateAutoModerationRule { .. }
            | Self::UpdateChannel { .. }
            | Self::UpdateCurrentMember { .. }
            | Self::UpdateCurrentUser
            | Self::UpdateCurrentUserVoiceState { .. }
            | Self::UpdateEmoji { .. }
            | Self::UpdateGlobalCommand { .. }
            | Self::UpdateGuild { .. }
            | Self::UpdateGuildChannels { .. }
            | Self::UpdateGuildCommand { .. }
            | Self::UpdateGuildMfa { .. }
            | Self::UpdateGuildWidgetSettings { .. }
            | Self::UpdateGuildIntegration { .. }
            | Self::UpdateGuildScheduledEvent { .. }
            | Self::UpdateGuildSticker { .. }
            | Self::UpdateGuildWelcomeScreen { .. }
            | Self::UpdateInteractionOriginal { .. }
            | Self::UpdateMember { .. }
            | Self::UpdateMessage { .. }
            | Self::UpdateNickname { .. }
            | Self::UpdateRole { .. }
            | Self::UpdateRolePositions { .. }
            | Self::UpdateStageInstance { .. }
            | Self::UpdateTemplate { .. }
            | Self::UpdateUserVoiceState { .. }
            | Self::UpdateWebhookMessage { .. }
            | Self::UpdateCurrentUserApplication
            | Self::UpdateApplicationEmoji { .. }
            | Self::UpdateWebhook { .. } => Method::Patch,
            Self::CreateChannel { .. }
            | Self::AddApplicationEmoji { .. }
            | Self::CreateGlobalCommand { .. }
            | Self::CreateGuildCommand { .. }
            | Self::CreateEmoji { .. }
            | Self::CreateForumThread { .. }
            | Self::CreateGuild
            | Self::CreateAutoModerationRule { .. }
            | Self::CreateGuildFromTemplate { .. }
            | Self::CreateGuildIntegration { .. }
            | Self::CreateGuildPrune { .. }
            | Self::CreateGuildScheduledEvent { .. }
            | Self::CreateGuildSticker { .. }
            | Self::CreateInvite { .. }
            | Self::CreateMessage { .. }
            | Self::CreatePrivateChannel
            | Self::CreateThread { .. }
            | Self::CreateThreadFromMessage { .. }
            | Self::CreateRole { .. }
            | Self::CreateStageInstance { .. }
            | Self::CreateTemplate { .. }
            | Self::CreateTestEntitlement { .. }
            | Self::CreateTypingTrigger { .. }
            | Self::CreateWebhook { .. }
            | Self::CrosspostMessage { .. }
            | Self::DeleteMessages { .. }
            | Self::EndPoll { .. }
            | Self::ExecuteWebhook { .. }
            | Self::FollowNewsChannel { .. }
            | Self::InteractionCallback { .. }
            | Self::SyncGuildIntegration { .. } => Method::Post,
            Self::AddGuildMember { .. }
            | Self::AddMemberRole { .. }
            | Self::AddThreadMember { .. }
            | Self::CreateBan { .. }
            | Self::CreateReaction { .. }
            | Self::JoinThread { .. }
            | Self::PinMessage { .. }
            | Self::SetGlobalCommands { .. }
            | Self::SetGuildCommands { .. }
            | Self::SyncTemplate { .. }
            | Self::UpdateCommandPermissions { .. }
            | Self::UpdateGuildOnboarding { .. }
            | Self::UpdatePermissionOverwrite { .. } => Method::Put,
        }
    }

    /// Typed path of the route.
    ///
    /// Paths are used with a [`Ratelimiter`].
    ///
    /// # Examples
    ///
    /// Use a route's path to retrieve a ratelimiter ticket:
    ///
    /// ```
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    /// use twilight_http::routing::Route;
    /// use twilight_http_ratelimiting::{InMemoryRatelimiter, Ratelimiter};
    ///
    /// let ratelimiter = InMemoryRatelimiter::new();
    /// let route = Route::CreateMessage { channel_id: 123 };
    ///
    /// // Take a ticket from the ratelimiter.
    /// let rx = ratelimiter.ticket(route.to_path()).await?;
    ///
    /// // Wait to be told that a request can be made...
    /// let _tx = rx.await;
    ///
    /// // The request can now be made.
    /// # Ok(()) }
    /// ```
    ///
    /// [`Ratelimiter`]: twilight_http_ratelimiting::Ratelimiter
    #[allow(clippy::too_many_lines)]
    pub fn to_path(&self) -> Path {
        match *self {
            Self::AddGuildMember { guild_id, .. }
            | Self::GetMember { guild_id, .. }
            | Self::RemoveMember { guild_id, .. }
            | Self::UpdateMember { guild_id, .. } => Path::GuildsIdMembersId(guild_id),
            Self::AddMemberRole { guild_id, .. } | Self::RemoveMemberRole { guild_id, .. } => {
                Path::GuildsIdMembersIdRolesId(guild_id)
            }
            Self::AddThreadMember { channel_id, .. }
            | Self::GetThreadMember { channel_id, .. }
            | Self::GetThreadMembers { channel_id, .. }
            | Self::JoinThread { channel_id, .. }
            | Self::LeaveThread { channel_id, .. }
            | Self::RemoveThreadMember { channel_id, .. } => {
                Path::ChannelsIdThreadMembers(channel_id)
            }
            Self::CreateAutoModerationRule { guild_id, .. }
            | Self::GetGuildAutoModerationRules { guild_id, .. } => {
                Path::GuildsIdAutoModerationRules(guild_id)
            }
            Self::CreateBan { guild_id, .. } | Self::DeleteBan { guild_id, .. } => {
                Path::GuildsIdBansUserId(guild_id)
            }
            Self::CreateChannel { guild_id } => Path::GuildsIdChannels(guild_id),
            Self::CreateEmoji { guild_id } | Self::GetEmojis { guild_id } => {
                Path::GuildsIdEmojis(guild_id)
            }
            Self::CreateGlobalCommand { application_id }
            | Self::GetGlobalCommands { application_id, .. }
            | Self::SetGlobalCommands { application_id } => {
                Path::ApplicationCommand(application_id)
            }
            Self::CreateGuild => Path::Guilds,
            Self::CreateGuildFromTemplate { template_code, .. }
            | Self::GetTemplate { template_code, .. } => {
                Path::GuildsTemplatesCode(template_code.to_string())
            }
            Self::CreateGuildCommand { application_id, .. }
            | Self::DeleteGuildCommand { application_id, .. }
            | Self::GetGuildCommand { application_id, .. }
            | Self::GetGuildCommandPermissions { application_id, .. }
            | Self::GetGuildCommands { application_id, .. }
            | Self::SetGuildCommands { application_id, .. }
            | Self::UpdateGuildCommand { application_id, .. } => {
                Path::ApplicationGuildCommand(application_id)
            }
            Self::CreateGuildIntegration { guild_id } => Path::GuildsIdIntegrationsId(guild_id),
            Self::CreateGuildPrune { guild_id, .. } | Self::GetGuildPruneCount { guild_id, .. } => {
                Path::GuildsIdPrune(guild_id)
            }
            Self::CreateGuildSticker { guild_id, .. }
            | Self::DeleteGuildSticker { guild_id, .. }
            | Self::GetGuildSticker { guild_id, .. }
            | Self::GetGuildStickers { guild_id, .. }
            | Self::UpdateGuildSticker { guild_id, .. } => Path::GuildsIdStickers(guild_id),
            Self::CreateInvite { channel_id } | Self::GetChannelInvites { channel_id } => {
                Path::ChannelsIdInvites(channel_id)
            }
            Self::CreateMessage { channel_id } | Self::GetMessages { channel_id, .. } => {
                Path::ChannelsIdMessages(channel_id)
            }
            Self::CreatePrivateChannel | Self::GetUserPrivateChannels => Path::UsersIdChannels,
            Self::CreateReaction { channel_id, .. }
            | Self::DeleteReactionCurrentUser { channel_id, .. }
            | Self::DeleteReaction { channel_id, .. } => {
                Path::ChannelsIdMessagesIdReactionsUserIdType(channel_id)
            }
            Self::CreateRole { guild_id } | Self::GetGuildRoles { guild_id } => {
                Path::GuildsIdRoles(guild_id)
            }
            Self::CreateStageInstance { .. }
            | Self::DeleteStageInstance { .. }
            | Self::GetStageInstance { .. }
            | Self::UpdateStageInstance { .. } => Path::StageInstances,
            Self::CreateTemplate { guild_id } | Self::GetTemplates { guild_id } => {
                Path::GuildsIdTemplates(guild_id)
            }
            Self::CreateForumThread { channel_id }
            | Self::CreateThread { channel_id, .. }
            | Self::GetJoinedPrivateArchivedThreads { channel_id, .. }
            | Self::GetPrivateArchivedThreads { channel_id, .. }
            | Self::GetPublicArchivedThreads { channel_id, .. } => {
                Path::ChannelsIdThreads(channel_id)
            }
            Self::CreateThreadFromMessage { channel_id, .. } => {
                Path::ChannelsIdMessagesIdThreads(channel_id)
            }
            Self::CreateTestEntitlement { application_id }
            | Self::GetEntitlements { application_id, .. }
            | Self::DeleteTestEntitlement { application_id, .. } => {
                Path::ApplicationIdEntitlements(application_id)
            }
            Self::CreateTypingTrigger { channel_id } => Path::ChannelsIdTyping(channel_id),
            Self::CreateWebhook { channel_id } | Self::GetChannelWebhooks { channel_id } => {
                Path::ChannelsIdWebhooks(channel_id)
            }
            Self::CrosspostMessage { channel_id, .. } => {
                Path::ChannelsIdMessagesIdCrosspost(channel_id)
            }
            Self::DeleteAutoModerationRule { guild_id, .. }
            | Self::GetAutoModerationRule { guild_id, .. }
            | Self::UpdateAutoModerationRule { guild_id, .. } => {
                Path::GuildsIdAutoModerationRulesId(guild_id)
            }
            Self::DeleteChannel { channel_id } => Path::ChannelsId(channel_id),
            Self::DeleteEmoji { guild_id, .. } => Path::GuildsIdEmojisId(guild_id),
            Self::DeleteGlobalCommand { application_id, .. }
            | Self::GetGlobalCommand { application_id, .. }
            | Self::UpdateGlobalCommand { application_id, .. } => {
                Path::ApplicationCommandId(application_id)
            }
            Self::DeleteGuild { guild_id } => Path::GuildsId(guild_id),
            Self::DeleteGuildIntegration { guild_id, .. }
            | Self::UpdateGuildIntegration { guild_id, .. } => {
                Path::GuildsIdIntegrationsId(guild_id)
            }
            Self::DeleteInteractionOriginal {
                application_id,
                interaction_token,
                ..
            }
            | Self::GetFollowupMessage {
                application_id,
                interaction_token,
                ..
            }
            | Self::GetInteractionOriginal {
                application_id,
                interaction_token,
                ..
            }
            | Self::UpdateInteractionOriginal {
                application_id,
                interaction_token,
                ..
            } => Path::WebhooksIdTokenMessagesId(application_id, interaction_token.to_string()),
            Self::DeleteInvite { .. }
            | Self::GetInvite { .. }
            | Self::GetInviteWithExpiration { .. } => Path::InvitesCode,
            Self::DeleteMessageReactions { channel_id, .. }
            | Self::DeleteMessageSpecificReaction { channel_id, .. }
            | Self::GetReactionUsers { channel_id, .. } => {
                Path::ChannelsIdMessagesIdReactions(channel_id)
            }
            Self::DeleteMessage { message_id, .. } => {
                Path::ChannelsIdMessagesId(Method::Delete, message_id)
            }
            Self::DeleteMessages { channel_id } => Path::ChannelsIdMessagesBulkDelete(channel_id),
            Self::DeletePermissionOverwrite { channel_id, .. }
            | Self::UpdatePermissionOverwrite { channel_id, .. } => {
                Path::ChannelsIdPermissionsOverwriteId(channel_id)
            }
            Self::DeleteRole { guild_id, .. }
            | Self::GetRole { guild_id, .. }
            | Self::UpdateRole { guild_id, .. }
            | Self::UpdateRolePositions { guild_id } => Path::GuildsIdRolesId(guild_id),
            Self::DeleteTemplate {
                guild_id,
                template_code,
                ..
            }
            | Self::SyncTemplate {
                guild_id,
                template_code,
                ..
            }
            | Self::UpdateTemplate {
                guild_id,
                template_code,
                ..
            } => Path::GuildsIdTemplatesCode(guild_id, template_code.to_string()),
            Self::DeleteWebhookMessage {
                webhook_id, token, ..
            }
            | Self::GetWebhookMessage {
                webhook_id, token, ..
            }
            | Self::UpdateWebhookMessage {
                webhook_id, token, ..
            } => Path::WebhooksIdTokenMessagesId(webhook_id, token.to_string()),
            Self::DeleteWebhook {
                webhook_id,
                token: Some(token),
                ..
            }
            | Self::ExecuteWebhook {
                webhook_id, token, ..
            }
            | Self::GetWebhook {
                webhook_id,
                token: Some(token),
                ..
            }
            | Self::UpdateWebhook {
                webhook_id,
                token: Some(token),
            } => Path::WebhooksIdToken(webhook_id, token.to_string()),
            Self::DeleteWebhook { webhook_id, .. }
            | Self::GetWebhook { webhook_id, .. }
            | Self::UpdateWebhook { webhook_id, .. } => Path::WebhooksId(webhook_id),
            Self::FollowNewsChannel { channel_id } => Path::ChannelsIdFollowers(channel_id),
            Self::GetActiveThreads { guild_id, .. } => Path::GuildsIdThreads(guild_id),
            Self::GetApplicationEmojis { application_id, .. }
            | Self::UpdateApplicationEmoji { application_id, .. }
            | Self::AddApplicationEmoji { application_id }
            | Self::DeleteApplicationEmoji { application_id, .. } => {
                Path::ApplicationEmojis(application_id)
            }
            Self::GetAuditLogs { guild_id, .. } => Path::GuildsIdAuditLogs(guild_id),
            Self::GetBan { guild_id, .. } => Path::GuildsIdBansId(guild_id),
            Self::GetBans { guild_id } | Self::GetBansWithParameters { guild_id, .. } => {
                Path::GuildsIdBans(guild_id)
            }
            Self::GetGatewayBot => Path::GatewayBot,
            Self::GetChannel { channel_id } | Self::UpdateChannel { channel_id } => {
                Path::ChannelsId(channel_id)
            }
            Self::GetChannels { guild_id } | Self::UpdateGuildChannels { guild_id } => {
                Path::GuildsIdChannels(guild_id)
            }
            Self::GetCommandPermissions { application_id, .. }
            | Self::UpdateCommandPermissions { application_id, .. } => {
                Path::ApplicationGuildCommandId(application_id)
            }
            Self::GetCurrentAuthorizationInformation => Path::OauthMe,
            Self::GetCurrentUserApplicationInfo | Self::UpdateCurrentUserApplication => {
                Path::ApplicationsMe
            }
            Self::GetCurrentUser | Self::GetUser { .. } | Self::UpdateCurrentUser => Path::UsersId,
            Self::GetCurrentUserGuildMember { .. } => Path::UsersIdGuildsIdMember,
            Self::GetEmoji { guild_id, .. } | Self::UpdateEmoji { guild_id, .. } => {
                Path::GuildsIdEmojisId(guild_id)
            }
            Self::GetGateway => Path::Gateway,
            Self::GetGuild { guild_id, .. } | Self::UpdateGuild { guild_id } => {
                Path::GuildsId(guild_id)
            }
            Self::GetGuildWidget { guild_id } => Path::GuildsIdWidgetJson(guild_id),
            Self::GetGuildWidgetSettings { guild_id }
            | Self::UpdateGuildWidgetSettings { guild_id } => Path::GuildsIdWidget(guild_id),
            Self::GetGuildIntegrations { guild_id } => Path::GuildsIdIntegrations(guild_id),
            Self::GetGuildInvites { guild_id } => Path::GuildsIdInvites(guild_id),
            Self::GetGuildMembers { guild_id, .. } | Self::UpdateCurrentMember { guild_id, .. } => {
                Path::GuildsIdMembers(guild_id)
            }
            Self::GetGuildOnboarding { guild_id } | Self::UpdateGuildOnboarding { guild_id } => {
                Path::GuildsIdOnboarding(guild_id)
            }
            Self::CreateGuildScheduledEvent { guild_id, .. }
            | Self::GetGuildScheduledEvents { guild_id, .. } => {
                Path::GuildsIdScheduledEvents(guild_id)
            }
            Self::DeleteGuildScheduledEvent { guild_id, .. }
            | Self::GetGuildScheduledEvent { guild_id, .. }
            | Self::UpdateGuildScheduledEvent { guild_id, .. } => {
                Path::GuildsIdScheduledEventsId(guild_id)
            }
            Self::GetGuildScheduledEventUsers { guild_id, .. } => {
                Path::GuildsIdScheduledEventsIdUsers(guild_id)
            }
            Self::GetGuildPreview { guild_id } => Path::GuildsIdPreview(guild_id),
            Self::GetGuildVanityUrl { guild_id } => Path::GuildsIdVanityUrl(guild_id),
            Self::GetGuildVoiceRegions { guild_id } => Path::GuildsIdRegions(guild_id),
            Self::GetGuildWelcomeScreen { guild_id }
            | Self::UpdateGuildWelcomeScreen { guild_id } => Path::GuildsIdWelcomeScreen(guild_id),
            Self::GetGuildWebhooks { guild_id } => Path::GuildsIdWebhooks(guild_id),
            Self::GetGuilds { .. } => Path::UsersIdGuilds,
            Self::GetMessage { channel_id, .. } => {
                Path::ChannelsIdMessagesId(Method::Get, channel_id)
            }
            Self::GetNitroStickerPacks { .. } => Path::StickerPacks,
            Self::GetPins { channel_id } | Self::PinMessage { channel_id, .. } => {
                Path::ChannelsIdPins(channel_id)
            }
            Self::GetSKUs { application_id } => Path::ApplicationIdSKUs(application_id),
            Self::GetSticker { .. } => Path::Stickers,
            Self::GetUserConnections => Path::UsersIdConnections,
            Self::GetVoiceRegions => Path::VoiceRegions,
            Self::InteractionCallback { interaction_id, .. } => {
                Path::InteractionCallback(interaction_id)
            }
            Self::LeaveGuild { .. } => Path::UsersIdGuildsId,
            Self::SearchGuildMembers { guild_id, .. } => Path::GuildsIdMembersSearch(guild_id),
            Self::SyncGuildIntegration { guild_id, .. } => {
                Path::GuildsIdIntegrationsIdSync(guild_id)
            }
            Self::UnpinMessage { channel_id, .. } => Path::ChannelsIdPinsMessageId(channel_id),
            Self::GetCurrentUserVoiceState { guild_id, .. }
            | Self::GetUserVoiceState { guild_id, .. }
            | Self::UpdateCurrentUserVoiceState { guild_id }
            | Self::UpdateUserVoiceState { guild_id, .. } => Path::GuildsIdVoiceStates(guild_id),
            Self::UpdateMessage { channel_id, .. } => {
                Path::ChannelsIdMessagesId(Method::Patch, channel_id)
            }
            Self::UpdateNickname { guild_id } => Path::GuildsIdMembersMeNick(guild_id),
            Self::UpdateGuildMfa { guild_id } => Path::GuildsIdMfa(guild_id),
            Self::EndPoll { channel_id, .. } | Self::GetAnswerVoters { channel_id, .. } => {
                Path::ChannelsIdPolls(channel_id)
            }
        }
    }
}

/// Display formatter of the route portion of a URL.
///
/// # Examples
///
/// Create a formatted representation of the [`GetPins`] route:
///
/// ```
/// use twilight_http::routing::Route;
///
/// let route = Route::GetPins { channel_id: 123 };
/// assert_eq!("channels/123/pins", route.to_string());
/// ```
///
/// Create a formatted representation of the [`GetInvite`] route, which
/// includes a query parameter:
///
/// ```
/// use twilight_http::routing::Route;
///
/// let route = Route::GetInvite {
///     code: "twilight-rs",
///     with_counts: true,
/// };
///
/// assert_eq!("invites/twilight-rs?with_counts=true", route.to_string());
/// ```
///
/// [`GetInvite`]: Self::GetInvite
/// [`GetPins`]: Self::GetPins
impl Display for Route<'_> {
    // Notably, we don't use macros like `write!` or `format_args!` due to them
    // both compiling slowly and performing slowly during runtime.
    //
    // See:
    // <https://github.com/rust-lang/rust/issues/76490>
    // <https://github.com/rust-lang/rust/issues/10761>
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Route::AddGuildMember { guild_id, user_id }
            | Route::GetMember { guild_id, user_id }
            | Route::RemoveMember { guild_id, user_id }
            | Route::UpdateMember { guild_id, user_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/members/")?;

                Display::fmt(user_id, f)
            }
            Route::AddMemberRole {
                guild_id,
                role_id,
                user_id,
            }
            | Route::RemoveMemberRole {
                guild_id,
                role_id,
                user_id,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/members/")?;
                Display::fmt(user_id, f)?;
                f.write_str("/roles/")?;

                Display::fmt(role_id, f)
            }
            Route::AddThreadMember {
                channel_id,
                user_id,
            }
            | Route::GetThreadMember {
                channel_id,
                user_id,
            }
            | Route::RemoveThreadMember {
                channel_id,
                user_id,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/thread-members/")?;

                Display::fmt(user_id, f)
            }
            Route::CreateAutoModerationRule { guild_id, .. }
            | Route::GetGuildAutoModerationRules { guild_id, .. } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/auto-moderation/rules")
            }
            Route::CreateChannel { guild_id }
            | Route::GetChannels { guild_id }
            | Route::UpdateGuildChannels { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/channels")
            }
            Route::CreateEmoji { guild_id } | Route::GetEmojis { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/emojis")
            }
            Route::CreateGlobalCommand { application_id }
            | Route::SetGlobalCommands { application_id } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;

                f.write_str("/commands")
            }
            Route::DeleteAutoModerationRule {
                auto_moderation_rule_id,
                guild_id,
                ..
            }
            | Route::GetAutoModerationRule {
                auto_moderation_rule_id,
                guild_id,
                ..
            }
            | Route::UpdateAutoModerationRule {
                auto_moderation_rule_id,
                guild_id,
                ..
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/auto-moderation/rules/")?;

                Display::fmt(auto_moderation_rule_id, f)
            }
            Route::GetAnswerVoters {
                after,
                answer_id,
                channel_id,
                limit,
                message_id,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/polls/")?;
                Display::fmt(message_id, f)?;
                f.write_str("/answers/")?;
                Display::fmt(answer_id, f)?;
                f.write_str("?")?;

                let mut writer = QueryStringFormatter::new(f);
                writer.write_opt_param("after", after.as_ref())?;
                writer.write_opt_param("limit", limit.as_ref())
            }
            Route::GetGlobalCommands {
                application_id,
                with_localizations,
            } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;
                f.write_str("/commands")?;

                let mut writer = QueryStringFormatter::new(f);

                writer.write_opt_param("with_localizations", with_localizations.as_ref())
            }
            Route::CreateGuild => f.write_str("guilds"),
            Route::CreateGuildCommand {
                application_id,
                guild_id,
            }
            | Route::SetGuildCommands {
                application_id,
                guild_id,
            } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;
                f.write_str("/guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/commands")
            }
            Route::GetGuildCommands {
                application_id,
                guild_id,
                with_localizations,
            } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;
                f.write_str("/guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/commands")?;

                let mut writer = QueryStringFormatter::new(f);
                writer.write_opt_param("with_localizations", with_localizations.as_ref())
            }
            Route::CreateGuildFromTemplate { template_code }
            | Route::GetTemplate { template_code } => {
                f.write_str("guilds/templates/")?;

                f.write_str(template_code)
            }
            Route::CreateTestEntitlement { application_id } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;

                f.write_str("/entitlements")
            }
            Route::CreateGuildIntegration { guild_id }
            | Route::GetGuildIntegrations { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/integrations")
            }
            Route::CreateGuildPrune {
                compute_prune_count,
                days,
                guild_id,
                include_roles,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/prune")?;

                let mut writer = QueryStringFormatter::new(f);

                writer.write_opt_param("compute_prune_count", compute_prune_count.as_ref())?;
                writer.write_opt_param("days", days.as_ref())?;

                if !include_roles.is_empty() {
                    writer.write_param("include_roles", &QueryArray(*include_roles))?;
                }

                Ok(())
            }
            Route::CreateGuildScheduledEvent { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/scheduled-events")
            }
            Route::CreateGuildSticker { guild_id, .. }
            | Route::GetGuildStickers { guild_id, .. } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/stickers")
            }
            Route::CreateInvite { channel_id } | Route::GetChannelInvites { channel_id } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;

                f.write_str("/invites")
            }
            Route::CreateMessage { channel_id } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;

                f.write_str("/messages")
            }
            Route::CreatePrivateChannel | Route::GetUserPrivateChannels => {
                f.write_str("users/@me/channels")
            }
            Route::CreateReaction {
                channel_id,
                emoji,
                message_id,
            }
            | Route::DeleteReactionCurrentUser {
                channel_id,
                emoji,
                message_id,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/messages/")?;
                Display::fmt(message_id, f)?;
                f.write_str("/reactions/")?;
                Display::fmt(&emoji, f)?;

                f.write_str("/@me")
            }
            Route::CreateRole { guild_id }
            | Route::GetGuildRoles { guild_id }
            | Route::UpdateRolePositions { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/roles")
            }
            Route::CreateStageInstance { .. } => f.write_str("stage-instances"),
            Route::CreateTemplate { guild_id } | Route::GetTemplates { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/templates")
            }
            Route::CreateForumThread { channel_id } | Route::CreateThread { channel_id } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;

                f.write_str("/threads")
            }
            Route::CreateThreadFromMessage {
                channel_id,
                message_id,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/messages/")?;
                Display::fmt(message_id, f)?;

                f.write_str("/threads")
            }
            Route::CreateTypingTrigger { channel_id } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;

                f.write_str("/typing")
            }
            Route::CreateWebhook { channel_id } | Route::GetChannelWebhooks { channel_id } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;

                f.write_str("/webhooks")
            }
            Route::CrosspostMessage {
                channel_id,
                message_id,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/messages/")?;
                Display::fmt(message_id, f)?;

                f.write_str("/crosspost")
            }
            Route::DeleteBan { guild_id, user_id }
            | Route::GetBan { guild_id, user_id }
            | Route::CreateBan { guild_id, user_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/bans/")?;

                Display::fmt(user_id, f)
            }
            Route::DeleteChannel { channel_id }
            | Route::GetChannel { channel_id }
            | Route::UpdateChannel { channel_id } => {
                f.write_str("channels/")?;

                Display::fmt(channel_id, f)
            }
            Route::DeleteEmoji { emoji_id, guild_id }
            | Route::GetEmoji { emoji_id, guild_id }
            | Route::UpdateEmoji { emoji_id, guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/emojis/")?;

                Display::fmt(emoji_id, f)
            }
            Route::GetEntitlements {
                after,
                application_id,
                before,
                exclude_ended,
                guild_id,
                limit,
                sku_ids,
                user_id,
            } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;
                f.write_str("/entitlements")?;

                f.write_str("?")?;

                if let Some(after) = after {
                    f.write_str("after=")?;
                    Display::fmt(after, f)?;
                }

                if let Some(before) = before {
                    f.write_str("&before=")?;
                    Display::fmt(before, f)?;
                }

                if let Some(exclude_ended) = exclude_ended {
                    f.write_str("&exclude_ended=")?;
                    Display::fmt(exclude_ended, f)?;
                }

                if let Some(guild_id) = guild_id {
                    f.write_str("&guild_id=")?;
                    Display::fmt(guild_id, f)?;
                }

                if let Some(limit) = limit {
                    f.write_str("&limit=")?;
                    Display::fmt(limit, f)?;
                }

                if !sku_ids.is_empty() {
                    let sku_id_count = sku_ids.len() - 1;

                    f.write_str("&sku_ids=")?;

                    for (idx, sku_id) in sku_ids.iter().enumerate() {
                        Display::fmt(sku_id, f)?;

                        if idx < sku_id_count {
                            f.write_str(",")?;
                        }
                    }
                }

                if let Some(user_id) = user_id {
                    f.write_str("&user_id=")?;
                    Display::fmt(user_id, f)?;
                }

                Ok(())
            }
            Route::DeleteGlobalCommand {
                application_id,
                command_id,
            }
            | Route::GetGlobalCommand {
                application_id,
                command_id,
            }
            | Route::UpdateGlobalCommand {
                application_id,
                command_id,
            } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;
                f.write_str("/commands/")?;

                Display::fmt(command_id, f)
            }
            Route::DeleteGuild { guild_id } | Route::UpdateGuild { guild_id } => {
                f.write_str("guilds/")?;

                Display::fmt(guild_id, f)
            }
            Route::DeleteGuildCommand {
                application_id,
                command_id,
                guild_id,
            }
            | Route::GetGuildCommand {
                application_id,
                command_id,
                guild_id,
            }
            | Route::UpdateGuildCommand {
                application_id,
                command_id,
                guild_id,
            } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;
                f.write_str("/guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/commands/")?;

                Display::fmt(command_id, f)
            }
            Route::DeleteGuildIntegration {
                guild_id,
                integration_id,
            }
            | Route::UpdateGuildIntegration {
                guild_id,
                integration_id,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/integrations/")?;

                Display::fmt(integration_id, f)
            }
            Route::DeleteInteractionOriginal {
                application_id,
                interaction_token,
            }
            | Route::GetInteractionOriginal {
                application_id,
                interaction_token,
            }
            | Route::UpdateInteractionOriginal {
                application_id,
                interaction_token,
            } => {
                f.write_str("webhooks/")?;
                Display::fmt(application_id, f)?;
                f.write_str("/")?;
                f.write_str(interaction_token)?;

                f.write_str("/messages/@original")
            }
            Route::DeleteInvite { code } => {
                f.write_str("invites/")?;

                f.write_str(code)
            }
            Route::DeleteMessageReactions {
                channel_id,
                message_id,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/messages/")?;
                Display::fmt(message_id, f)?;

                f.write_str("/reactions")
            }
            Route::DeleteMessageSpecificReaction {
                channel_id,
                message_id,
                emoji,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/messages/")?;
                Display::fmt(message_id, f)?;
                f.write_str("/reactions/")?;

                Display::fmt(&emoji, f)
            }
            Route::DeleteMessage {
                channel_id,
                message_id,
            }
            | Route::GetMessage {
                channel_id,
                message_id,
            }
            | Route::UpdateMessage {
                channel_id,
                message_id,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/messages/")?;

                Display::fmt(message_id, f)
            }
            Route::DeleteMessages { channel_id } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;

                f.write_str("/messages/bulk-delete")
            }
            Route::DeletePermissionOverwrite {
                channel_id,
                target_id,
            }
            | Route::UpdatePermissionOverwrite {
                channel_id,
                target_id,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/permissions/")?;

                Display::fmt(target_id, f)
            }
            Route::DeleteReaction {
                channel_id,
                emoji,
                message_id,
                user_id,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/messages/")?;
                Display::fmt(message_id, f)?;
                f.write_str("/reactions/")?;
                Display::fmt(&emoji, f)?;
                f.write_str("/")?;

                Display::fmt(user_id, f)
            }
            Route::DeleteRole { guild_id, role_id }
            | Route::GetRole { guild_id, role_id }
            | Route::UpdateRole { guild_id, role_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/roles/")?;

                Display::fmt(role_id, f)
            }
            Route::DeleteStageInstance { channel_id }
            | Route::GetStageInstance { channel_id }
            | Route::UpdateStageInstance { channel_id } => {
                f.write_str("stage-instances/")?;

                Display::fmt(channel_id, f)
            }
            Route::DeleteTemplate {
                guild_id,
                template_code,
            }
            | Route::SyncTemplate {
                guild_id,
                template_code,
            }
            | Route::UpdateTemplate {
                guild_id,
                template_code,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/templates/")?;

                f.write_str(template_code)
            }
            Route::DeleteWebhookMessage {
                message_id,
                thread_id,
                token,
                webhook_id,
            }
            | Route::GetFollowupMessage {
                application_id: webhook_id,
                interaction_token: token,
                thread_id,
                message_id,
            }
            | Route::GetWebhookMessage {
                message_id,
                token,
                thread_id,
                webhook_id,
            }
            | Route::UpdateWebhookMessage {
                message_id,
                thread_id,
                token,
                webhook_id,
            } => {
                f.write_str("webhooks/")?;
                Display::fmt(webhook_id, f)?;
                f.write_str("/")?;
                f.write_str(token)?;
                f.write_str("/messages/")?;
                Display::fmt(message_id, f)?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("thread_id", thread_id.as_ref())
            }
            Route::DeleteWebhook { token, webhook_id }
            | Route::GetWebhook { token, webhook_id }
            | Route::UpdateWebhook { token, webhook_id } => {
                f.write_str("webhooks/")?;
                Display::fmt(webhook_id, f)?;

                if let Some(token) = token {
                    f.write_str("/")?;
                    f.write_str(token)?;
                }

                Ok(())
            }
            Route::EndPoll {
                channel_id,
                message_id,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/polls/")?;
                Display::fmt(message_id, f)?;

                f.write_str("/expire")
            }
            Route::ExecuteWebhook {
                thread_id,
                token,
                wait,
                webhook_id,
            } => {
                f.write_str("webhooks/")?;
                Display::fmt(webhook_id, f)?;
                f.write_str("/")?;
                f.write_str(token)?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("thread_id", thread_id.as_ref())?;
                query_formatter.write_opt_param("wait", wait.as_ref())
            }
            Route::DeleteTestEntitlement {
                application_id,
                entitlement_id,
            } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;
                f.write_str("/entitlements/")?;

                Display::fmt(entitlement_id, f)
            }
            Route::FollowNewsChannel { channel_id } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;

                f.write_str("/followers")
            }
            Route::GetActiveThreads { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/threads/active")
            }
            Route::DeleteApplicationEmoji {
                application_id,
                emoji_id,
            }
            | Route::UpdateApplicationEmoji {
                application_id,
                emoji_id,
            } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;
                f.write_str("/emojis/")?;

                Display::fmt(emoji_id, f)
            }
            Route::GetApplicationEmojis { application_id }
            | Route::AddApplicationEmoji { application_id } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;

                f.write_str("/emojis")
            }
            Route::GetAuditLogs {
                action_type,
                after,
                before,
                guild_id,
                limit,
                user_id,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/audit-logs")?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("action_type", action_type.as_ref())?;
                query_formatter.write_opt_param("after", after.as_ref())?;
                query_formatter.write_opt_param("before", before.as_ref())?;
                query_formatter.write_opt_param("limit", limit.as_ref())?;
                query_formatter.write_opt_param("user_id", user_id.as_ref())
            }
            Route::GetBans { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/bans")
            }
            Route::GetBansWithParameters {
                after,
                before,
                guild_id,
                limit,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/bans")?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("after", after.as_ref())?;
                query_formatter.write_opt_param("before", before.as_ref())?;
                query_formatter.write_opt_param("limit", limit.as_ref())
            }
            Route::GetGatewayBot => f.write_str("gateway/bot"),
            Route::GetCommandPermissions {
                application_id,
                command_id,
                guild_id,
            }
            | Route::UpdateCommandPermissions {
                application_id,
                command_id,
                guild_id,
            } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;
                f.write_str("/guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/commands/")?;
                Display::fmt(command_id, f)?;

                f.write_str("/permissions")
            }
            Route::GetCurrentAuthorizationInformation => f.write_str("oauth2/@me"),
            Route::GetCurrentUserApplicationInfo | Route::UpdateCurrentUserApplication => {
                f.write_str("applications/@me")
            }
            Route::GetCurrentUser | Route::UpdateCurrentUser => f.write_str("users/@me"),
            Route::GetCurrentUserGuildMember { guild_id } => {
                f.write_str("users/@me/guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/member")
            }
            Route::GetGateway => f.write_str("gateway"),
            Route::GetGuild {
                guild_id,
                with_counts,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                let mut query_formatter = QueryStringFormatter::new(f);

                if *with_counts {
                    query_formatter.write_param("with_counts", &true)?;
                }

                Ok(())
            }
            Route::GetGuildCommandPermissions {
                application_id,
                guild_id,
            } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;
                f.write_str("/guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/commands/permissions")
            }
            Route::GetGuildInvites { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/invites")
            }
            Route::GetGuildMembers {
                after,
                guild_id,
                limit,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/members")?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("after", after.as_ref())?;
                query_formatter.write_opt_param("limit", limit.as_ref())
            }
            Route::GetGuildOnboarding { guild_id } | Route::UpdateGuildOnboarding { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/onboarding")
            }
            Route::GetGuildPreview { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/preview")
            }
            Route::GetGuildPruneCount {
                days,
                guild_id,
                include_roles,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/prune")?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("days", days.as_ref())?;

                if !include_roles.is_empty() {
                    query_formatter.write_param("include_roles", &QueryArray(*include_roles))?;
                }

                Ok(())
            }
            Route::GetGuildScheduledEvent {
                guild_id,
                scheduled_event_id,
                with_user_count,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/scheduled-events/")?;
                Display::fmt(scheduled_event_id, f)?;

                let mut query_formatter = QueryStringFormatter::new(f);

                if *with_user_count {
                    query_formatter.write_param("with_user_count", &true)?;
                }

                Ok(())
            }
            Route::GetGuildScheduledEventUsers {
                after,
                before,
                guild_id,
                limit,
                scheduled_event_id,
                with_member,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/scheduled-events/")?;
                Display::fmt(scheduled_event_id, f)?;
                f.write_str("/users")?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("after", after.as_ref())?;
                query_formatter.write_opt_param("before", before.as_ref())?;
                query_formatter.write_opt_param("limit", limit.as_ref())?;

                if *with_member {
                    query_formatter.write_param("with_member", &true)?;
                }

                Ok(())
            }
            Route::GetGuildScheduledEvents {
                guild_id,
                with_user_count,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/scheduled-events")?;

                let mut query_formatter = QueryStringFormatter::new(f);

                if *with_user_count {
                    query_formatter.write_param("with_user_count", &true)?;
                }

                Ok(())
            }
            Route::GetGuildSticker {
                guild_id,
                sticker_id,
                ..
            }
            | Route::DeleteGuildSticker {
                guild_id,
                sticker_id,
                ..
            }
            | Route::UpdateGuildSticker {
                guild_id,
                sticker_id,
                ..
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/stickers/")?;

                Display::fmt(sticker_id, f)
            }
            Route::GetGuildVanityUrl { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/vanity-url")
            }
            Route::GetGuildVoiceRegions { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/regions")
            }
            Route::GetGuildWelcomeScreen { guild_id }
            | Route::UpdateGuildWelcomeScreen { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/welcome-screen")
            }
            Route::GetGuildWebhooks { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/webhooks")
            }
            Route::GetGuildWidget { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/widget.json")
            }
            Route::GetGuildWidgetSettings { guild_id }
            | Route::UpdateGuildWidgetSettings { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/widget")
            }
            Route::GetGuilds {
                after,
                before,
                limit,
            } => {
                f.write_str("users/@me/guilds")?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("after", after.as_ref())?;
                query_formatter.write_opt_param("before", before.as_ref())?;
                query_formatter.write_opt_param("limit", limit.as_ref())
            }
            Route::GetInvite { code, with_counts } => {
                f.write_str("invites/")?;
                f.write_str(code)?;

                let mut query_formatter = QueryStringFormatter::new(f);

                if *with_counts {
                    query_formatter.write_param("with_counts", &true)?;
                }

                Ok(())
            }
            Route::GetInviteWithExpiration {
                code,
                with_counts,
                with_expiration,
            } => {
                f.write_str("invites/")?;
                f.write_str(code)?;

                let mut query_formatter = QueryStringFormatter::new(f);

                if *with_counts {
                    query_formatter.write_param("with_counts", &true)?;
                }

                if *with_expiration {
                    query_formatter.write_param("with_expiration", &true)?;
                }

                Ok(())
            }
            Route::GetMessages {
                channel_id,
                after,
                around,
                before,
                limit,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/messages")?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("after", after.as_ref())?;
                query_formatter.write_opt_param("around", around.as_ref())?;
                query_formatter.write_opt_param("before", before.as_ref())?;
                query_formatter.write_opt_param("limit", limit.as_ref())
            }
            Route::GetNitroStickerPacks { .. } => f.write_str("sticker-packs"),
            Route::GetPins { channel_id } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;

                f.write_str("/pins")
            }
            Route::GetJoinedPrivateArchivedThreads {
                before,
                channel_id,
                limit,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/users/@me/threads/archived/private")?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("before", before.as_ref())?;
                query_formatter.write_opt_param("limit", limit.as_ref())
            }
            Route::GetPrivateArchivedThreads {
                before,
                channel_id,
                limit,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/threads/archived/private")?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("before", before.as_ref())?;
                query_formatter.write_opt_param("limit", limit.as_ref())
            }
            Route::GetPublicArchivedThreads {
                before,
                channel_id,
                limit,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/threads/archived/public")?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("before", before.as_ref())?;
                query_formatter.write_opt_param("limit", limit.as_ref())
            }
            Route::GetReactionUsers {
                after,
                channel_id,
                emoji,
                limit,
                message_id,
                kind,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/messages/")?;
                Display::fmt(message_id, f)?;
                f.write_str("/reactions/")?;
                Display::fmt(&emoji, f)?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("after", after.as_ref())?;
                query_formatter.write_opt_param("limit", limit.as_ref())?;
                query_formatter.write_opt_param("type", kind.as_ref())
            }
            Route::GetSticker { sticker_id } => {
                f.write_str("stickers/")?;

                Display::fmt(sticker_id, f)
            }
            Route::GetThreadMembers {
                after,
                channel_id,
                limit,
                with_member,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/thread-members")?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter.write_opt_param("after", after.as_ref())?;
                query_formatter.write_opt_param("limit", limit.as_ref())?;
                query_formatter.write_opt_param("with_member", with_member.as_ref())
            }
            Route::GetUserConnections => f.write_str("users/@me/connections"),
            Route::GetUser { user_id } => {
                f.write_str("users/")?;

                Display::fmt(user_id, f)
            }
            Route::GetVoiceRegions => f.write_str("voice/regions"),
            Route::InteractionCallback {
                interaction_id,
                interaction_token,
                with_response,
            } => {
                f.write_str("interactions/")?;
                Display::fmt(interaction_id, f)?;
                f.write_str("/")?;
                f.write_str(interaction_token)?;

                f.write_str("/callback")?;

                if *with_response {
                    f.write_str("?with_response=true")?;
                }

                Ok(())
            }
            Route::JoinThread { channel_id } | Route::LeaveThread { channel_id } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;

                f.write_str("/thread-members/@me")
            }
            Route::LeaveGuild { guild_id } => {
                f.write_str("users/@me/guilds/")?;

                Display::fmt(guild_id, f)
            }
            Route::PinMessage {
                channel_id,
                message_id,
            }
            | Route::UnpinMessage {
                channel_id,
                message_id,
            } => {
                f.write_str("channels/")?;
                Display::fmt(channel_id, f)?;
                f.write_str("/pins/")?;

                Display::fmt(message_id, f)
            }
            Route::SearchGuildMembers {
                guild_id,
                limit,
                query,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/members/search")?;

                let mut query_formatter = QueryStringFormatter::new(f);

                query_formatter
                    .write_param("query", &utf8_percent_encode(query, NON_ALPHANUMERIC))?;
                query_formatter.write_opt_param("limit", limit.as_ref())
            }
            Route::SyncGuildIntegration {
                guild_id,
                integration_id,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/integrations/")?;
                Display::fmt(integration_id, f)?;

                f.write_str("/sync")
            }
            Route::UpdateCurrentMember { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/members/@me")
            }
            Route::GetCurrentUserVoiceState { guild_id }
            | Route::UpdateCurrentUserVoiceState { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/voice-states/@me")
            }
            Route::DeleteGuildScheduledEvent {
                guild_id,
                scheduled_event_id,
            }
            | Route::UpdateGuildScheduledEvent {
                guild_id,
                scheduled_event_id,
            } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/scheduled-events/")?;

                Display::fmt(scheduled_event_id, f)
            }
            Route::UpdateNickname { guild_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/members/@me/nick")
            }
            Route::GetUserVoiceState { guild_id, user_id }
            | Route::UpdateUserVoiceState { guild_id, user_id } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;
                f.write_str("/voice-states/")?;

                Display::fmt(user_id, f)
            }
            Route::UpdateGuildMfa { guild_id, .. } => {
                f.write_str("guilds/")?;
                Display::fmt(guild_id, f)?;

                f.write_str("/mfa")
            }
            Route::GetSKUs { application_id } => {
                f.write_str("applications/")?;
                Display::fmt(application_id, f)?;

                f.write_str("/skus")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Route;
    use crate::request::{channel::reaction::RequestReactionType, Method};
    use twilight_model::id::Id;

    /// Test a route for each method.
    #[test]
    fn methods() {
        assert_eq!(
            Method::Delete,
            Route::DeleteInvite {
                code: "twilight-rs",
            }
            .method()
        );
        assert_eq!(
            Method::Get,
            Route::GetInvite {
                code: "twilight-rs",
                with_counts: false,
            }
            .method()
        );
        assert_eq!(
            Method::Patch,
            Route::UpdateMessage {
                channel_id: 123,
                message_id: 456,
            }
            .method()
        );
        assert_eq!(Method::Post, Route::CreateGuild.method());
        assert_eq!(
            Method::Put,
            Route::SyncTemplate {
                guild_id: 123,
                template_code: "abc",
            }
            .method()
        );
    }

    // Test display implementation

    const APPLICATION_ID: u64 = 1;
    const CHANNEL_ID: u64 = 2;
    const CODE: &str = "invitecode";
    const COMMAND_ID: u64 = 3;
    const EMOJI_ID: u64 = 4;
    const GUILD_ID: u64 = 5;
    const INTERACTION_ID: u64 = 6;
    const INTERACTION_TOKEN: &str = "interactiontoken";
    const INTEGRATION_ID: u64 = 7;
    const MESSAGE_ID: u64 = 8;
    const ROLE_ID: u64 = 9;
    const STICKER_ID: u64 = 10;
    const TEMPLATE_CODE: &str = "templatecode";
    const USER_ID: u64 = 11;
    const SCHEDULED_EVENT_ID: u64 = 12;
    const AUTO_MODERATION_RULE_ID: u64 = 13;

    const fn emoji() -> RequestReactionType<'static> {
        RequestReactionType::Custom {
            id: Id::new(EMOJI_ID),
            name: None,
        }
    }

    #[test]
    fn get_public_archived_threads() {
        let route = Route::GetPublicArchivedThreads {
            channel_id: 1,
            before: Some("2021-01-01T00:00:00Z"),
            limit: None,
        };

        assert_eq!(
            "channels/1/threads/archived/public?before=2021-01-01T00:00:00Z",
            route.to_string()
        );
    }

    #[test]
    fn update_webhook_message_thread_id() {
        let route = Route::UpdateWebhookMessage {
            message_id: 1,
            thread_id: Some(2),
            token: "token",
            webhook_id: 3,
        };

        assert_eq!("webhooks/3/token/messages/1?thread_id=2", route.to_string());
    }

    #[test]
    fn add_guild_member() {
        let route = Route::AddGuildMember {
            guild_id: GUILD_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/members/{USER_ID}")
        );
    }

    #[test]
    fn get_member() {
        let route = Route::GetMember {
            guild_id: GUILD_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/members/{USER_ID}")
        );
    }

    #[test]
    fn remove_member() {
        let route = Route::RemoveMember {
            guild_id: GUILD_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/members/{USER_ID}")
        );
    }

    #[test]
    fn update_member() {
        let route = Route::UpdateMember {
            guild_id: GUILD_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/members/{USER_ID}")
        );
    }

    #[test]
    fn add_member_role() {
        let route = Route::AddMemberRole {
            guild_id: GUILD_ID,
            role_id: ROLE_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/members/{USER_ID}/roles/{ROLE_ID}")
        );
    }

    #[test]
    fn remove_member_role() {
        let route = Route::RemoveMemberRole {
            guild_id: GUILD_ID,
            role_id: ROLE_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/members/{USER_ID}/roles/{ROLE_ID}")
        );
    }

    #[test]
    fn add_thread_member() {
        let route = Route::AddThreadMember {
            channel_id: CHANNEL_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/thread-members/{USER_ID}")
        );
    }

    #[test]
    fn get_thread_member() {
        let route = Route::GetThreadMember {
            channel_id: CHANNEL_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/thread-members/{USER_ID}")
        );
    }

    #[test]
    fn remove_thread_member() {
        let route = Route::RemoveThreadMember {
            channel_id: CHANNEL_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/thread-members/{USER_ID}")
        );
    }

    #[test]
    fn create_channel() {
        let route = Route::CreateChannel { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/channels"));
    }

    #[test]
    fn get_channels() {
        let route = Route::GetChannels { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/channels"));
    }

    #[test]
    fn update_guild_channels() {
        let route = Route::UpdateGuildChannels { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/channels"));
    }

    #[test]
    fn create_emoji() {
        let route = Route::CreateEmoji { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/emojis"));
    }

    #[test]
    fn get_emojis() {
        let route = Route::GetEmojis { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/emojis"));
    }

    #[test]
    fn create_global_command() {
        let route = Route::CreateGlobalCommand {
            application_id: APPLICATION_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/commands")
        );
    }

    #[test]
    fn get_global_commands() {
        let route = Route::GetGlobalCommands {
            application_id: APPLICATION_ID,
            with_localizations: Some(true),
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/commands?with_localizations=true")
        );

        let route = Route::GetGlobalCommands {
            application_id: APPLICATION_ID,
            with_localizations: None,
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/commands")
        );
    }

    #[test]
    fn set_global_commands() {
        let route = Route::SetGlobalCommands {
            application_id: APPLICATION_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/commands")
        );
    }

    #[test]
    fn create_guild() {
        let route = Route::CreateGuild;
        assert_eq!(route.to_string(), "guilds");
    }

    #[test]
    fn create_guild_command() {
        let route = Route::CreateGuildCommand {
            application_id: APPLICATION_ID,
            guild_id: GUILD_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/guilds/{GUILD_ID}/commands")
        );
    }

    #[test]
    fn get_guild_commands() {
        let route = Route::GetGuildCommands {
            application_id: APPLICATION_ID,
            guild_id: GUILD_ID,
            with_localizations: Some(true),
        };
        assert_eq!(
            route.to_string(),
            format!(
                "applications/{APPLICATION_ID}/guilds/{GUILD_ID}/commands?with_localizations=true"
            )
        );

        let route = Route::GetGuildCommands {
            application_id: APPLICATION_ID,
            guild_id: GUILD_ID,
            with_localizations: None,
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/guilds/{GUILD_ID}/commands")
        );
    }

    #[test]
    fn set_guild_commands() {
        let route = Route::SetGuildCommands {
            application_id: APPLICATION_ID,
            guild_id: GUILD_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/guilds/{GUILD_ID}/commands")
        );
    }

    #[test]
    fn create_guild_from_template() {
        let route = Route::CreateGuildFromTemplate {
            template_code: TEMPLATE_CODE,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/templates/{TEMPLATE_CODE}")
        );
    }

    #[test]
    fn get_template() {
        let route = Route::GetTemplate {
            template_code: TEMPLATE_CODE,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/templates/{TEMPLATE_CODE}")
        );
    }

    #[test]
    fn create_guild_integration() {
        let route = Route::CreateGuildIntegration { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/integrations"));
    }

    #[test]
    fn get_guild_integrations() {
        let route = Route::GetGuildIntegrations { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/integrations"));
    }

    #[test]
    fn create_guild_sticker() {
        let route = Route::CreateGuildSticker { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/stickers"));
    }

    #[test]
    fn get_guild_stickers() {
        let route = Route::GetGuildStickers { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/stickers"));
    }

    #[test]
    fn create_invite() {
        let route = Route::CreateInvite {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("channels/{CHANNEL_ID}/invites"));
    }

    #[test]
    fn get_channel_invites() {
        let route = Route::GetChannelInvites {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("channels/{CHANNEL_ID}/invites"));
    }

    #[test]
    fn create_message() {
        let route = Route::CreateMessage {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("channels/{CHANNEL_ID}/messages"));
    }

    #[test]
    fn create_private_channel() {
        let route = Route::CreatePrivateChannel;
        assert_eq!(route.to_string(), "users/@me/channels");
    }

    #[test]
    fn get_user_private_channels() {
        let route = Route::GetUserPrivateChannels;
        assert_eq!(route.to_string(), "users/@me/channels");
    }

    #[test]
    fn create_reaction() {
        let emoji = emoji();

        let route = Route::CreateReaction {
            channel_id: CHANNEL_ID,
            emoji: &emoji,
            message_id: MESSAGE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/messages/{MESSAGE_ID}/reactions/{emoji}/@me")
        );
    }

    #[test]
    fn delete_reaction_current_user() {
        let emoji = emoji();

        let route = Route::DeleteReactionCurrentUser {
            channel_id: CHANNEL_ID,
            emoji: &emoji,
            message_id: MESSAGE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/messages/{MESSAGE_ID}/reactions/{emoji}/@me")
        );
    }

    #[test]
    fn create_role() {
        let route = Route::CreateRole { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/roles"));
    }

    #[test]
    fn get_guild_roles() {
        let route = Route::GetGuildRoles { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/roles"));
    }

    #[test]
    fn update_role_positions() {
        let route = Route::UpdateRolePositions { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/roles"));
    }

    #[test]
    fn create_stage_instance() {
        let route = Route::CreateStageInstance;
        assert_eq!(route.to_string(), "stage-instances");
    }

    #[test]
    fn create_template() {
        let route = Route::CreateTemplate { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/templates"));
    }

    #[test]
    fn get_templates() {
        let route = Route::GetTemplates { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/templates"));
    }

    #[test]
    fn create_thread() {
        let route = Route::CreateThread {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("channels/{CHANNEL_ID}/threads"));
    }

    #[test]
    fn create_thread_from_message() {
        let route = Route::CreateThreadFromMessage {
            channel_id: CHANNEL_ID,
            message_id: MESSAGE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/messages/{MESSAGE_ID}/threads")
        );
    }

    #[test]
    fn create_typing_trigger() {
        let route = Route::CreateTypingTrigger {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("channels/{CHANNEL_ID}/typing"));
    }

    #[test]
    fn create_webhook() {
        let route = Route::CreateWebhook {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("channels/{CHANNEL_ID}/webhooks"));
    }

    #[test]
    fn get_channel_webhooks() {
        let route = Route::GetChannelWebhooks {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("channels/{CHANNEL_ID}/webhooks"));
    }

    #[test]
    fn crosspost_message() {
        let route = Route::CrosspostMessage {
            channel_id: CHANNEL_ID,
            message_id: MESSAGE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/messages/{MESSAGE_ID}/crosspost")
        );
    }

    #[test]
    fn delete_ban() {
        let route = Route::DeleteBan {
            guild_id: GUILD_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/bans/{USER_ID}")
        );
    }

    #[test]
    fn get_ban() {
        let route = Route::GetBan {
            guild_id: GUILD_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/bans/{USER_ID}")
        );
    }

    #[test]
    fn delete_channel() {
        let route = Route::DeleteChannel {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("channels/{CHANNEL_ID}"));
    }

    #[test]
    fn get_channel() {
        let route = Route::GetChannel {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("channels/{CHANNEL_ID}"));
    }

    #[test]
    fn update_channel() {
        let route = Route::UpdateChannel {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("channels/{CHANNEL_ID}"));
    }

    #[test]
    fn delete_emoji() {
        let route = Route::DeleteEmoji {
            emoji_id: EMOJI_ID,
            guild_id: GUILD_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/emojis/{EMOJI_ID}")
        );
    }

    #[test]
    fn get_emoji() {
        let route = Route::GetEmoji {
            emoji_id: EMOJI_ID,
            guild_id: GUILD_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/emojis/{EMOJI_ID}")
        );
    }

    #[test]
    fn update_emoji() {
        let route = Route::UpdateEmoji {
            emoji_id: EMOJI_ID,
            guild_id: GUILD_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/emojis/{EMOJI_ID}")
        );
    }

    #[test]
    fn delete_global_command() {
        let route = Route::DeleteGlobalCommand {
            application_id: APPLICATION_ID,
            command_id: COMMAND_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/commands/{COMMAND_ID}")
        );
    }

    #[test]
    fn get_global_command() {
        let route = Route::GetGlobalCommand {
            application_id: APPLICATION_ID,
            command_id: COMMAND_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/commands/{COMMAND_ID}")
        );
    }

    #[test]
    fn update_global_command() {
        let route = Route::UpdateGlobalCommand {
            application_id: APPLICATION_ID,
            command_id: COMMAND_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/commands/{COMMAND_ID}")
        );
    }

    #[test]
    fn delete_guild() {
        let route = Route::DeleteGuild { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}"));
    }

    #[test]
    fn update_guild() {
        let route = Route::UpdateGuild { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}"));
    }

    #[test]
    fn delete_guild_command() {
        let route = Route::DeleteGuildCommand {
            application_id: APPLICATION_ID,
            command_id: COMMAND_ID,
            guild_id: GUILD_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/guilds/{GUILD_ID}/commands/{COMMAND_ID}")
        );
    }

    #[test]
    fn get_guild_command() {
        let route = Route::GetGuildCommand {
            application_id: APPLICATION_ID,
            command_id: COMMAND_ID,
            guild_id: GUILD_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/guilds/{GUILD_ID}/commands/{COMMAND_ID}")
        );
    }

    #[test]
    fn update_guild_command() {
        let route = Route::UpdateGuildCommand {
            application_id: APPLICATION_ID,
            command_id: COMMAND_ID,
            guild_id: GUILD_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/guilds/{GUILD_ID}/commands/{COMMAND_ID}")
        );
    }

    #[test]
    fn delete_guild_integration() {
        let route = Route::DeleteGuildIntegration {
            guild_id: GUILD_ID,
            integration_id: INTEGRATION_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/integrations/{INTEGRATION_ID}")
        );
    }

    #[test]
    fn update_guild_integration() {
        let route = Route::UpdateGuildIntegration {
            guild_id: GUILD_ID,
            integration_id: INTEGRATION_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/integrations/{INTEGRATION_ID}")
        );
    }

    #[test]
    fn delete_interaction_original() {
        let route = Route::DeleteInteractionOriginal {
            application_id: APPLICATION_ID,
            interaction_token: INTERACTION_TOKEN,
        };
        assert_eq!(
            route.to_string(),
            format!("webhooks/{APPLICATION_ID}/{INTERACTION_TOKEN}/messages/@original")
        );
    }

    #[test]
    fn get_interaction_original() {
        let route = Route::GetInteractionOriginal {
            application_id: APPLICATION_ID,
            interaction_token: INTERACTION_TOKEN,
        };
        assert_eq!(
            route.to_string(),
            format!("webhooks/{APPLICATION_ID}/{INTERACTION_TOKEN}/messages/@original")
        );
    }

    #[test]
    fn update_interaction_original() {
        let route = Route::UpdateInteractionOriginal {
            application_id: APPLICATION_ID,
            interaction_token: INTERACTION_TOKEN,
        };
        assert_eq!(
            route.to_string(),
            format!("webhooks/{APPLICATION_ID}/{INTERACTION_TOKEN}/messages/@original")
        );
    }

    #[test]
    fn delete_invite() {
        let route = Route::DeleteInvite { code: CODE };
        assert_eq!(route.to_string(), format!("invites/{CODE}"));
    }

    #[test]
    fn delete_message_reactions() {
        let route = Route::DeleteMessageReactions {
            channel_id: CHANNEL_ID,
            message_id: MESSAGE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/messages/{MESSAGE_ID}/reactions")
        );
    }

    #[test]
    fn delete_message_specific_reaction() {
        let emoji = emoji();

        let route = Route::DeleteMessageSpecificReaction {
            channel_id: CHANNEL_ID,
            message_id: MESSAGE_ID,
            emoji: &emoji,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/messages/{MESSAGE_ID}/reactions/{emoji}")
        );
    }

    #[test]
    fn delete_message() {
        let route = Route::DeleteMessage {
            channel_id: CHANNEL_ID,
            message_id: MESSAGE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/messages/{MESSAGE_ID}")
        );
    }

    #[test]
    fn get_message() {
        let route = Route::GetMessage {
            channel_id: CHANNEL_ID,
            message_id: MESSAGE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/messages/{MESSAGE_ID}")
        );
    }

    #[test]
    fn update_message() {
        let route = Route::UpdateMessage {
            channel_id: CHANNEL_ID,
            message_id: MESSAGE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/messages/{MESSAGE_ID}")
        );
    }

    #[test]
    fn delete_messages() {
        let route = Route::DeleteMessages {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/messages/bulk-delete")
        );
    }

    #[test]
    fn delete_permission_overwrite() {
        let route = Route::DeletePermissionOverwrite {
            channel_id: CHANNEL_ID,
            target_id: ROLE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/permissions/{ROLE_ID}")
        );
    }

    #[test]
    fn update_permission_overwrite() {
        let route = Route::UpdatePermissionOverwrite {
            channel_id: CHANNEL_ID,
            target_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/permissions/{USER_ID}")
        );
    }

    #[test]
    fn delete_reaction() {
        let emoji = emoji();

        let route = Route::DeleteReaction {
            channel_id: CHANNEL_ID,
            emoji: &emoji,
            message_id: MESSAGE_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/messages/{MESSAGE_ID}/reactions/{emoji}/{USER_ID}")
        );
    }

    #[test]
    fn delete_role() {
        let route = Route::DeleteRole {
            guild_id: GUILD_ID,
            role_id: ROLE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/roles/{ROLE_ID}")
        );
    }

    #[test]
    fn update_role() {
        let route = Route::UpdateRole {
            guild_id: GUILD_ID,
            role_id: ROLE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/roles/{ROLE_ID}")
        );
    }

    #[test]
    fn delete_stage_instance() {
        let route = Route::DeleteStageInstance {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("stage-instances/{CHANNEL_ID}"));
    }

    #[test]
    fn get_stage_instance() {
        let route = Route::GetStageInstance {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("stage-instances/{CHANNEL_ID}"));
    }

    #[test]
    fn update_stage_instance() {
        let route = Route::UpdateStageInstance {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("stage-instances/{CHANNEL_ID}"));
    }

    #[test]
    fn delete_template() {
        let route = Route::DeleteTemplate {
            guild_id: GUILD_ID,
            template_code: TEMPLATE_CODE,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/templates/{TEMPLATE_CODE}")
        );
    }

    #[test]
    fn sync_template() {
        let route = Route::SyncTemplate {
            guild_id: GUILD_ID,
            template_code: TEMPLATE_CODE,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/templates/{TEMPLATE_CODE}")
        );
    }

    #[test]
    fn update_template() {
        let route = Route::UpdateTemplate {
            guild_id: GUILD_ID,
            template_code: TEMPLATE_CODE,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/templates/{TEMPLATE_CODE}")
        );
    }

    #[test]
    fn follow_news_channel() {
        let route = Route::FollowNewsChannel {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/followers")
        );
    }

    #[test]
    fn get_active_threads() {
        let route = Route::GetActiveThreads { guild_id: GUILD_ID };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/threads/active")
        );
    }

    #[test]
    fn get_bans() {
        let route = Route::GetBans { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/bans"));
    }

    #[test]
    fn get_bans_with_parameters() {
        let route = Route::GetBansWithParameters {
            after: None,
            before: None,
            guild_id: GUILD_ID,
            limit: None,
        };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/bans"));

        let route = Route::GetBansWithParameters {
            after: Some(USER_ID),
            before: None,
            guild_id: GUILD_ID,
            limit: None,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/bans?after={USER_ID}")
        );

        let route = Route::GetBansWithParameters {
            after: None,
            before: Some(USER_ID),
            guild_id: GUILD_ID,
            limit: None,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/bans?before={USER_ID}")
        );

        let route = Route::GetBansWithParameters {
            after: None,
            before: None,
            guild_id: GUILD_ID,
            limit: Some(100),
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/bans?limit={limit}", limit = 100)
        );

        let route = Route::GetBansWithParameters {
            after: Some(USER_ID),
            before: Some(USER_ID + 100),
            guild_id: GUILD_ID,
            limit: Some(25),
        };
        assert_eq!(
            route.to_string(),
            format!(
                "guilds/{GUILD_ID}/bans?after={USER_ID}&before={before}&limit={limit}",
                before = USER_ID + 100,
                limit = 25,
            )
        );
    }

    #[test]
    fn get_gateway_bot() {
        let route = Route::GetGatewayBot;
        assert_eq!(route.to_string(), "gateway/bot");
    }

    #[test]
    fn get_entitlements() {
        let route = Route::GetEntitlements {
            after: Some(32),
            application_id: 1,
            before: Some(2),
            exclude_ended: Some(true),
            guild_id: Some(42),
            limit: Some(99),
            sku_ids: &[Id::new(7)],
            user_id: Some(11),
        };

        assert_eq!(
            route.to_string(),
            "applications/1/entitlements?after=32&before=2&exclude_ended=true&guild_id=42&limit=99&sku_ids=7&user_id=11"
        );
    }

    #[test]
    fn create_test_entitlement() {
        let route = Route::CreateTestEntitlement { application_id: 1 };

        assert_eq!(route.to_string(), "applications/1/entitlements");
    }

    #[test]
    fn get_command_permissions() {
        let route = Route::GetCommandPermissions {
            application_id: APPLICATION_ID,
            command_id: COMMAND_ID,
            guild_id: GUILD_ID,
        };
        assert_eq!(
            route.to_string(),
            format!(
                "applications/{APPLICATION_ID}/guilds/{GUILD_ID}/commands/{COMMAND_ID}/permissions"
            )
        );
    }

    #[test]
    fn update_command_permissions() {
        let route = Route::UpdateCommandPermissions {
            application_id: APPLICATION_ID,
            command_id: COMMAND_ID,
            guild_id: GUILD_ID,
        };
        assert_eq!(
            route.to_string(),
            format!(
                "applications/{APPLICATION_ID}/guilds/{GUILD_ID}/commands/{COMMAND_ID}/permissions"
            )
        );
    }

    #[test]
    fn get_current_authorization_info() {
        let route = Route::GetCurrentAuthorizationInformation;
        assert_eq!(route.to_string(), "oauth2/@me");
    }

    #[test]
    fn get_current_user_application_info() {
        let route = Route::GetCurrentUserApplicationInfo;
        assert_eq!(route.to_string(), "applications/@me");
    }

    #[test]
    fn update_current_user_application() {
        let route = Route::UpdateCurrentUserApplication;
        assert_eq!(route.to_string(), "applications/@me");
    }

    #[test]
    fn get_current_user() {
        let route = Route::GetCurrentUser;
        assert_eq!(route.to_string(), "users/@me");
    }

    #[test]
    fn get_current_user_guild_member() {
        let route = Route::GetCurrentUserGuildMember { guild_id: GUILD_ID };
        assert_eq!(
            route.to_string(),
            format!("users/@me/guilds/{GUILD_ID}/member")
        );
    }

    #[test]
    fn update_current_user() {
        let route = Route::UpdateCurrentUser;
        assert_eq!(route.to_string(), "users/@me");
    }

    #[test]
    fn get_gateway() {
        let route = Route::GetGateway;
        assert_eq!(route.to_string(), "gateway");
    }

    #[test]
    fn get_guild_command_permissions() {
        let route = Route::GetGuildCommandPermissions {
            application_id: APPLICATION_ID,
            guild_id: GUILD_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("applications/{APPLICATION_ID}/guilds/{GUILD_ID}/commands/permissions")
        );
    }

    #[test]
    fn get_guild_invites() {
        let route = Route::GetGuildInvites { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/invites"));
    }

    #[test]
    fn get_guild_preview() {
        let route = Route::GetGuildPreview { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/preview"));
    }

    #[test]
    fn get_guild_sticker() {
        let route = Route::GetGuildSticker {
            guild_id: GUILD_ID,
            sticker_id: STICKER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/stickers/{STICKER_ID}")
        );
    }

    #[test]
    fn delete_guild_sticker() {
        let route = Route::DeleteGuildSticker {
            guild_id: GUILD_ID,
            sticker_id: STICKER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/stickers/{STICKER_ID}")
        );
    }

    #[test]
    fn update_guild_sticker() {
        let route = Route::UpdateGuildSticker {
            guild_id: GUILD_ID,
            sticker_id: STICKER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/stickers/{STICKER_ID}")
        );
    }

    #[test]
    fn get_guild_vanity_url() {
        let route = Route::GetGuildVanityUrl { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/vanity-url"));
    }

    #[test]
    fn get_guild_voice_regions() {
        let route = Route::GetGuildVoiceRegions { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/regions"));
    }

    #[test]
    fn get_guild_welcome_screen() {
        let route = Route::GetGuildWelcomeScreen { guild_id: GUILD_ID };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/welcome-screen")
        );
    }

    #[test]
    fn update_guild_welcome_screen() {
        let route = Route::UpdateGuildWelcomeScreen { guild_id: GUILD_ID };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/welcome-screen")
        );
    }

    #[test]
    fn get_guild_webhooks() {
        let route = Route::GetGuildWebhooks { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/webhooks"));
    }

    #[test]
    fn get_guild_widget() {
        let route = Route::GetGuildWidget { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/widget.json"));
    }

    #[test]
    fn get_guild_widget_settings() {
        let route = Route::GetGuildWidgetSettings { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/widget"));
    }

    #[test]
    fn update_guild_widget_settings() {
        let route = Route::UpdateGuildWidgetSettings { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/widget"));
    }

    #[test]
    fn get_nitro_sticker_packs() {
        let route = Route::GetNitroStickerPacks;

        assert_eq!(route.to_string(), "sticker-packs");
    }

    #[test]
    fn get_pins() {
        let route = Route::GetPins {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(route.to_string(), format!("channels/{CHANNEL_ID}/pins"));
    }

    #[test]
    fn get_sticker() {
        let route = Route::GetSticker {
            sticker_id: STICKER_ID,
        };
        assert_eq!(route.to_string(), format!("stickers/{STICKER_ID}"));
    }

    #[test]
    fn get_thread_members() {
        let route = Route::GetThreadMembers {
            after: None,
            channel_id: CHANNEL_ID,
            limit: None,
            with_member: None,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/thread-members")
        );

        let route = Route::GetThreadMembers {
            after: Some(USER_ID),
            channel_id: CHANNEL_ID,
            limit: Some(1),
            with_member: Some(true),
        };

        assert_eq!(
            route.to_string(),
            format!(
                "channels/{CHANNEL_ID}/thread-members?after={USER_ID}&limit=1&with_member=true"
            )
        );
    }

    #[test]
    fn get_user_connections() {
        let route = Route::GetUserConnections;
        assert_eq!(route.to_string(), "users/@me/connections");
    }

    #[test]
    fn get_user() {
        let route = Route::GetUser { user_id: USER_ID };
        assert_eq!(route.to_string(), format!("users/{USER_ID}"));
    }

    #[test]
    fn get_voice_regions() {
        let route = Route::GetVoiceRegions;
        assert_eq!(route.to_string(), "voice/regions");
    }

    #[test]
    fn interaction_callback() {
        let route = Route::InteractionCallback {
            interaction_id: INTERACTION_ID,
            interaction_token: INTERACTION_TOKEN,
        };
        assert_eq!(
            route.to_string(),
            format!("interactions/{INTERACTION_ID}/{INTERACTION_TOKEN}/callback")
        );
    }

    #[test]
    fn join_thread() {
        let route = Route::JoinThread {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/thread-members/@me")
        );
    }

    #[test]
    fn leave_thread() {
        let route = Route::LeaveThread {
            channel_id: CHANNEL_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/thread-members/@me")
        );
    }

    #[test]
    fn leave_guild() {
        let route = Route::LeaveGuild { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("users/@me/guilds/{GUILD_ID}"));
    }

    #[test]
    fn pin_message() {
        let route = Route::PinMessage {
            channel_id: CHANNEL_ID,
            message_id: MESSAGE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/pins/{MESSAGE_ID}")
        );
    }

    #[test]
    fn unpin_message() {
        let route = Route::UnpinMessage {
            channel_id: CHANNEL_ID,
            message_id: MESSAGE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("channels/{CHANNEL_ID}/pins/{MESSAGE_ID}")
        );
    }

    #[test]
    fn sync_guild_integration() {
        let route = Route::SyncGuildIntegration {
            guild_id: GUILD_ID,
            integration_id: INTEGRATION_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/integrations/{INTEGRATION_ID}/sync")
        );
    }

    #[test]
    fn update_current_member() {
        let route = Route::UpdateCurrentMember { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/members/@me"));
    }

    #[test]
    fn get_current_user_voice_state() {
        let route = Route::GetCurrentUserVoiceState { guild_id: GUILD_ID };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/voice-states/@me")
        );
    }

    #[test]
    fn update_current_user_voice_state() {
        let route = Route::UpdateCurrentUserVoiceState { guild_id: GUILD_ID };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/voice-states/@me")
        );
    }

    #[test]
    fn update_nickname() {
        let route = Route::UpdateNickname { guild_id: GUILD_ID };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/members/@me/nick")
        );
    }

    #[test]
    fn get_user_voice_state() {
        let route = Route::GetUserVoiceState {
            guild_id: GUILD_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/voice-states/{USER_ID}")
        );
    }

    #[test]
    fn update_user_voice_state() {
        let route = Route::UpdateUserVoiceState {
            guild_id: GUILD_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/voice-states/{USER_ID}")
        );
    }

    #[test]
    fn create_ban() {
        let mut route = Route::CreateBan {
            guild_id: GUILD_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/bans/{USER_ID}")
        );

        route = Route::CreateBan {
            guild_id: GUILD_ID,
            user_id: USER_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/bans/{USER_ID}")
        );
    }

    #[test]
    fn create_guild_prune_none() {
        let route = Route::CreateGuildPrune {
            compute_prune_count: None,
            days: None,
            guild_id: GUILD_ID,
            include_roles: &[],
        };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/prune"));
    }

    #[test]
    fn create_guild_prune_compute_prune_count_true() {
        let route = Route::CreateGuildPrune {
            compute_prune_count: Some(true),
            days: None,
            guild_id: GUILD_ID,
            include_roles: &[],
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/prune?compute_prune_count=true")
        );
    }

    #[test]
    fn create_guild_prune_compute_prune_count_false() {
        let route = Route::CreateGuildPrune {
            compute_prune_count: Some(false),
            days: None,
            guild_id: GUILD_ID,
            include_roles: &[],
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/prune?compute_prune_count=false")
        );
    }

    #[test]
    fn create_guild_prune_days() {
        let route = Route::CreateGuildPrune {
            compute_prune_count: None,
            days: Some(4),
            guild_id: GUILD_ID,
            include_roles: &[],
        };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/prune?days=4"));
    }

    #[test]
    fn create_guild_prune_include_one_role() {
        let include_roles = [Id::new(1)];

        let route = Route::CreateGuildPrune {
            compute_prune_count: None,
            days: None,
            guild_id: GUILD_ID,
            include_roles: &include_roles,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/prune?include_roles=1")
        );
    }

    #[test]
    fn create_guild_prune_include_two_roles() {
        let include_roles = [Id::new(1), Id::new(2)];

        let route = Route::CreateGuildPrune {
            compute_prune_count: None,
            days: None,
            guild_id: GUILD_ID,
            include_roles: &include_roles,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/prune?include_roles=1,2")
        );
    }

    #[test]
    fn create_guild_prune_all() {
        let include_roles = [Id::new(1), Id::new(2)];

        let route = Route::CreateGuildPrune {
            compute_prune_count: Some(true),
            days: Some(4),
            guild_id: GUILD_ID,
            include_roles: &include_roles,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/prune?compute_prune_count=true&days=4&include_roles=1,2")
        );
    }

    #[test]
    fn get_guild_scheduled_events() {
        let route = Route::GetGuildScheduledEvents {
            guild_id: GUILD_ID,
            with_user_count: false,
        };

        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/scheduled-events")
        );

        let route = Route::GetGuildScheduledEvents {
            guild_id: GUILD_ID,
            with_user_count: true,
        };

        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/scheduled-events?with_user_count=true")
        );
    }

    #[test]
    fn create_guild_scheduled_event() {
        let route = Route::CreateGuildScheduledEvent { guild_id: GUILD_ID };

        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/scheduled-events")
        );
    }

    #[test]
    fn get_guild_scheduled_event() {
        let route = Route::GetGuildScheduledEvent {
            guild_id: GUILD_ID,
            scheduled_event_id: SCHEDULED_EVENT_ID,
            with_user_count: false,
        };

        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/scheduled-events/{SCHEDULED_EVENT_ID}")
        );

        let route = Route::GetGuildScheduledEvent {
            guild_id: GUILD_ID,
            scheduled_event_id: SCHEDULED_EVENT_ID,
            with_user_count: true,
        };

        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/scheduled-events/{SCHEDULED_EVENT_ID}?with_user_count=true")
        );
    }

    #[test]
    fn update_guild_scheduled_event() {
        let route = Route::UpdateGuildScheduledEvent {
            guild_id: GUILD_ID,
            scheduled_event_id: SCHEDULED_EVENT_ID,
        };

        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/scheduled-events/{SCHEDULED_EVENT_ID}")
        );
    }

    #[test]
    fn delete_guild_scheduled_event() {
        let route = Route::DeleteGuildScheduledEvent {
            guild_id: GUILD_ID,
            scheduled_event_id: SCHEDULED_EVENT_ID,
        };

        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/scheduled-events/{SCHEDULED_EVENT_ID}")
        );
    }

    #[test]
    fn get_guild_scheduled_event_users() {
        let route = Route::GetGuildScheduledEventUsers {
            after: None,
            before: Some(USER_ID),
            guild_id: GUILD_ID,
            limit: None,
            scheduled_event_id: SCHEDULED_EVENT_ID,
            with_member: true,
        };

        assert_eq!(
            route.to_string(),
            format!(
                "guilds/{GUILD_ID}/scheduled-events/{SCHEDULED_EVENT_ID}/users?before={USER_ID}&with_member=true"
            )
        );

        let route = Route::GetGuildScheduledEventUsers {
            after: Some(USER_ID),
            before: None,
            guild_id: GUILD_ID,
            limit: Some(101),
            scheduled_event_id: SCHEDULED_EVENT_ID,
            with_member: false,
        };

        assert_eq!(
            route.to_string(),
            format!(
                "guilds/{GUILD_ID}/scheduled-events/{SCHEDULED_EVENT_ID}/users?after={USER_ID}&limit=101"
            )
        );

        let route = Route::GetGuildScheduledEventUsers {
            after: Some(USER_ID),
            before: Some(USER_ID),
            guild_id: GUILD_ID,
            limit: Some(99),
            scheduled_event_id: SCHEDULED_EVENT_ID,
            with_member: false,
        };

        assert_eq!(
            route.to_string(),
            format!(
                "guilds/{GUILD_ID}/scheduled-events/{SCHEDULED_EVENT_ID}/users?after={USER_ID}&before={USER_ID}&limit=99"
            )
        );
    }

    #[test]
    fn search_guild_members() {
        let route = Route::SearchGuildMembers {
            guild_id: GUILD_ID,
            limit: Some(99),
            query: "foo bar",
        };

        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/members/search?query=foo%20bar&limit=99")
        );

        let route = Route::SearchGuildMembers {
            guild_id: GUILD_ID,
            limit: Some(99),
            query: "foo/bar",
        };

        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/members/search?query=foo%2Fbar&limit=99")
        );
    }

    #[test]
    fn update_guild_mfa() {
        let route = Route::UpdateGuildMfa { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/mfa"));
    }

    #[test]
    fn create_auto_moderation_rule() {
        let route = Route::CreateAutoModerationRule { guild_id: GUILD_ID };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/auto-moderation/rules")
        );
    }

    #[test]
    fn delete_auto_moderation_rule() {
        let route = Route::DeleteAutoModerationRule {
            guild_id: GUILD_ID,
            auto_moderation_rule_id: AUTO_MODERATION_RULE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/auto-moderation/rules/{AUTO_MODERATION_RULE_ID}")
        );
    }

    #[test]
    fn get_auto_moderation_rule() {
        let route = Route::GetAutoModerationRule {
            guild_id: GUILD_ID,
            auto_moderation_rule_id: AUTO_MODERATION_RULE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/auto-moderation/rules/{AUTO_MODERATION_RULE_ID}")
        );
    }

    #[test]
    fn get_guild_auto_moderation_rules() {
        let route = Route::GetGuildAutoModerationRules { guild_id: GUILD_ID };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/auto-moderation/rules")
        );
    }

    #[test]
    fn update_auto_moderation_rule() {
        let route = Route::UpdateAutoModerationRule {
            guild_id: GUILD_ID,
            auto_moderation_rule_id: AUTO_MODERATION_RULE_ID,
        };
        assert_eq!(
            route.to_string(),
            format!("guilds/{GUILD_ID}/auto-moderation/rules/{AUTO_MODERATION_RULE_ID}")
        );
    }

    #[test]
    fn get_guild_onboarding() {
        let route = Route::GetGuildOnboarding { guild_id: GUILD_ID };
        assert_eq!(route.to_string(), format!("guilds/{GUILD_ID}/onboarding"));
    }

    #[test]
    fn get_skus() {
        let route = Route::GetSKUs { application_id: 1 };
        assert_eq!(route.to_string(), format!("applications/1/skus"));
    }
}
