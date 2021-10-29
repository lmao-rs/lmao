//! Utility functions for working with events.
//!
//! This is in its own file for better maintainability when a new event is added.

use twilight_model::{channel::Channel, gateway::event::Event, id::GuildId};

/// Retrieve the guild ID of an event if it took place in a guild.
///
/// While events such as [`MessageDelete`] will never include a guild ID, events
/// such as [`BanAdd`] and only some [`Channel`] related events will include
/// one. [`GuildChannel`] variants will include a guild ID while
/// [`PrivateChannel`]s don't on the basis of not taking place in a guild.
///
/// [`BanAdd`]: twilight_model::gateway::payload::BanAdd
/// [`Channel`]: twilight_model::channel::Channel
/// [`GuildChannel`]: twilight_model::channel::GuildChannel
/// [`MessageDelete`]: twilight_model::gateway::payload::MessageDelete
/// [`PrivateChannel`]: twilight_model::channel::PrivateChannel
pub const fn guild_id(event: &Event) -> Option<GuildId> {
    match event {
        Event::BanAdd(e) => Some(e.guild_id),
        Event::BanRemove(e) => Some(e.guild_id),
        Event::ChannelCreate(e) => channel_guild_id(&e.0),
        Event::ChannelDelete(e) => channel_guild_id(&e.0),
        Event::ChannelUpdate(e) => channel_guild_id(&e.0),
        Event::GuildCreate(e) => Some(e.0.id),
        Event::GuildDelete(e) => Some(e.id),
        Event::GuildEmojisUpdate(e) => Some(e.guild_id),
        Event::GuildIntegrationsUpdate(e) => Some(e.guild_id),
        Event::GuildUpdate(e) => Some(e.0.id),
        Event::IntegrationCreate(e) => e.0.guild_id,
        Event::IntegrationDelete(e) => Some(e.guild_id),
        Event::IntegrationUpdate(e) => e.0.guild_id,
        Event::InteractionCreate(e) => e.0.guild_id(),
        Event::InviteCreate(e) => Some(e.guild_id),
        Event::InviteDelete(e) => Some(e.guild_id),
        Event::MemberAdd(e) => Some(e.0.guild_id),
        Event::MemberChunk(e) => Some(e.guild_id),
        Event::MemberRemove(e) => Some(e.guild_id),
        Event::MemberUpdate(e) => Some(e.guild_id),
        Event::MessageCreate(e) => e.0.guild_id,
        Event::PresenceUpdate(e) => Some(e.guild_id),
        Event::ReactionAdd(e) => e.0.guild_id,
        Event::ReactionRemove(e) => e.0.guild_id,
        Event::ReactionRemoveAll(e) => e.guild_id,
        Event::ReactionRemoveEmoji(e) => Some(e.guild_id),
        Event::RoleCreate(e) => Some(e.guild_id),
        Event::RoleDelete(e) => Some(e.guild_id),
        Event::RoleUpdate(e) => Some(e.guild_id),
        Event::StageInstanceCreate(e) => Some(e.0.guild_id),
        Event::StageInstanceDelete(e) => Some(e.0.guild_id),
        Event::StageInstanceUpdate(e) => Some(e.0.guild_id),
        Event::ThreadCreate(e) => channel_guild_id(&e.0),
        Event::ThreadDelete(e) => channel_guild_id(&e.0),
        Event::ThreadListSync(e) => Some(e.guild_id),
        Event::ThreadMembersUpdate(e) => Some(e.guild_id),
        Event::ThreadUpdate(e) => channel_guild_id(&e.0),
        Event::TypingStart(e) => e.guild_id,
        Event::UnavailableGuild(e) => Some(e.id),
        Event::VoiceServerUpdate(e) => e.guild_id,
        Event::VoiceStateUpdate(e) => e.0.guild_id,
        Event::WebhooksUpdate(e) => Some(e.guild_id),
        Event::ChannelPinsUpdate(_)
        | Event::GatewayHeartbeatAck
        | Event::GatewayHeartbeat(_)
        | Event::GatewayHello(_)
        | Event::GatewayInvalidateSession(_)
        | Event::GatewayReconnect
        | Event::GiftCodeUpdate
        | Event::MessageDelete(_)
        | Event::MessageDeleteBulk(_)
        | Event::MessageUpdate(_)
        | Event::PresencesReplace
        | Event::Ready(_)
        | Event::Resumed
        | Event::ShardConnected(_)
        | Event::ShardConnecting(_)
        | Event::ShardDisconnected(_)
        | Event::ShardIdentifying(_)
        | Event::ShardPayload(_)
        | Event::ShardReconnecting(_)
        | Event::ShardResuming(_)
        | Event::ThreadMemberUpdate(_) => None,
        Event::UserUpdate(_) => None,
    }
}

/// Retrieve the guild ID of a channel if it's a [`GuildChannel`].
///
/// [`GuildChannel`]: twilight_model::channel::GuildChannel
const fn channel_guild_id(channel: &Channel) -> Option<GuildId> {
    if let Channel::Guild(guild_channel) = channel {
        guild_channel.guild_id()
    } else {
        None
    }
}
