#![allow(clippy::wildcard_imports)]

pub mod gateway;
pub mod shard;

mod dispatch;
mod kind;

pub use self::{
    dispatch::{DispatchEvent, DispatchEventWithTypeDeserializer},
    gateway::{GatewayEvent, GatewayEventDeserializer, GatewayEventDeserializerOwned},
    kind::EventType,
};

use self::shard::*;
use super::payload::incoming::*;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

/// Any type of event that a shard emits.
///
/// This brings together all of the types of [`DispatchEvent`]s,
/// [`GatewayEvent`]s, and [`ShardEvent`]s.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    /// A user was banned from a guild.
    BanAdd(BanAdd),
    /// A user's ban from a guild was removed.
    BanRemove(BanRemove),
    /// A channel was created.
    ChannelCreate(Box<ChannelCreate>),
    /// A channel was deleted.
    ChannelDelete(Box<ChannelDelete>),
    /// A channel's pins were updated.
    ChannelPinsUpdate(ChannelPinsUpdate),
    /// A channel was updated.
    ChannelUpdate(Box<ChannelUpdate>),
    /// A heartbeat was sent to or received from the gateway.
    GatewayHeartbeat(u64),
    /// A heartbeat acknowledgement was received from the gateway.
    GatewayHeartbeatAck,
    /// A "hello" packet was received from the gateway.
    GatewayHello(u64),
    /// A shard's session was invalidated.
    ///
    /// `true` if resumable. If not, then the shard must do a full reconnect.
    GatewayInvalidateSession(bool),
    /// The gateway is indicating to perform a reconnect.
    GatewayReconnect,
    /// Undocumented event, should be ignored
    GiftCodeUpdate,
    /// A guild was created.
    GuildCreate(Box<GuildCreate>),
    /// A guild was deleted or the current user was removed from a guild.
    GuildDelete(Box<GuildDelete>),
    /// A guild's emojis were updated.
    GuildEmojisUpdate(GuildEmojisUpdate),
    /// A guild's integrations were updated.
    GuildIntegrationsUpdate(GuildIntegrationsUpdate),
    /// A guild was updated.
    GuildUpdate(Box<GuildUpdate>),
    /// A guild integration was created.
    IntegrationCreate(Box<IntegrationCreate>),
    /// A guild integration was updated.
    IntegrationDelete(IntegrationDelete),
    /// A guild integration was deleted.
    IntegrationUpdate(Box<IntegrationUpdate>),
    /// An interaction was invoked by a user.
    InteractionCreate(Box<InteractionCreate>),
    /// A invite was made.
    InviteCreate(Box<InviteCreate>),
    /// A invite was deleted.
    InviteDelete(InviteDelete),
    /// A user was added to a guild.
    MemberAdd(Box<MemberAdd>),
    /// A user was removed from a guild.
    MemberRemove(MemberRemove),
    /// A user's member object in a guild was updated.
    MemberUpdate(Box<MemberUpdate>),
    /// A chunk of members were received from the gateway.
    MemberChunk(MemberChunk),
    /// A message was created in a channel.
    MessageCreate(Box<MessageCreate>),
    /// A message was deleted in a channel.
    MessageDelete(MessageDelete),
    /// Multiple messages were deleted in a channel.
    MessageDeleteBulk(MessageDeleteBulk),
    /// A message was updated in a channel.
    MessageUpdate(Box<MessageUpdate>),
    /// A user's active presence (such as game or online status) was updated.
    PresenceUpdate(Box<PresenceUpdate>),
    /// Multiple presences outside of a guild were updated.
    ///
    /// For bots this is always empty and useless.
    PresencesReplace,
    /// A reaction was added to a message.
    ReactionAdd(Box<ReactionAdd>),
    /// A reaction was removed from a message.
    ReactionRemove(Box<ReactionRemove>),
    /// All reactions were removed from a message.
    ReactionRemoveAll(ReactionRemoveAll),
    /// All instances of a given emoji from the reactions of a message were
    /// removed.
    ReactionRemoveEmoji(ReactionRemoveEmoji),
    /// A shard is now "ready" and fully connected.
    Ready(Box<Ready>),
    /// A shard has successfully resumed.
    Resumed,
    /// A role was created in a guild.
    RoleCreate(RoleCreate),
    /// A role was deleted in a guild.
    RoleDelete(RoleDelete),
    /// A role was updated in a guild.
    RoleUpdate(RoleUpdate),
    /// A shard is now in a connected stage after being fully connected to the
    /// gateway.
    ShardConnected(Connected),
    /// A shard is now in a connecting stage after starting to connect to the
    /// gateway.
    ShardConnecting(Connecting),
    /// A shard is now in a disconnected stage after the connection was closed.
    ShardDisconnected(Disconnected),
    /// A shard is now in a identifying stage after starting a new session.
    ShardIdentifying(Identifying),
    /// A shard is now in a reconnecting stage after a disconnect or session was
    /// ended.
    ShardReconnecting(Reconnecting),
    /// A payload of bytes came in through the shard's connection.
    ShardPayload(Payload),
    /// A shard is now in a Resuming stage after a disconnect.
    ShardResuming(Resuming),
    /// A stage instance was created in a stage channel.
    StageInstanceCreate(StageInstanceCreate),
    /// A stage instance was deleted in a stage channel.
    StageInstanceDelete(StageInstanceDelete),
    /// A stage instance was updated in a stage channel.
    StageInstanceUpdate(StageInstanceUpdate),
    /// A thread has been created, relevant to the current user,
    /// or the current user has been added to a thread.
    ThreadCreate(Box<ThreadCreate>),
    /// A thread, relevant to the current user, has been deleted.
    ThreadDelete(ThreadDelete),
    /// The current user has gained access to a thread.
    ThreadListSync(ThreadListSync),
    /// The thread member object for the current user has been updated.
    ThreadMemberUpdate(Box<ThreadMemberUpdate>),
    /// A user has been added to or removed from a thread.
    ThreadMembersUpdate(ThreadMembersUpdate),
    /// A thread has been updated.
    ThreadUpdate(Box<ThreadUpdate>),
    /// A user started typing in a channel.
    TypingStart(Box<TypingStart>),
    /// A guild is now unavailable.
    UnavailableGuild(UnavailableGuild),
    /// The current user was updated.
    UserUpdate(UserUpdate),
    /// A voice server update was sent.
    VoiceServerUpdate(VoiceServerUpdate),
    /// A voice state in a voice channel was updated.
    VoiceStateUpdate(Box<VoiceStateUpdate>),
    /// A webhook was updated.
    WebhooksUpdate(WebhooksUpdate),
}

impl Event {
    pub const fn kind(&self) -> EventType {
        match self {
            Self::BanAdd(_) => EventType::BanAdd,
            Self::BanRemove(_) => EventType::BanRemove,
            Self::ChannelCreate(_) => EventType::ChannelCreate,
            Self::ChannelDelete(_) => EventType::ChannelDelete,
            Self::ChannelPinsUpdate(_) => EventType::ChannelPinsUpdate,
            Self::ChannelUpdate(_) => EventType::ChannelUpdate,
            Self::GatewayHeartbeat(_) => EventType::GatewayHeartbeat,
            Self::GatewayHeartbeatAck => EventType::GatewayHeartbeatAck,
            Self::GatewayHello(_) => EventType::GatewayHello,
            Self::GatewayInvalidateSession(_) => EventType::GatewayInvalidateSession,
            Self::GatewayReconnect => EventType::GatewayReconnect,
            Self::GiftCodeUpdate => EventType::GiftCodeUpdate,
            Self::GuildCreate(_) => EventType::GuildCreate,
            Self::GuildDelete(_) => EventType::GuildDelete,
            Self::GuildEmojisUpdate(_) => EventType::GuildEmojisUpdate,
            Self::GuildIntegrationsUpdate(_) => EventType::GuildIntegrationsUpdate,
            Self::GuildUpdate(_) => EventType::GuildUpdate,
            Self::IntegrationCreate(_) => EventType::IntegrationCreate,
            Self::IntegrationDelete(_) => EventType::IntegrationDelete,
            Self::IntegrationUpdate(_) => EventType::IntegrationUpdate,
            Self::InteractionCreate(_) => EventType::InteractionCreate,
            Self::InviteCreate(_) => EventType::InviteCreate,
            Self::InviteDelete(_) => EventType::InviteDelete,
            Self::MemberAdd(_) => EventType::MemberAdd,
            Self::MemberRemove(_) => EventType::MemberRemove,
            Self::MemberUpdate(_) => EventType::MemberUpdate,
            Self::MemberChunk(_) => EventType::MemberChunk,
            Self::MessageCreate(_) => EventType::MessageCreate,
            Self::MessageDelete(_) => EventType::MessageDelete,
            Self::MessageDeleteBulk(_) => EventType::MessageDeleteBulk,
            Self::MessageUpdate(_) => EventType::MessageUpdate,
            Self::PresenceUpdate(_) => EventType::PresenceUpdate,
            Self::PresencesReplace => EventType::PresencesReplace,
            Self::ReactionAdd(_) => EventType::ReactionAdd,
            Self::ReactionRemove(_) => EventType::ReactionRemove,
            Self::ReactionRemoveAll(_) => EventType::ReactionRemoveAll,
            Self::ReactionRemoveEmoji(_) => EventType::ReactionRemoveEmoji,
            Self::Ready(_) => EventType::Ready,
            Self::Resumed => EventType::Resumed,
            Self::RoleCreate(_) => EventType::RoleCreate,
            Self::RoleDelete(_) => EventType::RoleDelete,
            Self::RoleUpdate(_) => EventType::RoleUpdate,
            Self::ShardConnected(_) => EventType::ShardConnected,
            Self::ShardConnecting(_) => EventType::ShardConnecting,
            Self::ShardDisconnected(_) => EventType::ShardDisconnected,
            Self::ShardIdentifying(_) => EventType::ShardIdentifying,
            Self::ShardReconnecting(_) => EventType::ShardReconnecting,
            Self::ShardPayload(_) => EventType::ShardPayload,
            Self::ShardResuming(_) => EventType::ShardResuming,
            Self::StageInstanceCreate(_) => EventType::StageInstanceCreate,
            Self::StageInstanceDelete(_) => EventType::StageInstanceDelete,
            Self::StageInstanceUpdate(_) => EventType::StageInstanceUpdate,
            Self::ThreadCreate(_) => EventType::ThreadCreate,
            Self::ThreadDelete(_) => EventType::ThreadDelete,
            Self::ThreadListSync(_) => EventType::ThreadListSync,
            Self::ThreadMemberUpdate(_) => EventType::ThreadMemberUpdate,
            Self::ThreadMembersUpdate(_) => EventType::ThreadMembersUpdate,
            Self::ThreadUpdate(_) => EventType::ThreadUpdate,
            Self::TypingStart(_) => EventType::TypingStart,
            Self::UnavailableGuild(_) => EventType::UnavailableGuild,
            Self::UserUpdate(_) => EventType::UserUpdate,
            Self::VoiceServerUpdate(_) => EventType::VoiceServerUpdate,
            Self::VoiceStateUpdate(_) => EventType::VoiceStateUpdate,
            Self::WebhooksUpdate(_) => EventType::WebhooksUpdate,
        }
    }
}

impl From<Box<DispatchEvent>> for Event {
    fn from(event: Box<DispatchEvent>) -> Self {
        match *event {
            DispatchEvent::BanAdd(v) => Self::BanAdd(v),
            DispatchEvent::BanRemove(v) => Self::BanRemove(v),
            DispatchEvent::ChannelCreate(v) => Self::ChannelCreate(v),
            DispatchEvent::ChannelDelete(v) => Self::ChannelDelete(v),
            DispatchEvent::ChannelPinsUpdate(v) => Self::ChannelPinsUpdate(v),
            DispatchEvent::ChannelUpdate(v) => Self::ChannelUpdate(v),
            DispatchEvent::GiftCodeUpdate => Self::GiftCodeUpdate,
            DispatchEvent::GuildCreate(v) => Self::GuildCreate(v),
            DispatchEvent::GuildDelete(v) => Self::GuildDelete(v),
            DispatchEvent::GuildEmojisUpdate(v) => Self::GuildEmojisUpdate(v),
            DispatchEvent::GuildIntegrationsUpdate(v) => Self::GuildIntegrationsUpdate(v),
            DispatchEvent::IntegrationCreate(v) => Self::IntegrationCreate(v),
            DispatchEvent::IntegrationDelete(v) => Self::IntegrationDelete(v),
            DispatchEvent::IntegrationUpdate(v) => Self::IntegrationUpdate(v),
            DispatchEvent::InteractionCreate(v) => Self::InteractionCreate(v),
            DispatchEvent::InviteCreate(v) => Self::InviteCreate(v),
            DispatchEvent::InviteDelete(v) => Self::InviteDelete(v),
            DispatchEvent::MemberAdd(v) => Self::MemberAdd(v),
            DispatchEvent::MemberRemove(v) => Self::MemberRemove(v),
            DispatchEvent::MemberUpdate(v) => Self::MemberUpdate(v),
            DispatchEvent::MemberChunk(v) => Self::MemberChunk(v),
            DispatchEvent::RoleCreate(v) => Self::RoleCreate(v),
            DispatchEvent::RoleDelete(v) => Self::RoleDelete(v),
            DispatchEvent::RoleUpdate(v) => Self::RoleUpdate(v),
            DispatchEvent::GuildUpdate(v) => Self::GuildUpdate(v),
            DispatchEvent::MessageCreate(v) => Self::MessageCreate(v),
            DispatchEvent::MessageDelete(v) => Self::MessageDelete(v),
            DispatchEvent::MessageDeleteBulk(v) => Self::MessageDeleteBulk(v),
            DispatchEvent::MessageUpdate(v) => Self::MessageUpdate(v),
            DispatchEvent::PresenceUpdate(v) => Self::PresenceUpdate(v),
            DispatchEvent::PresencesReplace => Self::PresencesReplace,
            DispatchEvent::ReactionAdd(v) => Self::ReactionAdd(v),
            DispatchEvent::ReactionRemove(v) => Self::ReactionRemove(v),
            DispatchEvent::ReactionRemoveAll(v) => Self::ReactionRemoveAll(v),
            DispatchEvent::ReactionRemoveEmoji(v) => Self::ReactionRemoveEmoji(v),
            DispatchEvent::Ready(v) => Self::Ready(v),
            DispatchEvent::Resumed => Self::Resumed,
            DispatchEvent::StageInstanceCreate(v) => Self::StageInstanceCreate(v),
            DispatchEvent::StageInstanceDelete(v) => Self::StageInstanceDelete(v),
            DispatchEvent::StageInstanceUpdate(v) => Self::StageInstanceUpdate(v),
            DispatchEvent::ThreadCreate(v) => Self::ThreadCreate(v),
            DispatchEvent::ThreadDelete(v) => Self::ThreadDelete(v),
            DispatchEvent::ThreadListSync(v) => Self::ThreadListSync(v),
            DispatchEvent::ThreadMemberUpdate(v) => Self::ThreadMemberUpdate(v),
            DispatchEvent::ThreadMembersUpdate(v) => Self::ThreadMembersUpdate(v),
            DispatchEvent::ThreadUpdate(v) => Self::ThreadUpdate(v),
            DispatchEvent::TypingStart(v) => Self::TypingStart(v),
            DispatchEvent::UnavailableGuild(v) => Self::UnavailableGuild(v),
            DispatchEvent::UserUpdate(v) => Self::UserUpdate(v),
            DispatchEvent::VoiceServerUpdate(v) => Self::VoiceServerUpdate(v),
            DispatchEvent::VoiceStateUpdate(v) => Self::VoiceStateUpdate(v),
            DispatchEvent::WebhooksUpdate(v) => Self::WebhooksUpdate(v),
        }
    }
}

impl From<GatewayEvent> for Event {
    fn from(event: GatewayEvent) -> Self {
        match event {
            GatewayEvent::Dispatch(_, e) => Self::from(e),
            GatewayEvent::Heartbeat(interval) => Self::GatewayHeartbeat(interval),
            GatewayEvent::HeartbeatAck => Self::GatewayHeartbeatAck,
            GatewayEvent::Hello(interval) => Self::GatewayHello(interval),
            GatewayEvent::InvalidateSession(r) => Self::GatewayInvalidateSession(r),
            GatewayEvent::Reconnect => Self::GatewayReconnect,
        }
    }
}

impl From<ShardEvent> for Event {
    fn from(event: ShardEvent) -> Self {
        match event {
            ShardEvent::Connected(v) => Self::ShardConnected(v),
            ShardEvent::Connecting(v) => Self::ShardConnecting(v),
            ShardEvent::Disconnected(v) => Self::ShardDisconnected(v),
            ShardEvent::Identifying(v) => Self::ShardIdentifying(v),
            ShardEvent::Payload(v) => Self::ShardPayload(v),
            ShardEvent::Reconnecting(v) => Self::ShardReconnecting(v),
            ShardEvent::Resuming(v) => Self::ShardResuming(v),
        }
    }
}

/// An error that describes a failure to convert from one event type to another.
#[derive(Debug)]
pub struct EventConversionError {
    event: Event,
}

impl EventConversionError {
    pub const fn new(event: Event) -> EventConversionError {
        Self { event }
    }

    /// Return an immutable reference to the original event.
    pub const fn event_ref(&self) -> &Event {
        &self.event
    }

    /// Consume the error, returning the original event.
    #[allow(clippy::missing_const_for_fn)]
    pub fn into_event(self) -> Event {
        self.event
    }
}

impl Display for EventConversionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("event variant failed to convert")
    }
}

impl Error for EventConversionError {}

#[cfg(test)]
mod tests {
    use super::{super::payload::incoming::*, shard::*, Event};
    use std::mem;

    #[test]
    fn event_sizes() {
        assert_eq!(192, mem::size_of::<Event>());
        assert_eq!(184, mem::size_of::<BanAdd>());
        assert_eq!(184, mem::size_of::<BanRemove>());
        assert_eq!(704, mem::size_of::<ChannelCreate>());
        assert_eq!(704, mem::size_of::<ChannelDelete>());
        assert_eq!(32, mem::size_of::<ChannelPinsUpdate>());
        assert_eq!(704, mem::size_of::<ChannelUpdate>());
        assert_eq!(16, mem::size_of::<Connected>());
        assert_eq!(32, mem::size_of::<Connecting>());
        assert_eq!(40, mem::size_of::<Disconnected>());
        assert_eq!(632, mem::size_of::<GuildCreate>());
        assert_eq!(16, mem::size_of::<GuildDelete>());
        assert_eq!(32, mem::size_of::<GuildEmojisUpdate>());
        assert_eq!(8, mem::size_of::<GuildIntegrationsUpdate>());
        assert_eq!(400, mem::size_of::<GuildUpdate>());
        assert_eq!(16, mem::size_of::<Identifying>());
        assert_eq!(632, mem::size_of::<IntegrationCreate>());
        assert_eq!(24, mem::size_of::<IntegrationDelete>());
        assert_eq!(632, mem::size_of::<IntegrationUpdate>());
        assert_eq!(16, mem::size_of::<InteractionCreate>());
        assert_eq!(304, mem::size_of::<InviteCreate>());
        assert_eq!(40, mem::size_of::<InviteDelete>());
        assert_eq!(288, mem::size_of::<MemberAdd>());
        assert_eq!(184, mem::size_of::<MemberRemove>());
        assert_eq!(288, mem::size_of::<MemberUpdate>());
        assert_eq!(112, mem::size_of::<MemberChunk>());
        assert_eq!(1864, mem::size_of::<MessageCreate>());
        assert_eq!(24, mem::size_of::<MessageDelete>());
        assert_eq!(40, mem::size_of::<MessageDeleteBulk>());
        assert_eq!(352, mem::size_of::<MessageUpdate>());
        assert_eq!(24, mem::size_of::<Payload>());
        assert_eq!(736, mem::size_of::<PresenceUpdate>());
        assert_eq!(360, mem::size_of::<ReactionAdd>());
        assert_eq!(360, mem::size_of::<ReactionRemove>());
        assert_eq!(24, mem::size_of::<ReactionRemoveAll>());
        assert_eq!(64, mem::size_of::<ReactionRemoveEmoji>());
        assert_eq!(264, mem::size_of::<Ready>());
        assert_eq!(8, mem::size_of::<Reconnecting>());
        assert_eq!(16, mem::size_of::<Resuming>());
        assert_eq!(128, mem::size_of::<RoleCreate>());
        assert_eq!(16, mem::size_of::<RoleDelete>());
        assert_eq!(128, mem::size_of::<RoleUpdate>());
        assert_eq!(56, mem::size_of::<StageInstanceCreate>());
        assert_eq!(56, mem::size_of::<StageInstanceDelete>());
        assert_eq!(56, mem::size_of::<StageInstanceUpdate>());
        assert_eq!(704, mem::size_of::<ThreadCreate>());
        assert_eq!(32, mem::size_of::<ThreadDelete>());
        assert_eq!(80, mem::size_of::<ThreadListSync>());
        assert_eq!(552, mem::size_of::<ThreadMemberUpdate>());
        assert_eq!(72, mem::size_of::<ThreadMembersUpdate>());
        assert_eq!(704, mem::size_of::<ThreadUpdate>());
        assert_eq!(320, mem::size_of::<TypingStart>());
        assert_eq!(8, mem::size_of::<UnavailableGuild>());
        assert_eq!(168, mem::size_of::<UserUpdate>());
        assert_eq!(64, mem::size_of::<VoiceServerUpdate>());
        assert_eq!(384, mem::size_of::<VoiceStateUpdate>());
        assert_eq!(16, mem::size_of::<WebhooksUpdate>());
    }
}
