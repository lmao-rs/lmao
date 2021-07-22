mod data;

pub use self::data::MessageComponentInteractionData;

use super::InteractionType;
use crate::{
    channel::Message,
    guild::PartialMember,
    id::{ApplicationId, ChannelId, GuildId, InteractionId, UserId},
    user::User,
};
use serde::Serialize;

/// Information present in an [`Interaction::MessageComponent`].
///
/// [`Interaction::MessageComponent`]: super::Interaction::MessageComponent
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename(serialize = "Interaction"))]
pub struct MessageComponentInteraction {
    /// ID of the associated application.
    pub application_id: ApplicationId,
    /// ID of the channel the interaction was triggered from.
    pub channel_id: ChannelId,
    /// Data from the invoked command.
    pub data: MessageComponentInteractionData,
    /// ID of the guild the interaction was triggered from.
    pub guild_id: Option<GuildId>,
    /// ID of the interaction.
    pub id: InteractionId,
    /// Type of the interaction.
    #[serde(rename = "type")]
    pub kind: InteractionType,
    /// Member that triggered the interaction.
    ///
    /// Present when the command is used in a guild.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<PartialMember>,
    /// Message object for the message this button belongs to.
    ///
    /// This is currently *not* validated by the discord API and may be spoofed
    /// by malicious users.
    pub message: Message,
    /// Token of the interaction.
    pub token: String,
    /// User that triggered the interaction.
    ///
    /// Present when the command is used in a direct message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
}

impl MessageComponentInteraction {
    /// Extract the id of the user that invoked this interaction.
    ///
    /// If the interaction came from a guild, it will get the id
    /// from the member field.
    /// Similarly, if the interaction came from a Direct Message,
    /// it will get the id from the user field.
    ///
    /// Returns an [`Option`] to future-proof against any new fields
    /// that could be used to return the user id.
    pub fn author_id(&self) -> Option<UserId> {
        self.member.as_ref().map_or_else(
            || self.user.as_ref().map(|user| user.id),
            |member| member.user.as_ref().map(|u| u.id),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::MessageComponentInteraction;
    use serde::Serialize;
    use static_assertions::{assert_fields, assert_impl_all};
    use std::{fmt::Debug, hash::Hash};

    assert_fields!(
        MessageComponentInteraction: application_id,
        channel_id,
        data,
        guild_id,
        id,
        kind,
        member,
        message,
        token,
        user
    );
    assert_impl_all!(
        MessageComponentInteraction: Clone,
        Debug,
        Eq,
        Hash,
        PartialEq,
        Send,
        Serialize,
        Sync
    );
}
