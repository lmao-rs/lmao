//! Known list of available OAuth 2 scopes.
//!
//! Refer to [Discord Docs/OAuth 2 Scopes] for a complete up-to-date list.
//!
//! [Discord Docs/OAuth 2 Scopes]: https://discord.com/developers/docs/topics/oauth2#shared-resources-oauth2-scopes

use crate::util::known_string::KnownString;
use serde::{Deserialize, Serialize};

/// OAuth 2 scope.
///
/// # Examples
///
/// Match a requested scope and print what's being requested:
///
/// ```no_run
/// use twilight_model::oauth::Scope;
///
/// let scope = Scope::IDENTIFY;
///
/// match scope {
///     Scope::CONNECTIONS => println!("Your list of connections is being requested."),
///     Scope::EMAIL => println!("Your email address is being requested."),
///     Scope::IDENTIFY => println!("Information about your account is being requested."),
///     _ => {}
/// }
/// ````
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Scope(KnownString<64>);

impl Scope {
    /// Allows your app to fetch data from a user's
    /// "Now Playing/Recently Played" list.
    ///
    /// Requires approval from Discord.
    pub const ACTIVITIES_READ: Self = Self::from_bytes(b"activities.read");

    /// Allows your app to update a user's activity
    ///
    /// Requires approval from Discord, but is not required for the Game SDK
    /// activity manager.
    pub const ACTIVITIES_WRITE: Self = Self::from_bytes(b"activities.write");

    /// Allows your app to read build data for a user's applications.
    pub const APPLICATIONS_BUILDS_READ: Self = Self::from_bytes(b"applications.builds.read");

    /// Allows your app to upload/update builds for a user's applications.
    ///
    /// Requires approval from Discord.
    pub const APPLICATIONS_BUILDS_UPLOAD: Self = Self::from_bytes(b"applications.builds.upload");

    /// Allows your app to use commands in a guild.
    pub const APPLICATIONS_COMMANDS: Self = Self::from_bytes(b"applications.commands");

    /// Allows your app to update its commands using a Bearer token.
    ///
    /// This is a client credentials grant only.
    pub const APPLICATIONS_COMMANDS_UPDATE: Self =
        Self::from_bytes(b"applications.commands.update");

    /// Allows your app to update permissions for its commands in a guild a user
    /// has permissions to.
    pub const APPLICATIONS_COMMANDS_PERMISSIONS_UPDATE: Self =
        Self::from_bytes(b"applications.commands.permissions.update");

    /// Allows your app to read entitlements for a user's applications.
    pub const APPLICATIONS_ENTITLEMENTS: Self = Self::from_bytes(b"applications.entitlements");

    /// Allows your app to read and update store data (SKUs, store listings,
    /// achievements, etc.) for a user's applications.
    pub const APPLICATIONS_STORE_UPDATE: Self = Self::from_bytes(b"applications.store.update");

    /// For oauth2 bots, this puts the bot in the user's selected guild by
    /// default.
    pub const BOT: Self = Self::from_bytes(b"bot");

    /// Allows /users/@me/connections to return linked third-party accounts.
    pub const CONNECTIONS: Self = Self::from_bytes(b"connections");

    /// Allows your app to see information about the user's DMs and group DMs.
    ///
    /// Requires approval from Discord.
    pub const DM_CHANNELS_READ: Self = Self::from_bytes(b"dm_channels.read");

    /// Enables `GET /users/@me` returning an email.
    pub const EMAIL: Self = Self::from_bytes(b"email");

    /// Allows your app to join users to a group DM.
    pub const GDM_JOIN: Self = Self::from_bytes(b"gdm.join");

    /// Allows `GET /users/@me/guilds` to return basic information about all of
    /// a user's guilds.
    pub const GUILDS: Self = Self::from_bytes(b"guilds");

    /// Allows `GET /guilds/{guild.id}/members/{user.id}` to be used for joining
    /// users to a guild.
    pub const GUILDS_JOIN: Self = Self::from_bytes(b"guilds.join");

    /// Allows `GET /users/@me/guilds/{guild.id}/member` to return a user's
    /// member information in a guild.
    pub const GUILDS_MEMBERS_READ: Self = Self::from_bytes(b"guilds.members.read");

    /// Allows `GET /users/@me`, but without the user's email.
    pub const IDENTIFY: Self = Self::from_bytes(b"identify");

    /// For local RPC server API access, this allows you to read messages from
    /// all client channels (otherwise restricted to channels/guilds your app
    /// creates).
    pub const MESSAGES_READ: Self = Self::from_bytes(b"messages.read");

    /// Allows your app to know a user's friends and implicit relationships.
    ///
    /// Requires approval from Discord.
    pub const RELATIONSHIPS_READ: Self = Self::from_bytes(b"relationships.read");

    /// Allows your app to update a user's connection and metadata for the app.
    pub const ROLE_CONNECTIONS_WRITE: Self = Self::from_bytes(b"role_connections.write");

    /// For local RPC server access, this allows you to control a user's local
    /// Discord client.
    ///
    /// Requires approval from Discord.
    pub const RPC: Self = Self::from_bytes(b"rpc");

    /// For local rpc server access, this allows you to update a user's activity
    ///
    /// Requires approval from Discord.
    pub const RPC_ACTIVITIES_WRITE: Self = Self::from_bytes(b"rpc.activities.write");

    /// For local RPC server access, this allows you to receive notifications
    /// pushed out to the user.
    ///
    /// Requires approval from Discord.
    pub const RPC_NOTIFICATIONS_READ: Self = Self::from_bytes(b"rpc.notifications.read");

    /// For local RPC server access, this allows you to read a user's voice
    /// settings and listen for voice events.
    ///
    /// Requires approval from Discord.
    pub const RPC_VOICE_READ: Self = Self::from_bytes(b"rpc.voice.read");

    /// For local RPC server access, this allows you to update a user's voice
    /// settings.
    ///
    /// Requires approval from Discord.
    pub const RPC_VOICE_WRITE: Self = Self::from_bytes(b"rpc.voice.write");

    /// Allows your app to connect to voice on the user's behalf and see all the
    /// voice members.
    ///
    /// Requires approval from Discord.
    pub const VOICE: Self = Self::from_bytes(b"voice");

    /// This generates a webhook that is returned in the oauth token response for
    /// authorization code grants.
    pub const WEBHOOK_INCOMING: Self = Self::from_bytes(b"webhook.incoming");

    /// Name of the associated constant.
    ///
    /// Returns `None` if the value doesn't have a defined constant.
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::ACTIVITIES_READ => "ACTIVITIES_READ",
            Self::ACTIVITIES_WRITE => "ACTIVITIES_WRITE",
            Self::APPLICATIONS_BUILDS_READ => "APPLICATIONS_BUILDS_READ",
            Self::APPLICATIONS_BUILDS_UPLOAD => "APPLICATIONS_BUILDS_UPLOAD",
            Self::APPLICATIONS_COMMANDS => "APPLICATIONS_COMMANDS",
            Self::APPLICATIONS_COMMANDS_UPDATE => "APPLICATIONS_COMMANDS_UPDATE",
            Self::APPLICATIONS_COMMANDS_PERMISSIONS_UPDATE => {
                "APPLICATIONS_COMMANDS_PERMISSIONS_UPDATE"
            }
            Self::APPLICATIONS_ENTITLEMENTS => "APPLICATIONS_ENTITLEMENTS",
            Self::APPLICATIONS_STORE_UPDATE => "APPLICATIONS_STORE_UPDATE",
            Self::BOT => "BOT",
            Self::CONNECTIONS => "CONNECTIONS",
            Self::DM_CHANNELS_READ => "DM_CHANNELS_READ",
            Self::EMAIL => "EMAIL",
            Self::GDM_JOIN => "GDM_JOIN",
            Self::GUILDS => "GUILDS",
            Self::GUILDS_JOIN => "GUILDS_JOIN",
            Self::GUILDS_MEMBERS_READ => "GUILDS_MEMBERS_READ",
            Self::IDENTIFY => "IDENTIFY",
            Self::MESSAGES_READ => "MESSAGES_READ",
            Self::RELATIONSHIPS_READ => "RELATIONSHIPS_READ",
            Self::ROLE_CONNECTIONS_WRITE => "ROLE_CONNECTIONS_WRITE",
            Self::RPC => "RPC",
            Self::RPC_ACTIVITIES_WRITE => "RPC_ACTIVITIES_WRITE",
            Self::RPC_NOTIFICATIONS_READ => "RPC_NOTIFICATIONS_READ",
            Self::RPC_VOICE_READ => "RPC_VOICE_READ",
            Self::RPC_VOICE_WRITE => "RPC_VOICE_WRITE",
            Self::VOICE => "VOICE",
            Self::WEBHOOK_INCOMING => "WEBHOOK_INCOMING",
            _ => return None,
        })
    }
}

impl_typed!(Scope, String);

#[cfg(test)]
mod tests {
    use super::Scope;
    use serde::{Deserialize, Serialize};
    use static_assertions::assert_impl_all;
    use std::{fmt::Debug, hash::Hash, str::FromStr, string::ToString};

    assert_impl_all!(
        Scope: AsRef<str>,
        Clone,
        Copy,
        Debug,
        Deserialize<'static>,
        Eq,
        FromStr,
        Hash,
        PartialEq,
        Send,
        Serialize,
        Sync,
        ToString,
        TryFrom<&'static str>,
    );
}
