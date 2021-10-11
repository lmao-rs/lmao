//! # twilight-cache-inmemory
//!
//! [![discord badge][]][discord link] [![github badge][]][github link] [![license badge][]][license link] ![rust badge]
//!
//! `twilight-cache-inmemory` is an in-process-memory cache for the
//! [`twilight-rs`] ecosystem. It's responsible for processing events and
//! caching things like guilds, channels, users, and voice states.
//!
//! ## Features
//!
//! By default no feature is enabled.
//!
//! ### `permission-calculator`
//!
//! The `permission-calculator` feature flag will bring in support for the
//! `PermissionCalculator`; an API for calculating permissions through it is
//! exposed via `InMemoryCache::permissions`. Support for calculating the
//! permissions of a member on a root guild-level and in a guild channel is
//! included.
//!
//! Refer to the `permission` module for more documentation.
//!
//! ## Examples
//!
//! Update a cache with events that come in through the gateway:
//!
//! ```rust,no_run
//! use std::env;
//! use futures::stream::StreamExt;
//! use twilight_cache_inmemory::InMemoryCache;
//! use twilight_gateway::{Intents, Shard};
//!
//! # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let token = env::var("DISCORD_TOKEN")?;
//! let (shard, mut events) = Shard::new(token, Intents::GUILD_MESSAGES);
//! shard.start().await?;
//!
//! // Create a cache, caching up to 10 messages per channel:
//! let cache = InMemoryCache::builder().message_cache_size(10).build();
//!
//! while let Some(event) = events.next().await {
//!     // Update the cache with the event.
//!     cache.update(&event);
//! }
//! # Ok(()) }
//! ```
//!
//! ## License
//!
//! All first-party crates are licensed under [ISC][LICENSE.md]
//!
//! [LICENSE.md]: https://github.com/twilight-rs/twilight/blob/main/LICENSE.md
//! [discord badge]: https://img.shields.io/discord/745809834183753828?color=%237289DA&label=discord%20server&logo=discord&style=for-the-badge
//! [discord link]: https://discord.gg/7jj8n7D
//! [docs:discord:sharding]: https://discord.com/developers/docs/topics/gateway#sharding
//! [github badge]: https://img.shields.io/badge/github-twilight-6f42c1.svg?style=for-the-badge&logo=github
//! [github link]: https://github.com/twilight-rs/twilight
//! [license badge]: https://img.shields.io/badge/license-ISC-blue.svg?style=for-the-badge&logo=pastebin
//! [license link]: https://github.com/twilight-rs/twilight/blob/main/LICENSE.md
//! [rust badge]: https://img.shields.io/badge/rust-1.53+-93450a.svg?style=for-the-badge&logo=rust

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(
    clippy::missing_const_for_fn,
    missing_docs,
    rust_2018_idioms,
    rustdoc::broken_intra_doc_links,
    unsafe_code,
    unused,
    warnings
)]

pub mod model;

#[cfg(feature = "permission-calculator")]
#[cfg_attr(docsrs, doc(cfg(feature = "permission-calculator")))]
pub mod permission;

mod builder;
mod config;
mod event;
mod stats;

#[cfg(test)]
mod test;

pub use self::{
    builder::InMemoryCacheBuilder,
    config::{Config, ResourceType},
    stats::InMemoryCacheStats,
};

#[cfg(feature = "permission-calculator")]
#[cfg_attr(docsrs, doc(cfg(feature = "permission-calculator")))]
pub use self::permission::InMemoryCachePermissions;

use self::model::*;
use dashmap::{
    mapref::{entry::Entry, one::Ref},
    DashMap, DashSet,
};
use std::{
    collections::{BTreeSet, HashSet, VecDeque},
    fmt::{Debug, Formatter, Result as FmtResult},
    hash::Hash,
    ops::Deref,
    sync::Mutex,
};
use twilight_model::{
    channel::{message::sticker::StickerId, Group, GuildChannel, PrivateChannel, StageInstance},
    gateway::event::Event,
    guild::{GuildIntegration, Role},
    id::{ChannelId, EmojiId, GuildId, IntegrationId, MessageId, RoleId, StageId, UserId},
    user::{CurrentUser, User},
    voice::VoiceState,
};

/// Resource associated with a guild.
///
/// This is used when a resource does not itself include its associated guild's
/// ID. In lieu of the resource itself storing its guild's ID this relation
/// includes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuildResource<T> {
    guild_id: GuildId,
    value: T,
}

impl<T> GuildResource<T> {
    /// ID of the guild associated with the resource.
    pub const fn guild_id(&self) -> GuildId {
        self.guild_id
    }

    /// Immutable reference to the resource's value.
    pub const fn resource(&self) -> &T {
        &self.value
    }
}

impl<T> Deref for GuildResource<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.resource()
    }
}

/// Immutable reference to a resource in the cache.
// We need this so as not to expose the underlying cache implementation.
pub struct Reference<'a, K, V> {
    inner: Ref<'a, K, V>,
}

impl<'a, K: Eq + Hash, V> Reference<'a, K, V> {
    /// Create a new reference from a DashMap reference.
    fn new(inner: Ref<'a, K, V>) -> Self {
        Self { inner }
    }

    /// Immutable reference to the key identifying the resource.
    pub fn key(&'a self) -> &'a K {
        self.inner.key()
    }

    /// Immutable reference to the underlying value.
    pub fn value(&'a self) -> &'a V {
        self.inner.value()
    }
}

impl<K: Eq + Hash, V: Debug> Debug for Reference<'_, K, V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Reference")
            .field("inner", self.value())
            .finish()
    }
}

impl<'a, K: Eq + Hash, V> Deref for Reference<'a, K, V> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        self.value()
    }
}

fn upsert_guild_item<K: Eq + Hash, V: PartialEq>(
    map: &DashMap<K, GuildResource<V>>,
    guild_id: GuildId,
    key: K,
    value: V,
) {
    match map.entry(key) {
        Entry::Occupied(entry) if entry.get().value == value => {}
        Entry::Occupied(mut entry) => {
            entry.insert(GuildResource { guild_id, value });
        }
        Entry::Vacant(entry) => {
            entry.insert(GuildResource { guild_id, value });
        }
    }
}

fn upsert_item<K: Eq + Hash, V: PartialEq>(map: &DashMap<K, V>, k: K, v: V) {
    map.insert(k, v);
}

/// A thread-safe, in-memory-process cache of Discord data. It can be cloned and
/// sent to other threads.
///
/// This is an implementation of a cache designed to be used by only the
/// current process.
///
/// Events will only be processed if they are properly expressed with
/// [`Intents`]; refer to function-level documentation for more details.
///
/// # Using the cache in multiple tasks
///
/// To use a cache instance in multiple tasks, consider wrapping it in an
/// [`std::sync::Arc`] or [`std::rc::Rc`].
///
/// # Caution required
///
/// The cache uses a concurrent map for mutability of cached resources. Return
/// types of methods are immutable references to those resources. If a resource
/// is retrieved from the cache then care must be taken to only hold it for as long as
/// necessary. If the cache needs to mutate a resource to update it and a
/// reference to it is being held then calls to [`InMemoryCache::update`] may
/// be blocked.
///
/// In order to avoid blocking of cache updates care must be taken to hold them
/// for as little as possible. For example, consider dropping references during
/// long-running tasks such as HTTP requests. Processing HTTP requests takes
/// milliseconds to seconds; retrieving a new reference to a resource is on the
/// scale of nanoseconds. If only a couple of small fields are necessary from a
/// reference consider copying or cloning them.
///
/// [`Intents`]: ::twilight_model::gateway::Intents
// When adding a field here, be sure to add it to `InMemoryCache::clear` if
// necessary.
#[derive(Debug, Default)]
pub struct InMemoryCache {
    config: Config,
    channels_guild: DashMap<ChannelId, GuildResource<GuildChannel>>,
    channels_private: DashMap<ChannelId, PrivateChannel>,
    channel_messages: DashMap<ChannelId, VecDeque<MessageId>>,
    // So long as the lock isn't held across await or panic points this is fine.
    current_user: Mutex<Option<CurrentUser>>,
    emojis: DashMap<EmojiId, GuildResource<CachedEmoji>>,
    groups: DashMap<ChannelId, Group>,
    guilds: DashMap<GuildId, CachedGuild>,
    guild_channels: DashMap<GuildId, HashSet<ChannelId>>,
    guild_emojis: DashMap<GuildId, HashSet<EmojiId>>,
    guild_integrations: DashMap<GuildId, HashSet<IntegrationId>>,
    guild_members: DashMap<GuildId, HashSet<UserId>>,
    guild_presences: DashMap<GuildId, HashSet<UserId>>,
    guild_roles: DashMap<GuildId, HashSet<RoleId>>,
    guild_stage_instances: DashMap<GuildId, HashSet<StageId>>,
    guild_stickers: DashMap<GuildId, HashSet<StickerId>>,
    integrations: DashMap<(GuildId, IntegrationId), GuildResource<GuildIntegration>>,
    members: DashMap<(GuildId, UserId), CachedMember>,
    messages: DashMap<MessageId, CachedMessage>,
    presences: DashMap<(GuildId, UserId), CachedPresence>,
    roles: DashMap<RoleId, GuildResource<Role>>,
    stage_instances: DashMap<StageId, GuildResource<StageInstance>>,
    stickers: DashMap<StickerId, GuildResource<CachedSticker>>,
    unavailable_guilds: DashSet<GuildId>,
    users: DashMap<UserId, User>,
    user_guilds: DashMap<UserId, BTreeSet<GuildId>>,
    /// Mapping of channels and the users currently connected.
    voice_state_channels: DashMap<ChannelId, HashSet<(GuildId, UserId)>>,
    /// Mapping of guilds and users currently connected to its voice channels.
    voice_state_guilds: DashMap<GuildId, HashSet<UserId>>,
    /// Mapping of guild ID and user ID pairs to their voice states.
    voice_states: DashMap<(GuildId, UserId), VoiceState>,
}

/// Implemented methods and types for the cache.
impl InMemoryCache {
    /// Creates a new, empty cache.
    ///
    /// # Examples
    ///
    /// Creating a new `InMemoryCache` with a custom configuration, limiting
    /// the message cache to 50 messages per channel:
    ///
    /// ```
    /// use twilight_cache_inmemory::InMemoryCache;
    ///
    /// let cache = InMemoryCache::builder().message_cache_size(50).build();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new builder to configure and construct an in-memory cache.
    pub const fn builder() -> InMemoryCacheBuilder {
        InMemoryCacheBuilder::new()
    }

    /// Clear the state of the Cache.
    ///
    /// This is equal to creating a new empty cache.
    pub fn clear(&self) {
        self.channels_guild.clear();
        self.channels_private.clear();
        self.channel_messages.clear();
        self.current_user
            .lock()
            .expect("current user poisoned")
            .take();
        self.emojis.clear();
        self.groups.clear();
        self.guilds.clear();
        self.guild_channels.clear();
        self.guild_emojis.clear();
        self.guild_integrations.clear();
        self.guild_members.clear();
        self.guild_presences.clear();
        self.guild_roles.clear();
        self.guild_stage_instances.clear();
        self.guild_stickers.clear();
        self.integrations.clear();
        self.members.clear();
        self.messages.clear();
        self.presences.clear();
        self.roles.clear();
        self.stickers.clear();
        self.unavailable_guilds.clear();
        self.users.clear();
        self.voice_state_channels.clear();
        self.voice_state_guilds.clear();
        self.voice_states.clear();
    }

    /// Returns a copy of the config cache.
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Create an interface for retrieving statistics about the cache.
    ///
    /// # Examples
    ///
    /// Print the number of guilds in a cache:
    ///
    /// ```
    /// use twilight_cache_inmemory::InMemoryCache;
    ///
    /// let cache = InMemoryCache::new();
    ///
    /// // later on...
    /// let guilds = cache.stats().guilds();
    /// println!("guild count: {}", guilds);
    /// ```
    pub const fn stats(&self) -> InMemoryCacheStats<'_> {
        InMemoryCacheStats::new(self)
    }

    /// Create an interface for retrieving the permissions of a member in a
    /// guild or channel.
    ///
    /// [`ResourceType`]s must be configured for the permission interface to
    /// properly work; refer to the [`permission`] module-level documentation
    /// for more information.
    ///
    /// # Examples
    ///
    /// Calculate the permissions of a member in a guild channel:
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use twilight_cache_inmemory::{InMemoryCache, ResourceType};
    /// use twilight_model::id::{ChannelId, UserId};
    ///
    /// let resource_types = ResourceType::CHANNEL
    ///     | ResourceType::MEMBER
    ///     | ResourceType::ROLE;
    ///
    /// let cache = InMemoryCache::builder()
    ///     .resource_types(resource_types)
    ///     .build();
    ///
    /// let channel_id = ChannelId::new(4).expect("non zero");
    /// let user_id = UserId::new(5).expect("non zero");
    ///
    /// let permissions = cache.permissions().in_channel(user_id, channel_id)?;
    /// println!("member has these permissions: {:?}", permissions);
    /// # Ok(()) }
    /// ```
    #[cfg(feature = "permission-calculator")]
    #[cfg_attr(docsrs, doc(cfg(feature = "permission-calculator")))]
    pub const fn permissions(&self) -> InMemoryCachePermissions<'_> {
        InMemoryCachePermissions::new(self)
    }

    /// Update the cache with an event from the gateway.
    pub fn update(&self, value: &impl UpdateCache) {
        value.update(self);
    }

    /// Gets the current user.
    pub fn current_user(&self) -> Option<CurrentUser> {
        self.current_user
            .lock()
            .expect("current user poisoned")
            .clone()
    }

    /// Gets an emoji by ID.
    ///
    /// This requires the [`GUILD_EMOJIS`] intent.
    ///
    /// [`GUILD_EMOJIS`]: ::twilight_model::gateway::Intents::GUILD_EMOJIS
    pub fn emoji(
        &self,
        emoji_id: EmojiId,
    ) -> Option<Reference<'_, EmojiId, GuildResource<CachedEmoji>>> {
        self.emojis.get(&emoji_id).map(Reference::new)
    }

    /// Gets a group by ID.
    pub fn group(&self, channel_id: ChannelId) -> Option<Reference<'_, ChannelId, Group>> {
        self.groups.get(&channel_id).map(Reference::new)
    }

    /// Gets a guild by ID.
    ///
    /// This requires the [`GUILDS`] intent.
    ///
    /// [`GUILDS`]: ::twilight_model::gateway::Intents::GUILDS
    pub fn guild(&self, guild_id: GuildId) -> Option<Reference<'_, GuildId, CachedGuild>> {
        self.guilds.get(&guild_id).map(Reference::new)
    }

    /// Gets a channel by ID.
    ///
    /// This requires the [`GUILDS`] intent.
    ///
    /// [`GUILDS`]: ::twilight_model::gateway::Intents::GUILDS
    pub fn guild_channel(
        &self,
        channel_id: ChannelId,
    ) -> Option<Reference<'_, ChannelId, GuildResource<GuildChannel>>> {
        self.channels_guild.get(&channel_id).map(Reference::new)
    }

    /// Gets the set of channels in a guild.
    ///
    /// This requires the [`GUILDS`] intent.
    ///
    /// [`GUILDS`]: ::twilight_model::gateway::Intents::GUILDS
    pub fn guild_channels(
        &self,
        guild_id: GuildId,
    ) -> Option<Reference<'_, GuildId, HashSet<ChannelId>>> {
        self.guild_channels.get(&guild_id).map(Reference::new)
    }

    /// Gets the set of emojis in a guild.
    ///
    /// This requires both the [`GUILDS`] and [`GUILD_EMOJIS`] intents.
    ///
    /// [`GUILDS`]: ::twilight_model::gateway::Intents::GUILDS
    /// [`GUILD_EMOJIS`]: ::twilight_model::gateway::Intents::GUILD_EMOJIS
    pub fn guild_emojis(
        &self,
        guild_id: GuildId,
    ) -> Option<Reference<'_, GuildId, HashSet<EmojiId>>> {
        self.guild_emojis.get(&guild_id).map(Reference::new)
    }

    /// Gets the set of integrations in a guild.
    ///
    /// This requires the [`GUILD_INTEGRATIONS`] intent. The
    /// [`ResourceType::INTEGRATION`] resource type must be enabled.
    ///
    /// [`GUILD_INTEGRATIONS`]: twilight_model::gateway::Intents::GUILD_INTEGRATIONS
    pub fn guild_integrations(
        &self,
        guild_id: GuildId,
    ) -> Option<Reference<'_, GuildId, HashSet<IntegrationId>>> {
        self.guild_integrations.get(&guild_id).map(Reference::new)
    }

    /// Gets the set of members in a guild.
    ///
    /// This list may be incomplete if not all members have been cached.
    ///
    /// This requires the [`GUILD_MEMBERS`] intent.
    ///
    /// [`GUILD_MEMBERS`]: ::twilight_model::gateway::Intents::GUILD_MEMBERS
    pub fn guild_members(
        &self,
        guild_id: GuildId,
    ) -> Option<Reference<'_, GuildId, HashSet<UserId>>> {
        self.guild_members.get(&guild_id).map(Reference::new)
    }

    /// Gets the set of presences in a guild.
    ///
    /// This list may be incomplete if not all members have been cached.
    ///
    /// This requires the [`GUILD_PRESENCES`] intent.
    ///
    /// [`GUILD_PRESENCES`]: ::twilight_model::gateway::Intents::GUILD_PRESENCES
    pub fn guild_presences(
        &self,
        guild_id: GuildId,
    ) -> Option<Reference<'_, GuildId, HashSet<UserId>>> {
        self.guild_presences.get(&guild_id).map(Reference::new)
    }

    /// Gets the set of roles in a guild.
    ///
    /// This requires the [`GUILDS`] intent.
    ///
    /// [`GUILDS`]: ::twilight_model::gateway::Intents::GUILDS
    pub fn guild_roles(
        &self,
        guild_id: GuildId,
    ) -> Option<Reference<'_, GuildId, HashSet<RoleId>>> {
        self.guild_roles.get(&guild_id).map(Reference::new)
    }

    /// Gets the set of stage instances in a guild.
    ///
    /// This requires the [`GUILDS`] intent.
    ///
    /// [`GUILDS`]: twilight_model::gateway::Intents::GUILDS
    pub fn guild_stage_instances(
        &self,
        guild_id: GuildId,
    ) -> Option<Reference<'_, GuildId, HashSet<StageId>>> {
        self.guild_stage_instances
            .get(&guild_id)
            .map(Reference::new)
    }

    /// Gets the set of the stickers in a guild.
    ///
    /// This is an O(m) operation, where m is the amount of stickers in the
    /// guild. This requires the [`GUILDS`] intent and the [`STICKER`] resource
    /// type.
    ///
    /// [`GUILDS`]: twilight_model::gateway::Intents::GUILDS
    /// [`STICKER`]: crate::config::ResourceType::STICKER
    pub fn guild_stickers(
        &self,
        guild_id: GuildId,
    ) -> Option<Reference<'_, GuildId, HashSet<StickerId>>> {
        self.guild_stickers.get(&guild_id).map(Reference::new)
    }

    /// Gets an integration by guild ID and integration ID.
    ///
    /// This requires the [`GUILD_INTEGRATIONS`] intent. The
    /// [`ResourceType::INTEGRATION`] resource type must be enabled.
    ///
    /// [`GUILD_INTEGRATIONS`]: twilight_model::gateway::Intents::GUILD_INTEGRATIONS
    pub fn integration(
        &self,
        guild_id: GuildId,
        integration_id: IntegrationId,
    ) -> Option<Reference<'_, (GuildId, IntegrationId), GuildResource<GuildIntegration>>> {
        self.integrations
            .get(&(guild_id, integration_id))
            .map(Reference::new)
    }

    /// Gets a member by guild ID and user ID.
    ///
    /// This requires the [`GUILD_MEMBERS`] intent.
    ///
    /// [`GUILD_MEMBERS`]: ::twilight_model::gateway::Intents::GUILD_MEMBERS
    pub fn member(
        &self,
        guild_id: GuildId,
        user_id: UserId,
    ) -> Option<Reference<'_, (GuildId, UserId), CachedMember>> {
        self.members.get(&(guild_id, user_id)).map(Reference::new)
    }

    /// Gets a message by ID.
    ///
    /// This requires one or both of the [`GUILD_MESSAGES`] or
    /// [`DIRECT_MESSAGES`] intents.
    ///
    /// [`GUILD_MESSAGES`]: ::twilight_model::gateway::Intents::GUILD_MESSAGES
    /// [`DIRECT_MESSAGES`]: ::twilight_model::gateway::Intents::DIRECT_MESSAGES
    pub fn message(
        &self,
        message_id: MessageId,
    ) -> Option<Reference<'_, MessageId, CachedMessage>> {
        self.messages.get(&message_id).map(Reference::new)
    }

    /// Gets a presence by, optionally, guild ID, and user ID.
    ///
    /// This requires the [`GUILD_PRESENCES`] intent.
    ///
    /// [`GUILD_PRESENCES`]: ::twilight_model::gateway::Intents::GUILD_PRESENCES
    pub fn presence(
        &self,
        guild_id: GuildId,
        user_id: UserId,
    ) -> Option<Reference<'_, (GuildId, UserId), CachedPresence>> {
        self.presences.get(&(guild_id, user_id)).map(Reference::new)
    }

    /// Gets a private channel by ID.
    ///
    /// This requires the [`DIRECT_MESSAGES`] intent.
    ///
    /// [`DIRECT_MESSAGES`]: ::twilight_model::gateway::Intents::DIRECT_MESSAGES
    pub fn private_channel(
        &self,
        channel_id: ChannelId,
    ) -> Option<Reference<'_, ChannelId, PrivateChannel>> {
        self.channels_private.get(&channel_id).map(Reference::new)
    }

    /// Gets a role by ID.
    ///
    /// This requires the [`GUILDS`] intent.
    ///
    /// [`GUILDS`]: ::twilight_model::gateway::Intents::GUILDS
    pub fn role(&self, role_id: RoleId) -> Option<Reference<'_, RoleId, GuildResource<Role>>> {
        self.roles.get(&role_id).map(Reference::new)
    }

    /// Gets a stage instance by ID.
    ///
    /// This requires the [`GUILDS`] intent.
    ///
    /// [`GUILDS`]: twilight_model::gateway::Intents::GUILDS
    pub fn stage_instance(
        &self,
        stage_id: StageId,
    ) -> Option<Reference<'_, StageId, GuildResource<StageInstance>>> {
        self.stage_instances.get(&stage_id).map(Reference::new)
    }

    /// Gets a sticker by ID.
    ///
    /// This is the O(1) operation. This requires the [`GUILDS`] intent and the
    /// [`STICKER`] resource type.
    ///
    /// [`GUILDS`]: twilight_model::gateway::Intents::GUILDS
    /// [`STICKER`]: crate::config::ResourceType::STICKER
    pub fn sticker(
        &self,
        sticker_id: StickerId,
    ) -> Option<Reference<'_, StickerId, GuildResource<CachedSticker>>> {
        self.stickers.get(&sticker_id).map(Reference::new)
    }

    /// Gets a user by ID.
    ///
    /// This requires the [`GUILD_MEMBERS`] intent.
    ///
    /// [`GUILD_MEMBERS`]: ::twilight_model::gateway::Intents::GUILD_MEMBERS
    pub fn user(&self, user_id: UserId) -> Option<Reference<'_, UserId, User>> {
        self.users.get(&user_id).map(Reference::new)
    }

    /// Gets the voice states within a voice channel.
    ///
    /// This requires both the [`GUILDS`] and [`GUILD_VOICE_STATES`] intents.
    ///
    /// [`GUILDS`]: ::twilight_model::gateway::Intents::GUILDS
    /// [`GUILD_VOICE_STATES`]: ::twilight_model::gateway::Intents::GUILD_VOICE_STATES
    pub fn voice_channel_states(&self, channel_id: ChannelId) -> Option<VoiceChannelStates<'_>> {
        let user_ids = self.voice_state_channels.get(&channel_id)?;

        Some(VoiceChannelStates {
            index: 0,
            user_ids,
            voice_states: &self.voice_states,
        })
    }

    /// Gets a voice state by user ID and Guild ID.
    ///
    /// This requires both the [`GUILDS`] and [`GUILD_VOICE_STATES`] intents.
    ///
    /// [`GUILDS`]: ::twilight_model::gateway::Intents::GUILDS
    /// [`GUILD_VOICE_STATES`]: ::twilight_model::gateway::Intents::GUILD_VOICE_STATES
    pub fn voice_state(
        &self,
        user_id: UserId,
        guild_id: GuildId,
    ) -> Option<Reference<'_, (GuildId, UserId), VoiceState>> {
        self.voice_states
            .get(&(guild_id, user_id))
            .map(Reference::new)
    }

    /// Gets the highest role of a member.
    ///
    /// This requires both the [`GUILDS`] and [`GUILD_MEMBERS`] intents.
    ///
    /// [`GUILDS`]: twilight_model::gateway::Intents::GUILDS
    /// [`GUILD_MEMBERS`]: twilight_model::gateway::Intents::GUILD_MEMBERS
    pub fn member_highest_role(&self, guild_id: GuildId, user_id: UserId) -> Option<RoleId> {
        let member = match self.members.get(&(guild_id, user_id)) {
            Some(member) => member,
            None => return None,
        };

        let mut highest_role: Option<(i64, RoleId)> = None;

        for role_id in &member.roles {
            if let Some(role) = self.role(*role_id) {
                if let Some((position, id)) = highest_role {
                    if role.position < position || (role.position == position && role.id > id) {
                        continue;
                    }
                }

                highest_role = Some((role.position, role.id));
            }
        }

        highest_role.map(|(_, id)| id)
    }

    fn new_with_config(config: Config) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    /// Determine whether the configured cache wants a specific resource to be
    /// processed.
    const fn wants(&self, resource_type: ResourceType) -> bool {
        self.config.resource_types().contains(resource_type)
    }
}

/// Implemented for dispatch events.
pub trait UpdateCache {
    /// Updates the cache based on data contained within an event.
    // Allow this for presentation purposes in documentation.
    #[allow(unused_variables)]
    fn update(&self, cache: &InMemoryCache) {}
}

/// Iterator over a voice channel's list of voice states.
pub struct VoiceChannelStates<'a> {
    index: usize,
    user_ids: Ref<'a, ChannelId, HashSet<(GuildId, UserId)>>,
    voice_states: &'a DashMap<(GuildId, UserId), VoiceState>,
}

impl<'a> Iterator for VoiceChannelStates<'a> {
    type Item = Reference<'a, (GuildId, UserId), VoiceState>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((guild_id, user_id)) = self.user_ids.iter().nth(self.index) {
            if let Some(voice_state) = self.voice_states.get(&(*guild_id, *user_id)) {
                self.index += 1;

                return Some(Reference::new(voice_state));
            }
        }

        None
    }
}

impl UpdateCache for Event {
    #[allow(clippy::cognitive_complexity)]
    fn update(&self, c: &InMemoryCache) {
        use Event::*;

        match self {
            BanAdd(_) => {}
            BanRemove(_) => {}
            ChannelCreate(v) => c.update(v),
            ChannelDelete(v) => c.update(v),
            ChannelPinsUpdate(v) => c.update(v),
            ChannelUpdate(v) => c.update(v),
            GatewayHeartbeat(_) => {}
            GatewayHeartbeatAck => {}
            GatewayHello(_) => {}
            GatewayInvalidateSession(_v) => {}
            GatewayReconnect => {}
            GiftCodeUpdate => {}
            GuildCreate(v) => c.update(v.deref()),
            GuildDelete(v) => c.update(v.deref()),
            GuildEmojisUpdate(v) => c.update(v),
            GuildIntegrationsUpdate(_) => {}
            GuildUpdate(v) => c.update(v.deref()),
            IntegrationCreate(v) => c.update(v.deref()),
            IntegrationDelete(v) => c.update(v.deref()),
            IntegrationUpdate(v) => c.update(v.deref()),
            InteractionCreate(v) => c.update(v.deref()),
            InviteCreate(_) => {}
            InviteDelete(_) => {}
            MemberAdd(v) => c.update(v.deref()),
            MemberRemove(v) => c.update(v),
            MemberUpdate(v) => c.update(v.deref()),
            MemberChunk(v) => c.update(v),
            MessageCreate(v) => c.update(v.deref()),
            MessageDelete(v) => c.update(v),
            MessageDeleteBulk(v) => c.update(v),
            MessageUpdate(v) => c.update(v.deref()),
            PresenceUpdate(v) => c.update(v.deref()),
            PresencesReplace => {}
            ReactionAdd(v) => c.update(v.deref()),
            ReactionRemove(v) => c.update(v.deref()),
            ReactionRemoveAll(v) => c.update(v),
            ReactionRemoveEmoji(v) => c.update(v),
            Ready(v) => c.update(v.deref()),
            Resumed => {}
            RoleCreate(v) => c.update(v),
            RoleDelete(v) => c.update(v),
            RoleUpdate(v) => c.update(v),
            ShardConnected(_) => {}
            ShardConnecting(_) => {}
            ShardDisconnected(_) => {}
            ShardIdentifying(_) => {}
            ShardReconnecting(_) => {}
            ShardPayload(_) => {}
            ShardResuming(_) => {}
            StageInstanceCreate(v) => c.update(v),
            StageInstanceDelete(v) => c.update(v),
            StageInstanceUpdate(v) => c.update(v),
            ThreadCreate(v) => c.update(v),
            ThreadUpdate(v) => c.update(v),
            ThreadDelete(v) => c.update(v),
            ThreadListSync(v) => c.update(v),
            ThreadMemberUpdate(_) => {}
            ThreadMembersUpdate(_) => {}
            TypingStart(_) => {}
            UnavailableGuild(v) => c.update(v),
            UserUpdate(v) => c.update(v),
            VoiceServerUpdate(_) => {}
            VoiceStateUpdate(v) => c.update(v.deref()),
            WebhooksUpdate(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{test, InMemoryCache};
    use twilight_model::{
        gateway::payload::incoming::RoleDelete,
        guild::{Member, Permissions, Role},
        id::{EmojiId, GuildId, RoleId, UserId},
    };

    #[test]
    fn test_syntax_update() {
        let cache = InMemoryCache::new();
        cache.update(&RoleDelete {
            guild_id: GuildId::new(1).expect("non zero"),
            role_id: RoleId::new(1).expect("non zero"),
        });
    }

    #[test]
    fn test_clear() {
        let cache = InMemoryCache::new();
        cache.cache_emoji(
            GuildId::new(1).expect("non zero"),
            test::emoji(EmojiId::new(3).expect("non zero"), None),
        );
        cache.cache_member(
            GuildId::new(2).expect("non zero"),
            test::member(
                UserId::new(4).expect("non zero"),
                GuildId::new(2).expect("non zero"),
            ),
        );
        cache.clear();
        assert!(cache.emojis.is_empty());
        assert!(cache.members.is_empty());
    }

    #[test]
    fn test_highest_role() {
        let cache = InMemoryCache::new();
        let guild_id = GuildId::new(1).expect("non zero");
        let user = test::user(UserId::new(1).expect("non zero"));
        cache.cache_member(
            guild_id,
            Member {
                deaf: false,
                guild_id,
                hoisted_role: None,
                joined_at: None,
                mute: false,
                nick: None,
                pending: false,
                premium_since: None,
                roles: vec![
                    RoleId::new(1).expect("non zero"),
                    RoleId::new(2).expect("non zero"),
                ],
                user,
            },
        );

        cache.cache_roles(
            guild_id,
            vec![
                Role {
                    color: 0,
                    hoist: false,
                    id: RoleId::new(1).expect("non zero"),
                    managed: false,
                    mentionable: false,
                    name: "test".to_owned(),
                    permissions: Permissions::empty(),
                    position: 0,
                    tags: None,
                },
                Role {
                    color: 0,
                    hoist: false,
                    id: RoleId::new(2).expect("non zero"),
                    managed: false,
                    mentionable: false,
                    name: "test".to_owned(),
                    permissions: Permissions::empty(),
                    position: 1,
                    tags: None,
                },
            ],
        );

        assert_eq!(
            cache.member_highest_role(guild_id, UserId::new(1).expect("non zero")),
            Some(RoleId::new(2).expect("non zero"))
        );
    }
}
