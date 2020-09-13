use super::{config::Config, Shard};
use crate::queue::{LocalQueue, Queue};
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
    sync::Arc,
};
use twilight_http::Client as HttpClient;
use twilight_model::gateway::{payload::update_status::UpdateStatusInfo, Intents};

/// Large threshold configuration is invalid.
///
/// Returned by [`ShardBuilder::large_threshold`].
///
/// [`ShardBuilder::large_threshold`]: struct.ShardBuilder.html#method.large_threshold
#[derive(Debug)]
pub enum LargeThresholdError {
    /// Provided large threshold value is too few in number.
    TooFew {
        /// Provided value.
        value: u64,
    },
    /// Provided large threshold value is too many in number.
    TooMany {
        /// Provided value.
        value: u64,
    },
}

impl Display for LargeThresholdError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::TooFew { .. } => f.write_str("provided large threshold value is fewer than 50"),
            Self::TooMany { .. } => f.write_str("provided large threshold value is more than 250"),
        }
    }
}

impl Error for LargeThresholdError {}

/// Shard ID configuration is invalid.
///
/// Returned by [`ShardBuilder::shard`].
///
/// [`ShardBuilder::shard`]: struct.ShardBuilder.html#method.shard
#[derive(Debug)]
pub enum ShardIdError {
    /// Provided shard ID is higher than provided total shard count.
    IdTooLarge {
        /// Shard ID.
        id: u64,
        /// Total shard count.
        total: u64,
    },
}

impl Display for ShardIdError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::IdTooLarge { id, total } => f.write_fmt(format_args!(
                "provided shard ID {} is larger than the total {}",
                id, total,
            )),
        }
    }
}

impl Error for ShardIdError {}

/// Builder to configure and construct a shard.
///
/// Use [`ShardBuilder::new`] to start configuring a new [`Shard`].
///
/// # Examples
///
/// Create a new shard, setting the [`large_threshold`] to 100 and the
/// [`shard`] ID to 5 out of 10:
///
/// ```rust,no_run
/// use std::env;
/// use twilight_gateway::Shard;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let token = env::var("DISCORD_TOKEN")?;
///
/// let shard = Shard::builder(token)
///     .large_threshold(100)?
///     .shard(5, 10)?
///     .build();
/// # Ok(()) }
/// ```
///
/// [`ShardBuilder::new`]: #method.new
/// [`Shard`]: struct.Shard.html
/// [`large_threshold`]: #method.large_threshold
/// [`shard`]: #method.shard
#[derive(Clone, Debug)]
pub struct ShardBuilder(pub(crate) Config);

impl ShardBuilder {
    /// Create a new builder to configure and construct a shard.
    ///
    /// Refer to each method to learn their default values.
    pub fn new(token: impl Into<String>) -> Self {
        Self::_new(token.into())
    }

    fn _new(mut token: String) -> Self {
        if !token.starts_with("Bot ") {
            token.insert_str(0, "Bot ");
        }

        Self(Config {
            http_client: HttpClient::new(token.clone()),
            intents: None,
            large_threshold: 250,
            presence: None,
            queue: Arc::new(Box::new(LocalQueue::new())),
            shard: [0, 1],
            token,
            session_id: None,
            sequence: None,
        })
    }

    /// Consume the builder, constructing a shard.
    pub fn build(self) -> Shard {
        Shard::new_with_config(self.0)
    }

    /// Set the HTTP client to be used by the shard for getting gateway
    /// information.
    ///
    /// Default is a new, unconfigured instance of an HTTP client.
    pub fn http_client(mut self, http_client: HttpClient) -> Self {
        self.0.http_client = http_client;

        self
    }

    /// Set the gateway intents.
    ///
    /// Default is Discord's default.
    pub fn intents(mut self, intents: Intents) -> Self {
        self.0.intents.replace(intents);

        self
    }

    /// Set the maximum number of members in a guild to load the member list.
    ///
    /// Default value is `250`. The minimum value is `50` and the maximum is
    /// `250`.
    ///
    /// # Examples
    ///
    /// If you pass `200`, then if there are 250 members in a guild the member
    /// list won't be sent. If there are 150 members, then the list *will* be
    /// sent.
    ///
    /// # Errors
    ///
    /// Returns [`LargeThresholdError::TooFew`] if the provided value is below
    /// 50.
    ///
    /// Returns [`LargeThresholdError::TooMany`] if the provided value is above
    /// 250.
    ///
    /// [`LargeThresholdError::TooFew`]: enum.LargeThresholdError.html#variant.TooFew
    /// [`LargeThresholdError::TooMany`]: enum.LargeThresholdError.html#variant.TooMany
    pub fn large_threshold(mut self, large_threshold: u64) -> Result<Self, LargeThresholdError> {
        match large_threshold {
            0..=49 => {
                return Err(LargeThresholdError::TooFew {
                    value: large_threshold,
                })
            }
            50..=250 => {}
            251..=u64::MAX => {
                return Err(LargeThresholdError::TooMany {
                    value: large_threshold,
                })
            }
        }

        self.0.large_threshold = large_threshold;

        Ok(self)
    }

    /// Set the presence to use automatically when starting a new session.
    ///
    /// Default is no presence, which defaults to strictly being "online"
    /// with no special qualities.
    pub fn presence(mut self, presence: UpdateStatusInfo) -> Self {
        self.0.presence.replace(presence);

        self
    }

    /// Set the queue to use for queueing shard connections.
    ///
    /// You probably don't need to set this yourself, because the [`Cluster`]
    /// manages that for you. Refer to the [`queue`] module for more
    /// information.
    ///
    /// The default value is a queue used only by this shard, or a queue used by
    /// all shards when ran by a [`Cluster`].
    ///
    /// [`Cluster`]: ../cluster/struct.Cluster.html
    /// [`queue`]: ../queue/index.html
    pub fn queue(mut self, queue: Arc<Box<dyn Queue>>) -> Self {
        self.0.queue = queue;

        self
    }

    /// Set the shard ID to connect as, and the total number of shards used by
    /// the bot.
    ///
    /// The shard ID is 0-indexed, while the total is 1-indexed.
    ///
    /// The default value is a shard ID of 0 and a shard total of 1, which is
    /// good for smaller bots.
    ///
    /// **Note**: If your bot is in over 250'000 guilds then `shard_total`
    /// *should probably* be a multiple of 16 if you're in the "Large Bot
    /// Sharding" program.
    ///
    /// # Examples
    ///
    /// If you have 19 shards, then your last shard will have an ID of 18 out of
    /// a total of 19 shards:
    ///
    /// ```no_run
    /// use twilight_gateway::Shard;
    /// use std::env;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let token = env::var("DISCORD_TOKEN")?;
    ///
    /// let shard = Shard::builder(token).shard(18, 19)?.build();
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ShardIdError::IdTooLarge`] if the shard ID to connect as is
    /// larger than the total.
    ///
    /// [`ShardIdError::IdTooLarge`]: enum.ShardIdError.html#variant.IdTooLarge
    pub fn shard(mut self, shard_id: u64, shard_total: u64) -> Result<Self, ShardIdError> {
        if shard_id >= shard_total {
            return Err(ShardIdError::IdTooLarge {
                id: shard_id,
                total: shard_total,
            });
        }

        self.0.shard = [shard_id, shard_total];

        Ok(self)
    }
}

impl<T: Into<String>> From<T> for ShardBuilder {
    fn from(token: T) -> Self {
        Self::new(token.into())
    }
}
