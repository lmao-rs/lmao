use super::{
    config::Config as ClusterConfig,
    event::Events,
    r#impl::{Cluster, ClusterStartError},
    scheme::ShardScheme,
    ClusterStartErrorType,
};
use crate::{
    shard::{tls::TlsContainer, LargeThresholdError, ResumeSession, ShardBuilder},
    EventTypeFlags,
};
use std::{collections::HashMap, sync::Arc};
use twilight_gateway_queue::{LocalQueue, Queue};
use twilight_http::Client;
use twilight_model::gateway::{
    payload::outgoing::{identify::IdentifyProperties, update_presence::UpdatePresencePayload},
    Intents,
};

/// Builder to configure and construct a [`Cluster`].
///
/// # Examples
///
/// Create a cluster with only the `GUILD_MESSAGES` intents with a
/// [`large_threshold`] of 100.
///
/// ```no_run
/// use std::env;
/// use twilight_gateway::{Cluster, Intents};
///
/// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let token = env::var("DISCORD_TOKEN")?;
///
/// let cluster = Cluster::builder(token, Intents::GUILD_MESSAGES)
///     .large_threshold(100)?
///     .build()
///     .await?;
/// # Ok(()) }
/// ```
///
/// [`large_threshold`]: Self::large_threshold
#[derive(Debug)]
pub struct ClusterBuilder(ClusterConfig, ShardBuilder);

impl ClusterBuilder {
    /// Create a new builder to construct and configure a cluster.
    pub fn new(token: String, intents: Intents) -> Self {
        Self(
            ClusterConfig {
                queue: Arc::new(LocalQueue::new()),
                resume_sessions: HashMap::new(),
                shard_presence: None,
                shard_scheme: ShardScheme::Auto,
            },
            ShardBuilder::new(token, intents),
        )
    }

    /// Consume the builder and create the cluster.
    ///
    /// # Errors
    ///
    /// Returns a [`ClusterStartErrorType::RetrievingGatewayInfo`] error type if
    /// there was an HTTP error Retrieving the gateway information.
    ///
    /// [`ClusterStartErrorType::RetrievingGatewayInfo`]: super::ClusterStartErrorType::RetrievingGatewayInfo
    pub async fn build(mut self) -> Result<(Cluster, Events), ClusterStartError> {
        let tls = TlsContainer::new().map_err(|err| ClusterStartError {
            kind: ClusterStartErrorType::Tls,
            source: Some(Box::new(err)),
        })?;

        (self.1).0.tls = Some(tls);

        if (self.1).0.gateway_url.is_none() {
            let maybe_response = (self.1).0.http_client.gateway().authed().exec().await;

            if let Ok(response) = maybe_response {
                let gateway_url = response.model().await.ok().map(|info| info.url);

                self = self.gateway_url(gateway_url);
            }
        }

        Cluster::new_with_config(self.0, self.1 .0).await
    }

    /// Set the event types to process.
    ///
    /// This is an optimization technique; all events not included in the
    /// provided event type flags will not be deserialized by the gateway and
    /// will be discarded. All events will still be sent if
    /// [`EventTypeFlags::SHARD_PAYLOAD`] is enabled.
    ///
    /// [`EventTypeFlags::SHARD_PAYLOAD`]: crate::EventTypeFlags::SHARD_PAYLOAD
    #[allow(clippy::missing_const_for_fn)]
    pub fn event_types(mut self, event_types: EventTypeFlags) -> Self {
        self.1 = self.1.event_types(event_types);

        self
    }

    /// Set the URL that will be used to connect to the gateway.
    pub fn gateway_url(mut self, gateway_url: Option<String>) -> Self {
        self.1 = self.1.gateway_url(gateway_url);

        self
    }

    /// Set the `twilight_http` Client used by the cluster and the shards it
    /// manages.
    ///
    /// This is needed so that the cluster and shards can retrieve gateway
    /// information.
    ///
    /// Defaults to a new, default HTTP client is used.
    pub fn http_client(mut self, http_client: Arc<Client>) -> Self {
        self.1 = self.1.http_client(http_client);

        self
    }

    /// Set the properties for shards to identify with.
    ///
    /// This may be used if you want to set a different operating system, for
    /// example.
    ///
    /// # Examples
    ///
    /// Set the identify properties for a cluster:
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::env::{self, consts::OS};
    /// use twilight_gateway::{Intents, Cluster};
    /// use twilight_model::gateway::payload::outgoing::identify::IdentifyProperties;
    ///
    /// let token = env::var("DISCORD_TOKEN")?;
    /// let properties = IdentifyProperties::new(
    ///     "twilight.rs",
    ///     "twilight.rs",
    ///     OS,
    ///     "",
    ///     "",
    /// );
    ///
    /// let builder = Cluster::builder(token, Intents::empty())
    ///     .identify_properties(properties);
    /// # Ok(()) }
    /// ```
    #[allow(clippy::missing_const_for_fn)]
    pub fn identify_properties(mut self, identify_properties: IdentifyProperties) -> Self {
        self.1 = self.1.identify_properties(identify_properties);

        self
    }

    /// Set the "large threshold" of shards.
    ///
    /// Refer to the shard's [`ShardBuilder::large_threshold`] for more
    /// information.
    ///
    /// # Errors
    ///
    /// Returns a [`LargeThresholdErrorType::TooFew`] error type if the provided
    /// value is below 50.
    ///
    /// Returns a [`LargeThresholdErrorType::TooMany`] error type if the
    /// provided value is above 250.
    ///
    /// [`LargeThresholdErrorType::TooFew`]: crate::shard::LargeThresholdErrorType::TooFew
    /// [`LargeThresholdErrorType::TooMany`]: crate::shard::LargeThresholdErrorType::TooMany
    pub fn large_threshold(mut self, large_threshold: u64) -> Result<Self, LargeThresholdError> {
        self.1 = self.1.large_threshold(large_threshold)?;

        Ok(self)
    }

    /// Set the presence to use when identifying with the gateway.
    ///
    /// Refer to the shard's [`ShardBuilder::presence`] for more information.
    pub fn presence(mut self, presence: UpdatePresencePayload) -> Self {
        self.1 = self.1.presence(presence);

        self
    }

    /// Set specific shard presences to use when identifying with the gateway.
    ///
    /// Accepts a closure. The closure accepts a [`u64`] and returns an
    /// [`Option<UpdatePresencePayload>`]. This presence will override any set
    /// by [`presence`], even if the provided closure returns [`None`].
    ///
    /// [`presence`]: Self::presence
    pub fn shard_presence<F>(mut self, shard_presence: F) -> Self
    where
        F: Fn(u64) -> Option<UpdatePresencePayload> + Send + Sync + 'static,
    {
        self.0.shard_presence = Some(Box::new(shard_presence));

        self
    }

    /// Set the scheme to use for shard managing.
    ///
    /// For example, [`ShardScheme::Auto`] means that the cluster will
    /// automatically manage all of the shards that Discord recommends you use.
    /// [`ShardScheme::Range`] means that it will manage a range of shards, but
    /// not necessarily all of the shards that your bot uses.
    ///
    /// The default value is [`ShardScheme::Auto`]. For most setups this is an
    /// acceptable default.
    ///
    /// # Examples
    ///
    /// Configure a cluster to manage shards 0-9 out of 20 shards total:
    ///
    /// ```no_run
    /// use twilight_gateway::{cluster::{Cluster, ShardScheme}, Intents};
    /// use std::env;
    ///
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let token = env::var("DISCORD_TOKEN")?;
    /// let scheme = ShardScheme::try_from((0..=9, 20))?;
    ///
    /// let cluster = Cluster::builder(token, Intents::GUILD_MESSAGES)
    ///     .shard_scheme(scheme)
    ///     .build()
    ///     .await?;
    /// # Ok(()) }
    /// ```
    #[allow(clippy::missing_const_for_fn)]
    pub fn shard_scheme(mut self, scheme: ShardScheme) -> Self {
        self.0.shard_scheme = scheme;

        self
    }

    /// Set the queue to use for queueing shard connections.
    ///
    /// This is useful when you have a very large bot or when you have a more
    /// advanced setup with multiple processes connecting at the same time.
    ///
    /// Refer to the [`queue`] module for more information.
    ///
    /// [`queue`]: crate::queue
    pub fn queue(mut self, queue: Arc<dyn Queue>) -> Self {
        self.0.queue = Arc::clone(&queue);
        self.1 = self.1.queue(queue);

        self
    }

    /// Set the session information to resume shards with.
    ///
    /// This requires having recovered the resume data when shutting down the
    /// cluster via [`Cluster::down_resumable`].
    ///
    /// Note that this does not guarantee all or any of the shards will be able
    /// to resume. If their sessions are invalid they will have to re-identify
    /// to initialize a new session.
    #[allow(clippy::missing_const_for_fn)]
    pub fn resume_sessions(mut self, resume_sessions: HashMap<u64, ResumeSession>) -> Self {
        self.0.resume_sessions = resume_sessions;
        self
    }
}

impl From<(String, Intents)> for ClusterBuilder {
    fn from((token, intents): (String, Intents)) -> Self {
        Self::new(token, intents)
    }
}

#[cfg(test)]
mod tests {
    use super::ClusterBuilder;
    use crate::Intents;
    use static_assertions::assert_impl_all;
    use std::fmt::Debug;

    assert_impl_all!(ClusterBuilder: Debug, From<(String, Intents)>, Send, Sync);
}
