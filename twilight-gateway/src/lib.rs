#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![warn(
    clippy::missing_const_for_fn,
    clippy::missing_docs_in_private_items,
    clippy::pedantic,
    missing_docs,
    unsafe_code
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::unnecessary_wraps
)]

pub mod error;

mod channel;
mod command;
#[cfg(any(feature = "zlib-stock", feature = "zlib-simd", feature = "zstd"))]
mod compression;
mod config;
mod event;
#[cfg(all(
    any(feature = "zlib-stock", feature = "zlib-simd"),
    not(feature = "zstd")
))]
mod inflater;
mod json;
mod latency;
mod message;
mod ratelimiter;
mod session;
mod shard;
mod stream;

#[allow(deprecated)]
#[cfg(all(
    any(feature = "zlib-stock", feature = "zlib-simd"),
    not(feature = "zstd")
))]
pub use self::inflater::Inflater;
pub use self::{
    channel::MessageSender,
    command::Command,
    config::{Config, ConfigBuilder},
    event::EventTypeFlags,
    json::parse,
    latency::Latency,
    message::Message,
    ratelimiter::CommandRatelimiter,
    session::Session,
    shard::{Shard, ShardState},
    stream::StreamExt,
};
pub use twilight_model::gateway::{CloseFrame, Intents, ShardId};

#[doc(no_inline)]
pub use twilight_gateway_queue as queue;
#[doc(no_inline)]
pub use twilight_model::gateway::event::{Event, EventType};

#[cfg(feature = "twilight-http")]
use self::error::{StartRecommendedError, StartRecommendedErrorType};
#[cfg(feature = "twilight-http")]
use twilight_http::Client;

/// Discord Gateway API version used by this crate.
pub const API_VERSION: u8 = 10;

/// Create a single bucket's worth of shards.
///
/// Passing a primary config is required. Further customization of this config
/// may be performed in the callback.
///
/// Internally calls [`create_iterator`] with `(bucket_id..total).step_by(concurrency)`.
///
/// # Panics
///
/// Panics if `bucket_id >= total`, `bucket_id >= concurrency`, or `concurrency >= total`.
///
/// Panics if loading TLS certificates fails.
#[track_caller]
pub fn create_bucket<F, Q>(
    bucket_id: u16,
    concurrency: u16,
    total: u32,
    config: Config<Q>,
    per_shard_config: F,
) -> impl ExactSizeIterator<Item = Shard<Q>>
where
    F: Fn(ShardId, ConfigBuilder<Q>) -> Config<Q>,
    Q: Clone,
{
    assert!(
        u32::from(bucket_id) < total,
        "bucket id must be less than the total"
    );
    assert!(
        bucket_id < concurrency,
        "bucket id must be less than concurrency"
    );
    assert!(
        (u32::from(concurrency)) < total,
        "concurrency must be less than the total"
    );

    create_iterator(
        (u32::from(bucket_id)..total).step_by(concurrency.into()),
        total,
        config,
        per_shard_config,
    )
}

/// Create a iterator of shards.
///
/// Passing a primary config is required. Further customization of this config
/// may be performed in the callback.
///
/// # Examples
///
/// Start 10 out of 10 shards and count them:
///
/// ```no_run
/// use std::{collections::HashMap, env, sync::Arc};
/// use twilight_gateway::{Config, Intents};
///
/// let token = env::var("DISCORD_TOKEN")?;
///
/// let config = Config::new(token.clone(), Intents::GUILDS);
/// let shards = twilight_gateway::create_iterator(0..10, 10, config, |_, builder| builder.build());
///
/// assert_eq!(shards.len(), 10);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Panics
///
/// Panics if `range` contains values larger than `total`.
///
/// Panics if loading TLS certificates fails.
#[track_caller]
pub fn create_iterator<F, Q>(
    numbers: impl ExactSizeIterator<Item = u32>,
    total: u32,
    config: Config<Q>,
    per_shard_config: F,
) -> impl ExactSizeIterator<Item = Shard<Q>>
where
    F: Fn(ShardId, ConfigBuilder<Q>) -> Config<Q>,
    Q: Clone,
{
    numbers.map(move |index| {
        let id = ShardId::new(index, total);
        let config = per_shard_config(id, ConfigBuilder::from(config.clone()));

        Shard::with_config(id, config)
    })
}

/// Create a range of shards from Discord's recommendation.
///
/// Passing a primary config is required. Further customization of this config
/// may be performed in the callback.
///
/// Internally calls [`create_iterator`] with the values from [`GetGatewayAuthed`].
///
/// # Errors
///
/// Returns a [`StartRecommendedErrorType::Deserializing`] error type if the
/// response body failed to deserialize.
///
/// Returns a [`StartRecommendedErrorType::Request`] error type if the request
/// failed to complete.
///
/// # Panics
///
/// Panics if loading TLS certificates fails.
///
/// [`GetGatewayAuthed`]: twilight_http::request::GetGatewayAuthed
#[cfg(feature = "twilight-http")]
pub async fn create_recommended<F, Q>(
    client: &Client,
    config: Config<Q>,
    per_shard_config: F,
) -> Result<impl ExactSizeIterator<Item = Shard<Q>>, StartRecommendedError>
where
    F: Fn(ShardId, ConfigBuilder<Q>) -> Config<Q>,
    Q: Clone,
{
    let request = client.gateway().authed();
    let response = request.await.map_err(|source| StartRecommendedError {
        kind: StartRecommendedErrorType::Request,
        source: Some(Box::new(source)),
    })?;
    let info = response
        .model()
        .await
        .map_err(|source| StartRecommendedError {
            kind: StartRecommendedErrorType::Deserializing,
            source: Some(Box::new(source)),
        })?;

    Ok(create_iterator(
        0..info.shards,
        info.shards,
        config,
        per_shard_config,
    ))
}
