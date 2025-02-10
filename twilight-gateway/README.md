# twilight-gateway

[![codecov badge][]][codecov link] [![discord badge][]][discord link] [![github badge][]][github link] [![license badge][]][license link] ![rust badge]

`twilight-gateway` is an implementation of Discord's sharding gateway sessions.
This is responsible for receiving stateful events in real-time from Discord and
sending *some* stateful information.

The primary type is the `Shard`, a stateful interface to maintain a Websocket
connection to Discord's gateway. Much of its functionality can be configured,
and it's used to receive gateway events or raw Websocket messages, useful for
load balancing and microservices.

Multiple shards may easily be created at once, with a per shard config created
from a `Fn(ShardId, ConfigBuilder) -> Config` closure, with the help of the
`create_` set of functions. These functions will reuse shards' TLS context and
[session queue][queue], something otherwise achieved by cloning an existing
[`Config`].

## Features

* `simd-json`: use [`simd-json`] instead of [`serde_json`] for deserializing
  events
* TLS (mutually exclusive)
  * `native-tls`: platform's native TLS implementation via [`native-tls`]
  * `rustls-native-roots`: [`rustls`] using native root certificates
  * `rustls-platform-verifier` (*default*): [`rustls`] using operating system's
    certificate facilities via [`rustls-platform-verifier`]
  * `rustls-webpki-roots`: [`rustls`] using [`webpki-roots`] for root
    certificates, useful for `scratch` containers
* Crypto providers (required with [`rustls`])
  * `rustls-ring` (*default*): [`ring`] as the crypto provider, recommended for
    compatibility
  * `rustls-aws_lc_rs`: [`aws-lc-rs`] as the crypto provider, recommended for
    performance and widely used platforms
  * none of the above: install your own via [`CryptoProvider::install_default`]
* `twilight-http` (*default*): enable the `stream::create_recommended` function
* Compression (mutually exclusive)
  * `zlib-stock`: [`flate2`]'s stock zlib implementation (*deprecated*)
  * `zlib-simd`: use [`zlib-ng`] for zlib, may have better performance (*deprecated*)
  * `zstd` (*default*): enable zstd transport compression

## Example

Create the recommended number of shards and loop over their guild events in
parallel

```rust,no_run
use std::{
    env,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::signal;
use twilight_gateway::{
    error::ReceiveMessageErrorType, CloseFrame, Config, Event, EventTypeFlags, Intents, Shard,
    StreamExt as _,
};
use twilight_http::Client;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let token = env::var("DISCORD_TOKEN")?;
    let client = Client::new(token.clone());
    let config = Config::new(token, Intents::GUILDS);

    let shards =
        twilight_gateway::create_recommended(&client, config, |_, builder| builder.build()).await?;
    let mut senders = Vec::with_capacity(shards.len());
    let mut tasks = Vec::with_capacity(shards.len());

    for shard in shards {
        senders.push(shard.sender());
        tasks.push(tokio::spawn(runner(shard)));
    }

    signal::ctrl_c().await?;
    SHUTDOWN.store(true, Ordering::Relaxed);
    for sender in senders {
        // Ignore error if shard's already shutdown.
        _ = sender.close(CloseFrame::NORMAL);
    }

    for jh in tasks {
        _ = jh.await;
    }

    Ok(())
}

#[tracing::instrument(fields(shard = %shard.id()), skip_all)]
async fn runner(mut shard: Shard) {
    while let Some(item) = shard.next_event(EventTypeFlags::all()).await {
        let event = match item {
            Ok(Event::GatewayClose(_)) if SHUTDOWN.load(Ordering::Relaxed) => break,
            Ok(event) => event,
            Err(source) => {
                tracing::warn!(?source, "error receiving event");

                continue;
            }
        };

        // You'd normally want to spawn a new tokio task for each event and
        // handle the event there to not block the shard.
        tracing::debug!(?event, shard = ?shard.id(), "received event");
    }
}
```

There are a few additional examples located in the
[repository][github examples link].

[`CryptoProvider::install_default`]: https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html#method.install_default
[`aws-lc-rs`]: https://crates.io/crates/aws-lc-rs
[`flate2`]: https://crates.io/crates/flate2
[`native-tls`]: https://crates.io/crates/native-tls
[`ring`]: https://crates.io/crates/ring
[`rustls`]: https://crates.io/crates/rustls
[`rustls-platform-verifier`]: https://crates.io/crates/rustls-platform-verifier
[`serde_json`]: https://crates.io/crates/serde_json
[`simd-json`]: https://crates.io/crates/simd-json
[`webpki-roots`]: https://crates.io/crates/webpki-roots
[`zlib-ng`]: https://github.com/zlib-ng/zlib-ng
[codecov badge]: https://img.shields.io/codecov/c/gh/twilight-rs/twilight?logo=codecov&style=for-the-badge&token=E9ERLJL0L2
[codecov link]: https://app.codecov.io/gh/twilight-rs/twilight/
[discord badge]: https://img.shields.io/discord/745809834183753828?color=%237289DA&label=discord%20server&logo=discord&style=for-the-badge
[discord link]: https://discord.gg/7jj8n7D
[github badge]: https://img.shields.io/badge/github-twilight-6f42c1.svg?style=for-the-badge&logo=github
[github examples link]: https://github.com/twilight-rs/twilight/tree/main/examples
[github link]: https://github.com/twilight-rs/twilight
[license badge]: https://img.shields.io/badge/license-ISC-blue.svg?style=for-the-badge&logo=pastebin
[license link]: https://github.com/twilight-rs/twilight/blob/main/LICENSE.md
[rust badge]: https://img.shields.io/badge/rust-1.79+-93450a.svg?style=for-the-badge&logo=rust
