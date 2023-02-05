# Gateway

`twilight-gateway` is an implementation of a client over Discord's websocket
gateway.

The main type is the `Shard`: it connects to the gateway, receives messages,
parses and processes them, and then gives them to you. It will automatically
reconnect, resume, and identify, as well as do some additional connectivity
checks.

## Features

`twilight-gateway` includes a number of features for things ranging from
payload deserialization to TLS features.

### Deserialization

`twilight-gateway` supports [`serde_json`] and [`simd-json`] for deserializing
and serializing events.

#### SIMD

The `simd-json` feature enables usage of [`simd-json`], which uses modern CPU
features to more efficiently deserialize JSON data. It is not enabled by
default.

In addition to enabling the feature, you will need to add the following to your
`<project_root>/.cargo/config`:

```toml
[build]
rustflags = ["-C", "target-cpu=native"]
```

### TLS

`twilight-gateway` has features to enable [`tokio-tungstenite`]'s TLS features.
These features are mutually exclusive. `rustls-native-roots` is enabled by
default.

#### Native

The `native` feature enables [`tokio-tungstenite`]'s `native-tls` feature.

#### RusTLS

RusTLS allows specifying from where certificate roots are retrieved from.

##### Native roots

The `rustls-native-roots` feature enables [`tokio-tungstenite`]'s
`rustls-tls-native-roots` feature.

This is enabled by default.

##### Web PKI roots

The `rustls-webpki-roots` feature enables [`tokio-tungstenite`]'s
`rustls-tls-webpki-roots` feature.

### Zlib

#### Stock

The `zlib-stock` feature makes [flate2] use of the stock Zlib which is either
upstream or the one included with the operating system.

#### SIMD

`zlib-simd` enables the use of [zlib-ng] which is a modern fork of zlib that in
most cases will be more effective. However, this will add an external dependency
on [cmake].

If both are enabled or if the `zlib` feature of [flate2] is enabled anywhere in
the dependency tree it will make use of that instead of [zlib-ng].

## Example

Starting a `Shard` and printing the contents of new messages as they come in:

```rust,no_run
use std::{env, error::Error};
use twilight_gateway::{Intents, Shard, ShardId};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // Initialize the tracing subscriber.
    tracing_subscriber::fmt::init();

    let token = env::var("DISCORD_TOKEN")?;
    let intents = Intents::GUILD_MESSAGES;
    let mut shard = Shard::new(ShardId::ONE, token, intents);
    tracing::info!("created shard");

    loop {
        let event = match shard.next_event().await {
            Ok(event) => event,
            Err(source) => {
                tracing::warn!(?source, "error receiving event");

                if source.is_fatal() {
                    break;
                }

                continue;
            }
        };

        tracing::debug!(?event, "event");
    }

    Ok(())
}
```

## Links

*source*: <https://github.com/twilight-rs/twilight/tree/main/twilight-gateway>

*docs*: <https://docs.rs/twilight-gateway>

*crates.io*: <https://crates.io/crates/twilight-gateway>

[img:shard]: ./section_3_shard.png
[RusTLS]: https://crates.io/crates/rustls
[cmake]: https://cmake.org/
[flate2]: https://github.com/alexcrichton/flate2-rs
[zlib-ng]: https://github.com/zlib-ng/zlib-ng
[`hyper-rustls`]: https://crates.io/crates/hyper-rustls
[`hyper-tls`]: https://crates.io/crates/hyper-tls
[`serde_json`]: https://crates.io/crates/serde_json
[`simd-json`]: https://crates.io/crates/simd-json
[`tokio-tungstenite`]: https://crates.io/crates/tokio-tungstenite
