use twilight_gateway::{cluster::{Cluster, ShardScheme}, Intents};

use futures::StreamExt;
use std::{env, error::Error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // Initialize the tracing subscriber.
    tracing_subscriber::fmt::init();

    // This is also the default.
    let scheme = ShardScheme::Auto;

    let intents = Intents::GUILD_MESSAGES
        | Intents::GUILD_MESSAGE_REACTIONS
        | Intents::GUILD_MESSAGE_TYPING;
    let cluster = Cluster::builder(env::var("DISCORD_TOKEN")?, intents)
        .shard_scheme(scheme)
        .build()
        .await?;

    let mut events = cluster.events();

    let cluster_spawn = cluster.clone();

    tokio::spawn(async move {
        cluster_spawn.up().await;
    });

    while let Some((id, event)) = events.next().await {
        println!("Shard: {}, Event: {:?}", id, event.kind());
    }

    Ok(())
}
