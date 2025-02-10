//! Primary logic and implementation details of Discord gateway websocket
//! connections.
//!
//! Shards are, at their heart, a websocket connection with some state for
//! maintaining an identified session with the Discord gateway. For more
//! information about what a shard is in the context of Discord's gateway API,
//! refer to the documentation for [`Shard`].

#[cfg(feature = "zstd")]
use crate::compression::Decompressor;
#[allow(deprecated)]
#[cfg(all(
    any(feature = "zlib-stock", feature = "zlib-simd"),
    not(feature = "zstd")
))]
use crate::inflater::Inflater;
use crate::{
    channel::{MessageChannel, MessageSender},
    error::{ReceiveMessageError, ReceiveMessageErrorType},
    json,
    latency::Latency,
    queue::{InMemoryQueue, Queue},
    ratelimiter::CommandRatelimiter,
    session::Session,
    Command, Config, Message, ShardId, API_VERSION,
};
use futures_core::Stream;
use futures_sink::Sink;
use serde::{de::DeserializeOwned, Deserialize};
#[cfg(any(
    feature = "native-tls",
    feature = "rustls-native-roots",
    feature = "rustls-platform-verifier",
    feature = "rustls-webpki-roots"
))]
use std::io::ErrorKind as IoErrorKind;
use std::{
    env::consts::OS,
    fmt,
    future::Future,
    pin::Pin,
    str,
    task::{ready, Context, Poll},
};
use tokio::{
    net::TcpStream,
    sync::oneshot,
    time::{self, Duration, Instant, Interval, MissedTickBehavior},
};
use tokio_websockets::{ClientBuilder, Error as WebsocketError, Limits, MaybeTlsStream};
use twilight_model::gateway::{
    event::GatewayEventDeserializer,
    payload::{
        incoming::Hello,
        outgoing::{
            identify::{IdentifyInfo, IdentifyProperties},
            Heartbeat, Identify, Resume,
        },
    },
    CloseCode, CloseFrame, Intents, OpCode,
};

/// URL of the Discord gateway.
const GATEWAY_URL: &str = "wss://gateway.discord.gg";

/// Query argument depending on enabled compression features.
const COMPRESSION_FEATURES: &str = if cfg!(feature = "zstd") {
    "&compress=zstd-stream"
} else if cfg!(feature = "zlib-stock") || cfg!(feature = "zlib-simd") {
    "&compress=zlib-stream"
} else {
    ""
};

/// [`tokio_websockets`] library Websocket connection.
type Connection = tokio_websockets::WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Wrapper struct around an `async fn` with a `Debug` implementation.
struct ConnectionFuture(Pin<Box<dyn Future<Output = Result<Connection, WebsocketError>> + Send>>);

impl fmt::Debug for ConnectionFuture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ConnectionFuture")
            .field(&"<async fn>")
            .finish()
    }
}

/// Close initiator of a websocket connection.
#[derive(Clone, Debug)]
enum CloseInitiator {
    /// Gateway initiated the close.
    ///
    /// Contains an optional close code.
    Gateway(Option<u16>),
    /// Shard initiated the close.
    ///
    /// Contains a close code.
    Shard(CloseFrame<'static>),
    /// Transport error initiated the close.
    Transport,
}

/// Current state of a [Shard].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShardState {
    /// Shard is connected to the gateway with an active session.
    Active,
    /// Shard is disconnected from the gateway but may reconnect in the future.
    ///
    /// The websocket connection may still be open.
    Disconnected {
        /// Number of reconnection attempts that have been made.
        reconnect_attempts: u8,
    },
    /// Shard has fatally closed.
    ///
    /// Possible reasons may be due to [failed authentication],
    /// [invalid intents], or other reasons. Refer to the documentation for
    /// [`CloseCode`] for possible reasons.
    ///
    /// [failed authentication]: CloseCode::AuthenticationFailed
    /// [invalid intents]: CloseCode::InvalidIntents
    FatallyClosed,
    /// Shard is waiting to establish or resume a session.
    Identifying,
    /// Shard is replaying missed dispatch events.
    ///
    /// The shard is considered identified whilst resuming.
    Resuming,
}

impl ShardState {
    /// Determine the connection status from the close code.
    ///
    /// Defers to [`CloseCode::can_reconnect`] to determine whether the
    /// connection can be reconnected, defaulting to [`Self::Disconnected`] if
    /// the close code is unknown.
    fn from_close_code(close_code: Option<u16>) -> Self {
        match close_code.map(CloseCode::try_from) {
            Some(Ok(close_code)) if !close_code.can_reconnect() => Self::FatallyClosed,
            _ => Self::Disconnected {
                reconnect_attempts: 0,
            },
        }
    }

    /// Whether the shard has disconnected but may reconnect in the future.
    const fn is_disconnected(self) -> bool {
        matches!(self, Self::Disconnected { .. })
    }

    /// Whether the shard is identified with an active session.
    ///
    /// `true` if the status is [`Active`] or [`Resuming`].
    ///
    /// [`Active`]: Self::Active
    /// [`Resuming`]: Self::Resuming
    pub const fn is_identified(self) -> bool {
        matches!(self, Self::Active | Self::Resuming)
    }
}

/// Gateway event with only minimal required data.
#[derive(Deserialize)]
struct MinimalEvent<T> {
    /// Attached data of the gateway event.
    #[serde(rename = "d")]
    data: T,
}

/// Minimal [`Ready`] for light deserialization.
///
/// [`Ready`]: twilight_model::gateway::payload::incoming::Ready
#[derive(Deserialize)]
struct MinimalReady {
    /// Used for resuming connections.
    resume_gateway_url: Box<str>,
    /// ID of the new identified session.
    session_id: String,
}

/// Pending outgoing message indicator.
#[derive(Debug)]
struct Pending {
    /// The pending message, if not already sent.
    gateway_event: Option<Message>,
    /// Whether the pending gateway event is a heartbeat.
    is_heartbeat: bool,
}

impl Pending {
    /// Constructor for a pending gateway event.
    const fn text(json: String, is_heartbeat: bool) -> Option<Self> {
        Some(Self {
            gateway_event: Some(Message::Text(json)),
            is_heartbeat,
        })
    }
}

/// Gateway API client responsible for up to 2500 guilds.
///
/// Shards are responsible for maintaining the gateway connection by processing
/// events relevant to the operation of shards---such as requests from the
/// gateway to re-connect or invalidate a session---and then to pass them on to
/// the user.
///
/// Shards start out disconnected, but will on the first successful call to
/// [`poll_next`] try to reconnect to the gateway. [`poll_next`] must then
/// be repeatedly called in order for the shard to maintain its connection and
/// update its internal state.
///
/// Shards go through an [identify queue][`queue`] that rate limits concurrent
/// `Identify` events (across all shards) per 5 seconds. Exceeding this limit
/// invalidates the shard's session and it is therefore **very important** to
/// reuse the same queue for all shards.
///
/// # Sharding
///
/// A shard may not be connected to more than 2500 guilds, so large bots must
/// split themselves across multiple shards. See the
/// [Discord Docs/Sharding][docs:sharding] and [`ShardId`] documentation for
/// more info.
///
/// # Examples
///
/// Create and start a shard and print new and deleted messages:
///
/// ```no_run
/// use std::env;
/// use twilight_gateway::{Event, EventTypeFlags, Intents, Shard, ShardId, StreamExt as _};
///
/// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Use the value of the "DISCORD_TOKEN" environment variable as the bot's
/// // token. Of course, this value may be passed into the program however is
/// // preferred.
/// let token = env::var("DISCORD_TOKEN")?;
/// let wanted_event_types = EventTypeFlags::MESSAGE_CREATE | EventTypeFlags::MESSAGE_DELETE;
///
/// let mut shard = Shard::new(ShardId::ONE, token, Intents::GUILD_MESSAGES);
///
/// while let Some(item) = shard.next_event(EventTypeFlags::all()).await {
///     let Ok(event) = item else {
///         tracing::warn!(source = ?item.unwrap_err(), "error receiving event");
///
///         continue;
///     };
///
///     match event {
///         Event::MessageCreate(message) => {
///             println!("message received with content: {}", message.content);
///         }
///         Event::MessageDelete(message) => {
///             println!("message with ID {} deleted", message.id);
///         }
///         _ => {}
///     }
/// }
/// # Ok(()) }
/// ```
///
/// [docs:sharding]: https://discord.com/developers/docs/topics/gateway#sharding
/// [gateway commands]: Shard::command
/// [`poll_next`]: Shard::poll_next
/// [`queue`]: crate::queue
#[derive(Debug)]
pub struct Shard<Q = InMemoryQueue> {
    /// User provided configuration.
    ///
    /// Configurations are provided or created in shard initializing via
    /// [`Shard::new`] or [`Shard::with_config`].
    config: Config<Q>,
    /// Future to establish a WebSocket connection with the Gateway.
    connection_future: Option<ConnectionFuture>,
    /// Websocket connection, which may be connected to Discord's gateway.
    ///
    /// The connection should only be dropped after it has returned `Ok(None)`
    /// to comply with the WebSocket protocol.
    connection: Option<Connection>,
    /// Zstd decompressor.
    #[cfg(feature = "zstd")]
    decompressor: Decompressor,
    /// Interval of how often the gateway would like the shard to send
    /// heartbeats.
    ///
    /// The interval is received in the [`GatewayEvent::Hello`] event when
    /// first opening a new [connection].
    ///
    /// [`GatewayEvent::Hello`]: twilight_model::gateway::event::GatewayEvent::Hello
    /// [connection]: Self::connection
    heartbeat_interval: Option<Interval>,
    /// Whether an event has been received in the current heartbeat interval.
    heartbeat_interval_event: bool,
    /// ID of the shard.
    id: ShardId,
    /// Identify queue receiver.
    identify_rx: Option<oneshot::Receiver<()>>,
    /// Zlib decompressor.
    #[allow(deprecated)]
    #[cfg(all(
        any(feature = "zlib-stock", feature = "zlib-simd"),
        not(feature = "zstd")
    ))]
    inflater: Inflater,
    /// Potentially pending outgoing message.
    pending: Option<Pending>,
    /// Recent heartbeat latency statistics.
    ///
    /// The latency is reset on receiving [`GatewayEvent::Hello`] as the host
    /// may have changed, invalidating previous latency statistic.
    ///
    /// [`GatewayEvent::Hello`]: twilight_model::gateway::event::GatewayEvent::Hello
    latency: Latency,
    /// Command ratelimiter, if it was enabled via
    /// [`Config::ratelimit_messages`].
    ratelimiter: Option<CommandRatelimiter>,
    /// Used for resuming connections.
    resume_url: Option<Box<str>>,
    /// Active session of the shard.
    ///
    /// The shard may not have an active session if it hasn't yet identified and
    /// received a `READY` dispatch event response.
    session: Option<Session>,
    /// Current state of the shard.
    state: ShardState,
    /// Messages from the user to be relayed and sent over the Websocket
    /// connection.
    user_channel: MessageChannel,
}

impl Shard {
    /// Create a new shard with the default configuration.
    pub fn new(id: ShardId, token: String, intents: Intents) -> Self {
        Self::with_config(id, Config::new(token, intents))
    }
}

impl<Q> Shard<Q> {
    /// Create a new shard with the provided configuration.
    pub fn with_config(shard_id: ShardId, mut config: Config<Q>) -> Self {
        let session = config.take_session();
        let mut resume_url = config.take_resume_url();
        //ensure resume_url is only used if we have a session to resume
        if session.is_none() {
            resume_url = None;
        }

        Self {
            config,
            connection_future: None,
            connection: None,
            #[cfg(feature = "zstd")]
            decompressor: Decompressor::new(),
            heartbeat_interval: None,
            heartbeat_interval_event: false,
            id: shard_id,
            identify_rx: None,
            #[allow(deprecated)]
            #[cfg(all(
                any(feature = "zlib-stock", feature = "zlib-simd"),
                not(feature = "zstd")
            ))]
            inflater: Inflater::new(),
            pending: None,
            latency: Latency::new(),
            ratelimiter: None,
            resume_url,
            session,
            state: ShardState::Disconnected {
                reconnect_attempts: 0,
            },
            user_channel: MessageChannel::new(),
        }
    }

    /// Immutable reference to the configuration used to instantiate this shard.
    pub const fn config(&self) -> &Config<Q> {
        &self.config
    }

    /// ID of the shard.
    pub const fn id(&self) -> ShardId {
        self.id
    }

    /// Zlib decompressor statistics.
    ///
    /// Reset when reconnecting to the gateway.
    #[allow(deprecated)]
    #[cfg(all(
        any(feature = "zlib-stock", feature = "zlib-simd"),
        not(feature = "zstd")
    ))]
    #[deprecated(since = "0.16.1", note = "replaced by zstd compression")]
    pub const fn inflater(&self) -> &Inflater {
        &self.inflater
    }

    /// State of the shard.
    pub const fn state(&self) -> ShardState {
        self.state
    }

    /// Shard latency statistics, including average latency and recent heartbeat
    /// latency times.
    ///
    /// Reset when reconnecting to the gateway.
    pub const fn latency(&self) -> &Latency {
        &self.latency
    }

    /// Statistics about the number of available commands and when the command
    /// ratelimiter will refresh.
    ///
    /// This won't be present if ratelimiting was disabled via
    /// [`ConfigBuilder::ratelimit_messages`] or if the shard is disconnected.
    ///
    /// [`ConfigBuilder::ratelimit_messages`]: crate::ConfigBuilder::ratelimit_messages
    pub const fn ratelimiter(&self) -> Option<&CommandRatelimiter> {
        self.ratelimiter.as_ref()
    }

    /// Immutable reference to the gateways current resume URL.
    ///
    /// A resume URL might not be present if the shard had its session
    /// invalidated and has not yet reconnected.
    pub fn resume_url(&self) -> Option<&str> {
        self.resume_url.as_deref()
    }

    /// Immutable reference to the active gateway session.
    ///
    /// An active session may not be present if the shard had its session
    /// invalidated and has not yet reconnected.
    pub const fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// Queue a command to be sent to the gateway.
    ///
    /// Serializes the command and then calls [`send`].
    ///
    /// [`send`]: Self::send
    #[allow(clippy::missing_panics_doc)]
    pub fn command(&self, command: &impl Command) {
        self.send(json::to_string(command).expect("serialization cannot fail"));
    }

    /// Queue a JSON encoded gateway event to be sent to the gateway.
    #[allow(clippy::missing_panics_doc)]
    pub fn send(&self, json: String) {
        self.user_channel
            .command_tx
            .send(json)
            .expect("channel open");
    }

    /// Queue a websocket close frame.
    ///
    /// Invalidates the session and shows the application's bot as offline if
    /// the close frame code is `1000` or `1001`. Otherwise Discord will
    /// continue showing the bot as online until its presence times out.
    ///
    /// To read all remaining messages, continue calling [`poll_next`] until it
    /// returns [`Message::Close`].
    ///
    /// # Example
    ///
    /// Close the shard and process remaining messages:
    ///
    /// ```no_run
    /// # use twilight_gateway::{Intents, Shard, ShardId};
    /// # #[tokio::main] async fn main() {
    /// # let mut shard = Shard::new(ShardId::ONE, String::new(), Intents::empty());
    /// use tokio_stream::StreamExt;
    /// use twilight_gateway::{error::ReceiveMessageErrorType, CloseFrame, Message};
    ///
    /// shard.close(CloseFrame::NORMAL);
    ///
    /// while let Some(item) = shard.next().await {
    ///     match item {
    ///         Ok(Message::Close(_)) => break,
    ///         Ok(Message::Text(_)) => unimplemented!(),
    ///         Err(source) => unimplemented!(),
    ///     }
    /// }
    /// # }
    /// ```
    ///
    /// [`poll_next`]: Shard::poll_next
    pub fn close(&self, close_frame: CloseFrame<'static>) {
        _ = self.user_channel.close_tx.try_send(close_frame);
    }

    /// Retrieve a channel to send messages over the shard to the gateway.
    ///
    /// This is primarily useful for sending to other tasks and threads where
    /// the shard won't be available.
    ///
    /// # Example
    ///
    /// Queue a command in another process:
    ///
    /// ```no_run
    /// # use twilight_gateway::{Intents, Shard, ShardId};
    /// # #[tokio::main] async fn main() {
    /// # let mut shard = Shard::new(ShardId::ONE, String::new(), Intents::empty());
    /// use tokio_stream::StreamExt;
    ///
    /// while let Some(item) = shard.next().await {
    ///     match item {
    ///         Ok(message) => {
    ///             let sender = shard.sender();
    ///             tokio::spawn(async move {
    ///                 let command = unimplemented!();
    ///                 sender.send(command);
    ///             });
    ///         }
    ///         Err(source) => unimplemented!(),
    ///     }
    /// }
    /// # }
    /// ```
    pub fn sender(&self) -> MessageSender {
        self.user_channel.sender()
    }

    /// Update internal state from gateway disconnect.
    fn disconnect(&mut self, initiator: CloseInitiator) {
        // May not send any additional WebSocket messages.
        self.heartbeat_interval = None;
        self.ratelimiter = None;
        // Abort identify.
        self.identify_rx = None;
        self.state = match initiator {
            CloseInitiator::Gateway(close_code) => ShardState::from_close_code(close_code),
            _ => ShardState::Disconnected {
                reconnect_attempts: 0,
            },
        };
        if let CloseInitiator::Shard(frame) = initiator {
            // Not resuming, drop session and resume URL.
            // https://discord.com/developers/docs/topics/gateway#initiating-a-disconnect
            if matches!(frame.code, 1000 | 1001) {
                self.resume_url = None;
                self.session = None;
            }
            self.pending = Some(Pending {
                gateway_event: Some(Message::Close(Some(frame))),
                is_heartbeat: false,
            });
        }
    }

    /// Parse a JSON message into an event with minimal data for [processing].
    ///
    /// # Errors
    ///
    /// Returns a [`ReceiveMessageErrorType::Deserializing`] error type if the gateway
    /// event isn't a recognized structure, which may be the case for new or
    /// undocumented events.
    ///
    /// [processing]: Self::process
    fn parse_event<T: DeserializeOwned>(
        json: &str,
    ) -> Result<MinimalEvent<T>, ReceiveMessageError> {
        json::from_str::<MinimalEvent<T>>(json).map_err(|source| ReceiveMessageError {
            kind: ReceiveMessageErrorType::Deserializing {
                event: json.to_owned(),
            },
            source: Some(Box::new(source)),
        })
    }
}

impl<Q: Queue> Shard<Q> {
    /// Attempts to send due commands to the gateway.
    ///
    /// # Returns
    ///
    /// * `Poll::Pending` if sending is in progress
    /// * `Poll::Ready(Ok)` if no more scheduled commands remain
    /// * `Poll::Ready(Err)` if sending a command failed.
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), WebsocketError>> {
        loop {
            if let Some(pending) = self.pending.as_mut() {
                ready!(Pin::new(self.connection.as_mut().unwrap()).poll_ready(cx))?;

                if let Some(message) = &pending.gateway_event {
                    if let Some(ratelimiter) = self.ratelimiter.as_mut() {
                        if message.is_text() && !pending.is_heartbeat {
                            ready!(ratelimiter.poll_acquire(cx));
                        }
                    }

                    let ws_message = pending.gateway_event.take().unwrap().into_websocket_msg();
                    Pin::new(self.connection.as_mut().unwrap()).start_send(ws_message)?;
                }

                ready!(Pin::new(self.connection.as_mut().unwrap()).poll_flush(cx))?;

                if pending.is_heartbeat {
                    self.latency.record_sent();
                }
                self.pending = None;
            }

            if !self.state.is_disconnected() {
                if let Poll::Ready(frame) = self.user_channel.close_rx.poll_recv(cx) {
                    let frame = frame.expect("shard owns channel");

                    tracing::debug!("sending close frame from user channel");
                    self.disconnect(CloseInitiator::Shard(frame));

                    continue;
                }
            }

            if self
                .heartbeat_interval
                .as_mut()
                .is_some_and(|heartbeater| heartbeater.poll_tick(cx).is_ready())
            {
                // Discord never responded after the last heartbeat, connection
                // is failed or "zombied", see
                // https://discord.com/developers/docs/topics/gateway#heartbeat-interval-example-heartbeat-ack
                // Note that unlike documented *any* event is okay; it does not
                // have to be a heartbeat ACK.
                if self.latency.sent().is_some() && !self.heartbeat_interval_event {
                    tracing::info!("connection is failed or \"zombied\"");
                    self.disconnect(CloseInitiator::Shard(CloseFrame::RESUME));
                } else {
                    tracing::debug!("sending heartbeat");
                    self.pending = Pending::text(
                        json::to_string(&Heartbeat::new(self.session().map(Session::sequence)))
                            .expect("serialization cannot fail"),
                        true,
                    );
                    self.heartbeat_interval_event = false;
                }

                continue;
            }

            let not_ratelimited = self.ratelimiter.as_mut().map_or(true, |ratelimiter| {
                ratelimiter.poll_available(cx).is_ready()
            });

            if not_ratelimited {
                if let Some(Poll::Ready(canceled)) = self
                    .identify_rx
                    .as_mut()
                    .map(|rx| Pin::new(rx).poll(cx).map(|r| r.is_err()))
                {
                    if canceled {
                        self.identify_rx = Some(self.config.queue().enqueue(self.id.number()));
                        continue;
                    }

                    tracing::debug!("sending identify");

                    self.pending = Pending::text(
                        json::to_string(&Identify::new(IdentifyInfo {
                            compress: false,
                            intents: self.config.intents(),
                            large_threshold: self.config.large_threshold(),
                            presence: self.config.presence().cloned(),
                            properties: self
                                .config
                                .identify_properties()
                                .cloned()
                                .unwrap_or_else(default_identify_properties),
                            shard: Some(self.id),
                            token: self.config.token().to_owned(),
                        }))
                        .expect("serialization cannot fail"),
                        false,
                    );
                    self.identify_rx = None;

                    continue;
                }
            }

            if not_ratelimited && self.state.is_identified() {
                if let Poll::Ready(command) = self.user_channel.command_rx.poll_recv(cx) {
                    let command = command.expect("shard owns channel");

                    tracing::debug!("sending command from user channel");
                    self.pending = Some(Pending {
                        gateway_event: Some(Message::Text(command)),
                        is_heartbeat: false,
                    });

                    continue;
                }
            }

            return Poll::Ready(Ok(()));
        }
    }

    /// Updates the shard's internal state from a gateway event by recording
    /// and/or responding to certain Discord events.
    ///
    /// # Errors
    ///
    /// Returns a [`ReceiveMessageErrorType::Deserializing`] error type if the
    /// gateway event isn't a recognized structure.
    #[allow(clippy::too_many_lines)]
    fn process(&mut self, event: &str) -> Result<(), ReceiveMessageError> {
        let (raw_opcode, maybe_sequence, maybe_event_type) =
            GatewayEventDeserializer::from_json(event)
                .ok_or_else(|| ReceiveMessageError {
                    kind: ReceiveMessageErrorType::Deserializing {
                        event: event.to_owned(),
                    },
                    source: Some("missing opcode".into()),
                })?
                .into_parts();

        if self.latency.sent().is_some() {
            self.heartbeat_interval_event = true;
        }

        match OpCode::from(raw_opcode) {
            Some(OpCode::Dispatch) => {
                let event_type = maybe_event_type.ok_or_else(|| ReceiveMessageError {
                    kind: ReceiveMessageErrorType::Deserializing {
                        event: event.to_owned(),
                    },
                    source: Some("missing dispatch event type".into()),
                })?;
                let sequence = maybe_sequence.ok_or_else(|| ReceiveMessageError {
                    kind: ReceiveMessageErrorType::Deserializing {
                        event: event.to_owned(),
                    },
                    source: Some("missing sequence".into()),
                })?;
                tracing::debug!(%event_type, %sequence, "received dispatch");

                match event_type.as_ref() {
                    "READY" => {
                        let event = Self::parse_event::<MinimalReady>(event)?;

                        self.resume_url = Some(event.data.resume_gateway_url);
                        self.session = Some(Session::new(sequence, event.data.session_id));
                        self.state = ShardState::Active;
                    }
                    "RESUMED" => self.state = ShardState::Active,
                    _ => {}
                }

                if let Some(session) = self.session.as_mut() {
                    session.set_sequence(sequence);
                }
            }
            Some(OpCode::Heartbeat) => {
                tracing::debug!("received heartbeat");
                self.pending = Pending::text(
                    json::to_string(&Heartbeat::new(self.session().map(Session::sequence)))
                        .expect("serialization cannot fail"),
                    true,
                );
            }
            Some(OpCode::HeartbeatAck) => {
                let requested = self.latency.received().is_none() && self.latency.sent().is_some();
                if requested {
                    tracing::debug!("received heartbeat ack");
                    self.latency.record_received();
                } else {
                    tracing::info!("received unrequested heartbeat ack");
                }
            }
            Some(OpCode::Hello) => {
                let event = Self::parse_event::<Hello>(event)?;
                let heartbeat_interval = Duration::from_millis(event.data.heartbeat_interval);
                // First heartbeat should have some jitter, see
                // https://discord.com/developers/docs/topics/gateway#heartbeat-interval
                let jitter = heartbeat_interval.mul_f64(fastrand::f64());
                tracing::debug!(?heartbeat_interval, ?jitter, "received hello");

                if self.config().ratelimit_messages() {
                    self.ratelimiter = Some(CommandRatelimiter::new(heartbeat_interval));
                }

                let mut interval = time::interval_at(Instant::now() + jitter, heartbeat_interval);
                interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
                self.heartbeat_interval = Some(interval);

                // Reset `Latency` since the shard might have connected to a new
                // remote which invalidates the recorded latencies.
                self.latency = Latency::new();

                if let Some(session) = &self.session {
                    self.pending = Pending::text(
                        json::to_string(&Resume::new(
                            session.sequence(),
                            session.id(),
                            self.config.token(),
                        ))
                        .expect("serialization cannot fail"),
                        false,
                    );
                    self.state = ShardState::Resuming;
                } else {
                    self.identify_rx = Some(self.config.queue().enqueue(self.id.number()));
                }
            }
            Some(OpCode::InvalidSession) => {
                let resumable = Self::parse_event(event)?.data;
                tracing::debug!(resumable, "received invalid session");
                if resumable {
                    self.disconnect(CloseInitiator::Shard(CloseFrame::RESUME));
                } else {
                    self.disconnect(CloseInitiator::Shard(CloseFrame::NORMAL));
                }
            }
            Some(OpCode::Reconnect) => {
                tracing::debug!("received reconnect");
                self.disconnect(CloseInitiator::Shard(CloseFrame::RESUME));
            }
            _ => tracing::info!("received an unknown opcode: {raw_opcode}"),
        }

        Ok(())
    }
}

impl<Q: Queue + Unpin> Stream for Shard<Q> {
    type Item = Result<Message, ReceiveMessageError>;

    #[allow(clippy::too_many_lines)]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let message = loop {
            match self.state {
                ShardState::FatallyClosed => {
                    _ = ready!(Pin::new(
                        self.connection
                            .as_mut()
                            .expect("poll_next called after Poll::Ready(None)")
                    )
                    .poll_close(cx));
                    self.connection = None;
                    return Poll::Ready(None);
                }
                ShardState::Disconnected { reconnect_attempts } if self.connection.is_none() => {
                    if self.connection_future.is_none() {
                        let base_url = self
                            .resume_url
                            .as_deref()
                            .or_else(|| self.config.proxy_url())
                            .unwrap_or(GATEWAY_URL);
                        let uri = format!(
                            "{base_url}/?v={API_VERSION}&encoding=json{COMPRESSION_FEATURES}"
                        );

                        tracing::debug!(url = base_url, "connecting to gateway");

                        let tls = self.config.tls.clone();
                        self.connection_future = Some(ConnectionFuture(Box::pin(async move {
                            let secs = 2u8.saturating_pow(reconnect_attempts.into());
                            time::sleep(Duration::from_secs(secs.into())).await;

                            Ok(ClientBuilder::new()
                                .uri(&uri)
                                .expect("URL should be valid")
                                .limits(Limits::unlimited())
                                .connector(&tls)
                                .connect()
                                .await?
                                .0)
                        })));
                    }

                    let res =
                        ready!(Pin::new(&mut self.connection_future.as_mut().unwrap().0).poll(cx));
                    self.connection_future = None;
                    match res {
                        Ok(connection) => {
                            self.connection = Some(connection);
                            self.state = ShardState::Identifying;
                            #[cfg(feature = "zstd")]
                            self.decompressor.reset();
                            #[allow(deprecated)]
                            #[cfg(all(
                                not(feature = "zstd"),
                                any(feature = "zlib-stock", feature = "zlib-simd")
                            ))]
                            self.inflater.reset();
                        }
                        Err(source) => {
                            self.resume_url = None;
                            self.state = ShardState::Disconnected {
                                reconnect_attempts: reconnect_attempts + 1,
                            };

                            return Poll::Ready(Some(Err(ReceiveMessageError {
                                kind: ReceiveMessageErrorType::Reconnect,
                                source: Some(Box::new(source)),
                            })));
                        }
                    }
                }
                _ => {}
            }

            if ready!(self.poll_send(cx)).is_err() {
                self.disconnect(CloseInitiator::Transport);
                self.connection = None;

                return Poll::Ready(Some(Ok(Message::ABNORMAL_CLOSE)));
            }

            match ready!(Pin::new(self.connection.as_mut().unwrap()).poll_next(cx)) {
                Some(Ok(message)) => {
                    #[cfg(feature = "zstd")]
                    if message.is_binary() {
                        match self.decompressor.decompress(message.as_payload()) {
                            Ok(message) => break Message::Text(message),
                            Err(source) => {
                                self.disconnect(CloseInitiator::Shard(CloseFrame::RESUME));
                                return Poll::Ready(Some(Err(
                                    ReceiveMessageError::from_compression(source),
                                )));
                            }
                        }
                    }
                    #[cfg(all(
                        not(feature = "zstd"),
                        any(feature = "zlib-stock", feature = "zlib-simd")
                    ))]
                    if message.is_binary() {
                        match self.inflater.inflate(message.as_payload()) {
                            Ok(Some(message)) => break Message::Text(message),
                            Ok(None) => continue,
                            Err(source) => {
                                self.disconnect(CloseInitiator::Shard(CloseFrame::RESUME));
                                return Poll::Ready(Some(Err(
                                    ReceiveMessageError::from_compression(source),
                                )));
                            }
                        }
                    }
                    if let Some(message) = Message::from_websocket_msg(&message) {
                        break message;
                    }
                }
                // Discord, against recommendations from the WebSocket spec,
                // does not send a close_notify prior to shutting down the TCP
                // stream. This arm tries to gracefully handle this. The
                // connection is considered unusable after encountering an io
                // error, returning `None`.
                #[cfg(any(
                    feature = "native-tls",
                    feature = "rustls-native-roots",
                    feature = "rustls-platform-verifier",
                    feature = "rustls-webpki-roots"
                ))]
                Some(Err(WebsocketError::Io(e)))
                    if e.kind() == IoErrorKind::UnexpectedEof
                        && self.config.proxy_url().is_none()
                        && self.state.is_disconnected() =>
                {
                    continue
                }
                Some(Err(_)) => {
                    self.disconnect(CloseInitiator::Transport);
                    return Poll::Ready(Some(Ok(Message::ABNORMAL_CLOSE)));
                }
                None => {
                    _ = ready!(Pin::new(self.connection.as_mut().unwrap()).poll_close(cx));
                    tracing::debug!("gateway WebSocket connection closed");
                    // Unclean closure.
                    if !self.state.is_disconnected() {
                        self.disconnect(CloseInitiator::Transport);
                    }
                    self.connection = None;
                }
            }
        };

        match &message {
            Message::Close(frame) => {
                // tokio-websockets automatically replies to the close message.
                tracing::debug!(?frame, "received WebSocket close message");
                // Don't run `disconnect` if we initiated the close.
                if !self.state.is_disconnected() {
                    self.disconnect(CloseInitiator::Gateway(frame.as_ref().map(|f| f.code)));
                }
            }
            Message::Text(event) => {
                self.process(event)?;
            }
        }

        Poll::Ready(Some(Ok(message)))
    }
}

/// Default identify properties to use when the user hasn't customized it in
/// [`Config::identify_properties`].
///
/// [`Config::identify_properties`]: Config::identify_properties
fn default_identify_properties() -> IdentifyProperties {
    IdentifyProperties::new("twilight.rs", "twilight.rs", OS)
}

#[cfg(test)]
mod tests {
    use super::Shard;
    use static_assertions::{assert_impl_all, assert_not_impl_any};
    use std::fmt::Debug;

    assert_impl_all!(Shard: Debug, Send);
    assert_not_impl_any!(Shard: Sync);
}
