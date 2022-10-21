//! Various utility futures used by the [`Shard`].
//!
//! These tend to be used to get around lifetime and borrow requirements, but
//! are also sometimes used to simplify logic.
//!
//! [`Shard`]: crate::Shard

use crate::{connection::Connection, message::Message, CommandRatelimiter};
use futures_util::{future::FutureExt, stream::Next};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    sync::mpsc::UnboundedReceiver,
    time::{self, Duration, Interval},
};
use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;

/// Resolved value from polling a [`NextMessageFuture`].
///
/// **Be sure** to keep variants in sync with documented precedence in
/// [`NextMessageFuture`]!
pub enum NextMessageFutureOutput {
    /// Message has been received from the Websocket connection.
    ///
    /// If no message is present then the stream has ended and a new connection
    /// will need to be made.
    Message(Option<TungsteniteMessage>),
    /// Heartbeat must now be sent to Discord.
    SendHeartbeat,
    /// Message has been received from the user to be relayed over the Websocket
    /// connection.
    UserChannelMessage(Message),
}

/// Future to determine the next action when [`Shard::next_message`] is called.
///
/// Polled futures are given a consistent precedence, from first to last polled:
///
/// - [sending a heartbeat to Discord][1];
/// - [relaying a user's message][2] over the Websocket message;
/// - [receiving a message][3] from Discord
///
/// **Be sure** to keep documented precedence in sync with variants in
/// [`NextMessageFutureOutput`]!
///
/// [1]: NextMessageFutureOutput::SendHeartbeat
/// [2]: NextMessageFutureOutput::UserChannelMessage
/// [3]: NextMessageFutureOutput::Message
/// [`Shard::next_message`]: crate::Shard::next_message
pub struct NextMessageFuture<'a> {
    /// Future resolving when the user has sent a message over the channel, to
    /// be relayed over the Websocket connection.
    channel_receive_future: &'a mut UnboundedReceiver<Message>,
    /// Future resolving when the next Websocket message has been received.
    message_future: Next<'a, Connection>,
    /// Command ratelimiter, if enabled.
    maybe_ratelimiter: Option<&'a mut CommandRatelimiter>,
    /// Future resolving when the [`Shard`] must sent a heartbeat.
    ///
    /// [`Shard`]: crate::Shard
    tick_heartbeat_future: Option<&'a mut Interval>,
}

impl<'a> NextMessageFuture<'a> {
    /// Initialize a new series of futures determining the next action to take.
    pub fn new(
        rx: &'a mut UnboundedReceiver<Message>,
        message_future: Next<'a, Connection>,
        maybe_ratelimiter: Option<&'a mut CommandRatelimiter>,
        maybe_heartbeat_interval: Option<&'a mut Interval>,
    ) -> Self {
        Self {
            channel_receive_future: rx,
            message_future,
            maybe_ratelimiter,
            tick_heartbeat_future: maybe_heartbeat_interval,
        }
    }
}

impl Future for NextMessageFuture<'_> {
    type Output = NextMessageFutureOutput;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.as_mut();

        if let Some(heartbeat_interval) = &mut this.tick_heartbeat_future {
            if heartbeat_interval.poll_tick(cx).is_ready() {
                return Poll::Ready(NextMessageFutureOutput::SendHeartbeat);
            }
        }

        let ratelimited = this
            .maybe_ratelimiter
            .as_mut()
            .map_or(false, |ratelimiter| {
                ratelimiter.poll_available(cx).is_pending()
            });

        if !ratelimited {
            if let Poll::Ready(maybe_message) = this.channel_receive_future.poll_recv(cx) {
                let message = maybe_message.expect("shard owns channel");

                return Poll::Ready(NextMessageFutureOutput::UserChannelMessage(message));
            }
        }

        if let Poll::Ready(maybe_try_message) = this.message_future.poll_unpin(cx) {
            let maybe_message = maybe_try_message.and_then(Result::ok);

            return Poll::Ready(NextMessageFutureOutput::Message(maybe_message));
        }

        Poll::Pending
    }
}

/// Future that will resolve when the delay for a reconnect passes.
///
/// The duration of the future is defined by the number of attempts at
/// reconnecting that have already been made. The math behind it is
/// `2 ^ attempts`, maxing out at `MAX_WAIT_SECONDS`.
pub async fn reconnect_delay(reconnect_attempts: u8) {
    /// The maximum wait before resolving, in seconds.
    const MAX_WAIT_SECONDS: u8 = 128;

    let wait = 2_u8
        .saturating_pow(reconnect_attempts.into())
        .min(MAX_WAIT_SECONDS);

    time::sleep(Duration::from_secs(wait.into())).await;
}
